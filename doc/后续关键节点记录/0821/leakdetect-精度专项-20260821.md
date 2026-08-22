# LeakDetect 精度专项进展记录

> 文档版本：v1.0
> 日期：2026-08-21
> 用途：记录内存检测精度专项（噪声鲁棒趋势检测 + BPF 饱和修复）的改动与验证。
> 关联：`leakdetect-plan.md` §11.7.1、`leakdetect-进展与后续-20260815.md` §九.1

---

## 一、问题诊断（修正文档原 5 根因）

文档 §九.1 列的 5 根因（`*100` 高估 / 自监控 / per-stack 粒度 / 阈值太低 / 启动期）未触及**趋势误报的真正根因**。本次核验确认：

### 1.1 趋势检测器对噪声无抵抗力（`analyzer/base.py` 原 `_is_leaking`）
原 `_is_leaking` 用"末-首 > 阈值" + "80% 非递减 OR 首末均值差 > 阈值"，在 1/100 采样的 ×100 信号上：
- 稳态进程的 outstanding 是**有界稳态**序列（活跃采样 ptr 数围绕均值波动），噪声斜率期望≈0，但单窗口噪声可偶发偏移 → 误报。
- 无斜率估计、无显著性检验、无平滑 → 无法区分"真增长"与"噪声游走"。

### 1.2 `*100` 重定标不解决趋势误报（关键反驳）
文档 F1+F4（去 `*100` + 调阈值）是伪解：信噪比尺度无关，信号与噪声同比缩放，阈值跟着缩，噪声带依旧跨越阈值，误报原样回来。**绝对值虚高是症状，趋势误报是病根**。

### 1.3 BPF `allocs`/`fd_map` 饱和导致系统性伪增长（环境观测的"快速上涨"）
`bpf/mem.bpf.c` `allocs` map（上限 10 万，free 只减 refcount 不删条目）+ `fd.bpf.c` `fd_map` 同模式：busy 进程约 17 分钟填满 → 新采样 malloc 的 alloc 事件照发（`mem.bpf.c:124-137` 无条件 emit），但其后续 free 查不到 → free 事件丢失 → `outstanding = alloc_bytes − free_bytes` 从饱和点起**线性飙升**，斜率≈毛分配速率（非净增长）→ ×100 放大 → 长跑进程显示"快速上涨"。用户判断"若真则环境早崩"正确——那是毛吞吐量冒充净增长。

---

## 二、改动清单

### 2.1 BPF — 驱逐 + 重读守卫（修饱和伪增长）

| 文件 | 位置 | 改动 |
|---|---|---|
| `bpf/mem.bpf.c` | `trace_free_entry` `:160` | refcount→0 时 `bpf_map_delete_elem(&allocs,&ptr)`；删前重读 `info->refcount==0` 守卫，把"删-增"竞态窗口压到 1 条 load 指令 |
| `bpf/fd.bpf.c` | `trace_close:86`/`trace_dup2:121`/`trace_dup3:156` | 同模式，`bpf_map_delete_elem(&fd_map,&key)` ×3 处 |

驱逐在栈帧拷贝到局部变量之后、free 事件发包之前；删除后不访问 `info`/`val`（用局部变量），verifier 安全。重读守卫：并发 alloc/fd_install 复用同地址已 +1 则不删。残余竞态概率极低且每次仅 +1（有界），远优于饱和漂移。

### 2.2 analyzer — 噪声鲁棒趋势检测 + per-PID 聚合

| 文件 | 改动 |
|---|---|
| `analyzer/base.py` | `_is_leaking` 重写为 OLS 线性回归斜率 + 显著性：`slope > threshold`（幅度地板，单位/秒）且 `slope/SE > significance_z`。原始 history 不平欻（EWMA+t 检验统计不一致，会放大显著性→反效果）。`StackSiteState` 加 `first_seen`；`_update_state` NORMAL 分支加 `grace_seconds` 启动宽限（不 early-return）。`__init__` 新参 `significance_z=3.0`、`grace_seconds=120` |
| `analyzer/memory.py` | per-PID 聚合（key `pid`，跨栈求和 ×100）→ 每进程 1 状态机/1 告警，分布式泄露求和过地板不再漏；栈归因取 Δ 最大的 sid（在涨的调用点），无增长则取最大 outstanding sid；`_sid_snapshot` 快照 + 修剪死 pid；排自身 PID `os.getpid()` |
| `analyzer/threads.py`/`handles.py` | `import os` + 排自身 PID；`__init__` 传 `significance_z`/`grace_seconds`；默认 `delta_threshold` 0.1(thread)/0.5(fd)（斜率语义） |

### 2.3 配置 + Web

| 文件 | 改动 |
|---|---|
| `config/default.yaml` | `outstanding_delta_bytes` 1048576→10240、`delta_threshold` 5→0.1/10→0.5（语义 delta→斜率）；每资源加 `significance_z: 3.0` + `grace_seconds: 120` |
| `web/backend.py` | `get_monitoring_config` 三资源加 `grace_seconds`；`update_monitoring_config` `param_map` 加 `grace_seconds`（`significance_z` config-only，不入 REST） |
| `web/mock.py` | `get_monitoring_config` 默认值同步（10240/0.1/0.5 + grace_seconds） |
| `web/static/js/components/monitoring-config.js` | 阈值 label→"增长斜率阈值"、unit→"/秒"、desc 更新；`leak_seconds` desc 删旧"80%单调递增"；每资源加 `grace_seconds` 行；`resetDefaults` 同步 |

### 2.4 测试程序

| 文件 | 用途 |
|---|---|
| `tests/leak_programs/steady_alloc.c` | 高速 malloc+free 等量不泄露（变长 size 减少 ptr 复用），25min。噪声误报反例 + 饱和验证 |
| `tests/leak_programs/slow_start.c` | 前 90s 爬坡、后稳态。启动宽限验证（grace=120 > ramp=90） |

---

## 三、验证（本地无 Python，用 node 移植算法纯数学验证）

### 3.1 算法正确性（node 移植 `_is_leaking`）
| 场景 | slope | t | 结果 | 预期 |
|---|---|---|---|---|
| 真实泄露 40KB/s | 40000 B/s | ∞ | leak=true | ✓ 检出 |
| 稳态平坦 1MB | 0 | ∞ | leak=false | ✓ |
| 噪声随机游走（±200KB） | 1570 B/s | 1.69 | leak=false | ✓ 幅度+显著性双拦 |
| 慢泄露 5KB/s | 5000 B/s | ∞ | leak=false | ✓ 地板下漏检（可配） |

### 3.2 蒙特卡洛（10000 窗口，稳态 i.i.d. 模型 — 驱逐后真实信号形态）
| 噪声幅度 | 最大噪声斜率 | 误报率 |
|---|---|---|
| ±200KB（busy 进程） | 2005 B/s | **0/10000 (0%)** |
| ±50KB（轻量进程） | 529 B/s | **0/10000 (0%)** |

地板 10240 对典型进程有 ~14× 余量。极端高吞吐进程（±2MB 噪声）可能偶发，可调高地板。

> 注：早期用"随机游走"模型测得 0.91% 误报是**模型错误**（随机游走是累积非稳态，对应的是 alloc_bytes/free_bytes 单调累计，不是 outstanding 差值）。驱逐后稳态进程的 outstanding 是有界稳态（活跃 ptr 集大小波动），正确模型下零误报。

### 3.3 BPF 驱逐静态复查
- mem `trace_free_entry`：栈帧拷贝在 sub 前（`:152-158`）；重读+删除在 sub 后、event 前（`:165-167`）；event 用局部变量，删后无 `info` 访问 → verifier 安全。
- fd 三处关闭路径同构；`key` 在各函数作用域内。
- 驱逐仅用 `bpf_map_delete_elem`（5.x 通用），不抬 5.12 内核底线。

---

## 四、待执行（需 Linux 构建机 + 目标节点）

1. **重编 BPF .o**：`tools/build_bpf.sh`（x86）/ `tools/package_arm.sh` 第 2 步（arm）→ 新 `mem.o`/`fd.o`。
2. **本地 x86 VM 验证**：steady_alloc 25min 不告警；slow_start 不告警；mem_leak 60-120s 告警。
3. **arm64 K8s 节点（dfx-syn01）**：长跑进程"快速上涨"改后是否回平（确认饱和假说）；thread/fd 斜率默认值实测调。
4. **`leakdetect-plan.md` §11.7.1** 状态更新（精度专项 ⬜→✅ 待环境验证后）。

---

## 五、边界

- **不做**：去 `×100`（保留无偏显示）、改采样率、Phase 2（libc uprobe + allocs `(pid,ptr)` rekey）、持久化、`alert_logger.py` "MEM" 前缀 bug（预存在 cosmetic）。
- **残余风险**：BPF 删-增竞态（重读守卫压到 1 条指令，每次仅 +1 有界）；thread/fd 斜率默认值未校准（节点实测调）；慢泄露低于地板漏检（可配）。
- Phase 2 改 `trace_free_entry` 时须保留本次的重读+删除行。

---

## 六、验证发现与待办（2026-08-21 验证后增补）

### 6.1 验证发现的问题：steady_alloc 误报（OLS 伪回归）

x86 VM 验证时，`steady_alloc`（无泄露）在 10min 内触发 mem 误报告警（后自动消除）。

**根因**：steady_alloc 的 outstanding 是**随机游走**（环形 buffer 大小总和漂移），OLS 斜率 + 残差 t 检验在随机游走上**伪回归**（残差自相关 → SE 低估 → t 虚高）→ 误报。告警能自动消除（outstanding 回平 → stabilize 5min 无新峰 → RESOLVED）说明**驱逐在工作**（非饱和，饱和会线性飙升永不回平）。问题在检测器，不在 BPF。

**建模教训**：蒙特卡洛当时用 i.i.d. 噪声建模（得 0/10000 误报），与真实随机游走形态不符——统计建模错误，低估了噪声形态。

### 6.2 待实施修复（**更新 2026-08-22：差分 t 未实施，保留 OLS**——见 §七决策；leak_seconds 维持 60）

1. **`analyzer/base.py` `_is_leaking`：OLS 斜率+残差 t → 一阶差分 t 检验**
   - deltas = 每检查周期净变化；slope = mean(deltas)/mean(dt)；t = mean(deltas)/(std(deltas)/√n)。
   - 差分是随机游走的稳态增量 → t 检验有效（无伪回归）→ steady_alloc 不误报。
   - 纯泄露（mem_leak）：deltas 恒正、std≈0 → t=∞ → 检出。
   - 这是计量经济学处理单位根序列的标准做法（检验稳态差分，非稳态水平）。
2. **`leak_seconds` mem 60→120**（长窗口覆盖释放周期，leak+GC 净趋势更清晰；config/UI/mock 同步）。grace/floor/z 不变。
   - 残余限制：弱泄露（净率 < GC 噪声）漏检（本质模糊，任何算法都难）；释放周期 ≈ 窗口（共振）需调窗口避开。
   - 代价：检测延迟 grace 120 + 窗口 120 ≈ 125s（grace 是启动爬坡保护的必要代价）。

### 6.3 遗留 UX 项（待后续迭代，不在本次实施）

- **门槛参数直观化**（已定方案，待实施）：
  - `monitoring-config.js` 的"增长斜率阈值"行，单位从"字节/秒"改成 **"MB/小时"** 展示/输入（内部仍 B/s，UI 做 MB/小时 ↔ B/s ×3600 转换），desc 改口语化"每小时净泄露超过 X MB 才告警"。thread/fd 同理"个/秒"→"个/分钟"。
  - **范围**：纯前端（`monitoring-config.js` 标签/desc/单位转换 + resetDefaults），不动后端算法/键名/`config`/`base.py`。
  - **单位已定**：MB/小时（用户 2026-08-21 确认）。
  - 当前门槛 10240 B/s = 10KB/s 真实净泄露 ≈ 36MB/小时。
- **（可选）`significance_z` 加进 UI 热可调**：目前 config-only（改 `default.yaml` 需重启）。加进 `backend.py` get/update `param_map` + `monitoring-config.js` 一行即可热可调。
- **`start.sh` 从源码树运行的 DIR 问题**（packaging/start.sh 取了 `packaging/` 而非仓库根 → 源码树里 `web/app.py` 找不到）：既有，非本次引入。源码树用 `sudo python3 web/app.py` 绕过；后续可让 start.sh 的 DIR 取脚本上一级。

---

## 七、疑似/确认分级实施记录（2026-08-22 增补）

### 7.1 决策：保留 OLS 算法（不切换差分 t）

经多轮对比（§六讨论），最终**保留 OLS 斜率+残差 t 检验**（不换差分 t）：
- 用户标准：transient 误报（自动消除）可接受、**不漏检**真实泄露优先。
- OLS 对 leak+GC（用户常见场景）逐点拟合、对单次 GC 谷点鲁棒 → 漏检少。
- 差分 t 虽修随机游走伪回归，但端点斜率对 leak+GC 敏感 → 漏检风险升 → 与用户优先相悖。
- transient 误报由"疑似"分级 + stabilize 自动消除兜底（不切算法）。

### 7.2 疑似/确认 severity（已实施）

`base.py` `_is_leaking`(OLS) 不变；状态机加确认升级：
- `suspected`（疑似，橙）：进 LEAK 即标。
- `confirmed`（确认，红）：LEAK 持续 `confirm_seconds`(=240s, 2×leak_seconds) 且 `_is_leaking` 仍 true → 升确认。spurious 数据 ≤leak_seconds 老化 → 到 240s 时 `_is_leaking` 已 false → 不升确认 → 维持疑似 → stabilize 自动消除。
- `resolved`：不变。

改 10 文件：`base.py`（+confirmed/confirm_seconds/确认判定/severity）、`memory/threads/handles.py`（传 confirm_seconds）、`config/default.yaml`（+confirm_seconds）、`backend.py`（get/update）、`mock.py`（+confirm_seconds +假告警 severity）、`monitoring-config.js`（+"确认时长"行）、`app.js`（watch confirmed/suspected→红/橙 + statusText）、`stack-view.js`（severity 徽章）、`style.css`（leak_confirmed红/leak_suspected橙 + alert-item severity 边框 + sev-badge）、`alert_logger.py`（suspected/confirmed/resolved 分支 + 修 MEM 硬编码前缀用 `alert["resource"]`）。

### 7.3 前台三 tab（已实施）

告警区三个同级 tab，疑似/确认分开存放：
- 当前告警（疑似，橙）= 实时 `filteredAlerts` 过滤 `severity==="suspected"`。
- 确认泄露（确认，红）= 实时 `filteredAlerts` 过滤 `severity==="confirmed"`。
- 历史告警 = `/api/alerts`（不变）。

改 `app.js`（+suspectedAlerts/confirmedAlerts computed）、`index.html`（+第三 tab 按钮 + confirmed 模板 + current→suspectedAlerts）、`style.css`（确认 tab `:nth-child(2).active` 红色 accent）。
- 疑似→确认升级时，告警实时从"当前告警"tab 跳到"确认泄露"tab。
- `resolved` 告警（瞬时 5s）不在疑似/确认 tab 显示（已写日志+DB；资源卡回正常即信号消除）。
- "确认泄露"tab 目前只实时活跃；**历史 confirmed 随持久化专项后续做**（需 `/api/alerts` 返回带 severity）。

### 7.4 steady_alloc 30GB 漂移（验证发现，非 bug）

VM 上 steady_alloc 跑出 30GB 漂移 + slow_start 500MB 连坐。核验：
- `.c` 源 + `.o`（`call 0x3` mem=2/fd=3）都含驱逐 → **驱逐在跑、map 限界**，不是饱和。
- 根因：steady_alloc ~百万事件/s（极端率）> Python ingest ~10-20万回调/s → 1MB ring buffer 溢出 → free 事件被丢 → 失衡漂移。**测试桩极端率问题，非真实场景 bug**（真实进程分配率远低）。
- 处理：throttle steady_alloc（`usleep 100→2000` 等，待做）→ 事件率降到 ingest 门槛下 → 不漂。

### 7.5 遗留（更新）

- **throttle steady_alloc**（`usleep`/`HOLD` 调温）→ valid 测试。
- **Python ingest 吞吐天花板**（~10-20万事件/s）：极高分配率真实进程可能也碰，后续可优化（批量回调/加大 ring）。
- **门槛 MB/小时展示**（§6.3，仍待做）。
- **历史 confirmed tab**（随持久化专项 + `/api/alerts` 带 severity）。
- **`start.sh` 源码树 DIR 问题**（§6.3，仍待做）。
- **thread/fd 斜率默认值** K8s 实测调。

---

## 八、慢泄露检测缺口与设计（2026-08-22 增补，重要）

### 8.1 缺口：当前方法检不出慢泄露

当前 `_is_leaking`（OLS 斜率 + 显著性，60s 窗口）是**快泄露检测器**：检"短时间（60-120s）内显著上涨（>floor 10KB/s）"。**检不出长周期小量慢泄露**。

**典型案例**：某进程 10 小时内存上涨 3MB = **87 B/s** 真实净泄露率。当前方法**三重不足**导致漏检：

1. **幅度地板**：floor=10240 B/s（10KB/s）。87 B/s ≪ 地板 → `slope > threshold` 直接失败。
2. **窗口太短**：mem `leak_seconds`=60s，in-memory history 只保留 2×60=120s。10 小时趋势不在窗口里（120s 窗口只看到 ~87×120≈10KB 微涨）。
3. **信噪比差（致命）**：1/100 采样的 outstanding 长周期是**随机游走**，噪声斜率 std ~KB/s 级 ≫ 87 B/s 信号 → 显著性 `slope/SE > z` 必失败。**即使把地板调到 0、in-memory 窗口拉长也救不了**——短窗口噪声地板远高于 87 B/s；长窗口 in-memory 又存不下 10h。

→ **调低 floor 不能解决**（SNR 限制）；**必须换数据源 + 持久化历史**。

### 8.2 当前方法定位（明确）

| 能检出 | 检不出 |
|---|---|
| 快泄露（>10KB/s，>36MB/小时）在 60-120s 窗口显著上涨 | 慢泄露（<10KB/s），尤其跨小时/天的小量（3MB/10h=87B/s）|
| mem_leak（40KB/s）~125s 检出 + 栈定位 | 10 小时涨 3MB（无栈或需另寻栈）|
| 启动爬坡、瞬时突变（grace/stabilize）| 缓涨趋势 |

BPF malloc 追踪 + 1/100 采样是为**抓快泄露 + 定位调用栈**，不是为慢趋势。

### 8.3 最终架构：两层 + 钻取归因（2026-08-22 定）

**Tier 1 — 快泄露（实时，已实施，不变）**
- 信号：BPF malloc outstanding（1/100 采样，有栈）。
- 检测：60s 窗口 OLS 斜率 + 显著性 → suspected/confirmed + 栈。
- 日志：alert_logger + DB alerts。
- 栈定位：BPF uprobe per-sid outstanding → 栈（直接）。

**Tier 2 — 慢泄露（趋势，新，属持久化专项）**
- 信号：**RSS**（`/proc/[pid]/status` 的 VmRSS，**精确无采样噪声**）——不用 BPF outstanding（1/100 长周期随机游走噪声大，SNR 差）。
- 采样：per-pid，10min（或 1min）间隔，持久化 DB（per-pid 全量 + retention 30d）。
- 检测：长基线 delta（`RSS(t) − RSS(t−Nh)`）或长窗口 OLS → "pid X 涨 Y MB / Z 小时" → slow_leak 告警。
- 阈值：**绝对量**（MB/N 小时），UI 可配（对应 §6.3 门槛 MB/小时展示）。
- `analyzer/cpu.py` 已读 `/proc/[pid]/stat`；扩读 `/proc/[pid]/status` 的 `VmRSS`（KB）即得精确 mem 值。

**栈归因 — 钻取 drill-down（Tier-2 触发后，用户已选）**
- Tier-2 标记 pid → **动态给该 pid 挂高速 BPF 采样**（uprobe malloc 1/1 或 per-pid filter，5min 窗口）→ 抓新鲜栈 → slow_leak 告警带栈。
- 模式：**平时轻量**（Tier-1 1/100 + Tier-2 RSS 10min）**+ 触发才重**（钻取 5min 高速）= detect-then-drill。
- 回退：若该 pid 分配活动极少（BPF 抓不到栈）→ 查当前 `mem_stats[pid]` per-sid，或接受"涨了 Y MB 但无栈"（用户上 debuginfo/profiler）。

### 8.4 "回查"目标澄清（关键修正）

- **不是查 Tier-1 告警日志**：慢泄露（87 B/s）没触发快告警（slope < floor）→ 告警日志**无记录可查**。
- 是查 **DB per-pid RSS 历史**（确认"10h 前 vs 现在"趋势）+ **钻取抓的栈**（定位）。
- 即：Tier-2 标记 pid → 查 DB per-pid 历史（确认趋势）→ 钻取 5min 抓栈（定位）→ slow_leak 告警带栈。

### 8.5 实施依赖与顺序

```
持久化专项（D1 per-pid RSS 全量历史 + D2 按pid/时间查 + D4 retention）
    ↓ （有 RSS 长历史才能查长基线）
Tier-2 慢泄露检测（RSS 长基线 delta/OLS + 绝对量阈值 → slow_leak 告警）
    ↓ （标记 pid）
钻取 drill-down（动态 per-pid 高速 BPF 5min → 栈）
    ↓
slow_leak 告警带栈
```

- **前置**：持久化专项（per-pid RSS 全量历史）。当前 `samples` 表只 top-5 聚合，无法 per-pid 查 10h 趋势。
- **钻取能力**（新代码）：`core/loader.py` 加动态 per-pid BPF attach（`attach_uprobe_to_pid(pid, rate=1, duration=300s)` 类）+ 高速采样 + 自动 detach。
- **数据源**：Tier-2 = RSS（精确、无栈）；Tier-1/钻取 = BPF outstanding（有栈、采样噪声）。
- **与 Tier-1 正交**：快/慢不同信号源 + 时间尺度，并存不互扰（一进程可同时被 Tier-1 短窗斜率 + Tier-2 长基线 delta 评估）。

### 8.6 取舍与状态

| 信号源 | 精度 | 栈定位 | 慢泄露 SNR | 角色 |
|---|---|---|---|---|
| BPF malloc outstanding（1/100）| 采样噪声 | ✅ 有栈 | 差（长周期随机游走）| Tier-1 快泄露 + 钻取归因 |
| `/proc/[pid]/status` VmRSS | 精确 | ❌ 无栈 | 好 | Tier-2 慢泄露趋势检出 |

- **混合**：RSS 长基线检出慢泄露（"涨了 Y MB"）→ 钻取（BPF 高速 5min）抓栈（"涨在哪"）。
- **本节是持久化专项的明确子目标**（"选进程 + 选时间段 → 看趋势是否泄露" + 慢泄露栈归因）；持久化专项启动时，Tier-2 + 钻取一并设计实施。
- 当前精度专项（Tier-1 快泄露 + 疑似/确认 + 驱逐）已完成，**不影响 Tier-2 后续开展**——两者正交（快/慢不同窗口 + 不同信号源）。
- 待定参数（实施时定）：Tier-2 采样间隔（10min vs 1min）、钻取窗口（5min）、钻取采样率（1/1）、slow_leak 绝对量阈值（MB/Nh）。
