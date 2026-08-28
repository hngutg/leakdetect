# LeakDetect 待处理事项与未来方向

> 日期：2026-08-26
> 用途：记录截至 2026-08-26 所有未解决的问题、待处理事项和未来开发方向。
> 前置文档：`leakdetect-精度专项-进展总结-20260821.md` §七（sampler 修复）+ §八（死 pid 清理器）

---

## 一、本阶段已完成（2026-08-26）

| # | 事项 | 解决方式 | 验证 |
|---|---|---|---|
| 1 | sampler 100× 放大 + 误报 | `mem.bpf.c:15` `BPF_MAP_TYPE_HASH` → `BPF_MAP_TYPE_ARRAY` | x86 + arm 验证通过 |
| 2 | allocs/fd_map 死 pid 累积 → outstanding 漂移 | 清理器（60s 周期，遍历删死 pid 条目） | arm 验证：`cleaned 127 allocs + 7 fd_map dead pid entries` |
| 3 | arm K8s 验证 | dfx-syn01（kernel 6.x, Python 3.11.6）部署验证 | mem_leak 告警 / steady_alloc 不告警 / 值合理 |
| 4 | ×100 采样准确性确认 | mem_leak 39.9MB ≈ 40MB 真实 outstanding；steady_alloc 6.4MB 合理 | arm 对比验证 |
| 5 | churn 误报消除（代理验证） | steady_alloc（churn 代理）不告警 | x86 + arm |
| 6 | 打包改进 | `package_arm.sh` 增加交叉编译测试程序 | arm 节点不需 gcc 即可跑测试 |
| 7 | 文档同步 | 进展总结 §七 + §八；plan.md §11.7.1 订正 | 完成 |
| 8 | Tier 1: debuginfo 文件读取（符号解析） | `symbolizer/symbols.py`：三路径搜索 stripped binary 的 debuginfo（`/usr/lib/debug<path>` + `.gnu_debuglink` + `.note.gnu.build-id`），读 debuginfo `.symtab` 获取内部函数符号 | x86 装 libc6-dbg 后验证：`__libc_start_call_main` 等内部函数名解析成功 |
| 9 | Tier 2: DWARF .debug_line 源码行号 | `symbolizer/symbols.py`：`iter_CUs()` + `line_program_for_CU()` 读 DWARF `.debug_line`，二分查找地址对应源码行。修复两个 bug（`line_programs` 属性不存在 → 改用 `iter_CUs`；主 ELF 有 DWARF 头但行表空 → "始终找 debuginfo，更多就用"） | x86 装 libc6-dbg + python3-dbg 后验证：`__GI___libc_malloc (arena.c:3294)` 行号出现 |
| 10 | 兜底：库名+偏移（替代 [unknown]） | `symbolizer/symbols.py`：`_resolve_addr()` 在所有符号解析失败时返回 `libc.so.6+0x偏移` 替代 [unknown]。分层兜底：debuginfo > .dynsym > 库名+偏移 > [unknown] | ARM 无 debuginfo 验证：`libc.so.6+0x27784` 替代了 [unknown] |
| 11 | 栈展示修复（调用链顺序+嫌疑点位置） | `web/static/js/components/stack-view.js`：反转栈数组（`reversedStack`），调用者在上方，被调用者在下方；嫌疑点从最后一帧(程序入口)改为最内层帧(分配点malloc) | ARM 验证：`_start` 在上 → `malloc ← 嫌疑点` 在下 |
| 12 | 测试程序帧指针 + Python 泄露脚本 | `tools/package_arm.sh` 5 个测试程序加 `-fno-omit-frame-pointer`（减少 BPF 帧指针链断裂导致的垃圾帧）；新增 `tests/leak_programs/py_leak.py`（ctypes 调 libc malloc，测试 Python 进程泄露检测） | ARM 验证：垃圾帧减少；py_leak 告警触发 |
| 13 | P3 值算法不一致（根因 B） | `core/aggregator.py` 三处 sum-then-clamp → per-sid/per-entry clamp：`get_total_outstanding`/`get_total_thread_count`/`get_total_fd_count` | `tests/verify_p3.py` 11 场景全 PASS（x86 VM 验证） |
| 14 | P4 /api/alerts 接 DB | `storage/db.py` 新增 `query_alerts`；`web/backend.py` 新增 `get_alerts`；`web/api.py:36` 改为调 `_backend.get_alerts(range_tag)` | x86 VM 集成验证：DB 608 条告警 → API 返回真实告警列表（含栈） |

---

## 二、待处理事项（按优先级）

### P1：持久化专项（文档规划下一级）

> 详见 `leakdetect-plan.md` §11.7.2、`leakdetect-进展与后续-20260815.md` §九.2
> 状态：⬜ 待实施
> 工作量：大（~1-2 周）
> 依赖：sampler 修复后"值准确才值得存历史" ✅ 已满足

**目标**：用户能选一个进程 + 选一段时间 → 看资源趋势（是否泄露）+ 看告警 + 栈（泄露在哪）。

| # | 改动 | 要点 |
|---|---|---|
| D1 | sampler 写全量 PID + 填 container_id | 不再 `[:5]`，从 cgroup_enum 取 pid→cid |
| D2 | db.py 加按 pid/容器/时间查询 | `query_process_history` / `query_container_history` / `query_alerts_by_pid` |
| D3 | 激活降采样 | `samples` → `samples_downsampled`（7d→10min, 30d→1h） |
| D4 | retention purge | 定时 DELETE 旧数据，retention 可配 |
| D5 | 索引优化 | 加 `idx_alerts_pid_ts` |
| D6 | alerts 填 container_id | 从 cgroup_enum 取 pid→cid |

**一并解决**：
- `/api/alerts` 接 DB（当前 backend 模式返回空 `[]`）
- chart 按 target 过滤（当前 sampler 写全局 top-5）
- Tier-2 慢泄露检测（RSS 长基线 delta，需 per-pid RSS 全量历史）

### P2：Phase 2（全 libc uprobe）

> 详见 `leakdetect-plan.md` §11.2
> 状态：⬜ 待实施
> 工作量：中（~3-5 天）
> 依赖：持久化专项（容器 mem 有值才完整）

**问题**：容器进程用自己的 libc（不同 inode），host uprobe 抓不到 → 容器 mem=0。

**方案**：
- 给节点所有 libc inode（宿主 `/lib64` + `/usr/lib64` + 各容器 libc 经 `/proc/[pid]/root/` 访问）都挂 malloc/free uprobe
- 持续全量采集，不随选择切换
- 每 libc 用 pyelftools 重算 malloc 偏移
- 容器 libc 发现：读 `/proc/[pid]/maps` 精确匹配 `libc.so.6`/`libc-2.*.so`
- 边角限制：静态链接容器进程、自研 allocator（jemalloc/tcmalloc）抓不到

### ~~P3：值算法不一致（根因 B）~~ → ✅ 已实施（2026-08-27）

> 详见 `leakdetect-复杂环境验证问题集-20260821.md` §二 根因 B
> 状态：✅ 已实施（2026-08-27）
> 验证：`tests/verify_p3.py` 11 场景全 PASS（x86 VM 验证通过）
> 工作量：小（~1 小时）

**问题**：
- 告警值（`memory.py _iter_stats`）：`Σ max(0, 每个 sid 的 cur)` — per-sid clamp
- per-process 值（`aggregator.get_per_process_mem`）：`sum(max(0, alloc-free))` — per-sid clamp
- `aggregator.get_total_outstanding`：`max(0, Σ cur)` — sum-then-clamp

churn 进程多 sid 混号（有正有负）→ sum-then-clamp 负 sid 抵消正 sid → per-process 值=0 → 确认后从 top5 消失（但告警仍挂着）。

**修复**：`get_total_outstanding` 改 per-sid clamp（与 `get_per_process_mem` 一致）。

**实施记录**（2026-08-27）：
- 文件：`core/aggregator.py`，3 处改动
- `get_total_outstanding`（:34）：`max(0, Σcur)*100` → `Σmax(0,cur)*100`
- `get_total_thread_count`（:72）：`max(0, Σ(created-exited))` → `Σmax(0, created-exited)`
- `get_total_fd_count`（:92）：`max(0, Σ(open-close))` → `Σmax(0, open-close)`
- 验证脚本：`tests/verify_p3.py`，11 场景全 PASS（内存 5 + 线程 3 + 句柄 3）
- 数值对照：混合正负 sid 改前 350M（低估）→ 改后 500M（正确），差额 150M；线程混合改前 4 → 改后 7
- 注：三个 `get_total_*` 方法当前为死代码（backend 用 `sum(get_per_process_mem values)` 求和，不调 `get_total_*`），此修复消除算法不一致隐患，运行时行为不变

### ~~P3.5：栈 [unknown] 符号解析~~ → ✅ 已实施（见 §一 #8-10）

> 状态：✅ 已实施（2026-08-26）
> 实施内容：Tier 1（debuginfo 文件读取）+ Tier 2（DWARF .debug_line 行号）+ 兜底（库名+偏移替代 [unknown]）
> 详见 §一 #8-10 + 使用文档 §十

**原问题**：告警栈中大量帧显示 `[unknown]`，用户无法定位泄露调用点。

**根因分析**（4 个来源，实施后覆盖 A + 兜底覆盖 B/C 的不可解部分）：

| # | 环节 | 原因 | 代码能解? | 实施状态 |
|---|---|---|---|---|
| **A** | `_get_symbols` 返回空 | **stripped binary**——`.symtab` 被移除，`.dynsym` 只有导出函数；内部函数不在 `.dynsym` → 查不到 → [unknown] | ✅ 读 debuginfo 文件 | ✅ Tier 1 已实施（§一 #8） |
| B | `_resolve_addr` 偏移算错 | PIE/共享库 maps `offset` 是文件偏移非虚拟地址偏移 | ✅ 读 ELF program header | ⬜ Tier 3 未实施（低优先级，影响面极小） |
| C | `bpf_get_stack` 丢帧 | `-fomit-frame-pointer`，RBP 链断裂 → 丢帧 | ⚠️ 难（BPF 层限制） | 部分缓解：测试程序加 `-fno-omit-frame-pointer`（§一 #12） |
| D | 内核帧 | `BPF_F_USER_STACK` 只抓用户栈 | 不需 | 不涉及 |

**实施结果**：

| 环境 | 改前 | 改后 |
|---|---|---|
| x86（有 libc6-dbg） | `malloc → [unknown] → [unknown] → main+0x4c → [unknown]` | `__GI___libc_malloc (arena.c:3294) → __libc_start_call_main (libc-start.c:74) → main+0x3a (mem_leak.c:22) → _start (mem_leak.c:86)` ✅ |
| ARM（无 debuginfo） | `malloc → [unknown] → [unknown] → main+0x4c → [unknown]` | `malloc → libc.so.6+0x27784 → libc.so.6+0x27868 → main+0x4c → _start+0x30` ✅ 兜底 |

**分层解析链**（最终效果）：
1. debuginfo `.symtab` + `.debug_line` → `func+0xoff (file:line)` ← 有 debuginfo 时（Tier 1 + Tier 2）
2. `.dynsym` → `func+0xoff` ← 导出函数
3. 兜底 → `library.so+0xoff` ← 库名+偏移（替代 [unknown]）
4. `[unknown]` ← 地址不在任何映射（极罕见）

**环境前置**：有 debuginfo 时自动读取（apt install libc6-dbg 等）；无 debuginfo 时走兜底。详见使用文档 §十。

**剩余**：来源 B（Tier 3 PIE 偏移修正）低优先级，影响面极小（§三 #10）；来源 C（帧指针）BPF 架构限制，代码不可解。

**已知不可代码解（来源 C）**：帧指针缺失导致 `bpf_get_stack` 丢帧。需装 debuginfo 或编译时加 `-fno-omit-frame-pointer`。方案 A libunwind（DWARF 全栈回溯）为可选增强，但 BPF 层实现复杂。

### ~~P4：`/api/alerts` 接 DB~~ → ✅ 已实施（2026-08-28）

> 状态：✅ 已实施（2026-08-28）
> 验证：`tests/verify_p4.py` 9 场景全 PASS + x86 VM 集成验证（DB 608 条 → API 返回真实告警）
> 工作量：极小（~1 小时）

**问题**：`backend._analyzer_loop` 已调 `db.write_alert(a)` 写入 alerts 表，但 `web/api.py` 的 `/api/alerts` 在 backend 模式返回空 `[]`（注释"B2/B4: 接 SQLite alerts 表"）。历史告警 tab 在 backend 模式下一直空。

**修复**：`/api/alerts` 调 `db.query_alerts(range_tag)` 返回 DB 中的告警。

**实施记录**（2026-08-28）：
- `storage/db.py`：新增 `query_alerts(range_tag)` 方法（SELECT 8 列 + `json.loads` 反序列化 stack_json + ORDER BY timestamp DESC）
- `web/backend.py`：新增 `get_alerts(range_tag)` 方法（委托 `db.query_alerts`）
- `web/api.py:36`：`return jsonify({"alerts": []})` → `return jsonify({"alerts": _backend.get_alerts(range_tag)})`
- 验证脚本：`tests/verify_p4.py`，9 场景全 PASS（count/sort/字段格式/stack解析/INSERT-OR-REPLACE/时间过滤/空栈/未知range/空DB）
- 集成验证：x86 VM（kernel 6.x），DB 608 条告警 → `/api/alerts?range=24h` 返回真实告警列表（含栈含 debuginfo 行号）
- 注：告警写入路径（`backend._analyzer_loop` → `db.write_alert`，INSERT OR REPLACE）之前已正常工作，此修复仅补全读取路径

### P5：黑白名单（filter_manager）

> 详见 `leakdetect-plan.md` §5.4
> 状态：⬜ stub（`core/filter_manager.py` 仅 6 行 TODO）
> 工作量：中（~2-3 天）

**问题**：抓取层过滤（黑白名单 + pid_filter_map）未实现。当前过滤仅靠 `cgroup_enum` 的 display_target 显示过滤（capture all, filter at display）。

**方案**：
- Python 后端解析 name_regex → 遍历 /proc/[pid]/comm 匹配 → PID 集合
- 合并用户 pid_list → 写入 BPF pid_filter_map
- 持久化到 config/runtime.yaml
- 定时刷新（30s，进程启停 PID 变化）

### P6：导出功能

> 来源：`doc/第一次改动/大体内容.txt`
> 状态：⬜
> 工作量：小-中

| # | 功能 | 说明 |
|---|---|---|
| 1 | 导出当前告警的进程信息（Excel） | 用户需求 |
| 2 | 按进程导出所有泄露信息 | 用户需求 |

### P7：打包自带 debuginfo（尝试过，暂阻塞）

> 状态：⬜ 阻塞（需 EulerOS 内部渠道获取 .debug 文件）
> 工作量：极小（代码 2 行 + 打包 3 行），前置是获取 .debug 文件
> 文件：`symbolizer/symbols.py` + `tools/package_arm.sh`

#### debuginfo 处理路径（按目标环境）

| 目标环境 | 有无网络 | debuginfo 来源 | 栈效果 |
|---|---|---|---|
| x86 VM（Ubuntu） | 有 | `sudo apt install libc6-dbg python3-dbg` | 函数名+行号 ✅ |
| ARM（EulerOS SP15，当前） | 无 | 无法安装 | 导出函数名 + `libc.so.6+0x偏移`（兜底） |
| ARM（未来，拿到 .debug 后） | 无 | 打包自带（build-id 匹配时自动使用） | 函数名+行号 ✅ |

#### 背景

ARM 目标节点（EulerOS 2.0 SP15 aarch64）无网络、无 debuginfo。工具部署后：
- 导出函数有名字（malloc, main, __libc_start_main — 来自 .dynsym）✅
- 内部函数显示 `libc.so.6+0x偏移`（兜底）✅
- 内部函数名+源码行号缺失 ❌（需 debuginfo）

**为什么不打包 debuginfo 通用解决**：debuginfo 与二进制版本严格绑定（通过 build-id 匹配）。不同发行版、不同版本、不同补丁 → 不同 build-id → debuginfo 不匹配 → 无法使用。不能预打包通用 debuginfo。

#### 尝试过程

1. 确认 ARM 目标信息：
   - 发行版：EulerOS 2.0 SP15
   - 架构：aarch64
   - glibc：2.38
   - libc build-id：`deb27bbd3a900a5a803cab7634a68883cceb7043`
   - libc 包版本：`glibc-2.38-47.h32.eulerosv2r15.aarch64`
   - libc 完全 stripped（无 .symtab，仅有 .dynsym 71976 bytes）

2. 搜索公开镜像：
   - 华为镜像站 `repo.huaweicloud.com/euler/`：只有 EulerOS 2.10（glibc 2.28），无 SP15
   - 公开镜像无 `glibc-debuginfo` 包（只有 `glibc-debugutils` 40KB，是调试工具不是调试符号）

3. 尝试内部渠道：
   - 找到同版本 EulerOS SP15 aarch64 机器（`kwephis31343558`）
   - 该机器也无网络、无 yum 仓库配置（`/etc/yum.repos.d/` 空目录）
   - DNF 缓存 `packages` 目录为空（无缓存 RPM）
   - `curl` 不通

4. **阻塞原因**：EulerOS SP15 的 debuginfo 包不在公开镜像，需要通过华为内部渠道获取 `glibc-debuginfo-2.38-47.h32.eulerosv2r15.aarch64.rpm`

#### 拿到 debuginfo 后的实施方案

**代码改动（2 行）**：`symbolizer/symbols.py` 的 `_find_debuginfo()` 增加一条搜索路径：

```python
# 现有搜索路径（系统级）：
/usr/lib/debug/.build-id/de/b27bbd3a900a5a803cab7634a68883cceb7043.debug

# 新增搜索路径（包自带）：
<包目录>/debug/.build-id/de/b27bbd3a900a5a803cab7634a68883cceb7043.debug
```

build-id 匹配 → 用包自带的 debuginfo → 内部函数名 + 源码行号
build-id 不匹配 → 文件不存在 → 返回 None → 走兜底（库名+偏移）

**打包改动（3 行）**：`tools/package_arm.sh` 增加一步，把 `.debug` 文件拷进包的 `debug/.build-id/de/` 目录。

**效果**：

| 场景 | 改前(兜底) | 改后(打包 debuginfo) |
|---|---|---|
| 部署到 build-id 匹配的节点 | `libc.so.6+0x27784` | `__libc_start_call_main (libc-start.c:74)` ✅ |
| 部署到 build-id 不匹配的节点 | `libc.so.6+0x27784` | `libc.so.6+0x27784`（回退兜底）✅ |

**局限**：只对该 build-id 对应的 libc 版本有效。其他节点（不同 glibc 版本/补丁）需要各自的 .debug 文件。

#### 获取 debuginfo 的途径

1. **华为内部渠道**：提交工单，说明需要 `glibc-debuginfo-2.38-47.h32.eulerosv2r15.aarch64.rpm`，提供 build-id `deb27bbd3a900a5a803cab7634a68883cceb7043`
2. **同版本有网络机器**：在有网络的 EulerOS SP15 aarch64 机器上 `sudo debuginfo-install glibc`，拷出 `/usr/lib/debug/.build-id/de/b27bbd3a900a5a803cab7634a68883cceb7043.debug`
3. **EulerOS 内部仓库**：如果找到内部仓库 URL，在 x86 构建机上 `wget` 下载 RPM，`rpm2cpio | cpio -idmv` 提取 .debug 文件

---

## 三、低优 / 可选增强

| # | 方向 | 说明 | 优先级 |
|---|---|---|---|
| 1 | Werkzeug WS 修复 | `async_mode="threading"` 不支持 WS 升级 → 500（cosmetic，回退 long-polling 正常）；装 eventlet 或 `allow_upgrades=False` | P3 |
| 2 | mmap/munmap hook | eBPF 不 hook mmap，漏检 mmap 泄漏（当前 outstanding 只追踪 malloc） | 可选 |
| 3 | 方案 A libunwind | kprobe/tracepoint 栈全栈回溯（改善 [unknown]） | 可选 |
| 4 | fd close 侧 close_fd kprobe | 长跑 fd 虚高复现再做 | 延后 |
| 5 | 容器内存统计（cgroup v2） | 按 cgroup 聚合 RSS（cgroup.statm） | 可选 |
| 6 | CPU 火焰图 | on-CPU 火焰图（用户需求） | 可选 |
| 7 | 内存 perf 图 | 某次上涨分配到哪里（用户需求） | 可选 |
| 8 | BPF_ATOMIC 5.10 兼容 | 条件编译两套 .o（原子/非原子）→ 复杂度高，设为环境需求（内核 ≥5.12） | 不做 |
| 9 | cgroup v2 支持 | 解析 v2 单行格式（M12） | 可选 |
| 10 | Tier 3: PIE 偏移修正 | `_resolve_addr` 里 `elf_addr = addr - start + offset` 在极少数 ELF（`p_vaddr ≠ p_offset`）时偏移算错 → 查不到符号。大多数 ELF text 段 offset=0，当前计算正确。出错也只是走兜底（库名+偏移），不崩溃 | 低 |

---

## 四、代码/仓库卫生

| # | 问题 | 说明 |
|---|---|---|
| 1 | README 过时 | 仍写"MVP 加载层 BCC"（实际 libbpf ctypes）；项目结构写 `logging/`（实际 `alert_logging/`） |
| 2 | start.sh 源码树 DIR bug | `packaging/start.sh` 的 DIR 指向 `packaging/` 而非仓库根；源码树用 `sudo python3 web/app.py` 绕过 |
| 3 | 运行时产物被 git 提交 | `data/leakdetect.db` + `data/leakdetect.log` 在仓库里 |
| 4 | 测试二进制被 git 提交 | `tests/leak_programs/mem_leak` 等 ELF 二进制在仓库里 |

---

## 五、已解决事项汇总（截至 2026-08-26）

| 日期 | 事项 | 文档位置 |
|---|---|---|
| 2026-07 | F0-F4 前端 + B0-B4 后端 + M9-M11 libbpf 迁移 | 初期设计文档 |
| 2026-08-15 | C1/C2 REST 接线 + 符号修复 + Phase 1 容器选择 + 打包兼容 | `leakdetect-进展与后续-20260815.md` |
| 2026-08-21 | 精度专项：OLS + per-PID + 驱逐 + 疑似/确认 + B 方案 map 聚合 + 双计数器 | `leakdetect-精度专项-20260821.md` |
| 2026-08-26 | sampler 修复（HASH→ARRAY）| 进展总结 §七 |
| 2026-08-26 | allocs/fd_map 死 pid 清理器 | 进展总结 §八 |
| 2026-08-26 | arm K8s 验证（dfx-syn01） | 进展总结 §七.5 |
| 2026-08-26 | 打包改进（交叉编译测试程序）| 进展总结 §七.8 |
| 2026-08-26 | Tier 1: debuginfo 文件读取（符号解析） | symbols.py |
| 2026-08-26 | Tier 2: DWARF .debug_line 源码行号 | symbols.py |
| 2026-08-26 | 兜底：库名+偏移（替代 [unknown]） | symbols.py |
| 2026-08-26 | 栈展示修复（调用链顺序+嫌疑点位置） | stack-view.js |
| 2026-08-26 | 测试程序帧指针 + py_leak.py | package_arm.sh + py_leak.py |
| 2026-08-27 | P3 值算法不一致（sum-then-clamp → per-sid clamp） | 0826 文档 §二 P3 |
| 2026-08-28 | P4 /api/alerts 接 DB（query_alerts + get_alerts） | 0826 文档 §二 P4 |

---

## 六、建议实施顺序

```
sampler 修复 ✅ + 死 pid 清理器 ✅ + 栈符号解析(Tier 1/2/兜底) ✅ + 栈展示修复 ✅（已完成）
    ↓ （值准确 + 长跑不漂移 + 栈可用）
值算法一致（根因 B, P3, ~1h）✅ + /api/alerts 接 DB（P4, ~1h）✅  ← 均已完成
    ↓
持久化专项（P1, ~1-2 周）  ← 文档规划下一级
    ↓ （有 per-pid RSS 全量历史）
Tier-2 慢泄露检测（RSS 长基线 delta）
    ↓ （容器 mem 有值才完整）
Phase 2 全 libc uprobe（P2, ~3-5 天）
    ↓
黑白名单（P5）/ 导出功能（P6）/ 可选增强
```
