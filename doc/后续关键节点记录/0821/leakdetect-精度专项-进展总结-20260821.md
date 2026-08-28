# LeakDetect 精度专项进展总结

> 日期：2026-08-21
> VM：101.35.44.81（x86_64，kernel 6.8.0-124-generic）
> arm：dfx-syn01-csp-c-arm-0（kernel 5.10，BPF_ATOMIC 不支持，需 ≥5.12）

## 一、已完成的改动

### 1. B 方案：Map 聚合替代 Ring Buffer（根因 C 修复）

**问题**：高事件率下 ring buffer 溢出 → 所有进程数据漂移（根因 C）。

**改动**：
- 删除 mem/fd 的 events ring buffer
- 新增 BPF `outstanding_map`（per-(pid,stack) 内存聚合）+ `fd_count_map`（per-pid fd 聚合）
- Python `map_reader` 线程每 1s 读 BPF map → `set_mem_stats`/`set_fd_stats`
- threads 保留 ring buffer（低频事件）
- 涉及 8 个文件：`common.h`、`mem.bpf.c`、`fd.bpf.c`、`loader.py`、`ingest.py`、`aggregator.py`、`backend.py`、`base.py`

### 2. 双计数器修复：消除 atomic sub 的 u64 回绕窗口

**问题**：B 方案中 `outstanding_map` 用单计数器 `outstanding`（alloc 时 add、free 时 sub + 下溢 re-add）。`__sync_fetch_and_sub` 与 re-add 之间产生临时 u64 回绕巨值（如 18446744073709551566），map-reader 在此窗口内读到 → ×100 放大 → 687MB/130MB/1844... 虚高 + 误报。

**修复**：改为两个独立计数器（仅 add，无 sub → 无回绕窗口）：
- `outstanding_val_t`：`outstanding` → `alloc_bytes` + `free_bytes`
- `fd_count_val_t`：`count` → `open_count` + `close_count`
- Python 侧 `OutstandingVal`/`FdCountVal` ctypes 同步更新
- `read_outstanding_map`/`read_fd_count_map` 读真实双计数器（删除硬编码 `free_bytes:0`/`close_count:0`）
- 涉及 4 文件：`common.h`、`mem.bpf.c`、`fd.bpf.c`、`loader.py`

**验证结果**：
- barad_agent：130MB → 559KB ✓
- python3 自身：687MB → 不显示（后续移除 self-pid 排除后显示 16.8MB）✓
- 无误报（0 mem alerts）✓
- 巨值 1844... 不再出现 ✓

### 3. Self-pid 排除移除

**改动**：
- `loader.py`：`read_outstanding_map`/`read_fd_count_map` 去掉 `and pid != os.getpid()`
- `memory.py`/`handles.py`/`threads.py`：`_iter_stats` 去掉 `if pid == my_pid: continue` + 删除 `import os`
- python3 自身现在出现在 dashboard + 参与检测

### 4. 其他精度专项改动（更早批次）

| 改动 | 文件 | 说明 |
|---|---|---|
| per-sid clamp | `aggregator.py` | `get_per_process_mem` 用 `sum(max(0, alloc-free))` per-sid（非 sum 后 clamp）|
| OLS 斜率 + 显著性 | `base.py` | `_is_leaking` 线性回归 slope > threshold 且 slope/SE > z |
| 启动宽限 | `base.py` | `grace_seconds=120`：新进程前 N 秒只攒历史不判定 |
| 疑似→确认 | `base.py` | `confirm_seconds=240`：LEAK 持续 240s 且仍 leaking 才升 confirmed |
| cmdline 显示 | `cgroup_enum.py`、`backend.py` | `/proc/[pid]/cmdline` 缓存 30s，覆盖 process_name |
| 三页签前端 | `app.js`、`index.html`、`style.css` | 当前告警/确认泄露/历史告警 |
| BPF 驱逐修复 | `mem.bpf.c`、`fd.bpf.c` | 移除 outstanding_map/fd_count_map 的 `bpf_map_delete_elem`（use-after-free 竞态）|

## 二、当前状态

### 正常工作

- BPF 编译 + 加载（malloc/free/clone/exit/fd_install/close/dup2/dup3 全部 attach）
- 双计数器修复消除 sub 窗口 → 无 687MB/130MB/1844... 虚高
- barad_agent 正常（559KB，非 130MB）
- threads ring buffer 正常
- self-pid 可见 + 参与检测

### ~~当前问题：×100 放大 + pymalloc arena 导致误报（P0）~~ → 已解决（sampler 修复，见 §七）

> **2026-08-26 订正**：原判断 P0 根因为"×100 放大 + pymalloc arena"，实际根因是 **sampler map 类型笔误（HASH→ARRAY）**，详见 §七。sampler 修复后 P0 已解决，×100 是正确的采样补偿（1/100×100=1×），无需去掉。

**修复前现象**：
- python3 (web.app)：dashboard 显示 350MB，top RSS=102MB → 3.4× 高估
- barad_agent / YDService / python3 均在 3 分钟内疑似 → 4 分钟后确认
- `top` 显示 RSS 稳定，但 eBPF ×100 outstanding 持续增长

**原根因判断（已订正）**：

| 层 | eBPF 看到的 | 实际（RSS） | 原判断 | 实际根因（2026-08-26 订正） |
|---|---|---|---|---|
| sampler | 1/100 采样失效 → 100% 处理 | — | （原判断未识别） | **HASH map lookup 返回 NULL → 采样跳过 → 100% malloc 被追踪** |
| ×100 | 100% × 100 = 100× 放大 → 350MB | — | 原判断"pymalloc arena 积累" | **实际是 100× 采样失效放大（3.5MB × 100 = 350MB）** |
| OLS 斜率 | 100× 放大斜率 >> 10KB/s → confirmed | RSS slope ≈ 0 | 原判断"eBPF 增长非真实泄漏" | **实际是 100× 放大的虚假斜率** |

**实际根因**：BCC→libbpf 迁移重写 BPF 程序时，`mem.bpf.c` sampler map 类型从 `BPF_MAP_TYPE_ARRAY`（预分配，lookup 永远非 NULL）笔误为 `BPF_MAP_TYPE_HASH`（不预分配，key 0 未插入 → lookup 返回 NULL → `if(cnt)` false → 采样逻辑跳过 → 100% malloc 被处理）。×100 从采样补偿（1/100×100=1×）变成 100× 放大（1/1×100=100×）。ring buffer 时代 BCC 用 `BPF_ARRAY`（ARRAY），采样正常，无误报。

### 其他问题

| # | 问题 | 优先级 | 说明 |
|---|---|---|---|
| 1 | ×100 放大误报 | **P0** | 上述当前问题 |
| 2 | arm 验证阻塞 | P2 | arm kernel 5.10 不支持 BPF_ATOMIC（需 ≥5.12）|
| 3 | allocs/fd_map 死 pid 累积 | P2 | 长期运行可能饱和 1M cap（pre-existing）|
| 4 | Werkzeug 3.x WebSocket 报错 | P3 | `async_mode="threading"` 不支持 WS 升级 → 500（cosmetic，回退 long-polling 正常）|

## 三、数值对比：eBPF ×100 vs RSS

### 逐场景

| 场景 | eBPF ×100 | RSS | 哪个准 |
|---|---|---|---|
| Python（pymalloc）| 350-600MB（虚高，arena 积累）| 102MB（真实）| **RSS** |
| 真实 C 泄漏（100KB/s）| ~6MB（×100 还原）| ~6MB | 两者接近 |
| churn（malloc+free 平衡）| ~0 | 稳定 | 两者都对 |
| mmap 泄漏 | **0（eBPF 不 hook mmap，漏检）** | 增长 | **RSS** |
| jemalloc 内部池 | ~0（free 已记）| 稳定偏高 | 两者都对 |

### 核心差异

| 维度 | eBPF ×100 outstanding | RSS (/proc/statm) |
|---|---|---|
| 测的是什么 | libc malloc 层未归还量 | 物理驻留内存 |
| 对 Python/agent | 350-600MB（虚高 3-6×）| 102MB（真实）|
| 采样精度 | ±√N 方差（1/100 采样噪声）| 精确 |
| 栈归因 | ✅ per-(pid, 调用栈) | ❌ per-pid only |
| mmap 追踪 | ❌ 只 hook malloc | ✅ 所有驻留页 |
| 检测可靠性 | Python 误报、mmap 漏检 | 稳定可靠 |

## 四、待决策：检测架构方案

> **2026-08-26 更新**：P0 误报已通过 sampler 修复解决（§七），×100 是正确的采样补偿。以下三个方案原为解决 P0 提出，现 **RSS 方案降级为可选 UX 改进**（非必要）。
>
> **关键发现**：mem_leak 测试证明 BPF malloc 追踪比 RSS 更能检出 demand-paged 泄露（进程 malloc 不写页 → RSS 不涨 → RSS 会漏检）。因此不建议用 RSS 替代 eBPF 做检测主指标。
>
> RSS 方案仍有价值的场景：慢泄露检测（Tier-2，长基线 RSS delta，属持久化专项）。

### 方案 A：保持 eBPF ×100 检测 + RSS 交叉校验

**思路**：检测主指标仍是 eBPF ×100 outstanding，但在 `_is_leaking` / `_update_state` 中加 RSS 交叉校验：×100 涨但 RSS 不涨 → 抑制告警。

| 优点 | 缺点 |
|---|---|
| eBPF 是主检测指标 | 需维护双 history（×100 + RSS）|
| RSS 仅做校验 | dashboard 仍显示 350MB（误导）|
| | 交叉逻辑复杂（何时抑制？何时确认？）|

### 方案 B：RSS 检测 + eBPF 栈归因（推荐）

**思路**：检测 + 展示改用 RSS，eBPF 仅用于栈归因（哪个 malloc 调用点在涨）。

| 优点 | 缺点 |
|---|---|
| 检测准确（RSS = 真实内存）| 检测指标来自 /proc，非 eBPF |
| 展示与 top 一致（102MB 而非 350MB）| |
| 栈归因仍来自 eBPF（告警指向调用点）| |
| 能检测 mmap 泄漏（eBPF 漏检的）| |
| 改动小（2 文件 6 处）| |

**改动范围**：
- `core/aggregator.py`：加 `_read_rss(pid)`，`get_per_process_mem`/`get_total_outstanding` 用 RSS
- `analyzer/memory.py`：`_iter_stats` 用 RSS 做 value，`best_sid` 仍用 `alloc_bytes - free_bytes`

### 方案 C：纯 eBPF（修阈值/采样率）

**思路**：保持 ×100 检测，调阈值或采样率减少误报。

| 优点 | 缺点 |
|---|---|
| 纯 eBPF | **无法解决 pymalloc arena 本质问题** |
| | 调高阈值 → 漏检慢泄漏 |
| | 调低采样率 → 精度下降 |

## 五、未来方向

| # | 方向 | 依赖 | 说明 | 状态 |
|---|---|---|---|---|
| 1 | ~~RSS 检测 + eBPF 归因（解决 P0）~~ | ~~原定方案~~ | P0 已通过 sampler 修复解决（§七）；RSS 方案降级为可选 UX 改进 | ⬇️ 降级 |
| 2 | **慢泄露检测（Tier-2）** | 持久化专项 | RSS 长基线 delta（N 小时涨 Y MB），当前 60s 窗口检不出 2KB/s 慢泄露 | ⬜ 待实施 |
| 3 | ~~arm 验证~~ | ~~arm kernel ≥5.12~~ | 已在 dfx-syn01（kernel 6.x）验证通过 | ✅ 已完成 |
| 4 | ~~allocs/fd_map 定期清理~~ | ~~低优~~ | 死 pid 累积 → free 匹配失败 → outstanding 漂移；清理器已实施（§八） | ✅ 已实施 |
| 5 | Werkzeug WS 修复 | 低优 | `allow_upgrades=False` 或装 eventlet | ⬜ |
| 6 | 容器内存统计 | cgroup v2 | 按 cgroup 聚合 RSS（cgroup.statm）| ⬜ |
| 7 | mmap/munmap hook | 可选增强 | 让 eBPF 追踪 mmap 分配（目前漏检 mmap 泄漏）| ⬜ |

## 六、改动文件清单（当前状态）

| 文件 | 改动批次 | 状态 |
|---|---|---|
| `bpf/common.h` | 双计数器 | ✅ 已上传 VM + 编译 |
| `bpf/mem.bpf.c` | 双计数器 + B 方案 | ✅ 已上传 VM + 编译 |
| `bpf/fd.bpf.c` | 双计数器 + B 方案 | ✅ 已上传 VM + 编译 |
| `bpf/threads.bpf.c` | 未改 | — |
| `core/loader.py` | 双计数器 + self-pid 移除 | ✅ 已上传 VM |
| `core/ingest.py` | B 方案（删 mem/fd event）| ✅ 已上传 VM |
| `core/aggregator.py` | B 方案 + per-sid clamp | ✅ 已上传 VM，**待 RSS 改动** |
| `analyzer/base.py` | OLS + grace + confirm | ✅ 已上传 VM |
| `analyzer/memory.py` | self-pid 移除 | ✅ 已上传 VM，**待 RSS 改动** |
| `analyzer/handles.py` | self-pid 移除 | ✅ 已上传 VM |
| `analyzer/threads.py` | self-pid 移除 | ✅ 已上传 VM |
| `web/backend.py` | B 方案 map_reader | ✅ 已上传 VM |
| `web/app.py` | — | 未改 |
| `config/default.yaml` | — | 未改（阈值 10240 bytes/sec）|

---

## 七、sampler 修复（2026-08-26 增补）

> 本节为精度专项的延续。P0（×100 放大 + 误报）的真正根因在 2026-08-26 确认并修复。

### 7.1 问题现象

arm K8s 节点（dfx-syn01）上：
- **各进程内存均显著上涨**（python3 显示 350MB vs RSS 102MB → 3.4× 高估）
- **短时间误报告警**（2-3 分钟内环境进程告警 + 升确认）
- **对比 ring buffer 时代**：同环境进程无误报（BCC 用 ARRAY，采样正常）

### 7.2 诊断过程（含纠偏）

| 轮次 | 诊断 | 结果 |
|---|---|---|
| 第一轮 | ×100/pymalloc arena 通胀 + ring 溢出压制 | ❌ 用户指出 ring buffer 时代同环境进程无误报 |
| 第二轮 | ring 溢出意外压低数值，B 方案暴露真实通胀 | ❌ 无法解释"从一开始就高"（溢出前应准） |
| 第三轮 | 用户提供外部分析：sampler ARRAY→HASH 笔误 | ✅ **命中**——代码验证确认 |

### 7.3 根因：sampler map 类型笔误

**`bpf/mem.bpf.c:15`**：sampler 类型为 `BPF_MAP_TYPE_HASH`，设计文档（B1 §5.2、M9-M11 §3.3）均指定 `BPF_MAP_TYPE_ARRAY`。

BCC→libbpf 迁移重写 BPF 程序时笔误。

| | ARRAY（设计意图 / ring buffer 时代） | HASH（B 方案代码 bug） |
|---|---|---|
| 预分配 | 是，所有条目初始化为 0 | 否，需显式插入 |
| `lookup(key=0)` | 返回有效指针 → `cnt` 非 NULL | 返回 NULL（key 0 从未插入）|
| `if (cnt)` | true → 采样逻辑执行 | **false → 采样逻辑跳过** |
| 实际采样率 | 1/100 | **1/1（全量）** |
| ×100 后 | 1/100 × 100 = **1× 真实值** ✓ | 1/1 × 100 = **100× 真实值** ✗ |

全仓 grep 确认：无代码对 sampler 做 `bpf_map_update_elem`（无初始化）。`fd.bpf.c`/`threads.bpf.c` 无 sampler（全量追踪，不受影响）。

### 7.4 修复

`bpf/mem.bpf.c` 第 15 行：`BPF_MAP_TYPE_HASH` → `BPF_MAP_TYPE_ARRAY`。一行。

改回后：ARRAY 预分配 → lookup 返回有效指针 → `if(cnt)` true → `*cnt%100` → 1/100 采样恢复 → ×100 = 1× 真实 outstanding。

### 7.5 验证结果

**x86 VM（Phase 1-3）**：

| 验证项 | 结果 |
|---|---|
| python3 显示 | 0.7MB（非 350MB）→ 100× 通胀消除 ✅ |
| mem_leak 真阳性 | 告警 + 栈含 malloc→main ✅ |
| steady_alloc 真阴性 | 25min 不告警（churn 噪声过滤）✅ |
| slow_start 宽限 | 不告警（grace 120 > ramp 90）✅ |
| 长跑稳定 | 无急速上升 ✅ |

**arm K8s（Phase 4，dfx-syn01，kernel 6.x，Python 3.11.6）**：

| 验证项 | 结果 |
|---|---|
| sampler 修复生效 | mem 值合理（39.9MB 非 350MB）✅ |
| mem_leak 真阳性 | 39.9MB ≈ 40MB 真实 outstanding，告警触发 ✅ |
| steady_alloc 真阴性 | 6.4MB（持有集），不告警 ✅ |
| fd 精确 | 20 vs 真实 23 ✅ |
| ×100 采样准确 | 两测试程序值均吻合真实 outstanding ✅ |
| python3 长跑（1h）| 11.4MB vs RSS 240MB（malloc outstanding 是 RSS 子集）✅ |

### 7.6 关键认知纠偏

| 原判断 | 实际 |
|---|---|
| ×100/pymalloc 是误报根因 → 需要 RSS 方案 | ❌ 根因是 sampler 笔误；×100 在采样正常时是正确的采样补偿 |
| 39.9MB vs RSS 2.1MB 是 ×100 采样噪声 | ❌ 是 demand paging（mem_leak 不写页，RSS 不反映虚拟分配）；leakdetect 值准确 |
| ring 溢出意外压低数值 | ❌ ring 时代 sampler 是 ARRAY（正常），B 方案重写时笔误成 HASH |
| 需要 RSS 方案修误报 | ❌ sampler 修复后误报已消除；BPF malloc 追踪反而比 RSS 更能检出 demand-paged 泄露 |

### 7.7 残留项

| # | 项 | 说明 | 修复方向 |
|---|---|---|---|
| 1 | 慢泄露检测缺口 | 2KB/s << 10KB/s 阈值，60s 窗口检不出长周期慢趋势 | Tier-2 RSS 长基线（属持久化专项）|
| 2 | ~~allocs/fd_map 死 pid 累积~~ | ~~长跑后死进程 ptr 条目不清理 → free 匹配失败 → outstanding 漂移~~ | ✅ 已修复（§八） |
| 3 | arm 长跑观察 | ovs 不假确认、无急速上升——进行中 | 观察 1-2h |

### 7.8 改动文件清单（本批次）

| 文件 | 改动 |
|---|---|
| `bpf/mem.bpf.c` | 第 15 行 `BPF_MAP_TYPE_HASH` → `BPF_MAP_TYPE_ARRAY`（sampler 修复）|
| `tools/package_arm.sh` | 增加交叉编译测试程序（`aarch64-linux-gnu-gcc`），arm 节点不需 gcc |

---

## 八、allocs/fd_map 死 pid 清理器（2026-08-26 增补）

> 本节为精度专项的延续。allocs/fd_map 配对追踪 map 中死进程条目永不清理 → 长跑累积 → outstanding 漂移。2026-08-26 实施清理器修复。

### 8.1 问题

`allocs`（mem 配对追踪 map，key=ptr）和 `fd_map`（fd 配对追踪 map，key={pid,fd}）中，进程退出后条目永不清理：

- 驱逐只在 `free()`/`close()` 调用时触发（refcount→0 → `bpf_map_delete_elem`）
- 进程退出后无 `free()`/`close()` 调用 → refcount 停 1 → 条目永久留存
- 累积 → map 填满（cap 1M）→ 新 alloc 的 ptr 存不进 → free 查不到配对 → free_bytes 不增 → outstanding 漂移上涨

**对比**：`outstanding_map`/`fd_count_map`（B 方案聚合 map）有 Python 侧清理（`read_outstanding_map`/`read_fd_count_map` 检查 `/proc/[pid]` 删死 key）；`allocs`/`fd_map`（配对追踪 map）无清理。

### 8.2 根因

| map | key 含 pid? | 有清理? | 原因 |
|---|---|---|---|
| outstanding_map | 是（key={pid,stack}） | ✅ 有 | `loader.py:read_outstanding_map` 检查 /proc/[pid] |
| fd_count_map | 是（key={pid}） | ✅ 有 | `loader.py:read_fd_count_map` 检查 /proc/[pid] |
| **allocs** | **否**（key=ptr） | ❌ 无 | value `alloc_info_t` 无 pid 字段，无法判断条目属哪个进程 |
| **fd_map** | **是**（key={pid,fd}） | ❌ 无 | key 有 pid 但无 Python 清理代码 |

### 8.3 修复

**BPF 改动**（需重编 .o）：

| 文件 | 改动 |
|---|---|
| `bpf/common.h` | `alloc_info_t` 末尾加 `u32 pid` 字段（96 字节，原 88） |
| `bpf/mem.bpf.c` | `trace_malloc_return`：pid 声明提前到 allocs 块前 + `alloc->pid = (u32)pid` |
| `bpf/fd.bpf.c` | **不改**（fd_key_t 已含 pid） |

**Python 改动**（不需重编）：

| 文件 | 改动 |
|---|---|
| `core/loader.py` | 加 4 ctypes 结构（AllocsKey/AllocsVal/FdKey/FdVal）+ `clean_dead_pid_allocs()`/`clean_dead_pid_fd_map()` 方法 |
| `web/backend.py` | 加 `_dead_pid_cleaner_loop` 线程（60s 周期） |

**清理器模式**：复用 `read_outstanding_map` 的遍历+删死 key 模式：
1. `bpf_map_get_next_key` 遍历 map
2. `bpf_map_lookup_elem` 读 value
3. 检查 `/proc/[pid]` 是否存在
4. 不存在 → 收集 key
5. 迭代结束后 `bpf_map_delete_elem` 删死 key

**线程分离**：
- `_map_reader_loop`（1s）：读 outstanding_map/fd_count_map（时间敏感，需快）
- `_dead_pid_cleaner_loop`（60s）：清 allocs/fd_map（不时间敏感，可慢）

### 8.4 验证

```
# mem_leak 跑 30s 后 kill
./tests/leak_programs/mem_leak &
sleep 30
kill <mem_leak PID>

# 预期：60s 内日志打印
[backend] cleaned 127 allocs + 7 fd_map dead pid entries
```

- 127 allocs 条目 = mem_leak 的采样 malloc ptr + 其他已退出进程的累积条目
- 7 fd_map 条目 = 死进程的未关闭 fd
- 清理器正确遍历 → 检测死 pid → 删除 → 打印计数 ✅

### 8.5 ctypes 布局验证

| 结构 | 字段 | C 偏移 | ctypes 偏移 | sizeof | 匹配 |
|---|---|---|---|---|---|
| AllocsVal | refcount+size+stack_cnt+pad+stack_addrs[8]+pid+pad | 0-95 | 0-95 | 96 | ✅ |
| FdKey | pid+fd | 0-7 | 0-7 | 8 | ✅ |
| FdVal | refcount+stack_cnt+pad+stack_addrs[8] | 0-79 | 0-79 | 80 | ✅ |
| AllocsKey | ptr | 0-7 | 0-7 | 8 | ✅ |

### 8.6 改动文件清单（本批次）

| 文件 | 改动 | 需重编 .o? |
|---|---|---|
| `bpf/common.h` | alloc_info_t 加 `u32 pid` | 是 |
| `bpf/mem.bpf.c` | pid 提前声明 + `alloc->pid = (u32)pid` | 是 |
| `bpf/fd.bpf.c` | 不改 | 否 |
| `core/loader.py` | 加 4 ctypes 结构 + 2 清理方法 | 否 |
| `web/backend.py` | 加清理线程 + 方法 | 否 |
