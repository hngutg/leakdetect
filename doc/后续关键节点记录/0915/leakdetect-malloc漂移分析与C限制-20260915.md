# LeakDetect malloc 漂移分析与 C/C++ 限定方案

> 日期：2026-09-15
> 用途：记录 malloc 追踪漂移问题的根因分析、验证数据、当前限制与未来需求
> 前置文档：`leakdetect-现阶段进展总结-20260903.md` §二（fd 漂移）、`leakdetect-fd追踪修复-20260903.md`

---

## 一、问题现象

工具长时间运行（~2 天）后，前端 dashboard 显示的 malloc 值持续虚高：

| 进程 | 前台显示（BPF 追踪） | 实际值（/proc） | 漂移量 |
|---|---|---|---|
| python3 web/app.py（工具自身） | 420.5 MB | 177 MB（VmRSS） | +243 MB |
| systemd（PID 1）fd | 467 | 125（/proc/1/fd） | +342 |

malloc 值单调上涨，但进程实际内存并未增长（RSS 甚至在下降）。fd 值同理虚高。

---

## 二、根因分析

### 2.1 BPF malloc 追踪机制

```
trace_malloc_entry（uprobe libc malloc，1/100 采样）
  → 采样命中 → entry_info[tid] = {size}

trace_malloc_return（uretprobe libc malloc）
  → 查 entry_info[tid] → 命中 → allocs[ptr] = {size, pid, stack}
  → outstanding_map[(pid, stack)].alloc_bytes += size（原子加，单调递增）

trace_free_entry（uprobe libc free，全量触发，不采样）
  → 查 allocs[ptr] → 命中 → outstanding_map[(pid, stack)].free_bytes += size
  → 删除 allocs[ptr]
  → 未命中（malloc 未被采样）→ 跳过
```

outstanding = alloc_bytes - free_bytes，显示值 = outstanding × 100（采样补偿）。

### 2.2 漂移根因：Python pymalloc 的 free 不走 libc

**关键发现：漂移只影响 Python 进程，C/C++ 程序不漂移。**

| 进程类型 | malloc 路径 | free 路径 | 采样配对 | 漂移？ |
|---|---|---|---|---|
| C/C++ 程序 | libc malloc（被 uprobe 采样） | libc free（uprobe 全量检查 allocs） | ✅ 采样的 malloc 对应的 free 能配对 | ❌ 不漂移 |
| Python 进程 | libc malloc（arena 分配，被采样） | **pymalloc 内部 free list（不走 libc free）** | ❌ 采样的 arena malloc 的 free 永远不触发 uprobe | ✅ 漂移 |

**Python pymalloc 机制**：
1. Python 调 libc `malloc(256KB)` 分配 arena → 被 1/100 采样 → `allocs[ptr]` 创建，`alloc_bytes` 增加
2. Python 从 arena 内部分配小对象 → 不调 libc malloc，不被追踪
3. Python 释放小对象 → **回到 pymalloc 内部 free list，不调 libc `free()`**
4. free uprobe 只挂在 libc `free()` 上 → pymalloc 的内部释放**不触发 uprobe**
5. `allocs[ptr]` 永远不会被匹配删除 → `alloc_bytes` 只增不减 → outstanding 单调上涨

**本质：这是"free 路径覆盖不全"问题，与 fd 的 close 路径覆盖不全是同一类问题。**

### 2.3 为什么不能从 BPF 源头修复 Python malloc

pymalloc 的分配/释放模式与 ptr 维度追踪**根本不兼容**：
- arena 批量分配（libc malloc，被采样，ptr = arena 基地址）
- 小对象零散释放（pymalloc 内部，不走 libc free，ptr = 小对象地址 ≠ arena 基地址）

即使 hook `PyObject_Free`（pymalloc 内部释放函数），小对象的 ptr 也对不上 arena 的 `allocs[ptr]`。**这是 pymalloc 架构决定的，无法用 uprobe 修复。**

---

## 三、验证数据

### 3.1 C 程序不漂移（steady_alloc，10 分钟对比）

环境：x86 VM（Ubuntu 24.04，kernel 6.8），libc6-dbg 已安装

```
steady_alloc：等速 malloc+free，不泄露

         alloc_bytes      free_bytes      outstanding
第1次    334,267,309      334,171,707     95,602
第2次    2,121,016,189    2,120,940,020   76,169
(10min)  +1,786,748,880  +1,786,768,313   -19,433(基本不动)
```

alloc_bytes 和 free_bytes 各涨 ~1.79G，**同步增长，差值（outstanding）稳定**。C 程序的 malloc/free 都走 libc，1/100 采样后 free uprobe 能配对追踪，不漂移。

### 3.2 Python 进程漂移（python3 web/app.py，2 天）

```
python3 web/app.py（工具自身）：

         前台显示（BPF ×100）   实际 VmRSS    漂移量
2天后    420.5 MB              177 MB        +243 MB
```

alloc_bytes 持续增长（采样的 arena malloc 累积），free_bytes 几乎不动（pymalloc 的 free 不触发 uprobe），outstanding 单调上涨。

### 3.3 fd 漂移（systemd，2 天）

```
systemd（PID 1）：

         前台显示（BPF）   实际 /proc/1/fd   漂移量
2天后    467               125              +342（~7/hour）
```

fd 漂移根因是 close 路径覆盖不全（file_close_fd + filp_close 漏部分 close 路径），详见 `leakdetect-fd追踪修复-20260903.md`。漂移率 ~7/hour，与 0903 文档的 0.9%/hour 一致。

### 3.4 进程内存（RSS）2 天趋势

通过 `_diag_loop` 诊断日志（每 5min 打印各数据结构大小）：

| 时间点 | RSS | elf缓存 | dwarf缓存 | BPF map条目 |
|---|---|---|---|---|
| 启动时 | 49 MB | 0 | 0 | ~1 |
| 5分钟后 | 458 MB | 2(18317符号) | 1(337049行) | 343 |
| 2天后 | 181 MB | 9(19997符号) | 6(364056行) | 2417 |

**RSS 从 458MB 降到 181MB**——启动时 DWARF 解析的分配 churn 残留被内核逐步回收。BPF map 条目从 343 增到 2417（正常增长，系统进程活动），但数据结构总量 < 20MB，不是 RSS 的主要贡献者。

---

## 四、当前限制：malloc 暂时只追踪 C/C++ 程序

### 4.1 限制内容

基于验证数据（C 程序不漂移、Python 漂移、Python 漂移无法从 BPF 源头修复），决定：

- **malloc 追踪暂时限定于 C/C++ 程序**
- **Python 进程从 malloc 追踪中排除**（`memory.py` `_iter_stats` 跳过 Python PID）
- 排除方式：`pid == os.getpid()`（工具自身）+ `/proc/pid/exe` 含 "python"（其他 Python 进程）

### 4.2 不影响的部分

| 功能 | 影响 | 说明 |
|---|---|---|
| C/C++ 程序 malloc 追踪 | ✅ 不受影响 | 已验证不漂移，保持 BPF 追踪 |
| C/C++ 程序 malloc 告警 + 栈归因 | ✅ 不受影响 | 值准确 → 告警可信 → 栈可信 |
| mmap 追踪（所有进程） | ✅ 不受影响 | free 侧用 tracepoint（全量），不漂移 |
| thread/fd 追踪 | ✅ 不受影响 | fd 校准修值，thread 全量覆盖 |
| Python 进程的 mmap/thread/fd/CPU | ✅ 不受影响 | 这些不依赖 libc free uprobe |

### 4.3 影响的部分

| 功能 | 影响 | 说明 |
|---|---|---|
| Python 进程的 malloc 值 | ❌ 不再显示 | 从 per_process 列表和告警中排除 |
| Python 进程的 malloc 告警 | ❌ 不再触发 | 无法检测 Python 进程的堆内存泄露 |

---

## 五、未来需求：Python malloc 高精准度

**Python 部分的 malloc 精准度必须实现，这是明确要求。**

### 5.1 技术方向（待研究）

| 方向 | 思路 | 可行性 | 复杂度 |
|---|---|---|---|
| A. /proc VmRSS 取值 + BPF 取栈 | Python 进程的"是否泄露"用 VmRSS 判断，"在哪里泄露"用 BPF malloc uprobe 取栈 | ✅ 可行 | 中 |
| B. hook pymalloc 内部函数 | uprobe 挂 `PyObject_Free`，但 ptr 维度对不上 arena | ❌ 不兼容 | — |
| C. Python tracemalloc | Python 层面追踪分配，不走 BPF | ✅ 可行 | 高（侵入式） |
| D. 双维度校准 | BPF 值定期用 VmRSS 校准（调整 free_bytes） | ⚠️ 近似 | 中 |

方向 A 是当前最可行的方案：值用 /proc（准确无漂移），栈用 BPF（malloc 调用点不变，准确）。当 VmRSS 确认泄露时，从 BPF outstanding_map 取 alloc_bytes 最大的栈作为嫌疑点。

### 5.2 前置条件

- fd 校准机制先实施（fd 漂移影响所有进程，不限于 Python）
- C/C++ malloc 追踪保持准确（已验证）
- 持久化专项实施后（有历史数据才能评估 VmRSS 趋势）

---

## 六、修复方案（本次实施）

### 6.1 fd 漂移修复：定期校准（所有进程）

**机制**：每 5min，对 fd_count_map 每个 PID：
1. 读 `/proc/pid/fd` → 真实 fd 数
2. 调整 BPF `close_count = open_count - 实际fd数`
3. 用 `bpf_map_update_elem` 写回（保留 stack_addrs/comm/stack_cnt）

校准后 outstanding = open - close = 实际fd数。漂移上限 = 5min × 7/hour ≈ 0.6 fd。

**不破坏长线**：fd 校准是改值不是清零，趋势连续。

### 6.2 malloc：排除 Python 进程

**机制**：在 `memory.py` 的 `_iter_stats` 中跳过 Python PID：
- `pid == os.getpid()` → 跳过
- `/proc/pid/exe` 含 "python" → 跳过
- C/C++ 进程保持 BPF 追踪（已验证不漂移）

**不破坏长线**：C/C++ 值连续不重置，趋势完整。

### 6.3 改动文件

| 文件 | 改动 | 行数 |
|---|---|---|
| `core/loader.py` | 加 `bpf_map_update_elem` 声明 + `calibrate_fd_count()` | ~35 |
| `web/backend.py` | 加 `_calibrate_loop()` + mem per_process 过滤 Python PID | ~25 |
| `analyzer/memory.py` | `_iter_stats` 加 Python PID 过滤 | ~15 |
| `config/default.yaml` | 加 `calibration.interval: 300` | 2 |
| BPF C 代码 | **不改** | 0 |

### 6.4 验证

- fd：校准后 systemd 应显示 ~125（实际值），不漂移到 467
- malloc：前端只显示 C/C++ 进程，不显示 python3 的 420MB
- C/C++ malloc：跑 steady_alloc，值稳定不动
- 告警：跑 mem_leak（C 程序），告警正常触发

---

## 七、总结

| 问题 | 根因 | 当前修复 | 未来 |
|---|---|---|---|
| fd 漂移（所有进程） | close 路径覆盖不全 | 定期校准（/proc/pid/fd） | ✅ 一劳永逸 |
| malloc 漂移（Python） | pymalloc free 不走 libc | 排除 Python，只追踪 C/C++ | 未来实现 Python 高精准度 |
| malloc（C/C++） | 不漂移 | 保持现状 | 不需要修 |
