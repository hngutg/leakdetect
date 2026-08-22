# B1 里程碑设计文档 — 内存抓取 + 分析

> 文档版本：v1.0  
> 日期：2026-07-08  
> 状态：⬜ 待实施  
> 关联文档：`D:\leakdetect-backend-design.md`、`D:\leakdetect-b0-design.md`

---

## 一、B1 目标

实现**内存泄露检测端到端闭环**：eBPF 抓 malloc/free → Python 聚合分析 → 趋势检测 → 告警 + 栈定位 → 前端展示真实数据。

| 交付 | 说明 |
|---|---|
| mem.bpf.c | malloc/free uprobe + 配对追踪 + 1/100 采样 |
| Python 分析层 | loader → ingest → aggregator → symbolizer → memory detector |
| Flask 对接 | 替换 mock 内存部分，前端内存数据来自 eBPF |
| mem_leak.c | 合成泄露程序，验证端到端 |
| 泄露检测算法 | 双条件判定 + 状态生命周期 + 防抖 |

**B1 完成后**：前端内存折线图/告警/栈展示全部来自真实 eBPF 数据（非 mock）。线程/句柄/CPU 仍用 mock 或 /proc 简单轮询，B2 替换。

---

## 二、前置条件

| 条件 | 状态 | 说明 |
|---|---|---|
| B0 技术验证 | ✅ | 4 项全部通过 |
| BCC 可用 | ✅ | `from bcc import BPF` |
| 前端 F1-F4 | ✅ | 契约稳定，替换数据源即可 |
| SQLite schema | ✅ | F1 已建表 |
| config/default.yaml | ✅ | 阈值已定义（B1 扩展） |

---

## 三、B1 数据流

```
┌── mem.bpf.c ──────────────────────────────────────┐
│  uprobe malloc entry  → PT_REGS_PARM1 = size      │
│  uretprobe malloc ret → PT_REGS_RC = ptr          │
│  uprobe free entry    → PT_REGS_PARM1 = ptr       │
│                                                    │
│  采样 1/100：sampler map 计数                     │
│  配对追踪：allocs[ptr] = {size, stack_id}         │
│  栈捕获：stack_traces.get_stackid()               │
└──────────────────┬─────────────────────────────────┘
                   │ perf buffer (mem_event_t)
                   ▼
┌── core/ingest.py ─────────────────────────────────┐
│  解码 C struct → Python dict                      │
│  分发到 aggregator                                 │
└──────────────────┬─────────────────────────────────┘
                   │
                   ▼
┌── core/aggregator.py ─────────────────────────────┐
│  按 (PID, stack_id) 聚合：                        │
│    alloc_bytes += event.size (op='a')             │
│    free_bytes  += event.size (op='f')             │
│  outstanding = alloc_bytes - free_bytes           │
└──────────────────┬─────────────────────────────────┘
                   │
         ┌─────────┼─────────┐
         ▼         ▼         ▼
┌── analyzer/   ┌── db.py   ┌── backend.py
│  memory.py    │  采样写入  │  组装 DashboardUpdate
│  双条件检测   │  SQLite    │  → web/sockets.py
│  状态生命周期 │            │  → WebSocket 推送
│  生成告警     │            │
└──────┬───────└───────────└──────────┬─────────────┘
       │                                │
       ▼                                ▼
┌── alert_logger.py            ┌── 前端（不变）
│  写 leakdetect.log           │  内存折线图 + 告警 + 栈
└──────────────────────────────┘
```

---

## 四、泄露检测算法（核心设计）

### 4.1 检测指标

| 指标 | 定义 | 计算方式 |
|---|---|---|
| outstanding_bytes | 未释放的分配字节数 | `Σalloc_bytes - Σfree_bytes`（按 PID + stack_id 聚合） |
| outstanding_est | 估算真实值 | `outstanding_bytes × 100`（采样率 1/100 的补偿） |
| 时间序列 | outstanding_est 随时间的变化 | `[(timestamp, outstanding_est), ...]` |

### 4.2 双条件判定

泄露判定采用**双条件**，**任一满足即触发**，覆盖两种泄露模式：

| 条件 | 名称 | 检测模式 | 适用场景 |
|---|---|---|---|
| 条件 A | 持续增长 | 80% 时间点上升 + 净增 > 阈值 | 连续型泄露（不停 malloc 不 free） |
| 条件 B | 净增长 | 首尾均值差 > 阈值 | 锯齿型泄露（alloc/free 反复但总体上升） |

#### 条件 A：持续增长

| 子条件 | 要求 | 说明 |
|---|---|---|
| 采样点数 | ≥ 10 | 确保有足够数据判断趋势 |
| 时间跨度 | ≥ `leak_seconds`（默认 60s） | 过滤短暂分配 |
| 单调性 | ≥ 80% 的点 `value[i] >= value[i-1]` | 允许 20% 波动 |
| 净增量 | `last_value - first_value > outstanding_delta_bytes`（默认 1MB） | 确保有实质增长 |

#### 条件 B：净增长

| 子条件 | 要求 | 说明 |
|---|---|---|
| 采样点数 | ≥ 10 | 同上 |
| 时间跨度 | ≥ `leak_seconds`（默认 60s） | 同上 |
| 首尾均值差 | `last_avg - first_avg > outstanding_delta_bytes` | 比较首尾各 N 个点的均值 |
| 均值窗口 N | `min(5, len(history) // 2)` | 取首尾各 5 个点求均值，避免单点尖峰误判 |

#### 双条件覆盖矩阵

| 内存模式 | 时序示意 | 条件 A（80%单调） | 条件 B（净增长） | 判定 |
|---|---|---|---|---|
| 连续增长 | `↗↗↗↗↗↗` | ✅ 100% > 80% | ✅ 净增 > 1MB | **泄露** |
| 锯齿增长 | `↗↘↗↘↗↘↗` | ❌ 50% < 80% | ✅ last_avg > first_avg | **泄露** |
| 增长后稳定 | `↗↗↗→→→→` | ❌ 50% < 80% | ❌ 净增不够 | 不告警 |
| 完全稳定 | `→→→→→→→` | ❌ 0% < 80% | ❌ 差值为 0 | 不告警 |
| 增长后回落 | `↗↗↘↘↘↘` | ❌ < 80% | ❌ last_avg < first_avg | 不告警 |
| 临时尖峰 | `→→↗→→→→` | ❌ < 80% | ❌ 均值差小 | 不告警 |

### 4.3 状态生命周期

每个 (PID, stack_id) 维护一个状态机，避免误报和告警抖动：

```
┌────────┐  增长>30s   ┌──────────┐  持续到60s  ┌───────────────┐
│ normal │ ─────────→ │ observing│ ──────────→│ leak_suspected │
│        │             │ (黄色)   │             │ (红色)         │
└────────┘             └──────────┘             └───────────────┘
     ↑                      │                         │
     │     增长停止          │  下降>峰值50%           │  下降>峰值50%
     │     超60s            │  持续30s                │  持续30s
     │                      ▼                         ▼
     │                 ┌────────┐              ┌──────────┐
     │                 │ normal │              │ resolved │
     │                 │        │              │ (已恢复)  │
     └─────────────────┘        └──────────┘ ──── 超60s ──→ normal
```

| 状态 | 进入条件 | 前端展示 | 日志 | 说明 |
|---|---|---|---|---|
| `normal` | 默认 / resolved 后 60s 无新增长 | 无告警 | — | 正常态 |
| `observing` | outstanding 增长持续 > `observe_seconds`（30s） | 黄色"观察中" | **不写** | 疑似但不确认 |
| `leak_suspected` | 从 observing 持续增长到 `leak_seconds`（60s）+ 条件 A 或 B 满足 | 红色"疑似泄露" | **写告警** | 确认泄露 |
| `resolved` | 从 leak_suspected 状态，outstanding 下降到峰值 × `clear_ratio`（50%）以下，持续 `clear_seconds`（30s） | 显示"已恢复" | **写恢复** | 泄露缓解 |

### 4.4 防抖机制（Hysteresis）

防止 outstanding 小幅波动导致状态频繁切换：

| 状态切换 | 触发条件 | 持续要求 | 防抖目的 |
|---|---|---|---|
| normal → observing | outstanding 增长 | 持续 `observe_seconds`（30s） | 避免短暂分配误触发 |
| observing → leak_suspected | 条件 A 或 B 满足 | 持续到 `leak_seconds`（60s） | 确认不是短暂增长 |
| leak_suspected → resolved | outstanding < 峰值 × `clear_ratio`（50%） | 持续 `clear_seconds`（30s） | 避免小幅释放误判为恢复 |
| resolved → normal | 无新增长 | 持续 `resolve_seconds`（60s） | 清理旧告警 |
| observing → normal | 增长停止 | outstanding 不再上升 | 回到正常 |

### 4.5 峰值追踪

`leak_suspected` 状态下追踪 outstanding 的历史峰值，用于判断是否"恢复"：

```python
# 进入 leak_suspected 时记录峰值
state.peak_outstanding = current_outstanding

# 恢复判定：当前值降到峰值 50% 以下
if current_outstanding < state.peak_outstanding * clear_ratio:
    # 进入 resolved
```

### 4.6 完整检测流程示例

**场景：锯齿型泄露（alloc/free 反复但总体上升）**

```
时间(s):  0    5   10   15   20   25   30   35   40   45   50   55   60   65   70
值(MB):   0   ↗8  ↘3  ↗12 ↘5  ↗15 ↘8  ↗18 ↘10 ↗22 ↘12 ↗25 ↘15 ↗28 ↘18

状态:     normal ──────────→ observing(30s) ──────────→ leak_suspected(60s)
                                  ↑ 增长持续30s            ↑ 条件B满足(净增>1MB)

日志:
  [60s] MEM LEAK PID=1234 nginx | outstanding +15MB in 60s | main → malloc
```

**场景：分配后最终释放（非泄露）**

```
时间(s):  0    10   20   30   40   50   60   70   80   90   100  110  120
值(MB):   0   ↗5  ↗10 ↗15 ↗20 ↗25 ↗30  ↘25 ↘20 ↘15 ↘10  ↘5   ↘0

状态:     normal → observing(30s) → leak_suspected(60s) → resolved(80s) → normal(120s)
                                       ↑ 告警发出           ↑ 下降到峰值50%    ↑ 清除

日志:
  [60s] MEM LEAK PID=1234 | outstanding +30MB | main → malloc
  [80s] RESOLVED PID=1234 | outstanding dropped to 15MB (peak was 30MB)
```

---

## 五、mem.bpf.c 设计

### 5.1 数据结构

```c
#include <uapi/linux/ptrace.h>

// 事件结构（perf buffer 传输）
struct mem_event_t {
    u32 pid;
    u32 tid;
    u64 size;       // malloc size（free 时为匹配的 alloc size）
    u64 ptr;        // malloc 返回值 / free 参数
    int stack_id;   // 栈 map ID（-1 = 无栈）
    char op;        // 'a'=alloc, 'f'=free
    char comm[16];
};

// 暂存 entry probe 的信息（按 tid 索引）
struct alloc_info_t {
    u64 size;
    int stack_id;
};
```

### 5.2 BPF Maps

```c
// perf buffer：事件输出
BPF_PERF_OUTPUT(events);

// 栈追踪
BPF_STACK_TRACE(stack_traces, 16384);

// 采样计数器
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} sampler SEC(".maps");

// entry probe 暂存：tid → {size, stack_id}
BPF_HASH(entry_info, u32, struct alloc_info_t, 10000);

// alloc 追踪：ptr → {size, stack_id}
BPF_HASH(allocs, u64, struct alloc_info_t, 1000000);
```

### 5.3 探针函数

#### malloc entry — 采样 + 记录 size + 捕获栈

```c
int trace_malloc_entry(struct pt_regs *ctx) {
    // 采样 1/100
    u32 zero = 0;
    u64 *cnt = sampler.lookup(&zero);
    if (cnt) {
        *cnt += 1;
        if (*cnt % 100 != 0) return 0;
    }

    u32 tid = (u32)bpf_get_current_pid_tgid();
    struct alloc_info_t info = {};
    info.size = PT_REGS_PARM1(ctx);
    info.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);
    entry_info.update(&tid, &info);
    return 0;
}
```

> **架构兼容**：`PT_REGS_PARM1(ctx)` 自动选 RDI(x86_64)/X0(aarch64)。

#### malloc return — 取 ptr + 存 allocs map + 发事件

```c
int trace_malloc_return(struct pt_regs *ctx) {
    u64 ptr = PT_REGS_RC(ctx);
    if (ptr == 0) return 0;  // malloc 失败

    u32 tid = (u32)bpf_get_current_pid_tgid();
    struct alloc_info_t *info = entry_info.lookup(&tid);
    if (!info) return 0;  // 未被采样

    // 存入 allocs 追踪 map
    struct alloc_info_t alloc = {};
    alloc.size = info->size;
    alloc.stack_id = info->stack_id;
    allocs.update(&ptr, &alloc);

    // 发 alloc 事件
    struct mem_event_t event = {};
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.tid = tid;
    event.size = info->size;
    event.ptr = ptr;
    event.stack_id = info->stack_id;
    event.op = 'a';
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    events.perf_submit(ctx, &event, sizeof(event));

    entry_info.delete(&tid);
    return 0;
}
```

> **架构兼容**：`PT_REGS_RC(ctx)` 自动选 RAX(x86_64)/X0(aarch64)。

#### free entry — 查配对 + 发事件

```c
int trace_free_entry(struct pt_regs *ctx) {
    u64 ptr = PT_REGS_PARM1(ctx);
    struct alloc_info_t *info = allocs.lookup(&ptr);
    if (!info) return 0;  // 非采样 alloc，跳过

    // 发 free 事件（含原始 alloc 的 size + stack_id）
    struct mem_event_t event = {};
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.tid = (u32)bpf_get_current_pid_tgid();
    event.size = info->size;
    event.ptr = ptr;
    event.stack_id = info->stack_id;
    event.op = 'f';
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    events.perf_submit(ctx, &event, sizeof(event));

    allocs.delete(&ptr);
    return 0;
}
```

### 5.4 采样策略

| 点 | 说明 |
|---|---|
| 采样率 | 1/100（每 100 次 malloc 抓 1 次） |
| 采样位置 | malloc entry（return 和 free 自动跟随，因为配对追踪） |
| outstanding 值 | 仅为真实值的 1/100。展示时乘以 100 估算 |
| 泄露检测 | 不受采样影响——趋势（单调增长/净增长）在 1/100 采样下仍然成立 |
| 未匹配的 free | 99/100 的 free 找不到配对，直接跳过（不发事件） |
| allocs map 溢出 | max_entries=1000000，溢出时 BPF 自动淘汰旧条目 |

### 5.5 attach 方式（Python 端）

```python
b = BPF(text=bpf_text)
b.attach_uprobe(name="c", sym="malloc", fn_name="trace_malloc_entry")
b.attach_uretprobe(name="c", sym="malloc", fn_name="trace_malloc_return")
b.attach_uprobe(name="c", sym="free", fn_name="trace_free_entry")
```

> `name="c"` BCC 自动解析 libc 路径，x86_64/aarch64 兼容。

---

## 六、Python 后端模块设计

### 6.1 core/loader.py — BPF 加载器

```python
class BpfLoader:
    def __init__(self, config):
        self.config = config
        self.bpf = None

    def load_mem(self):
        """加载内存 BPF 程序并 attach 探针。"""
        with open("bpf/mem.bpf.c") as f:
            bpf_text = f.read()

        self.bpf = BPF(text=bpf_text)
        self.bpf.attach_uprobe(name="c", sym="malloc",
                               fn_name="trace_malloc_entry")
        self.bpf.attach_uretprobe(name="c", sym="malloc",
                                  fn_name="trace_malloc_return")
        self.bpf.attach_uprobe(name="c", sym="free",
                               fn_name="trace_free_entry")

    def start_event_loop(self, callback):
        """启动 perf buffer 读取（阻塞，应在后台线程运行）。"""
        self.bpf["events"].open_perf_buffer(callback)
        while True:
            self.bpf.perf_buffer_poll()

    def cleanup(self):
        if self.bpf:
            self.bpf.cleanup()
```

### 6.2 core/ingest.py — 事件摄入

```python
import ctypes as ct

class MemEvent(ct.Structure):
    _fields_ = [
        ("pid", ct.c_uint),
        ("tid", ct.c_uint),
        ("size", ct.c_ulonglong),
        ("ptr", ct.c_ulonglong),
        ("stack_id", ct.c_int),
        ("op", ct.c_char),
        ("comm", ct.c_char * 16),
    ]


class IngestManager:
    def __init__(self, aggregator, symbolizer):
        self.aggregator = aggregator
        self.symbolizer = symbolizer

    def on_event(self, cpu, data, size):
        """perf buffer 回调。"""
        event = ct.cast(data, ct.POINTER(MemEvent)).contents
        self.aggregator.on_mem_event({
            "pid": event.pid,
            "tid": event.tid,
            "size": event.size,
            "ptr": event.ptr,
            "stack_id": event.stack_id,
            "op": chr(event.op),
            "comm": event.comm.decode('utf-8', errors='replace'),
        })
```

### 6.3 core/aggregator.py — 聚合器

```python
import threading

class Aggregator:
    def __init__(self):
        self._lock = threading.Lock()
        self.mem_stats = {}
        # {pid: {stack_id: {alloc_bytes, alloc_count, free_bytes, free_count, comm}}}

    def on_mem_event(self, event):
        pid = event["pid"]
        sid = event["stack_id"]
        op = event["op"]

        with self._lock:
            if pid not in self.mem_stats:
                self.mem_stats[pid] = {}
            if sid not in self.mem_stats[pid]:
                self.mem_stats[pid][sid] = {
                    "alloc_bytes": 0, "alloc_count": 0,
                    "free_bytes": 0, "free_count": 0,
                    "comm": event["comm"],
                }
            stats = self.mem_stats[pid][sid]
            if op == 'a':
                stats["alloc_bytes"] += event["size"]
                stats["alloc_count"] += 1
            elif op == 'f':
                stats["free_bytes"] += event["size"]
                stats["free_count"] += 1

    def get_total_outstanding(self):
        """所有进程 outstanding 总和（×100 估算）。"""
        total = 0
        with self._lock:
            for stacks in self.mem_stats.values():
                for s in stacks.values():
                    total += s["alloc_bytes"] - s["free_bytes"]
        return total * 100

    def get_per_process_mem(self):
        """按进程汇总，前端 per_process 展示。"""
        result = []
        with self._lock:
            for pid, stacks in self.mem_stats.items():
                total = sum(s["alloc_bytes"] - s["free_bytes"]
                           for s in stacks.values())
                comm = next(iter(stacks.values()))["comm"] if stacks else ""
                result.append({
                    "pid": pid, "name": comm,
                    "value": total * 100, "delta_60s": 0,
                })
        return sorted(result, key=lambda x: x["value"], reverse=True)[:5]

    def get_snapshot(self):
        """供 SQLite 采样调用。"""
        return self.get_per_process_mem()
```

### 6.4 symbolizer/symbols.py — 符号解析

```python
class Symbolizer:
    def __init__(self, bpf):
        self.bpf = bpf

    def resolve(self, stack_id, pid):
        """解析栈为 [{func, addr}] 列表。"""
        if stack_id < 0:
            return []
        frames = []
        for addr in self.bpf["stack_traces"].walk(stack_id):
            try:
                sym = self.bpf.sym(addr, pid,
                                   show_module=True, show_offset=True)
                frames.append({
                    "func": sym.decode('utf-8', errors='replace'),
                    "addr": "0x%x" % addr,
                })
            except Exception:
                frames.append({"func": "[unknown]", "addr": "0x%x" % addr})
        return frames
```

### 6.5 analyzer/memory.py — 内存泄露检测器

**核心模块：双条件判定 + 状态生命周期 + 防抖。**

```python
import time
import threading

# 状态枚举
STATE_NORMAL = "normal"
STATE_OBSERVING = "observing"
STATE_LEAK = "leak_suspected"
STATE_RESOLVED = "resolved"


class StackSiteState:
    """单个 (PID, stack_id) 的状态追踪。"""
    def __init__(self):
        self.state = STATE_NORMAL
        self.history = []          # [(timestamp, outstanding_est)]
        self.peak_outstanding = 0  # leak 状态下的峰值
        self.state_since = 0       # 进入当前状态的时间
        self.last_check_outstanding = 0  # 上次检查的值


class MemoryLeakDetector:
    def __init__(self, config):
        cfg = config["thresholds"]["mem"]
        self.threshold_bytes = cfg["outstanding_delta_bytes"]
        self.observe_seconds = cfg.get("observe_seconds", 30)
        self.leak_seconds = cfg.get("leak_seconds", 60)
        self.clear_ratio = cfg.get("clear_ratio", 0.5)
        self.clear_seconds = cfg.get("clear_seconds", 30)
        self.resolve_seconds = cfg.get("resolve_seconds", 60)

        self._lock = threading.Lock()
        # {(pid, stack_id): StackSiteState}
        self.states = {}
        self.active_alerts = []

    def check(self, aggregator, symbolizer):
        """周期调用：检查所有聚合数据，更新状态 + 告警。"""
        now = time.time()
        new_alerts = []

        with self._lock:
            for pid, stacks in aggregator.mem_stats.items():
                for sid, stats in stacks.items():
                    outstanding = stats["alloc_bytes"] - stats["free_bytes"]
                    outstanding_est = outstanding * 100  # ×100 估算
                    key = (pid, sid)

                    if key not in self.states:
                        self.states[key] = StackSiteState()
                    st = self.states[key]

                    # 记录时间序列
                    st.history.append((now, outstanding_est))
                    # 清理窗口外数据（leak_seconds * 2）
                    cutoff = now - self.leak_seconds * 2
                    st.history = [(t, v) for t, v in st.history if t >= cutoff]

                    # 状态机流转
                    self._update_state(st, key, now, outstanding_est)

                    # 状态行为
                    if st.state == STATE_LEAK:
                        # 生成/更新告警
                        stack = symbolizer.resolve(sid, pid)
                        alert = {
                            "id": "mem-%d-%d" % (pid, sid),
                            "resource": "mem",
                            "pid": pid,
                            "process_name": stats["comm"],
                            "severity": "leak",
                            "detail": "outstanding +%d bytes in %ds" % (
                                outstanding_est, int(now - st.state_since)
                            ),
                            "timestamp": int(now),
                            "stack": stack,
                        }
                        new_alerts.append(alert)

                    elif st.state == STATE_RESOLVED:
                        # 保留告警但标记已恢复
                        stack = symbolizer.resolve(sid, pid)
                        alert = {
                            "id": "mem-%d-%d" % (pid, sid),
                            "resource": "mem",
                            "pid": pid,
                            "process_name": stats["comm"],
                            "severity": "resolved",
                            "detail": "resolved: outstanding dropped to %d (peak was %d)" % (
                                outstanding_est, st.peak_outstanding
                            ),
                            "timestamp": int(now),
                            "stack": stack,
                        }
                        new_alerts.append(alert)

            self.active_alerts = new_alerts
        return new_alerts

    def _update_state(self, st, key, now, outstanding):
        """状态机流转逻辑。"""
        elapsed_in_state = now - st.state_since

        if st.state == STATE_NORMAL:
            # 检查是否开始增长
            if len(st.history) >= 2 and outstanding > st.last_check_outstanding:
                if self._is_growing(st.history, self.observe_seconds):
                    st.state = STATE_OBSERVING
                    st.state_since = now

        elif st.state == STATE_OBSERVING:
            # 检查是否确认泄露
            if self._is_leaking(st.history):
                st.state = STATE_LEAK
                st.state_since = now
                st.peak_outstanding = outstanding
            elif not self._is_growing(st.history, self.observe_seconds):
                # 增长停止，回到 normal
                st.state = STATE_NORMAL
                st.state_since = now

        elif st.state == STATE_LEAK:
            # 更新峰值
            if outstanding > st.peak_outstanding:
                st.peak_outstanding = outstanding
            # 检查是否恢复
            if (outstanding < st.peak_outstanding * self.clear_ratio
                and elapsed_in_state > self.clear_seconds):
                st.state = STATE_RESOLVED
                st.state_since = now

        elif st.state == STATE_RESOLVED:
            # 检查是否清除
            if elapsed_in_state > self.resolve_seconds:
                st.state = STATE_NORMAL
                st.state_since = now
                st.history = []
                st.peak_outstanding = 0

        st.last_check_outstanding = outstanding

    def _is_growing(self, history, duration):
        """检查最近 duration 秒内是否在增长。"""
        if len(history) < 2:
            return False
        cutoff = history[-1][0] - duration
        recent = [(t, v) for t, v in history if t >= cutoff]
        if len(recent) < 2:
            return False
        return recent[-1][1] > recent[0][1]

    def _is_leaking(self, history):
        """双条件判定：条件 A（持续增长）或条件 B（净增长）。"""
        if len(history) < 10:
            return False

        first_t, _ = history[0]
        last_t, _ = history[-1]
        if last_t - first_t < self.leak_seconds:
            return False

        # 条件 A：80% 单调性 + 净增
        increasing = sum(1 for i in range(1, len(history))
                        if history[i][1] >= history[i-1][1])
        cond_a = (increasing >= len(history) * 0.8 and
                  history[-1][1] - history[0][1] > self.threshold_bytes)

        # 条件 B：首尾均值差
        n = min(5, len(history) // 2)
        first_avg = sum(v for _, v in history[:n]) / n
        last_avg = sum(v for _, v in history[-n:]) / n
        cond_b = (last_avg - first_avg > self.threshold_bytes)

        return cond_a or cond_b

    def get_active_alerts(self):
        with self._lock:
            return list(self.active_alerts)
```

### 6.6 storage/db.py — SQLite 存储

```python
import sqlite3
import time
import threading

class Database:
    def __init__(self, path):
        self.path = path
        self._lock = threading.Lock()
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self._init_schema()

    def _init_schema(self):
        with open("storage/schema.sql") as f:
            self.conn.executescript(f.read())
            self.conn.commit()

    def write_sample(self, resource, pid, value, container_id=None):
        with self._lock:
            self.conn.execute(
                "INSERT INTO samples (timestamp, resource, pid, value, container_id) "
                "VALUES (?, ?, ?, ?, ?)",
                (int(time.time()), resource, pid, value, container_id)
            )
            self.conn.commit()

    def write_alert(self, alert):
        import json
        with self._lock:
            self.conn.execute(
                "INSERT OR REPLACE INTO alerts (id, timestamp, resource, pid, "
                "process_name, severity, detail, stack_json) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (alert["id"], alert["timestamp"], alert["resource"],
                 alert["pid"], alert.get("process_name", ""),
                 alert["severity"], alert["detail"],
                 json.dumps(alert.get("stack", [])))
            )
            self.conn.commit()

    def query_history(self, resource, range_tag):
        ranges = {"1d": 86400, "7d": 604800, "30d": 2592000}
        duration = ranges.get(range_tag, 86400)
        cutoff = int(time.time()) - duration
        with self._lock:
            cur = self.conn.execute(
                "SELECT timestamp, value FROM samples "
                "WHERE resource=? AND timestamp>=? ORDER BY timestamp",
                (resource, cutoff)
            )
            series = [{"t": row[0], "v": row[1]} for row in cur.fetchall()]
        return {"range": range_tag, "series": series}
```

### 6.7 logging/alert_logger.py — 告警日志

```python
from datetime import datetime

class AlertLogger:
    def __init__(self, path):
        self.path = path

    def log(self, alert):
        with open(self.path, "a") as f:
            stack_str = " → ".join(
                frame.get("func", "?") for frame in alert.get("stack", [])
            )
            if alert["severity"] == "leak":
                f.write("[%s] MEM LEAK PID=%d %s | %s | %s\n" % (
                    datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    alert["pid"], alert.get("process_name", ""),
                    alert["detail"], stack_str,
                ))
            elif alert["severity"] == "resolved":
                f.write("[%s] MEM RESOLVED PID=%d %s | %s\n" % (
                    datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    alert["pid"], alert.get("process_name", ""),
                    alert["detail"],
                ))
```

### 6.8 backend.py — 集成层

```python
import time
import threading

class Backend:
    def __init__(self, config):
        self.config = config
        self.loader = BpfLoader(config)
        self.aggregator = Aggregator()
        self.symbolizer = None
        self.analyzer = MemoryLeakDetector(config)
        self.db = Database(config["storage"]["sqlite_path"])
        self.logger = AlertLogger(config["logging"]["alert_log"])

    def start(self):
        self.loader.load_mem()
        self.symbolizer = Symbolizer(self.loader.bpf)
        ingest = IngestManager(self.aggregator, self.symbolizer)

        # 事件读取线程
        threading.Thread(
            target=self.loader.start_event_loop,
            args=(ingest.on_event,), daemon=True
        ).start()

        # 分析线程（每 5s 检查泄露）
        threading.Thread(target=self._analyzer_loop, daemon=True).start()

        # SQLite 采样线程（每 60s）
        threading.Thread(target=self._sampler_loop, daemon=True).start()

    def _analyzer_loop(self):
        while True:
            alerts = self.analyzer.check(self.aggregator, self.symbolizer)
            for a in alerts:
                self.logger.log(a)
                self.db.write_alert(a)
            time.sleep(5)

    def _sampler_loop(self):
        while True:
            for p in self.aggregator.get_snapshot():
                self.db.write_sample("mem", p["pid"], p["value"])
            time.sleep(60)

    def get_dashboard_update(self):
        now = int(time.time())
        alerts = self.analyzer.get_active_alerts()
        return {
            "type": "dashboard_update",
            "timestamp": now,
            "filter": {"container_id": None, "pid": None},
            "latest_points": {
                "mem": {"t": now, "v": self.aggregator.get_total_outstanding()},
                "thread": {"t": now, "v": 0},
                "fd": {"t": now, "v": 0},
                "cpu": {"t": now, "v": 0},
            },
            "per_process": {
                "mem": self.aggregator.get_per_process_mem(),
                "thread": [], "fd": [], "cpu": [],
            },
            "alerts": alerts,
            "containers": [],
        }

    def get_history(self, resource, range_tag):
        return self.db.query_history(resource, range_tag)


backend = None
```

---

## 七、配置项（config/default.yaml 扩展）

B1 需在 `config/default.yaml` 的 `thresholds.mem` 下新增状态生命周期参数：

```yaml
thresholds:
  mem:
    outstanding_delta_bytes: 1048576   # 告警增量阈值（1MB）
    alloc_free_diff: 10000            # alloc-free 差值阈值
    observe_seconds: 30               # 观察期时长（normal→observing）
    leak_seconds: 60                  # 确认泄露时长（observing→leak）
    clear_ratio: 0.5                  # 恢复阈值（峰值百分比）
    clear_seconds: 30                 # 恢复确认时长（leak→resolved）
    resolve_seconds: 60               # 清除时长（resolved→normal）
```

---

## 八、与 Flask 对接

### 8.1 web/app.py 修改

```python
from backend import Backend, backend
from core.config import load_config

config = load_config("config/default.yaml")
backend = Backend(config)
backend.start()
```

### 8.2 web/sockets.py 修改

```python
# 修改前
from mock import producer
data = producer.get_dashboard_update()

# 修改后
from backend import backend
data = backend.get_dashboard_update()
```

### 8.3 web/api.py 修改

```python
# /api/history 修改
return jsonify(backend.get_history(resource, range_tag))

# 其他路由暂不改动（B2/B3 替换）
```

### 8.4 切换策略

B1 只替换**内存相关**数据源：
- `latest_points.mem` + `per_process.mem` + `alerts` → backend
- `/api/history?resource=mem` → backend.db
- thread/fd/cpu → 暂为 0（B2 实现）

---

## 九、mem_leak.c 验证程序

```c
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

int main() {
    printf("Starting memory leak simulation...\n");
    printf("Allocating 1MB every 0.1s without free\n");
    for (int i = 0; i < 10000; i++) {
        void *p = malloc(1024 * 1024);
        if (p == NULL) {
            printf("malloc failed at iteration %d\n", i);
            break;
        }
        usleep(100000);  // 0.1s
    }
    printf("Done. Keeping process alive for monitoring.\n");
    sleep(600);
    return 0;
}
```

编译：
```bash
gcc -o tests/leak_programs/mem_leak tests/leak_programs/mem_leak.c
```

---

## 十、线程模型

```
主线程
  ├── Flask + SocketIO（Web 服务）
  ├── pusher 线程（每 1s 调 backend.get_dashboard_update() → WebSocket 推送）
  ├── BPF 事件读取线程（perf_buffer_poll，阻塞）
  ├── 分析线程（每 5s：聚合数据 → 双条件检测 → 状态流转 → 告警/日志/SQLite）
  └── 采样线程（每 60s：快照 → SQLite samples 表）
```

**线程安全**：
- `Aggregator`：`threading.Lock` 保护 mem_stats
- `Database`：`threading.Lock` 保护 SQLite 连接
- `MemoryLeakDetector`：`threading.Lock` 保护 states + active_alerts

---

## 十一、修改文件清单

| 文件 | 操作 | 说明 |
|---|---|---|
| `bpf/mem.bpf.c` | **实现** | malloc/free uprobe + 配对追踪 + 采样 + 栈捕获 |
| `bpf/common.h` | **实现** | 共享定义（事件结构 + map 骨架） |
| `core/loader.py` | **实现** | BCC 加载 + attach + perf buffer |
| `core/ingest.py` | **实现** | 事件解码 + 分发 |
| `core/aggregator.py` | **实现** | 聚合 + outstanding + 线程安全 |
| `core/config.py` | **实现** | YAML 配置加载 |
| `symbolizer/symbols.py` | **实现** | 栈符号解析 |
| `analyzer/base.py` | **实现** | 检测器基类 |
| `analyzer/memory.py` | **实现** | 双条件检测 + 状态生命周期 + 防抖 |
| `storage/db.py` | **实现** | SQLite 读写 + 查询 |
| `logging/alert_logger.py` | **实现** | 告警 + 恢复日志 |
| `web/backend.py` | **新增** | 集成层，替代 mock |
| `web/app.py` | **修改** | 启动时初始化 backend |
| `web/sockets.py` | **修改** | pusher 调 backend |
| `web/api.py` | **修改** | /api/history 调 backend.db |
| `config/default.yaml` | **修改** | 新增状态生命周期配置项 |
| `tests/leak_programs/mem_leak.c` | **实现** | 合成泄露程序 |

**不变的文件**：
- 前端全部（`web/static/*`、`web/mock.py` 保留但不再用于内存）
- `storage/schema.sql`（F1 已建）
- vendor 库

---

## 十二、验证标准

| # | 验证项 | 方法 | 预期 |
|---|---|---|---|
| 1 | BPF 加载 | `python3 web/app.py` | 无编译错误，服务启动 |
| 2 | 前端连接 | 浏览器打开 | WebSocket 连接，内存数值非 0 |
| 3 | malloc 事件 | 系统运行 | 内存 outstanding 值持续更新 |
| 4 | 折线图 | 观察内存图 | 显示真实 outstanding 趋势 |
| 5 | per_process | 看进程表 | 显示真实进程（nginx/python3 等） |
| 6 | 跑 mem_leak | `./mem_leak &` | 内存图明显上升 |
| 7 | 观察状态 | 等 30s | 内存卡片变黄"观察中" |
| 8 | 告警触发 | 等 60s | 内存卡片变红"疑似泄露" + 告警出现 |
| 9 | 栈展示 | 点击告警 | 显示 malloc 调用栈（函数名） |
| 10 | 日志 | `cat data/leakdetect.log` | 告警写入日志文件 |
| 11 | SQLite | 前端切 1天 范围 | 历史数据来自 SQLite（非 mock） |
| 12 | 线程/句柄/CPU | 看其他卡片 | 暂为 0（B2 实现） |

---

## 十三、已知限制（B1 范围外）

| 限制 | 何时补 | 里程碑 |
|---|---|---|
| 线程/句柄/CPU 仍为 0 | B2 | threads/fd BPF + /proc |
| /api/alerts 仍为 mock | B2/B4 | 接 SQLite alerts 表 |
| /api/containers 仍为 mock | B3 | cgroup 枚举 |
| /api/config/filter 仍为 mock | B3 | pid_filter_map |
| select_container 无效果 | B3 | BPF cgroup map |
| outstanding 是 ×100 估算 | 设计如此 | 采样率可调 |
| allocs map 可能溢出 | B1 监控 | max_entries=1000000，溢出时丢弃旧条目 |

---

## 十四、实施步骤

| 步骤 | 文件 | 耗时 |
|---|---|---|
| 1 | `bpf/common.h` + `bpf/mem.bpf.c` | 2h |
| 2 | `core/config.py`（YAML 加载 + 新阈值） | 30min |
| 3 | `core/loader.py`（BCC 加载 + attach） | 1h |
| 4 | `core/ingest.py`（事件解码） | 1h |
| 5 | `core/aggregator.py`（聚合 + outstanding） | 1.5h |
| 6 | `symbolizer/symbols.py`（栈解析） | 30min |
| 7 | `analyzer/base.py` + `analyzer/memory.py`（双条件 + 状态机） | 2.5h |
| 8 | `storage/db.py`（SQLite 读写） | 1h |
| 9 | `logging/alert_logger.py`（日志） | 30min |
| 10 | `web/backend.py`（集成层） | 1h |
| 11 | `web/app.py` + `web/sockets.py` + `web/api.py`（对接） | 1h |
| 12 | `config/default.yaml`（新增配置项） | 15min |
| 13 | `tests/leak_programs/mem_leak.c`（验证程序） | 15min |
| 14 | 上传 + 启动 + 调试 | 2-3h |

**预计总耗时：2-3 天**

---

## 十五、实施变更记录

以下为 B1 实施过程中相对原设计的变更，均已验证：

### 变更 1：`logging/` 目录改名为 `alert_logging/`

| 项 | 说明 |
|---|---|
| 原因 | Python 标准库有 `logging` 模块，`from logging.alert_logger import` 找到的是 stdlib 而非项目目录 |
| 影响 | `web/backend.py` 的 import 改为 `from alert_logging.alert_logger import AlertLogger` |
| 状态 | ✅ 已修复 |

### 变更 2：BPF 加载方式改为 `BPF(src_file=..., cflags=...)`

| 项 | 说明 |
|---|---|
| 原设计 | `BPF(text=bpf_text)` 读取文件内容后编译 |
| 问题 | BCC 的 `text=` 模式从虚拟文件编译，找不到 `#include "common.h"` |
| 修复 | 改为 `BPF(src_file=bpf_file, cflags=["-I" + bpf_dir])` 显式指定 include 路径 |
| 状态 | ✅ 已修复 |

### 变更 3：BPF 源文件去除 UTF-8 BOM

| 项 | 说明 |
|---|---|
| 原因 | Windows 写文件时自动添加 UTF-8 BOM（`EF BB BF`），clang 编译报 `unknown type name` |
| 影响 | `bpf/mem.bpf.c` 和 `bpf/common.h` 去除 BOM |
| 状态 | ✅ 已修复 |

### 变更 4：进程退出检测（analyzer/memory.py）

| 项 | 说明 |
|---|---|
| 原设计 | 泄露恢复仅依赖 outstanding 下降（free 事件） |
| 问题 | 进程被 kill 后内存由 OS 回收，不经过 `free()`，BPF 无 free 事件，outstanding 不下降，告警永久停留 |
| 修复 | `_update_state()` 的 `STATE_LEAK` 分支新增 `/proc/[pid]` 存在性检查；进程不存在 → 直接进入 `STATE_RESOLVED` |
| 状态 | ✅ 已修复 |

### 变更 5：aggregator 死进程清理（core/aggregator.py）

| 项 | 说明 |
|---|---|
| 原设计 | aggregator 不清理已退出进程的统计 |
| 问题 | 进程 kill 后 `mem_stats` 仍保留旧数据，top-N 表和总内存值不回落 |
| 修复 | 新增 `cleanup_dead()` 方法，检查 `/proc/[pid]` 并移除死进程条目；`backend.py` 的分析循环每次先调 `cleanup_dead()` |
| 状态 | ✅ 已修复 |

### 变更 6：泄露程序速率调整（mem_leak.c）

| 项 | 原设计 | 修改后 |
|---|---|---|
| 每次分配 | `malloc(1024 * 1024)` = 1MB | `malloc(4096)` = 4KB |
| 速率 | 10MB/s | 40KB/s |
| 60s 累计 | 600MB（过快） | 2.4MB（刚好触发阈值，图上可见缓慢上升） |
| 状态 | ✅ 已修改 |

### 变更 7：root 用户 Python 依赖安装

| 项 | 说明 |
|---|---|
| 原因 | eBPF 需 root 运行，但 pip 包装在 `/home/ubuntu/.local/`，sudo 下找不到 |
| 修复 | `sudo pip3 install --break-system-packages --ignore-installed flask flask-socketio pyyaml eventlet` |
| 状态 | ✅ 已修复 |

### 变更 8：检测范围说明

| 项 | 说明 |
|---|---|
| 当前覆盖 | `malloc` + `free`（libc uprobe） |
| 间接覆盖 | `calloc`/`realloc`（内部调 malloc，已被覆盖） |
| 未覆盖 | `mmap`/`munmap`（设计文档提及，B1 未实现） |
| 决策 | B1 仅覆盖 malloc/free，满足最常见堆泄露场景；mmap 可选增强 |
