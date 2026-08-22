# B2 里程碑设计文档 — 线程 + 句柄 + CPU

> 文档版本：v1.0  
> 日期：2026-07-08  
> 状态：⬜ 待实施  
> 关联文档：`D:\leakdetect-backend-design.md`、`D:\leakdetect-b1-design.md`

---

## 一、B2 目标

在 B1 内存检测基础上，补全剩余 3 个资源，实现 **4 资源全真实数据**：

| 资源 | 数据来源 | 检测方式 | 状态 |
|---|---|---|---|
| 内存 | eBPF malloc/free（B1 已实现） | 趋势检测 | ✅ B1 完成 |
| **线程** | **eBPF clone/exit tracepoint** | **趋势检测** | ⬜ B2 实现 |
| **句柄** | **eBPF openat/close tracepoint** | **趋势检测** | ⬜ B2 实现 |
| **CPU** | **/proc 轮询（无 BPF）** | **仅监控** | ⬜ B2 实现 |

**B2 完成后**：前端 4 资源折线图/告警/进程表全部来自真实数据，mock 完全废弃。

---

## 二、前置条件

| 条件 | 状态 | 说明 |
|---|---|---|
| B1 内存检测 | ✅ | 内存 eBPF + 分析层已工作 |
| B0 技术验证 | ✅ | tracepoint + uprobe + stack 均已验证 |
| 前端 F1-F4 | ✅ | 契约稳定 |
| config/default.yaml | ✅ | thread/fd 阈值已定义 |

---

## 三、架构变更

### 3.1 多 BPF 对象

B1 只有一个 BPF 对象（mem）。B2 新增两个：

```
BPF 对象 1: bpf_mem     (B1 已有)    → mem.bpf.c
BPF 对象 2: bpf_threads (B2 新增)    → threads.bpf.c
BPF 对象 3: bpf_fd      (B2 新增)    → fd.bpf.c
```

每个 BPF 对象有独立的 `events` perf buffer 和 `stack_traces` map。

### 3.2 多线程事件读取

每个 BPF 对象需要一个独立的 `perf_buffer_poll()` 线程：

```
主线程
  ├── Flask + SocketIO
  ├── pusher 线程（每 1s 推 DashboardUpdate）
  ├── BPF mem 事件读取线程（B1 已有）
  ├── BPF threads 事件读取线程（B2 新增）
  ├── BPF fd 事件读取线程（B2 新增）
  ├── CPU 轮询线程（B2 新增，每 1s 读 /proc）
  ├── 分析线程（每 5s：mem + thread + fd 泄露检测）
  └── 采样线程（每 60s：SQLite 快照）
```

### 3.3 Symbolizer 变更

每个 BPF 对象有独立的 `stack_traces` map。Symbolizer 需要知道用哪个 map：

```python
# B1: resolve(stack_id, pid)
# B2: resolve(resource, stack_id, pid)  ← 新增 resource 参数
```

| resource | 使用的 stack_traces map |
|---|---|
| `"mem"` | `bpf_mem["stack_traces"]` |
| `"thread"` | `bpf_threads["stack_traces"]` |
| `"fd"` | `bpf_fd["stack_traces"]` |

---

## 四、common.h 扩展

新增线程和句柄的事件结构：

```c
/* 线程事件结构 */
struct thread_event_t {
    u32 pid;
    u32 tid;
    int stack_id;
    char op;        /* 'c'=create, 'e'=exit */
    char comm[16];
};

/* 句柄事件结构 */
struct fd_event_t {
    u32 pid;
    int fd;
    int fd_type;    /* 0=file, 1=socket, 2=pipe, 3=eventfd */
    int stack_id;
    char op;        /* 'o'=open, 'c'=close */
    char comm[16];
};

/* fd 配对追踪的 key */
struct fd_key_t {
    u32 pid;
    int fd;
};
```

---

## 五、threads.bpf.c 设计

### 5.1 Hook 点

| Hook | tracepoint | 抓取 | 采样 |
|---|---|---|---|
| 线程创建 | `syscalls:sys_enter_clone` | PID, stack_id | 全量 |
| 线程创建 | `syscalls:sys_enter_clone3` | PID, stack_id | 全量 |
| 线程退出 | `sched:sched_process_exit` | PID, TID | 全量 |

### 5.2 BPF 程序

```c
#include "common.h"

BPF_PERF_OUTPUT(events);
BPF_STACK_TRACE(stack_traces, 16384);

/* clone: 线程创建 */
TRACEPOINT_PROBE(syscalls, sys_enter_clone) {
    struct thread_event_t event = {};
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
    event.op = 'c';
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}

/* clone3: 线程创建（新版 syscall） */
TRACEPOINT_PROBE(syscalls, sys_enter_clone3) {
    struct thread_event_t event = {};
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
    event.op = 'c';
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}

/* 线程退出 */
TRACEPOINT_PROBE(sched, sched_process_exit) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;

    /* 只追踪线程退出（tid != pid），不追踪主线程退出 */
    if (tid == pid) return 0;

    struct thread_event_t event = {};
    event.pid = pid;
    event.tid = tid;
    event.op = 'e';
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}
```

> **架构兼容**：tracepoint 名称跨架构一致；`bpf_get_current_pid_tgid()` 跨架构。

### 5.3 检测逻辑

```
指标：thread_count = created - exited（按 PID 聚合）
判定：thread_count 单调增长，持续 > 120s
告警：包含创建栈（clone 调用点）
```

---

## 六、fd.bpf.c 设计

### 6.1 Hook 点

| Hook | tracepoint | 抓取 | 采样 |
|---|---|---|---|
| 文件打开 | `syscalls:sys_exit_openat` | fd=返回值, stack_id | 全量 |
| socket 创建 | `syscalls:sys_exit_socket` | fd=返回值, stack_id | 全量 |
| 文件关闭 | `syscalls:sys_enter_close` | fd=参数 | 全量 |

> fd 值在 syscall 返回时才有（返回值 = fd），所以用 `sys_exit_*` 抓 open 类事件。close 用 `sys_enter_*` 抓参数。

### 6.2 fd 配对追踪

与 B1 的 malloc/free 配对类似，用 BPF hash map 存 `{pid, fd} → stack_id`：

- open 时：存入 map + 发 open 事件（含 stack_id）
- close 时：查 map → 拿到原始 open 的 stack_id → 发 close 事件 → 删除 map 条目

### 6.3 BPF 程序

```c
#include "common.h"

BPF_PERF_OUTPUT(events);
BPF_STACK_TRACE(stack_traces, 16384);
BPF_HASH(fd_map, struct fd_key_t, int, 100000);

/* openat 返回：fd = 返回值 */
TRACEPOINT_PROBE(syscalls, sys_exit_openat) {
    int fd = args->ret;
    if (fd < 0) return 0;

    u32 pid = bpf_get_current_pid_tgid() >> 32;
    int sid = stack_traces.get_stackid(args, BPF_F_USER_STACK);

    /* 存入 fd_map 供 close 时匹配 */
    struct fd_key_t key = {.pid = pid, .fd = fd};
    fd_map.update(&key, &sid);

    struct fd_event_t event = {};
    event.pid = pid;
    event.fd = fd;
    event.fd_type = 0;  /* file */
    event.stack_id = sid;
    event.op = 'o';
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}

/* socket 返回：fd = 返回值 */
TRACEPOINT_PROBE(syscalls, sys_exit_socket) {
    int fd = args->ret;
    if (fd < 0) return 0;

    u32 pid = bpf_get_current_pid_tgid() >> 32;
    int sid = stack_traces.get_stackid(args, BPF_F_USER_STACK);

    struct fd_key_t key = {.pid = pid, .fd = fd};
    fd_map.update(&key, &sid);

    struct fd_event_t event = {};
    event.pid = pid;
    event.fd = fd;
    event.fd_type = 1;  /* socket */
    event.stack_id = sid;
    event.op = 'o';
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}

/* close 入口：fd = 参数 */
TRACEPOINT_PROBE(syscalls, sys_enter_close) {
    int fd = args->fd;
    if (fd < 0) return 0;

    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct fd_key_t key = {.pid = pid, .fd = fd};
    int *sid_ptr = fd_map.lookup(&key);

    struct fd_event_t event = {};
    event.pid = pid;
    event.fd = fd;
    event.op = 'c';
    if (sid_ptr) {
        event.stack_id = *sid_ptr;
        fd_map.delete(&key);
    } else {
        event.stack_id = -1;  /* 无匹配 open（tracing 启动前打开的 fd） */
    }
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}
```

### 6.4 检测逻辑

```
指标：fd_count = open - close（按 PID + stack_id 聚合）
判定：fd_count 单调增长，持续 > 120s
告警：包含 open 栈（openat/socket 调用点）
```

---

## 七、泄露检测算法（线程 + 句柄）

### 7.1 与 B1 内存检测的关系

线程和句柄检测**复用 B1 的双条件 + 状态生命周期**，仅指标和阈值不同：

| | 内存（B1） | 线程（B2） | 句柄（B2） |
|---|---|---|---|
| 指标 | outstanding_bytes | thread_count | fd_count |
| 聚合维度 | PID + stack_id | PID | PID + stack_id |
| observe_seconds | 30 | 30 | 30 |
| leak_seconds | 60 | 120 | 120 |
| delta 阈值 | 1MB | 5 个线程 | 10 个 fd |
| clear_ratio | 0.5 | 0.5 | 0.5 |

### 7.2 状态生命周期（与 B1 一致）

```
normal → observing(30s) → leak_suspected(120s) → resolved(下降恢复) → normal
```

### 7.3 双条件判定（与 B1 一致）

- 条件 A：80% 单调性 + 净增 > 阈值
- 条件 B：首尾均值差 > 阈值

### 7.4 进程退出检测（与 B1 一致）

`STATE_LEAK` 分支检查 `/proc/[pid]`，进程不存在 → `STATE_RESOLVED`。

---

## 八、Python 模块变更

### 8.1 core/loader.py — 多 BPF 加载

```python
class BpfLoader:
    def __init__(self, config):
        self.config = config
        self.bpf_mem = None
        self.bpf_threads = None
        self.bpf_fd = None
        self._bpf_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "bpf")

    def load_mem(self):
        """B1 已有，不变。"""
        ...

    def load_threads(self):
        """B2 新增：加载线程 BPF。"""
        bpf_file = os.path.join(self._bpf_dir, "threads.bpf.c")
        self.bpf_threads = BPF(src_file=bpf_file,
                               cflags=["-I" + self._bpf_dir])

    def load_fd(self):
        """B2 新增：加载句柄 BPF。"""
        bpf_file = os.path.join(self._bpf_dir, "fd.bpf.c")
        self.bpf_fd = BPF(src_file=bpf_file,
                          cflags=["-I" + self._bpf_dir])

    def start_event_loop(self, callbacks):
        """启动所有 BPF 的 perf buffer 读取（每 BPF 一个线程）。"""
        # mem (B1)
        self.bpf_mem["events"].open_perf_buffer(callbacks["mem"])
        threading.Thread(target=self._poll, args=(self.bpf_mem,),
                         daemon=True).start()
        # threads (B2)
        self.bpf_threads["events"].open_perf_buffer(callbacks["threads"])
        threading.Thread(target=self._poll, args=(self.bpf_threads,),
                         daemon=True).start()
        # fd (B2)
        self.bpf_fd["events"].open_perf_buffer(callbacks["fd"])
        threading.Thread(target=self._poll, args=(self.bpf_fd,),
                         daemon=True).start()

    def _poll(self, bpf):
        while True:
            bpf.perf_buffer_poll()
```

### 8.2 core/ingest.py — 多事件类型

```python
class ThreadEvent(ct.Structure):
    _fields_ = [
        ("pid", ct.c_uint), ("tid", ct.c_uint),
        ("stack_id", ct.c_int), ("op", ct.c_char),
        ("comm", ct.c_char * 16),
    ]

class FdEvent(ct.Structure):
    _fields_ = [
        ("pid", ct.c_uint), ("fd", ct.c_int),
        ("fd_type", ct.c_int), ("stack_id", ct.c_int),
        ("op", ct.c_char), ("comm", ct.c_char * 16),
    ]

class IngestManager:
    def __init__(self, aggregator, symbolizer=None):
        self.aggregator = aggregator
        self.symbolizer = symbolizer

    def on_mem_event(self, cpu, data, size):
        """B1 已有。"""
        ...

    def on_thread_event(self, cpu, data, size):
        """B2 新增。"""
        event = ct.cast(data, ct.POINTER(ThreadEvent)).contents
        self.aggregator.on_thread_event({
            "pid": event.pid, "tid": event.tid,
            "stack_id": event.stack_id,
            "op": chr(event.op[0]) if isinstance(event.op, bytes) else chr(event.op),
            "comm": event.comm.decode('utf-8', errors='replace'),
        })

    def on_fd_event(self, cpu, data, size):
        """B2 新增。"""
        event = ct.cast(data, ct.POINTER(FdEvent)).contents
        self.aggregator.on_fd_event({
            "pid": event.pid, "fd": event.fd,
            "fd_type": event.fd_type, "stack_id": event.stack_id,
            "op": chr(event.op[0]) if isinstance(event.op, bytes) else chr(event.op),
            "comm": event.comm.decode('utf-8', errors='replace'),
        })
```

### 8.3 core/aggregator.py — 线程 + 句柄聚合

```python
class Aggregator:
    def __init__(self):
        self._lock = threading.Lock()
        self.mem_stats = {}      # B1 已有
        self.thread_stats = {}   # B2: {pid: {created, exited, comm, stack_id}}
        self.fd_stats = {}       # B2: {pid: {stack_id: {open_count, close_count, comm}}}

    def on_mem_event(self, event):
        """B1 已有。"""
        ...

    def on_thread_event(self, event):
        """B2 新增。"""
        pid = event["pid"]
        with self._lock:
            if pid not in self.thread_stats:
                self.thread_stats[pid] = {"created": 0, "exited": 0,
                                          "comm": event["comm"],
                                          "stack_id": event.get("stack_id", -1)}
            if event["op"] == 'c':
                self.thread_stats[pid]["created"] += 1
            elif event["op"] == 'e':
                self.thread_stats[pid]["exited"] += 1

    def on_fd_event(self, event):
        """B2 新增。"""
        pid = event["pid"]
        sid = event["stack_id"]
        with self._lock:
            if pid not in self.fd_stats:
                self.fd_stats[pid] = {}
            if sid not in self.fd_stats[pid]:
                self.fd_stats[pid][sid] = {"open_count": 0, "close_count": 0,
                                            "comm": event["comm"]}
            if event["op"] == 'o':
                self.fd_stats[pid][sid]["open_count"] += 1
            elif event["op"] == 'c' and sid >= 0:
                self.fd_stats[pid][sid]["close_count"] += 1

    def get_total_thread_count(self):
        """所有进程线程数总和。"""
        with self._lock:
            return sum(s["created"] - s["exited"]
                       for s in self.thread_stats.values())

    def get_total_fd_count(self):
        """所有进程 fd 数总和。"""
        with self._lock:
            return sum(sum(s["open_count"] - s["close_count"]
                          for s in stacks.values())
                       for stacks in self.fd_stats.values())

    def get_per_process_thread(self):
        """按进程汇总线程数，top-5。"""
        result = []
        with self._lock:
            for pid, s in self.thread_stats.items():
                result.append({"pid": pid, "name": s["comm"],
                               "value": s["created"] - s["exited"]})
        return sorted(result, key=lambda x: x["value"], reverse=True)[:5]

    def get_per_process_fd(self):
        """按进程汇总 fd 数，top-5。"""
        result = []
        with self._lock:
            for pid, stacks in self.fd_stats.items():
                total = sum(s["open_count"] - s["close_count"]
                            for s in stacks.values())
                comm = next(iter(stacks.values()))["comm"] if stacks else ""
                result.append({"pid": pid, "name": comm, "value": total})
        return sorted(result, key=lambda x: x["value"], reverse=True)[:5]

    def cleanup_dead(self):
        """B1 已有 + B2 扩展：清理死进程的线程/fd 统计。"""
        with self._lock:
            dead = [pid for pid in list(self.mem_stats.keys())
                    if not os.path.exists("/proc/%d" % pid)]
            for pid in dead:
                self.mem_stats.pop(pid, None)
                self.thread_stats.pop(pid, None)
                self.fd_stats.pop(pid, None)
            # 也检查 thread/fd 独有的 PID
            dead2 = [pid for pid in list(self.thread_stats.keys())
                     if not os.path.exists("/proc/%d" % pid)]
            for pid in dead2:
                self.thread_stats.pop(pid, None)
                self.fd_stats.pop(pid, None)
```

### 8.4 symbolizer/symbols.py — 多 map 支持

```python
class Symbolizer:
    def __init__(self, bpf_mem, bpf_threads=None, bpf_fd=None):
        self.bpfs = {
            "mem": bpf_mem,
            "thread": bpf_threads,
            "fd": bpf_fd,
        }

    def resolve(self, resource, stack_id, pid):
        """B2 变更：新增 resource 参数。"""
        bpf = self.bpfs.get(resource)
        if not bpf or stack_id < 0:
            return []
        frames = []
        for addr in bpf["stack_traces"].walk(stack_id):
            try:
                sym = bpf.sym(addr, pid, show_module=True, show_offset=True)
                frames.append({
                    "func": sym.decode('utf-8', errors='replace'),
                    "addr": "0x%x" % addr,
                })
            except Exception:
                frames.append({"func": "[unknown]", "addr": "0x%x" % addr})
        return frames
```

> **B1 兼容**：B1 的 `analyzer/memory.py` 需改为 `symbolizer.resolve("mem", sid, pid)`。

### 8.5 analyzer/threads.py — 线程泄露检测器

复用 B1 的双条件 + 状态生命周期，指标改为 thread_count：

```python
class ThreadLeakDetector:
    """与 MemoryLeakDetector 结构相同，指标改为 created - exited。"""

    def __init__(self, config):
        cfg = config["thresholds"]["thread"]
        self.threshold = 5  # 5 个线程增量阈值
        self.observe_seconds = 30
        self.leak_seconds = cfg.get("leak_seconds", 120)
        self.clear_ratio = 0.5
        self.clear_seconds = 30
        self.resolve_seconds = 60
        self._lock = threading.Lock()
        self.states = {}  # {pid: StackSiteState}
        self.active_alerts = []

    def check(self, aggregator, symbolizer):
        """检查线程泄露，逻辑与 MemoryLeakDetector.check 相同。"""
        # 遍历 aggregator.thread_stats
        # 指标 = created - exited
        # 双条件检测 + 状态生命周期
        # 告警含 stack（symbolizer.resolve("thread", sid, pid)）
        ...
```

### 8.6 analyzer/handles.py — 句柄泄露检测器

```python
class HandleLeakDetector:
    """与 MemoryLeakDetector 结构相同，指标改为 open - close。"""

    def __init__(self, config):
        cfg = config["thresholds"]["fd"]
        self.threshold = 10  # 10 个 fd 增量阈值
        self.observe_seconds = 30
        self.leak_seconds = cfg.get("leak_seconds", 120)
        self.clear_ratio = 0.5
        self.clear_seconds = 30
        self.resolve_seconds = 60
        self._lock = threading.Lock()
        self.states = {}  # {(pid, stack_id): StackSiteState}
        self.active_alerts = []

    def check(self, aggregator, symbolizer):
        """检查 fd 泄露，逻辑与 MemoryLeakDetector.check 相同。"""
        # 遍历 aggregator.fd_stats
        # 指标 = open_count - close_count
        # 双条件检测 + 状态生命周期
        # 告警含 stack（symbolizer.resolve("fd", sid, pid)）
        ...
```

### 8.7 analyzer/cpu.py — CPU 监控

```python
import os
import time

class CpuMonitor:
    """轮询 /proc/[pid]/stat 计算 CPU%。"""

    def __init__(self, interval=1):
        self.interval = interval
        self._clk_tck = os.sysconf('SC_CLK_TCK')
        self._last = {}  # {pid: (utime, stime, timestamp)}

    def poll(self):
        """返回 [{pid, name, value(cpu%)}] top-5。"""
        now = time.time()
        result = []
        for entry in os.listdir("/proc"):
            if not entry.isdigit():
                continue
            pid = int(entry)
            try:
                with open("/proc/%d/stat" % pid) as f:
                    fields = f.read().split()
                utime = int(fields[13])
                stime = int(fields[14])
                comm = fields[1].strip("()")

                if pid in self._last:
                    old_ut, old_st, old_t = self._last[pid]
                    dt = now - old_t
                    if dt > 0:
                        delta_ticks = (utime + stime) - (old_ut + old_st)
                        cpu_pct = (delta_ticks / self._clk_tck) / dt * 100
                        result.append({
                            "pid": pid, "name": comm,
                            "value": round(cpu_pct, 1)
                        })
                self._last[pid] = (utime, stime, now)
            except (IOError, IndexError):
                continue

        # 清理死进程
        self._last = {pid: v for pid, v in self._last.items()
                      if os.path.exists("/proc/%d" % pid)}
        return sorted(result, key=lambda x: x["value"], reverse=True)[:5]
```

### 8.8 CPU 监控设计说明

#### 为什么 CPU 不用 BPF

| 原因 | 说明 |
|---|---|
| CPU 只需要占用率 | 不需要追踪调用栈、不需要泄露检测 |
| /proc 已提供精确数据 | `utime`/`stime` 是内核维护的每进程 CPU 时间 |
| BPF 开销不值得 | `sched_switch` tracepoint 每秒触发上千次，开销大；/proc 轮询每秒一次，开销极小 |
| 实现简单 | 读文件 + 算差值，无需 BPF 编程 |

#### CPU% 计算原理

```
/proc/[pid]/stat 第 14、15 字段：
  utime = 用户态运行时间（clock ticks，单位：时钟节拍）
  stime = 内核态运行时间（clock ticks）

计算公式：
  delta_ticks = (utime + stime)当前 - (utime + stime)上次
  cpu% = (delta_ticks / SC_CLK_TCK) / 间隔秒数 × 100

  示例：delta_ticks=100, SC_CLK_TCK=100(Hz), 间隔=1s
        cpu% = (100/100) / 1 × 100 = 100%

  示例：delta_ticks=25, SC_CLK_TCK=100(Hz), 间隔=1s
        cpu% = (25/100) / 1 × 100 = 25%
```

- `SC_CLK_TCK` 通过 `os.sysconf('SC_CLK_TCK')` 获取，通常为 100（每秒 100 个时钟节拍）
- 每秒轮询一次，取 top-5 进程按 CPU% 排序

#### 数据流

```
/proc/[pid]/stat → CpuMonitor.poll()
  → 读 utime/stime → 与上次差值 → 算 CPU%
  → 返回 [{pid, name, value}] top-5
  → backend._cpu_loop() 每 1s 调用
  → 存入 self.cpu_stats
  → get_dashboard_update() 时推给前端
```

#### 与 BPF 资源的区别

| 维度 | 内存/线程/句柄（BPF） | CPU（/proc 轮询） |
|---|---|---|
| 数据来源 | eBPF uprobe/tracepoint | /proc 文件系统 |
| 采样频率 | 事件驱动（实时） | 定时轮询（1s） |
| 栈追踪 | ✅ 有（泄露定位） | ❌ 无（仅需占用率） |
| 泄露检测 | ✅ 有（趋势检测） | ❌ 无（仅监控） |
| 开销 | 中等（1/100 采样） | 极低（读文件） |
| 线程模型 | 独立 perf buffer 线程 | 独立轮询线程 |

#### 未来增强（非 B2 范围）

如果后续需要 **on-CPU 火焰图**（哪个函数占 CPU 最多），可以用 BPF：
- `sched_switch` tracepoint 或 perf 采样
- 捕获 on-CPU 栈 → 聚合为火焰图
- 这是 B2 之外的可选增强，当前不做

---

## 九、backend.py 变更

```python
class Backend:
    def __init__(self, config):
        self.config = config
        self.loader = BpfLoader(config)
        self.aggregator = Aggregator()
        self.analyzer_mem = MemoryLeakDetector(config)
        self.analyzer_threads = ThreadLeakDetector(config)
        self.analyzer_fd = HandleLeakDetector(config)
        self.db = Database(config["storage"]["sqlite_path"])
        self.logger = AlertLogger(config["logging"]["alert_log"])
        self.cpu_monitor = CpuMonitor(config["sampling"]["cpu_interval"])
        self.cpu_stats = []

    def start(self):
        # 加载所有 BPF
        self.loader.load_mem()
        self.loader.load_threads()
        self.loader.load_fd()

        # Symbolizer（3 个 BPF 对象）
        self.symbolizer = Symbolizer(
            self.loader.bpf_mem,
            self.loader.bpf_threads,
            self.loader.bpf_fd
        )

        # 事件读取（3 个线程）
        ingest = IngestManager(self.aggregator, self.symbolizer)
        self.loader.start_event_loop({
            "mem": ingest.on_mem_event,
            "threads": ingest.on_thread_event,
            "fd": ingest.on_fd_event,
        })

        # 分析线程（每 5s）
        threading.Thread(target=self._analyzer_loop, daemon=True).start()
        # CPU 轮询线程（每 1s）
        threading.Thread(target=self._cpu_loop, daemon=True).start()
        # SQLite 采样线程（每 60s）
        threading.Thread(target=self._sampler_loop, daemon=True).start()

    def _analyzer_loop(self):
        while True:
            self.aggregator.cleanup_dead()
            alerts = []
            alerts += self.analyzer_mem.check(self.aggregator, self.symbolizer)
            alerts += self.analyzer_threads.check(self.aggregator, self.symbolizer)
            alerts += self.analyzer_fd.check(self.aggregator, self.symbolizer)
            for a in alerts:
                self.logger.log(a)
                self.db.write_alert(a)
            time.sleep(5)

    def _cpu_loop(self):
        while True:
            self.cpu_stats = self.cpu_monitor.poll()
            time.sleep(1)

    def _sampler_loop(self):
        while True:
            for p in self.aggregator.get_snapshot():
                self.db.write_sample("mem", p["pid"], p["value"])
            for p in self.aggregator.get_per_process_thread():
                self.db.write_sample("thread", p["pid"], p["value"])
            for p in self.aggregator.get_per_process_fd():
                self.db.write_sample("fd", p["pid"], p["value"])
            for p in self.cpu_stats:
                self.db.write_sample("cpu", p["pid"], p["value"])
            time.sleep(60)

    def get_dashboard_update(self):
        now = int(time.time())
        alerts = (self.analyzer_mem.get_active_alerts() +
                  self.analyzer_threads.get_active_alerts() +
                  self.analyzer_fd.get_active_alerts())
        return {
            "type": "dashboard_update",
            "timestamp": now,
            "filter": {"container_id": None, "pid": None},
            "latest_points": {
                "mem": {"t": now, "v": self.aggregator.get_total_outstanding()},
                "thread": {"t": now, "v": self.aggregator.get_total_thread_count()},
                "fd": {"t": now, "v": self.aggregator.get_total_fd_count()},
                "cpu": {"t": now, "v": sum(p["value"] for p in self.cpu_stats)},
            },
            "per_process": {
                "mem": self.aggregator.get_per_process_mem(),
                "thread": self.aggregator.get_per_process_thread(),
                "fd": self.aggregator.get_per_process_fd(),
                "cpu": self.cpu_stats,
            },
            "alerts": alerts,
            "containers": [],
        }
```

---

## 十、B1 兼容变更

B2 需要修改 B1 的代码以适配新架构：

| 文件 | 变更 | 说明 |
|---|---|---|
| `analyzer/memory.py` | `symbolizer.resolve(sid, pid)` → `symbolizer.resolve("mem", sid, pid)` | 适配 Symbolizer 新签名 |
| `core/loader.py` | 重构为多 BPF 对象 | `self.bpf` → `self.bpf_mem` + `bpf_threads` + `bpf_fd` |
| `symbolizer/symbols.py` | `resolve(stack_id, pid)` → `resolve(resource, stack_id, pid)` | 新增 resource 参数 |
| `web/backend.py` | 新增 threads/fd/cpu 初始化 + 分析 + 仪表盘数据 | 4 资源全真实数据 |

---

## 十一、验证程序

### thread_leak.c

```c
#include <pthread.h>
#include <unistd.h>
#include <stdio.h>

void* worker(void* arg) {
    while (1) sleep(1);  /* 线程不退出 → 泄露 */
    return NULL;
}

int main() {
    printf("Thread leak: creating 100 threads without join\n");
    for (int i = 0; i < 100; i++) {
        pthread_t t;
        pthread_create(&t, NULL, worker, NULL);
        usleep(500000);  /* 0.5s */
    }
    sleep(600);
    return 0;
}
```

### fd_leak.c

```c
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>

int main() {
    printf("FD leak: opening files without close\n");
    for (int i = 0; i < 1000; i++) {
        int fd = open("/dev/null", O_RDONLY);
        if (fd < 0) { printf("open failed at %d\n", i); break; }
        usleep(100000);  /* 0.1s */
    }
    sleep(600);
    return 0;
}
```

---

## 十二、修改文件清单

| 文件 | 操作 | 说明 |
|---|---|---|
| `bpf/common.h` | **修改** | 新增 thread_event_t + fd_event_t + fd_key_t |
| `bpf/threads.bpf.c` | **实现** | clone/clone3/sched_process_exit tracepoint |
| `bpf/fd.bpf.c` | **实现** | openat/socket/close tracepoint + fd 配对 |
| `core/loader.py` | **重写** | 多 BPF 对象 + 多线程 poll |
| `core/ingest.py` | **修改** | 新增 on_thread_event + on_fd_event |
| `core/aggregator.py` | **修改** | 新增 thread/fd 聚合 + 死进程清理扩展 |
| `symbolizer/symbols.py` | **修改** | resolve 新增 resource 参数 |
| `analyzer/base.py` | **不变** | — |
| `analyzer/memory.py` | **修改** | resolve 调用加 "mem" 参数 |
| `analyzer/threads.py` | **实现** | 线程泄露检测（复用双条件 + 状态机） |
| `analyzer/handles.py` | **实现** | 句柄泄露检测（复用双条件 + 状态机） |
| `analyzer/cpu.py` | **实现** | /proc 轮询 + CPU% 计算 |
| `web/backend.py` | **重写** | 4 资源全真实数据 |
| `tests/leak_programs/thread_leak.c` | **新增** | 合成线程泄露 |
| `tests/leak_programs/fd_leak.c` | **新增** | 合成句柄泄露 |
| `config/default.yaml` | **修改** | thread/fd 补充完整阈值 |

**不变的文件**：
- 前端全部
- `web/app.py`、`web/sockets.py`、`web/api.py`（B1 已对接）
- `storage/schema.sql`、`storage/db.py`（B1 已实现）
- `alert_logging/alert_logger.py`（B1 已实现）

---

## 十三、验证标准

| # | 验证项 | 方法 | 预期 |
|---|---|---|---|
| 1 | BPF 加载 | `python3 web/app.py` | 3 个 BPF 程序无编译错误 |
| 2 | 内存（B1 回归） | 跑 mem_leak | 内存检测仍正常 |
| 3 | 线程数据 | 看线程卡片 | 数值非 0，反映真实线程数 |
| 4 | 句柄数据 | 看句柄卡片 | 数值非 0，反映真实 fd 数 |
| 5 | CPU 数据 | 看 CPU 卡片 | 数值非 0，反映真实 CPU% |
| 6 | 线程泄露 | 跑 thread_leak | 线程图上升 → 120s 后告警 |
| 7 | 线程栈 | 点击告警 | 显示 clone 调用栈 |
| 8 | 句柄泄露 | 跑 fd_leak | 句柄图上升 → 120s 后告警 |
| 9 | 句柄栈 | 点击告警 | 显示 open 调用栈 |
| 10 | kill 线程泄露 | kill thread_leak | ≤5s 告警恢复 + top-N 清理 |
| 11 | kill 句柄泄露 | kill fd_leak | ≤5s 告警恢复 + top-N 清理 |
| 12 | CPU top-N | 看 CPU 卡片进程表 | 显示真实进程名 + CPU% |
| 13 | 4 资源折线图 | 看全部图表 | 全部有数据（非 0） |
| 14 | mock 废弃 | 检查代码 | 不再 import mock |

---

## 十四、已知限制（B2 范围外）

| 限制 | 何时补 | 里程碑 |
|---|---|---|
| pipe2/dup/eventfd2 未追踪 | 可选增强 | 后续 |
| fd 跨进程继承（fork 后子进程 close） | 未处理 | 后续 |
| pthread_create uprobe（更精确的栈） | 可选增强 | 后续 |
| /api/containers 仍为空 | B3 | cgroup 枚举 |
| /api/config/filter 仍为 stub | B3 | pid_filter_map |
| CPU 无告警（仅监控） | 设计如此 | — |

---

## 十五、实施步骤

| 步骤 | 文件 | 耗时 |
|---|---|---|
| 1 | `bpf/common.h` 扩展 | 15min |
| 2 | `bpf/threads.bpf.c` | 1h |
| 3 | `bpf/fd.bpf.c` | 1.5h |
| 4 | `core/loader.py` 重写（多 BPF） | 1h |
| 5 | `core/ingest.py` 新增事件类型 | 1h |
| 6 | `core/aggregator.py` 新增线程/fd 聚合 | 1.5h |
| 7 | `symbolizer/symbols.py` 改签名 | 30min |
| 8 | `analyzer/memory.py` 适配新签名 | 15min |
| 9 | `analyzer/threads.py` | 1.5h |
| 10 | `analyzer/handles.py` | 1.5h |
| 11 | `analyzer/cpu.py` | 1h |
| 12 | `web/backend.py` 重写 | 1h |
| 13 | `config/default.yaml` 补阈值 | 15min |
| 14 | `tests/leak_programs/thread_leak.c` + `fd_leak.c` | 30min |
| 15 | 上传 + 启动 + 调试 | 2-3h |

**预计总耗时：2-3 天**

---

## 十六、实施变更记录

### 变更 1：BPF 事件不到达 Python（只有 CPU 数据）

#### 现象

启动服务后，前端只有 CPU 卡片有数据（/proc 轮询），内存/线程/句柄全部为 0。终端日志显示 `_poll_all` 循环 16000+ 次但无 `[ingest]` 事件。

#### 诊断过程

| 步骤 | 操作 | 结果 | 结论 |
|---|---|---|---|
| 1 | B0 独立测试（无 Flask） | 正常输出事件 | BPF 环境正常，问题在 Flask 集成 |
| 2 | 改 `timeout=10` → 默认 | 仍无数据 | 不是 timeout 问题 |
| 3 | 加 `time.sleep(0)` yield | CPU 占用降低，仍无数据 | eventlet 调度不是根因 |
| 4 | `async_mode="eventlet"` → `"threading"` | 仍无数据 | eventlet 不是根因 |
| 5 | 加调试打印 `_poll_all cycle` + `[ingest]` | 循环在跑，事件不到达 | perf_buffer_poll 不处理事件 |
| 6 | 独立测试 `open_perf_buffer` + `perf_buffer_poll` | 正常工作 | BCC 本身没问题 |
| 7 | 用 backend.py 调用链复现 | 仍无 `perf buffer opened` | start_event_loop 有问题 |
| 8 | 手动复现 `for` 循环 | `bpf_obj=True` 但 `if` 块不进入 | 条件判断有问题 |
| 9 | 检查 `bool(bpf_mem)` | `False`，`len()=0`，`has __len__=True` | **根因找到** |

#### 根因

BCC 的 `BPF` 类定义了 `__len__()` 方法，返回 0。在 Python 中，当对象的 `__len__()` 返回 0 时，`bool(obj)` 返回 `False`。

```python
# start_event_loop 里的条件判断
if bpf_obj and callback:    # ← 检查 bool(bpf_obj)，BPF 对象 __len__=0 → bool=False
    bpf_obj["events"].open_perf_buffer(callback)  # ← 从未执行！
```

`bpf_obj` 是一个已加载的 BPF 对象（`is not None` = True），但因为 `__len__()` 返回 0，`bool(bpf_obj)` = False。`if bpf_obj and callback:` 条件永远为 False，`open_perf_buffer()` 从未被调用，perf buffer 从未打开，`perf_buffer_poll()` 没有东西可 poll，直接返回空。

```
BPF 对象加载成功 (bpf_mem is not None = True)
  → 但 bool(bpf_mem) = False (因为 __len__() = 0)
  → if bpf_obj and callback: → False
  → open_perf_buffer() 从未调用
  → perf_buffer_poll() 无 buffer 可 poll → 立即返回
  → 事件循环疯狂空转 (16000+ cycles)
  → 回调从未被调用
  → aggregator 无数据
  → 前端 mem/thread/fd 全为 0
  → 只有 CPU 有数据（/proc 轮询不依赖 BPF）
```

#### 最终修复

`core/loader.py` 第 63 行，一行改动：

```python
# 修改前（检查 truthiness，BPF 对象 falsy 导致跳过）
if bpf_obj and callback:

# 修改后（只检查 None，正确识别对象存在）
if bpf_obj is not None and callback is not None:
```

#### 附带修复

| 文件 | 改动 | 原因 |
|---|---|---|
| `web/app.py` | `async_mode="eventlet"` → `"threading"` | eventlet 的 `select.select()` 补丁影响 BCC 内部 I/O；threading 模式用真实 OS 线程，`perf_buffer_poll()` 不受干扰 |
| `core/loader.py` | `perf_buffer_poll(timeout=10)` → `perf_buffer_poll()` | 默认 timeout 让 BCC 正确等待事件 |
| `core/loader.py` | 加 `time.sleep(0)` + `try/except` | 异常防护 + 调度让出（threading 模式下无害但保留） |

---

### 变更 2：线程泄露检测误报（fork/vfork 被计为线程创建）

#### 现象

barad_agent（腾讯云监控 Agent）的线程数持续上升，触发线程泄露告警。但 barad_agent 并未发生真实线程泄露。

#### 根因

初始设计用 `CLONE_VM` (0x100) 标志区分线程和进程创建：

```c
// 初始设计（错误）
if (!(args->clone_flags & 0x100)) return 0;  // CLONE_VM
```

`CLONE_VM` 不能精确区分线程和 vfork：

| clone 类型 | CLONE_VM (0x100) | CLONE_THREAD (0x10000) | 初始过滤 | 正确过滤 |
|---|:---:|:---:|---|---|
| `fork()` | ❌ | ❌ | ✅ 跳过 | ✅ 跳过 |
| **`vfork()`** | **✅** | **❌** | **❌ 计为线程创建（错误）** | ✅ 应跳过 |
| `pthread_create()` | ✅ | ✅ | ✅ 计入 | ✅ 计入 |

**vfork 有 CLONE_VM 但没有 CLONE_THREAD。** vfork 创建的是子进程（不是线程），退出时 `tid == pid`，被 `sched_process_exit` 的 `if (tid == pid) return 0` 跳过。结果：vfork 创建被计入但退出不被计入 → thread_count 虚高 → 误报泄露。

barad_agent 使用 `vfork`/`posix_spawn` 执行监控子进程，导致 thread_count 持续上升。

#### 诊断过程

| 步骤 | 操作 | 结果 |
|---|---|---|
| 1 | 观察 barad_agent 线程数持续上升 | 怀疑 fork 被计为线程 |
| 2 | 上传 `CLONE_VM` (0x100) 过滤 | fork 被跳过，但 barad_agent 仍上升 |
| 3 | 分析 clone flags 矩阵 | 发现 vfork 有 CLONE_VM 但不是线程 |
| 4 | 确认 `CLONE_THREAD` (0x10000) 只在 pthread_create 时设置 | 找到正确过滤标志 |
| 5 | 上传 `CLONE_THREAD` 过滤 | barad_agent 线程数稳定 ✅ |

#### 最终修复

`bpf/threads.bpf.c`，两处改动（clone + clone3）：

```c
// 修改前（CLONE_VM：vfork 也有此标志，被误计）
if (!(args->clone_flags & 0x100)) return 0;
if (!(flags & 0x100)) return 0;

// 修改后（CLONE_THREAD：只有 pthread_create 有此标志）
if (!(args->clone_flags & 0x10000)) return 0;
if (!(flags & 0x10000)) return 0;
```

`CLONE_THREAD` (0x10000) 是 Linux 内核常量，定义在 `linux/sched.h`，所有架构和发行版相同，跨架构兼容。

#### 附带修复：线程数为 -1

| 现象 | 原因 | 修复 |
|---|---|---|
| barad_agent 线程数显示 -1 | 追踪前已存在的线程退出时，`exited++` 但 `created=0`（创建时 BPF 未加载） | `aggregator.py`：`if created > 0: exited += 1` |

`core/aggregator.py` 的 `on_thread_event`：

```python
# 修改前
elif event["op"] == 'e':
    self.thread_stats[pid]["exited"] += 1

# 修改后
elif event["op"] == 'e':
    if self.thread_stats[pid]["created"] > 0:
        self.thread_stats[pid]["exited"] += 1
```

#### 深入修复：线程数为 -1 的三层防御

##### 问题分析

`on_thread_event` 的 `if created > 0: exited += 1` 保护不够彻底。当先收到 create（`created=1`），再收到追踪前已存在的线程退出时，`created=1 > 0` → 退出被计入，但此退出无对应 create → `exited > created` → 负数。

```
时间线：
  BPF 加载 → create 事件(created=1) → 追踪前的旧线程退出(exited=1) → 真实线程退出(exited=2)
  结果：created=1, exited=2 → thread_count = -1
```

##### 解决方案：三层防御性 clamp

无法在事件入口精确区分"追踪前的退出"和"追踪后的退出"。采用三层防御：

| 层 | 位置 | 措施 | 作用 |
|---|---|---|---|
| 1. 入口保护 | `aggregator.on_thread_event` | `if created > 0: exited += 1` | 阻止 created=0 时的退出 |
| 2. 查询 clamp | `aggregator.get_total_thread_count` / `get_per_process_thread` | `max(0, created - exited)` | 前端永远不显示负数 |
| 3. 分析 clamp | `analyzer/threads.py._iter_stats` | `max(0, created - exited)` | 泄露检测器永远不收到负数 |

##### 安全性验证

| 检查项 | 结论 |
|---|---|
| 解决 -1 | ✅ 所有场景 max(0,...) 保证非负 |
| 不漏检真实泄露 | ✅ 真实泄露值始终为正且上升，max(0,...) 不影响正数 |
| 不引入误报 | ✅ max(0,...) 只能把负数→0 或保持正数不变，不可能制造虚假上升趋势 |
| 状态机不受影响 | ✅ 0 是合法的"无泄露"值 |
| 线程安全 | ✅ 都在 `with self._lock:` 内，max() 是纯函数 |
| 性能 | ✅ O(1)，无影响 |

##### 改动清单

`core/aggregator.py`：
```python
# get_total_thread_count
return max(0, sum(s["created"] - s["exited"] for s in self.thread_stats.values()))

# get_per_process_thread
count = max(0, s["created"] - s["exited"])
```

`analyzer/threads.py`：
```python
# _iter_stats
thread_count = max(0, stats["created"] - stats["exited"])
```

---

### 变更 3：其他修复

| 文件 | 改动 | 原因 |
|---|---|---|
| `bpf/common.h` | 新增 `thread_event_t` + `fd_event_t` + `fd_key_t` | B2 新资源的事件结构 |
| `bpf/threads.bpf.c` | 新增 | clone/clone3/sched_process_exit tracepoint |
| `bpf/fd.bpf.c` | 新增 | openat/socket/close tracepoint + fd 配对追踪 |
| `core/loader.py` | 重写 | 多 BPF 对象 + 单线程轮询 + `is not None` 修复 |
| `core/ingest.py` | 扩展 | 新增 ThreadEvent + FdEvent + 回调 |
| `core/aggregator.py` | 扩展 | 新增 thread_stats + fd_stats + `-1` 保护 |
| `symbolizer/symbols.py` | 改签名 | `resolve(resource, stack_id, pid)` 支持多 BPF map |
| `analyzer/base.py` | 重写 | TrendLeakDetector 通用基类 |
| `analyzer/memory.py` | 重构 | 继承 TrendLeakDetector |
| `analyzer/threads.py` | 新增 | 线程泄露检测 |
| `analyzer/handles.py` | 新增 | 句柄泄露检测 |
| `analyzer/cpu.py` | 新增 | /proc 轮询 CPU 监控 |
| `web/backend.py` | 重写 | 4 资源全真实数据 |
| `config/default.yaml` | 扩展 | thread/fd 阈值 + 状态生命周期参数 |
| `tests/leak_programs/thread_leak.c` | 新增 | 合成线程泄露 |
| `tests/leak_programs/fd_leak.c` | 新增 | 合成句柄泄露 |

---

### 变更 4：内存监控出现负数（allocs map TOCTOU 竞态）

#### 现象

终端日志显示 `[debug] mem=-900000(10pids)`，内存 outstanding 出现负数。此问题在 fd.bpf.c 从 3 个 handler 扩展到 6 个后开始显现。

#### 诊断过程

| 步骤 | 操作 | 结果 | 结论 |
|---|---|---|---|
| 1 | 检查 aggregator 是否有 `max(0,...)` 防御 | `get_total_outstanding` 和 `get_per_process_mem` 无 `max(0,...)` | 负数可传到前端 |
| 2 | 对比线程和句柄的 aggregator | `get_total_thread_count` 和 `get_total_fd_count` 有 `max(0,...)` | 内存 aggregator 缺少防御 |
| 3 | 分析 `mem.bpf.c` 的 `trace_free_entry` | `allocs.lookup(&ptr)` 后 `allocs.delete(&ptr)` 非原子 | TOCTOU 竞态 |
| 4 | 对比 `fd.bpf.c` 的 fd_map | fd_map 已用 refcount 方式修复过同类问题 | 确认根因 |

#### 根因

`mem.bpf.c` 的 `trace_free_entry` 中，`allocs.lookup(&ptr)` 和 `allocs.delete(&ptr)` 是两个独立的 BPF map 操作，非原子。在高频 malloc/free + ptr 复用场景下：

```
Thread A: free(ptr X) → lookup(X) → 找到 {size=100, stack_id=1}
Thread B: malloc → 返回 ptr X（复用）→ allocs.update(X, {size=200, stack_id=2})
Thread A: delete(X) → 删除了 Thread B 的条目！
```

Thread B 的 free 找不到匹配 → free 不计入 → outstanding 虚高（正向）。
或 free 事件携带错误 stack_id → 聚合到无对应 alloc 的 stack_id 下 → `free_bytes > alloc_bytes` → 负数。

#### 最终修复

采用 refcount 原子操作替代 delete（与 fd_map 的修复方式相同）：

`bpf/common.h` — `alloc_info_t` 新增 refcount 字段：
```c
struct alloc_info_t {
    u64 refcount;   /* 原子引用计数，替代 delete，消除 TOCTOU 竞态 */
    u64 size;
    int stack_id;
};
```

`bpf/mem.bpf.c` `trace_malloc_return` — refcount 递增替代 update：
```c
struct alloc_info_t *alloc = allocs.lookup(&ptr);
if (!alloc) {
    struct alloc_info_t zero = {};
    allocs.update(&ptr, &zero);
    alloc = allocs.lookup(&ptr);
}
if (alloc) {
    __sync_fetch_and_add(&alloc->refcount, 1);
    alloc->size = info->size;
    alloc->stack_id = info->stack_id;
}
```

`bpf/mem.bpf.c` `trace_free_entry` — 局部变量拷贝 + refcount 递减，不 delete：
```c
u64 size = info->size;           /* 原子操作前拷贝元数据 */
int stack_id = info->stack_id;
u64 old = __sync_fetch_and_sub(&info->refcount, 1);
if (old > 0) {
    /* 匹配成功，发 free 事件（使用局部拷贝的元数据） */
} else {
    __sync_fetch_and_add(&info->refcount, 1);  /* 回退 */
}
```

#### 附带修复：Python 侧 `max(0,...)` 防御补齐

内存 aggregator 缺少 `max(0,...)` 防御（线程和句柄已有），补齐以保持一致：

`core/aggregator.py`：
```python
# get_total_outstanding
return max(0, total) * 100

# get_per_process_mem
"value": max(0, total) * 100
```

`analyzer/memory.py` `_iter_stats`：
```python
outstanding = max(0, stats["alloc_bytes"] - stats["free_bytes"])
```

---

### 变更 5：句柄监控 fd_count 虚高（open 侧覆盖不全）

#### 现象

fd_count 远高于真实值（YDService: 192 vs 真实 35），导致系统服务被误报为句柄泄露。

#### 诊断过程

| # | 方案 | 结果 | 根因 |
|---|---|---|---|
| 1 | fd_map + delete | ❌ 虚高 | TOCTOU 竞态（lookup + delete 非原子） |
| 2 | fd_map 无 delete | ❌ 归零 | fd 号复用时 close 找到旧条目 → 过度计数 |
| 3 | 无 fd_map，per-PID 计数 | ❌ 归零 | 未追踪 open 的 close 被计入 close_count |
| 4 | fd_map + refcount | ⚠️ 部分改善 | close_unmatched 仍有 40166（12+ 种 open 未追踪） |
| 5 | 补充 dup2/dup3/close_range | ❌ 仍有遗漏 | 12+ 种 open 仍未追踪 + 引入内存负数 |

#### 根因

当前 `fd.bpf.c` 只追踪 `openat` 和 `socket` 两种 open 方式，但 Linux 有 12+ 种创建 fd 的 syscall：

```
openat, socket, accept, accept4, pipe, pipe2, socketpair,
eventfd, eventfd2, timerfd_create, epoll_create, epoll_create1,
inotify_init, memfd_create, userfaultfd, fcntl(F_DUPFD), open, openat2, creat
```

未追踪 open 的 close 经过 `sys_enter_close` 但找不到 fd_map 条目 → `close_unmatched` 高达 40166 → `close_count` 偏低 → `fd_count = open_count - close_count` 虚高。

#### 最终修复

用 kprobe 追踪内核汇聚点 `fd_install`，替代 2 个 open tracepoint：

`bpf/fd.bpf.c` — 删除 `sys_exit_openat` + `sys_exit_socket`，新增 `trace_fd_install` kprobe：
```c
/* fd_install(unsigned int fd, struct file *file)
 * 所有 fd 创建 syscall 都经过此函数 → 100% open 覆盖 */
int trace_fd_install(struct pt_regs *ctx) {
    unsigned int fd = PT_REGS_PARM1(ctx);
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    int sid = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);
    /* 查找或创建 fd_map 条目（refcount 方式） */
    struct fd_key_t key = {.pid = pid, .fd = (int)fd};
    struct fd_value_t *val = fd_map.lookup(&key);
    if (!val) {
        struct fd_value_t zero = {};
        fd_map.update(&key, &zero);
        val = fd_map.lookup(&key);
    }
    if (val) {
        __sync_fetch_and_add(&val->refcount, 1);
        val->stack_id = sid;
    }
    /* 发 open 事件 */
    ...
}
```

`core/loader.py` — `load_fd()` 新增 kprobe 挂载：
```python
self.bpf_fd.attach_kprobe(event="fd_install", fn_name="trace_fd_install")
```

保留 4 个 close tracepoint handler（close/dup2/dup3/close_range）不变。因为所有 open 都被 fd_install 追踪，close 事件能在 fd_map 中找到匹配，`close_unmatched` 降至接近 0。

#### 附带修复：close handler stack_id 局部变量拷贝

所有 close handler 的 `val->stack_id` 读取移到 `__sync_fetch_and_sub` 之前：

```c
// 修改前（有竞态窗口）
u64 old = __sync_fetch_and_sub(&val->refcount, 1);
if (old > 0) {
    event.stack_id = val->stack_id;  /* ← 原子操作后读，可能读到新 open 的 stack_id */
}

// 修改后（缩小竞态窗口）
int sid = val->stack_id;             /* ← 原子操作前拷贝 */
u64 old = __sync_fetch_and_sub(&val->refcount, 1);
if (old > 0) {
    event.stack_id = sid;            /* ← 使用局部拷贝 */
}
```

#### 已知限制

- `dup2`/`dup3` 的 open 侧不经过 `fd_install`（`do_dup2` 直接操作 fd 表），不被追踪。这是既有问题，close 侧反而因 fd_install 覆盖而改善。
- `fd_install` 无法区分 fd 类型（file/socket/pipe），`fd_type` 统一设 0。不影响泄露检测。
- `execve` + `O_CLOEXEC` 关闭不经过任何 close handler，极罕见。

#### 前置验证

在目标机器确认 `fd_install` 可用：
```bash
sudo cat /proc/kallsyms | grep " fd_install"
# 预期输出: ffffffff... T fd_install
```

---

### 变更 6：句柄监控 fd_count 残余虚高（get_stackid 失败 + close 发包逻辑）

#### 现象

变更 5 修复后，fd_count 仍虚高（PID 2982: 293 vs 真实 13），`close_unmatched=4284`。

#### 诊断过程

| 步骤 | 操作 | 结果 | 结论 |
|---|---|---|---|
| 1 | 对比内存监控与句柄监控的差异 | 内存无此问题，句柄有 | 两者发包和计数逻辑不同 |
| 2 | 检查内存 free handler | 仅在 `old > 0`（匹配）时发包 | 内存：不发包 unmatched |
| 3 | 检查句柄 close handler | `sys_enter_close` 总是发包（含 unmatched） | 句柄：发包 unmatched |
| 4 | 检查 aggregator | 内存 `on_mem_event` 无 stack_id 检查 | 内存：所有 free 都计入 |
| 5 | 检查 aggregator | 句柄 `on_fd_event` 有 `stack_id >= 0` 检查 | 句柄：仅计 stack_id≥0 的 close |
| 6 | 分析 stack_id=-1 的来源 | `fd_install` kprobe 中 `get_stackid` 对 stripped binary 返回 -1 | 匹配但无栈的 close 被漏计 |

#### 根因

`fd_install` kprobe 中 `get_stackid(ctx, BPF_F_USER_STACK)` 对部分进程（stripped binary、无 frame pointer）返回 -1。这导致：

```
fd_install → get_stackid 返回 -1 → fd_map 条目 stack_id = -1
close handler → refcount > 0（匹配成功！）→ 读 val->stack_id = -1 → 发 close 事件 stack_id=-1
aggregator → `if stack_id >= 0:` → False → 匹配的 close 不计入 close_count！
```

**关键差异**：`sys_enter_close` 是唯一"总是发包"的 close handler（dup2/dup3/close_range 已是"仅匹配时发包"）。内存 free handler 也是"仅匹配时发包"且 aggregator 无 stack_id 检查。

#### 最终修复

使句柄 close 侧与内存 free 侧保持一致：

`bpf/fd.bpf.c` `sys_enter_close` — 改为仅在匹配时发包：
```c
// 修改前：总是发包（含 unmatched）
struct fd_event_t event = {};
...
if (val) {
    ...
    if (old > 0) { event.stack_id = sid; }
    else { ...add_back...; event.stack_id = -1; }  // ← 仍发包
} else { event.stack_id = -1; }                     // ← 仍发包
bpf_get_current_comm(&event.comm, ...);
events.perf_submit(args, &event, sizeof(event));     // ← 总是执行

// 修改后：仅匹配时发包（与 dup2/dup3/close_range 一致）
if (val) {
    int sid = val->stack_id;
    u64 old = __sync_fetch_and_sub(&val->refcount, 1);
    if (old > 0) {
        struct fd_event_t event = {};
        ...
        event.stack_id = sid;
        bpf_get_current_comm(&event.comm, ...);
        events.perf_submit(args, &event, sizeof(event));  // ← 仅匹配时执行
    } else {
        __sync_fetch_and_add(&val->refcount, 1);
    }
}
return 0;  // ← 不匹配时直接返回
```

`core/aggregator.py` `on_fd_event` — 移除 stack_id 检查：
```python
// 修改前
elif event["op"] == 'c' and event["stack_id"] >= 0:
    self.fd_stats[pid]["close_count"] += 1

// 修改后（BPF 已保证所有发包的 close 都是匹配的）
elif event["op"] == 'c':
    self.fd_stats[pid]["close_count"] += 1
```

#### 效果

PID 2982：fd_count 从 293 降至 13（匹配真实值 `ls /proc/2982/fd | wc -l` = 13）。

---

### 变更 7：检测器 states 字典内存泄露（leakdetect 自身内存持续上升）

#### 现象

leakdetect 工具自身（python3）的内存使用量持续上升，但未触发泄露告警。

#### 诊断过程

| 步骤 | 操作 | 结果 | 结论 |
|---|---|---|---|
| 1 | 检查 aggregator 的 `mem_stats`/`thread_stats`/`fd_stats` | `cleanup_dead()` 定期清理死进程 | aggregator 正常 |
| 2 | 检查检测器的 `states` 字典 | `check()` 中 `self.states[key] = StackSiteState()` 只增不删 | **检测器 states 从不清理** |
| 3 | 确认 `cleanup_dead()` 是否清理检测器 | 只清理 aggregator，不清理检测器 | 检测器无对应清理 |
| 4 | 分析为何不触发告警 | Python 内存增长分散在多个 malloc 调用点 | per-(PID, stack_id) 聚合无法捕获分散增长 |

#### 根因

`TrendLeakDetector.states` 字典只增不删。进程退出后，`aggregator.cleanup_dead()` 从 `mem_stats` 等移除该 PID，但三个检测器的 `states` 字典中该 PID 的条目**永远保留**：

```
新进程 1234 → malloc 事件 → aggregator.mem_stats[1234] 创建 → detector.states[(1234, sid)] 创建
进程 1234 退出 → aggregator.cleanup_dead() 清理 mem_stats[1234]
  → _iter_stats() 不再 yield 1234
  → check() 不再更新 states[(1234, sid)]
  → 但 states[(1234, sid)] 永远留在字典中 ← 泄露
```

随进程启停（shell 命令、cron 任务、短命服务），`states` 字典无限增长。

**为何自身不触发告警**：Python 的内存增长来自 CPython 内部多个 malloc 调用点（pymalloc arena 分配、BCC、SQLite、Flask 等），每个调用点的 outstanding 都低于 1MB 阈值。per-(PID, stack_id) 聚合无法捕获分散增长。

#### 最终修复

`analyzer/base.py` — `TrendLeakDetector` 新增 `cleanup_dead_states()` 方法：
```python
def cleanup_dead_states(self):
    """清理已退出进程的状态条目（与 aggregator.cleanup_dead 对应）。"""
    with self._lock:
        pids = set()
        for key in self.states:
            pids.add(key[0] if isinstance(key, tuple) else key)
        dead_pids = {pid for pid in pids
                     if not os.path.exists("/proc/%d" % pid)}
        if dead_pids:
            self.states = {
                k: v for k, v in self.states.items()
                if (k[0] if isinstance(k, tuple) else k) not in dead_pids
            }
```

`web/backend.py` — `_analyzer_loop` 增加调用（顺序：aggregator 清理 → 检测器清理 → 检测）：
```python
self.aggregator.cleanup_dead()
self.analyzer_mem.cleanup_dead_states()
self.analyzer_threads.cleanup_dead_states()
self.analyzer_fd.cleanup_dead_states()
alerts = []
alerts += self.analyzer_mem.check(...)
...
```

#### 设计要点

- PID 去重：内存检测器的 key 是 `(pid, stack_id)` 元组，一个 PID 可能有几十个 stack_id。先提取唯一 PID 集合，每个 PID 只检查一次 `/proc/[pid]`。
- 调用顺序：`cleanup_dead()` 先从 aggregator 清理死 PID → `cleanup_dead_states()` 再从检测器清理 → `check()` 只处理存活 PID。

---

### 变更 8：告警稳定后不清除（"先升后稳"问题）

#### 现象

YDService 内存上升到约 1.1MB 后趋于稳定，但告警永久停留不清除。

#### 诊断过程

| 步骤 | 操作 | 结果 | 结论 |
|---|---|---|---|
| 1 | 分析 STATE_LEAK 的退出路径 | 仅有两条：进程死亡、outstanding 下降到峰值 50% | 无"稳定"退出路径 |
| 2 | 确认 YDService 的情况 | 内存稳定在 1.1MB（不下降） | 不满足 `value < peak × 0.5` |
| 3 | 推演状态流转 | `value (1.1MB)` 不满足 `< 0.55MB` → 永远停留 STATE_LEAK | 确认根因 |

#### 根因

`_update_state` 的 `STATE_LEAK` 分支只有两条出路：

| 路径 | 条件 | 适用场景 |
|---|---|---|
| 进程死亡 | `/proc/[pid]` 不存在 | 进程退出 |
| 下降恢复 | `value < peak × 0.5` 持续 30s | 内存释放后下降 |

内存"先上升后稳定"（不下降）时，`value` 不满足 `< peak × 0.5` → 永远无法退出 STATE_LEAK。

#### 最终修复

新增第三条出路：峰值长时间未刷新（内存稳定）→ STATE_RESOLVED。

`analyzer/base.py` — `StackSiteState` 新增 `peak_time` 字段：
```python
class StackSiteState:
    def __init__(self):
        ...
        self.peak_time = 0    # 峰值最后刷新时间
```

`analyzer/base.py` — `TrendLeakDetector.__init__` 新增 `stabilize_seconds` 参数（默认 300s）。

`analyzer/base.py` — `_update_state` STATE_LEAK 分支新增路径 B：
```python
elif st.state == STATE_LEAK:
    ...
    if value > st.peak_outstanding:
        st.peak_outstanding = value
        st.peak_time = now                    # ← 峰值刷新时记录时间

    # 路径 A（已有）：下降到峰值 50%
    if (value < st.peak_outstanding * self.clear_ratio
            and elapsed > self.clear_seconds):
        st.state = STATE_RESOLVED
        st.state_since = now
    # 路径 B（新增）：峰值 300s 未刷新（内存稳定）
    elif now - st.peak_time > self.stabilize_seconds:
        st.state = STATE_RESOLVED
        st.state_since = now
```

`analyzer/base.py` — 进入 STATE_LEAK 时初始化 `peak_time`：
```python
# STATE_OBSERVING → STATE_LEAK
st.peak_outstanding = value
st.peak_time = now                    # ← 新增
```

`analyzer/base.py` — STATE_RESOLVED → STATE_NORMAL 时重置：
```python
st.peak_outstanding = 0
st.peak_time = 0                      # ← 新增
```

`analyzer/memory.py` / `threads.py` / `handles.py` — 传递配置：
```python
stabilize_seconds=cfg.get("stabilize_seconds", 300),
```

`config/default.yaml` — 三资源各新增配置项：
```yaml
thresholds:
  mem:
    ...
    stabilize_seconds: 300    # 内存稳定后自动消除告警的时长（秒）
  thread:
    ...
    stabilize_seconds: 300
  fd:
    ...
    stabilize_seconds: 300
```

#### 修复后状态机流转

```
STATE_LEAK 三条出路:
  ├─ 进程死亡 → RESOLVED
  ├─ 路径 A: value < peak × 0.5 持续 30s → RESOLVED（更快，需下降）
  └─ 路径 B: peak_time 至今超过 300s → RESOLVED（更慢，不需下降）
```

路径 A 和 B 用 `elif` 连接，路径 A 优先（下降比稳定更有力地证明泄露已恢复）。

#### 场景验证

| 场景 | peak_time 刷新？ | 结果 |
|---|---|---|
| 内存持续上升（真实泄露） | 每次超峰值时刷新 | 告警保持 ✅ |
| 内存稳定不降（YDService） | 300s 未刷新 | 自动 RESOLVED → 60s 后 NORMAL，告警消失 ✅ |
| 内存下降到峰值 50% | — | 路径 A 先触发（30s，更快）✅ |
| 稳定后缓慢再增长 | 新峰值刷新 peak_time | 经 NORMAL→OBSERVING→LEAK 重新告警 ✅ |

---

### 变更 9：栈追踪表满导致栈展示为空（get_stackid → bpf_get_stack）

#### 现象

内存泄露告警触发后，点击告警栈展示为空。终端 `[ingest]` 打印的 `stack_id` 为 -1。

#### 诊断过程

| 步骤 | 操作 | 结果 | 结论 |
|---|---|---|---|
| 1 | 检查 symbolizer | `stack_id < 0` 时直接返回 `[]` | 栈为空是因为 stack_id=-1 |
| 2 | 检查 BPF 栈追踪表 | `BPF_STACK_TRACE(stack_traces, 16384)` | 表已满 |
| 3 | 扩容到 131072 | 短期有效，长期仍会满 | 扩容只是延缓 |
| 4 | 分析 map 机制 | `BPF_MAP_TYPE_STACK_TRACE` 不做 LRU 淘汰 | 条目只增不减 |

#### 根因

`BPF_MAP_TYPE_STACK_TRACE` 是固定大小的 hash map，不做 LRU 淘汰。每个唯一调用栈（不同进程的不同调用点 → 不同返回地址 → 不同哈希）占一个条目。系统上大量进程 + 短命进程（shell 命令、cron 任务）不断产生新的唯一栈，条目只增不减。map 满后 `get_stackid()` 对新调用栈返回 -1 → symbolizer 对 `stack_id < 0` 返回空列表 → 栈展示为空。

即使扩容到 131072 条目（约 16MB 内核内存），只要运行时间够长或调用 malloc 的点足够多，依然会满。扩容只是延缓，不解决根本问题。

#### 最终修复

用 `bpf_get_stack()` 替代 `get_stackid()` + map，将栈地址直接拷贝到事件 buffer：

```
当前：get_stackid(ctx) → 存入 map → 返回 ID → 后续 walk(ID) 取地址 → sym(addr)
      ↑ 依赖共享 map，满了就失败

改进：bpf_get_stack(ctx, buf, sizeof) → 地址直接拷贝到事件 → 后续直接 sym(addr)
      ↑ 不依赖任何 map，永不失效
```

改动范围（11 个文件）：

| 文件 | 变更 |
|---|---|
| `bpf/common.h` | 5 个结构体：`int stack_id` → `int stack_cnt` + `u64 stack_addrs[8]`；新增 `STACK_MAX_FRAMES` 宏 |
| `bpf/mem.bpf.c` | 删除 `BPF_STACK_TRACE`；`get_stackid` → `bpf_get_stack`；3 个 handler 拷贝 `stack_addrs[8]` |
| `bpf/threads.bpf.c` | 删除 `BPF_STACK_TRACE`；clone/clone3 用 `bpf_get_stack` |
| `bpf/fd.bpf.c` | 删除 `BPF_STACK_TRACE`；`fd_install` + 4 个 close handler 改用 `bpf_get_stack` |
| `core/ingest.py` | 3 个 ctypes Structure 新增 `stack_cnt` + `stack_addrs`；`_extract_addrs()` 辅助函数 |
| `core/aggregator.py` | 聚合 key 从 `stack_id`(int) → `tuple(stack_addrs)`；stats 存 `stack_addrs` + `stack_cnt` |
| `symbolizer/symbols.py` | `resolve()` 直接遍历地址调 `bpf.sym()`，省去 `walk(stack_id)` |
| `analyzer/base.py` | `check()` 解包 6-tuple；`resolve` 传 `stack_addrs, stack_cnt` |
| `analyzer/memory.py` | `_iter_stats` yield 6-tuple |
| `analyzer/threads.py` | 同上 |
| `analyzer/handles.py` | 同上 |

#### 关键设计要点

- `bpf_get_stack` 返回**字节数**（每帧 8 字节），需 `/ sizeof(u64)` 转换为帧数
- `BPF_F_USER_STACK` 在内核中使用 `current_pt_regs()`（不依赖传入的 ctx），因此 tracepoint 传 `args`、kprobe/uprobe 传 `ctx` 均可工作
- ctypes Structure 字段顺序必须与 C struct 完全一致，ctypes 自动处理 padding
- BPF 栈使用量：最大的 close_range handler 约 228 字节（< 512 限制）
- 事件增大 ~64 字节（8帧×8字节），perf buffer 512 页 ×4KB=2MB 可承受

#### 效果

栈地址跟随事件传输，不依赖共享 map。长期运行不再出现新进程栈展示为空的问题。

---

### 变更 10：线程/句柄泄露检测不触发或晚触发（测试程序增长期不足）

#### 现象

`thread_leak` 程序未触发线程泄露告警；`fd_leak` 程序在 ~125s 才触发（预期 ~120s）。

#### 诊断过程

分析状态机的时序矛盾。状态机流程：

```
NORMAL → OBSERVING（需 _is_growing 30s 窗口为 True）
       → LEAK（需 _is_leaking：≥10 历史点 + 跨度 ≥ leak_seconds）
       或回退 NORMAL（若 _is_growing 30s 窗口为 False）
```

`_is_leaking` 前置条件（`base.py:170-175`）：
```python
if len(history) < 10:                    # 需要 10 个历史点（5s 间隔 → 50s 数据）
    return False
if last_t - first_t < self.leak_seconds:  # 需要时间跨度 ≥ leak_seconds
    return False
```

线程泄露推演（`leak_seconds=120`，增长期 50s）：

| 时刻 | 历史点数 | span | _is_growing(30s) | _is_leaking | 状态 |
|---|---|---|---|---|---|
| t=10 | 2 | 5s | True | — | → OBSERVING |
| t=50 | 10 | 45s | True | False (span<120) | OBSERVING |
| t=80 | 16 | 75s | **False**（窗口50-80全平） | — | → **回退 NORMAL** |
| t=125 | — | — | — | — | 已在 NORMAL，永不重新进入 |

#### 根因

`leak_seconds=120` 要求 120s 时间跨度的持续增长数据，但 `thread_leak` 增长期仅 50s（100 线程 × 0.5s）。增长停止后 30s，OBSERVING 因 `_is_growing` 返回 False 而回退 NORMAL，此时 120s 跨度尚未满足。回退后线程数不再增长，永不重新进入 OBSERVING。

句柄泄露增长期 100s（1000 fd × 0.1s），恰好卡在 125s 边界触发（不稳定）。

#### 最终修复

保持 `leak_seconds=120` 不变（较长跨度有助于规避误报），延长测试程序增长期至 150s（> 120s + 30s observe 余量）：

| 程序 | 修改前 | 修改后 | 增长期 |
|---|---|---|---|
| `thread_leak.c` | 100 × 0.5s | 100 × **1.5s** | 50s → **150s** |
| `fd_leak.c` | 1000 × 0.1s | 1000 × **0.15s** | 100s → **150s** |

修复后推演：增长持续到 t=150s，在 t=125s 时 span=120 ≥ 120 且 `_is_growing` 仍为 True → 稳定触发 LEAK。

#### 设计说明

`leak_seconds=120` 的较长跨度要求 120s 的持续增长证据，能有效过滤短暂波动导致的误报。这是设计权衡 — 检测速度稍慢但更准确。测试程序的增长期应 ≥ `leak_seconds + observe_seconds` = 150s。

---

### 告警生命周期说明

> 本节为运行时行为说明，非 bug 修复。

告警由 `analyzer/base.py` 的 `check()` 方法每 5 秒重新生成。`active_alerts` 列表**每次完全重建**，不是累积的。同一个告警 ID 在不同状态下有不同内容：

#### 三个阶段

| 阶段 | 状态 | severity | detail 示例 | 前端表现 |
|---|---|---|---|---|
| 1. 告警触发 | LEAK | `"leak"` | `"+10 in 60s"` | 红色告警，detail 中的秒数持续增长 |
| 2. 告警恢复 | RESOLVED | `"resolved"` | `"resolved: 10 (peak 20)"` | detail 文本变化，告警条目仍在列表中 |
| 3. 告警消失 | NORMAL | — | — | 不生成告警，从列表中消失 |

#### detail 字段的生成逻辑

```python
# LEAK 状态（base.py:86-97）
if st.state == STATE_LEAK:
    new_alerts.append({
        "severity": "leak",
        "detail": "+%d in %ds" % (value, int(now - st.state_since)),
        #       ↑当前 outstanding    ↑进入 LEAK 至今的秒数
    })

# RESOLVED 状态（base.py:98-109）
elif st.state == STATE_RESOLVED:
    new_alerts.append({
        "severity": "resolved",
        "detail": "resolved: %d (peak %d)" % (value, st.peak_outstanding),
        #           ↑当前值           ↑历史峰值
    })

# NORMAL 状态 — 不生成告警
```

#### LEAK → RESOLVED 的三条触发路径

`base.py:134-149`：

| 路径 | 条件 | 适用场景 |
|---|---|---|
| 进程死亡 | `/proc/[pid]` 不存在 | kill 泄露程序后 |
| 下降恢复 | `value < peak × 0.5` 持续 30s | 内存释放后下降 |
| 稳定消除 | `now - peak_time > 300s` | 内存先升后稳（stabilize_seconds） |

#### RESOLVED → NORMAL

在 RESOLVED 状态持续 `resolve_seconds`（60s）后自动回到 NORMAL，告警从列表中消失。

#### 时间线示例

```
t=0       NORMAL → OBSERVING（检测到增长）
t=30s     → LEAK，detail="+10 in 0s"
t=60s     LEAK，detail="+10 in 30s"     ← 用户看到 "outstanding +10 in 60s"
...
t=X       → RESOLVED，detail="resolved: 10 (peak 20)"  ← "信息消失"（旧 detail 替换）
t=X+60s   → NORMAL，无告警                              ← "告警消失"
```
