# LeakDetect 后端设计文档

> 文档版本：v1.0  
> 日期：2026-07-08  
> 状态：⬜ 待实施  
> 关联文档：`D:\leakdetect-plan.md`（总体方案 v1.4）、`D:\leakdetect-frontend-design.md`（前端设计）

---

## 一、概述

### 1.1 文档范围

本文档定义后端（BPF 抓取层 + Python 分析层 + 迁移到 Go）的**完整设计**，覆盖 B0-B4 + M9-M13 全部里程碑。前端已完成（F0-F4），后端完成后两端通过数据契约对接。

### 1.2 后端职责

```
eBPF 程序（C）→ 抓取原始事件 → Python 分析层 → 产出 DashboardUpdate → 前端展示
```

| 层 | 职责 | 语言 | 里程碑 |
|---|---|---|---|
| BPF 抓取层 | uprobe/tracepoint 挂载，采集事件 | C（BPF C） | B1-B2 |
| 分析层 | 采样、聚合、泄露检测、符号解析 | Python | B1-B3 |
| 存储层 | SQLite 历史采样 + 告警记录 | Python + SQL | B1/B4 |
| Web 对接层 | 替换 mock，产出契约数据 | Python（Flask） | B1-B3 |
| 迁移层 | Go 替代 BCC | Go + Python | M9-M13 |

---

## 二、技术栈

| 层 | MVP（B0-B4） | 迁移后（M9-M13） | 说明 |
|---|---|---|---|
| BPF 程序 | C + BCC 运行时编译 | C + clang 预编译 .o（不变） | BPF 字节码跨架构 |
| BPF 加载 | BCC Python（`BPF(text=...)`） | Go + cilium/ebpf | 迁移后零依赖 |
| 事件传输 | perf buffer（BCC 内置） | unix socket + 二进制协议 | 进程隔离 |
| 分析层 | Python | Python（不变） | 仅 loader.py 换数据源 |
| 存储 | SQLite | SQLite（不变） | |
| Web 服务 | Flask + SocketIO | Flask + SocketIO（不变） | |

---

## 三、架构总览

```
┌─────────────────────────────────────────────────────────┐
│ 宿主机（root）                                            │
│                                                          │
│  ┌── BPF 程序 ──────────────────────────────┐           │
│  │  mem.bpf.c   threads.bpf.c   fd.bpf.c    │           │
│  │  uprobe malloc/free    tracepoint clone   │           │
│  │  tracepoint mmap/munmap uprobe pthread    │           │
│  │  tracepoint openat/close ...              │           │
│  └────────────────┬─────────────────────────┘           │
│                   │ perf buffer / ring buffer            │
│                   ▼                                      │
│  ┌── BCC 加载层（B1-B4）/ Go collector（M9-M13）──┐     │
│  │  loader.py        → 加载 + attach + 读事件      │     │
│  └────────────────┬─────────────────────────────┘       │
│                   │ Contract 1: 原始事件                  │
│                   ▼                                      │
│  ┌── Python 分析层 ─────────────────────────────┐       │
│  │  ingest.py       → 采样 + 解码               │       │
│  │  aggregator.py   → 按 (PID, stack) 聚合      │       │
│  │  symbolizer      → 栈地址 → 函数名           │       │
│  │  analyzer/       → 泄露趋势检测 + 告警生成    │       │
│  │  filter_manager  → 黑白名单 + pid_filter_map │       │
│  │  cgroup_enum     → 容器枚举 + cgroup 映射     │       │
│  │  storage/db.py   → SQLite 采样 + 告警存储     │       │
│  │  logging/        → 告警本地日志               │       │
│  └────────────────┬─────────────────────────────┘       │
│                   │ Contract 2: DashboardUpdate          │
│                   ▼                                      │
│  ┌── Flask + SocketIO（已有，F1-F4）──────────────┐     │
│  │  sockets.py  → WebSocket 推送                   │     │
│  │  api.py      → REST 历史查询                    │     │
│  └────────────────────────────────────────────────┘     │
└──────────────────────────────────────────────────────────┘
```

---

## 四、数据契约

### 4.1 Contract 1：原始事件（BPF → 分析层）

BPF 程序产出、分析层消费的原始事件格式：

**内存事件**
```c
struct mem_event_t {
    u32 pid;
    u32 tid;
    u64 size;       // malloc size（free 时为 0）
    u64 ptr;        // malloc 返回值（free 时为参数）
    int stack_id;   // BPF 栈 map ID
    char op;        // 'a'=alloc, 'f'=free
    char comm[16];
};
```

**线程事件**
```c
struct thread_event_t {
    u32 pid;
    u32 tid;
    int stack_id;
    char op;        // 'c'=create, 'e'=exit
    char comm[16];
};
```

**句柄事件**
```c
struct fd_event_t {
    u32 pid;
    int fd;
    int fd_type;    // 0=file, 1=socket, 2=pipe, 3=eventfd
    int stack_id;
    char op;        // 'o'=open, 'c'=close
    char comm[16];
};
```

### 4.2 Contract 2：DashboardUpdate（分析层 → 前端）

已在 `leakdetect-frontend-design.md` §5.2 定义，后端产出时遵守同一格式。**前端零改动。**

---

## 五、BPF 程序设计

### 5.1 通用骨架（所有 BPF 程序共享）

```c
#include <uapi/linux/ptrace.h>

// cgroup 过滤（B3 阶段启用，默认空=全量）
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);     // cgroup_id
    __type(value, __u8);    // 1=监控
    __uint(max_entries, 1024);
} target_cgroups SEC(".maps");

// PID 黑白名单（B3 阶段启用）
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);     // PID
    __type(value, __u8);    // 1=在列表
    __uint(max_entries, 65536);
} pid_filter_map SEC(".maps");

// 栈追踪 map
BPF_STACK_TRACE(stack_traces);

// 采样控制（mem 专用，1/100）
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} sampler SEC(".maps");
```

### 5.2 mem.bpf.c

| Hook | 类型 | 抓取 | 采样 |
|---|---|---|---|
| `malloc` entry | uprobe | `PT_REGS_PARM1(ctx)` = size | 1/100 |
| `malloc` return | uretprobe | `PT_REGS_RC(ctx)` = ptr | 同上 |
| `free` entry | uprobe | `PT_REGS_PARM1(ctx)` = ptr | 同上 |
| `mmap` | tracepoint | size 参数 | 全量 |
| `munmap` | tracepoint | ptr 参数 | 全量 |

**malloc/free 配对追踪**：用 BPF hash map 存 `ptr → {size, stack_id}`，free 时查 map 拿 size，实现精确 outstanding 计算。

```c
struct alloc_info_t {
    u64 size;
    int stack_id;
};

BPF_HASH(allocs, u64, struct alloc_info_t, 1000000);

// malloc entry: 记录 size + stack
int trace_malloc_entry(struct pt_regs *ctx) {
    // 采样 1/100
    u32 key = 0;
    u64 *cnt = sampler.lookup(&key);
    if (cnt && (*cnt + 1) % 100 != 0) return 0;

    struct alloc_info_t info = {};
    info.size = PT_REGS_PARM1(ctx);
    info.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);
    // 暂存到 thread local（通过 hash map + tid）
    return 0;
}

// malloc return: 记录 ptr → {size, stack_id}
int trace_malloc_return(struct pt_regs *ctx) {
    u64 ptr = PT_REGS_RC(ctx);
    if (ptr == 0) return 0;  // malloc 失败
    // 从 entry 暂存中取出 size + stack_id
    // 写入 allocs map: allocs[ptr] = {size, stack_id}
    return 0;
}

// free entry: 查 allocs map，计算 outstanding
int trace_free_entry(struct pt_regs *ctx) {
    u64 ptr = PT_REGS_PARM1(ctx);
    struct alloc_info_t *info = allocs.lookup(&ptr);
    if (info) {
        // 产出 free 事件（含 size 和原 alloc stack_id）
        allocs.delete(&ptr);
    }
    return 0;
}
```

> **架构兼容**：`PT_REGS_PARM1` 和 `PT_REGS_RC` 均为跨架构宏，x86_64/aarch64 自动适配。

### 5.3 threads.bpf.c

| Hook | 类型 | 抓取 | 采样 |
|---|---|---|---|
| `clone` | tracepoint `sys_enter_clone` | PID, TID, stack_id | 全量 |
| `clone3` | tracepoint `sys_enter_clone3` | 同上 | 全量 |
| `exit` | tracepoint `sched_process_exit` | PID, TID | 全量 |
| `pthread_create` | uprobe | PID, stack_id | 全量 |

### 5.4 fd.bpf.c

| Hook | 类型 | 抓取 | 采样 |
|---|---|---|---|
| `openat` | tracepoint `sys_enter_openat` | PID, fd, stack_id | 全量 |
| `socket` | tracepoint `sys_enter_socket` | PID, fd, type | 全量 |
| `pipe2` | tracepoint `sys_enter_pipe2` | PID, fd | 全量 |
| `dup` | tracepoint `sys_enter_dup` | PID, fd | 全量 |
| `close` | tracepoint `sys_enter_close` | PID, fd | 全量 |

> fd 事件的 fd 值在 tracepoint return 时才有（系统调用返回值），需用 tracepoint `sys_exit_*` 或 kretprobe 抓返回值。

---

## 六、Python 后端模块设计

### 6.1 core/loader.py — BPF 加载器

**职责**：用 BCC 加载 BPF 程序，attach 探针，启动事件读取。

```python
class BpfLoader:
    def __init__(self, config):
        self.config = config
        self.bpf = None

    def load_mem(self):
        """加载内存 BPF 程序。"""
        bpf_text = open("bpf/mem.bpf.c").read()
        self.bpf = BPF(text=bpf_text)
        self.bpf.attach_uprobe(name="c", sym="malloc",
                               fn_name="trace_malloc_entry")
        self.bpf.attach_uretprobe(name="c", sym="malloc",
                                  fn_name="trace_malloc_return")
        self.bpf.attach_uprobe(name="c", sym="free",
                               fn_name="trace_free_entry")

    def start_event_loop(self, callback):
        """启动 perf buffer 读取循环。"""
        self.bpf["events"].open_perf_buffer(callback)
        while True:
            self.bpf.perf_buffer_poll()
```

**B1 实现**：内存 BPF 加载 + 事件读取  
**B2 实现**：线程 + 句柄 BPF 加载  
**B3 实现**：cgroup/pid_filter map 更新  
**M11 替换**：改为 unix socket 客户端，不加载 BPF

### 6.2 core/ingest.py — 事件摄入

**职责**：接收原始事件，采样控制，解码为 Python dict。

```python
class IngestManager:
    def __init__(self, config):
        self.sampling_rate = config["sampling"]["mem"]  # 100 = 1/100

    def on_event(self, cpu, data, size):
        """perf buffer 回调：解码事件 + 送聚合器。"""
        event = self.decode_event(data)
        # 按 op 分发
        if event["resource"] == "mem":
            self.aggregator.on_mem_event(event)
        elif event["resource"] == "thread":
            self.aggregator.on_thread_event(event)
        elif event["resource"] == "fd":
            self.aggregator.on_fd_event(event)
```

### 6.3 core/aggregator.py — 聚合器

**职责**：按 (PID, stack_id) 聚合事件，维护 outstanding 指标。

```python
class Aggregator:
    def __init__(self):
        # 内存: {pid: {stack_id: {alloc_bytes, alloc_count, free_bytes, free_count}}}
        self.mem_stats = {}
        # 线程: {pid: {created, exited}}
        self.thread_stats = {}
        # 句柄: {pid: {stack_id: {open_count, close_count}}}
        self.fd_stats = {}

    def on_mem_event(self, event):
        pid = event["pid"]
        sid = event["stack_id"]
        if event["op"] == "a":  # alloc
            self.mem_stats.setdefault(pid, {}).setdefault(sid, {
                "alloc_bytes": 0, "alloc_count": 0,
                "free_bytes": 0, "free_count": 0
            })
            self.mem_stats[pid][sid]["alloc_bytes"] += event["size"]
            self.mem_stats[pid][sid]["alloc_count"] += 1
        elif event["op"] == "f":  # free
            if sid in self.mem_stats.get(pid, {}):
                self.mem_stats[pid][sid]["free_bytes"] += event["size"]
                self.mem_stats[pid][sid]["free_count"] += 1

    def get_outstanding(self, pid, stack_id):
        """返回 outstanding_bytes = alloc - free。"""
        s = self.mem_stats.get(pid, {}).get(stack_id)
        if not s: return 0
        return s["alloc_bytes"] - s["free_bytes"]
```

### 6.4 symbolizer/symbols.py — 符号解析

**职责**：stack_id → 帧地址列表 → 函数名。

```python
class Symbolizer:
    def __init__(self, bpf):
        self.bpf = bpf  # BCC BPF 对象

    def resolve(self, stack_id, pid):
        """解析栈为函数名列表。"""
        if stack_id < 0:
            return []
        frames = []
        for addr in self.bpf["stack_traces"].walk(stack_id):
            try:
                sym = self.bpf.sym(addr, pid,
                                   show_module=True, show_offset=True)
                frames.append(sym.decode('utf-8', errors='replace'))
            except Exception:
                frames.append("0x%x" % addr)
        return frames
```

### 6.5 analyzer/ — 泄露检测器

**内存泄露检测器**（`analyzer/memory.py`）：

```python
class MemoryLeakDetector:
    def __init__(self, config):
        self.threshold_bytes = config["thresholds"]["mem"]["outstanding_delta_bytes"]
        self.duration = config["thresholds"]["mem"]["duration_seconds"]
        self.history = {}  # {pid_stack_key: [(timestamp, outstanding)]}

    def check(self, aggregator, symbolizer):
        """检查所有聚合数据，返回告警列表。"""
        alerts = []
        for pid, stacks in aggregator.mem_stats.items():
            for sid, stats in stacks.items():
                outstanding = stats["alloc_bytes"] - stats["free_bytes"]
                key = (pid, sid)
                self._record(key, outstanding)
                if self._is_leaking(key):
                    alerts.append({
                        "resource": "mem",
                        "pid": pid,
                        "stack": symbolizer.resolve(sid, pid),
                        "detail": "outstanding +%d bytes in %ds" % (
                            outstanding - self.history[key][0][1],
                            self.duration
                        ),
                    })
        return alerts

    def _is_leaking(self, key):
        """outstanding 单调增长 > threshold 且持续 > duration。"""
        history = self.history.get(key, [])
        if len(history) < 2: return False
        # 检查最近 duration 秒内是否单调增长且 delta > threshold
        ...
```

**线程/句柄检测器**类似，追踪 created-exited 和 open-close 的差值趋势。

### 6.6 storage/db.py — SQLite 存储

**职责**：周期采样 + 告警存储 + 历史查询。

```python
class Database:
    def __init__(self, path):
        self.conn = sqlite3.connect(path)
        self._init_schema()

    def write_sample(self, resource, pid, value, container_id=None):
        """每分钟调用一次，写入 samples 表。"""

    def write_alert(self, alert):
        """告警写入 alerts 表。"""

    def query_history(self, resource, range_tag):
        """查询历史时序数据（REST /api/history 调用）。"""
        # 1d: 直接查 samples
        # 7d/30d: 查 samples_downsampled 或聚合

    def downsample(self):
        """定时任务：将 1min 采样聚合为 10min/30min。"""
```

### 6.7 logging/alert_logger.py — 告警日志

```python
class AlertLogger:
    def __init__(self, path):
        self.path = path

    def log(self, alert):
        """写入本地日志文件。"""
        with open(self.path, "a") as f:
            f.write("[%s] %s leak PID=%d %s | %s\n" % (
                datetime.now().isoformat(),
                alert["resource"],
                alert["pid"],
                alert.get("process_name", ""),
                alert["detail"],
            ))
```

### 6.8 core/filter_manager.py — 黑白名单

```python
class FilterManager:
    def __init__(self, bpf, config):
        self.bpf = bpf
        self.config = config

    def apply(self, mode, name_regex, pid_list):
        """解析正则 → PID 集合 → 更新 pid_filter_map。"""
        import re, os
        matched_pids = []
        for pid_dir in os.listdir("/proc"):
            if not pid_dir.isdigit(): continue
            pid = int(pid_dir)
            try:
                comm = open("/proc/%s/comm" % pid).read().strip()
                if name_regex and re.search(name_regex, comm):
                    matched_pids.append(pid)
            except: pass
        matched_pids.extend(pid_list)

        # 更新 BPF map
        for pid in matched_pids:
            self.bpf["pid_filter_map"][pid] = 1

    def start_refresh(self, interval=30):
        """定时刷新（进程启停，PID 变化）。"""
```

### 6.9 core/cgroup_enum.py — 容器枚举

```python
class CgroupEnumerator:
    def enumerate(self):
        """遍历 /proc/*/cgroup，返回容器列表。"""
        containers = {}  # {cid: {name, cgroup_id, pids}}
        for pid_dir in os.listdir("/proc"):
            if not pid_dir.isdigit(): continue
            pid = int(pid_dir)
            try:
                lines = open("/proc/%d/cgroup" % pid).readlines()
                for line in lines:
                    if not line.startswith("4:cpu:"): continue
                    path = line.split(":", 2)[2].strip()
                    cid = self._parse_container_id(path)
                    if cid:
                        containers.setdefault(cid, {
                            "id": cid, "name": cid[:12],
                            "cgroup_id": None, "pids": []
                        })
                        containers[cid]["pids"].append(pid)
            except: pass
        return list(containers.values())
```

---

## 七、泄露检测算法

### 7.1 内存泄露

```
指标：outstanding_bytes = Σalloc_bytes - Σfree_bytes（按 PID + stack_id 聚合）
判定：outstanding_bytes 单调增长，持续 > 60s，增量 > 1MB
告警：包含调用栈（symbolizer 解析）
```

### 7.2 线程泄露

```
指标：thread_count = created - exited（按 PID 聚合）
判定：thread_count 单调增长，持续 > 120s
告警：包含创建栈
```

### 7.3 句柄泄露

```
指标：fd_count = open - close（按 PID + stack_id 聚合）
判定：fd_count 单调增长，持续 > 120s
告警：包含 open 栈
```

### 7.4 算法实现要点

- 每个 (PID, stack_id) 维护一个时间序列 `[(timestamp, value)]`
- "单调增长"定义：序列末尾值 > 序列起始值（在 duration 窗口内）
- 窗口外的旧数据定期清理
- 阈值可在 `config/default.yaml` 配置

---

## 八、历史数据采样与存储

### 8.1 采样策略

| 时间范围 | 采样间隔 | 实现 |
|---|---|---|
| 1天 | 1 分钟 | 后台线程每 60s 快照一次各资源状态 |
| 7天 | 10 分钟 | 定时聚合 1min → 10min |
| 30天 | 30 分钟 | 定时聚合 10min → 30min |

### 8.2 SQLite Schema

已在 `storage/schema.sql` 定义（F1 阶段创建）：
- `samples` 表：1min 采样
- `samples_downsampled` 表：7d/30d 降采样
- `alerts` 表：告警记录
- `filter_config` 表：黑白名单配置

### 8.3 采样线程

```python
def start_sampler(db, aggregator, interval=60):
    """后台线程：每 interval 秒快照一次。"""
    def loop():
        while True:
            for resource in ["mem", "thread", "fd", "cpu"]:
                for pid, value in aggregator.get_snapshot(resource):
                    db.write_sample(resource, pid, value)
            time.sleep(interval)
    threading.Thread(target=loop, daemon=True).start()
```

---

## 九、与前端对接

### 9.1 对接方式

**替换 mock，不改前端。** 后端产出的数据遵守 Contract 2（DashboardUpdate），前端零改动。

### 9.2 对接点

| 前端接口 | 当前（mock） | B1-B3 后 | 实现 |
|---|---|---|---|
| WebSocket `dashboard_update` | `mock.get_dashboard_update()` | `backend.get_dashboard_update()` | 分析层聚合数据 + 告警 |
| REST `/api/history` | `mock.get_history()` | `db.query_history()` | SQLite 查询 |
| REST `/api/alerts` | `mock.get_alerts()` | `db.query_alerts()` | SQLite 查询 |
| REST `/api/containers` | `mock.containers` | `cgroup_enum.enumerate()` | /proc 遍历 |
| REST `/api/config/filter` | `mock.filter_config` | `filter_manager` | BPF map |
| WebSocket `select_container` | `mock.set_selected_container()` | `loader.update_cgroup_filter()` | BPF map 更新 |

### 9.3 切换流程

```
B1 完成：内存资源接真实数据（mock 内存部分替换）
B2 完成：4 资源全真实数据（mock 完全替换）
B3 完成：容器/黑白名单接真实数据（mock stub 全部替换）
```

每步替换时，前端代码不变，只改后端 `web/sockets.py` 和 `web/api.py` 的数据源。

---

## 十、架构兼容性

### 10.1 设计原则

后端代码**架构无关**，x86_64 开发 → aarch64 部署无需改代码。

### 10.2 兼容点

| 点 | 兼容方式 |
|---|---|
| uprobe 参数寄存器 | `PT_REGS_PARM1(ctx)` 宏自动选 RDI(x86)/X0(ARM) |
| uprobe 返回值 | `PT_REGS_RC(ctx)` 宏自动选 RAX(x86)/X0(ARM) |
| libc 路径 | `attach_uprobe(name="c")` BCC 自动 `find_library("c")` |
| BPF 字节码 | 跨架构（CO-RE + BTF） |
| 栈回溯 | `get_stackid` + `BPF_F_USER_STACK` 架构无关 |
| 符号解析 | `b.sym(addr, pid)` 读 ELF，架构无关 |
| /proc 路径 | 统一 `/proc`，架构无关 |
| cgroup 路径 | v1 格式统一，架构无关 |

### 10.3 验证策略

- x86_64 开发环境验证全部功能
- aarch64 生产环境重点验证 `PT_REGS_PARM1` 取值（Test 2 的 malloc size 值合理）
- BPF .o 跨架构（如走 CO-RE 路线）；BCC 运行时编译则各自编译

---

## 十一、里程碑详细划分

### B0：技术验证（1-2 天）

| 验证项 | 方法 | 通过标准 |
|---|---|---|
| BCC 加载 BPF | Hello BPF tracepoint | trace_print 持续输出 |
| uprobe malloc | 挂 malloc + PT_REGS_PARM1 | size 值合理 |
| cgroup_id | bpf_get_current_cgroup_id | cgid 非 0 |
| stack trace | get_stackid + b.sym | 解析出函数名 |

> 详细设计见 `D:\leakdetect-b0-design.md`

### B1：内存抓取 + 分析（~1.5 周）

| 步骤 | 文件 | 交付物 |
|---|---|---|
| 1. 编写 mem.bpf.c | `bpf/mem.bpf.c` | malloc/free uprobe + 配对追踪 + 采样 |
| 2. 实现 loader.py | `core/loader.py` | BCC 加载 + attach + perf buffer 读取 |
| 3. 实现 ingest.py | `core/ingest.py` | 事件解码 + 分发 |
| 4. 实现 aggregator.py | `core/aggregator.py` | (PID, stack) 聚合 + outstanding 计算 |
| 5. 实现 symbols.py | `symbolizer/symbols.py` | stack_id → 函数名 |
| 6. 实现 memory.py | `analyzer/memory.py` | 趋势检测 + 告警生成 |
| 7. 实现 db.py | `storage/db.py` | SQLite 写入 + 查询 |
| 8. 实现 alert_logger.py | `logging/alert_logger.py` | 告警写日志 |
| 9. 替换 mock（内存部分） | `web/sockets.py` | WebSocket 推真实内存数据 |
| 10. 验证 | 跑 mem_leak.c | 触发告警 + 栈定位 + 前端展示 |

**验证标准**：跑合成泄露程序 → 前端内存折线图上升 → 30s 后告警出现 → 栈展示正确函数名

### B2：线程 + 句柄 + CPU（~1.5 周）

| 步骤 | 文件 | 交付物 |
|---|---|---|
| 1. 编写 threads.bpf.c | `bpf/threads.bpf.c` | clone/exit tracepoint + pthread_create uprobe |
| 2. 编写 fd.bpf.c | `bpf/fd.bpf.c` | openat/close/socket/pipe tracepoint |
| 3. 实现 threads.py | `analyzer/threads.py` | created-exited 趋势检测 |
| 4. 实现 handles.py | `analyzer/handles.py` | open-close 趋势检测 |
| 5. 实现 cpu.py | `analyzer/cpu.py` | /proc/[pid]/stat 轮询 + CPU% 计算 |
| 6. loader.py 扩展 | `core/loader.py` | 加载 threads/fd BPF |
| 7. aggregator.py 扩展 | `core/aggregator.py` | 线程/句柄聚合 |
| 8. 替换 mock（全部） | `web/sockets.py` | 4 资源全真实数据 |
| 9. 验证 | 跑 thread_leak.c + fd_leak.c | 线程/句柄告警 + 栈 |

**验证标准**：4 资源全真实数据 → 前端折线图/告警/进程表全部来自 eBPF

### B3：cgroup 过滤 + 黑白名单（4-5 天）

| 步骤 | 文件 | 交付物 |
|---|---|---|
| 1. 实现 cgroup_enum.py | `core/cgroup_enum.py` | /proc/*/cgroup 遍历 + 容器映射 |
| 2. 实现 filter_manager.py | `core/filter_manager.py` | 正则解析 + pid_filter_map + 30s 刷新 |
| 3. loader.py 扩展 | `core/loader.py` | cgroup 过滤 map + pid_filter_map 更新 |
| 4. 替换 REST stub | `web/api.py` | /api/containers /api/config/filter 接真实 |
| 5. WebSocket 联动 | `web/sockets.py` | select_container 更新 BPF map |
| 6. 验证 | 容器下拉切换 + 黑白名单 | 过滤生效 |

**验证标准**：容器下拉切换 → 数据范围变化 → 黑白名单配置 → 进程过滤生效

### B4：配置 + 打包（~1 周）

| 步骤 | 文件 | 交付物 |
|---|---|---|
| 1. 配置完善 | `config/default.yaml` | 全部阈值/采样率/路径可配 |
| 2. 采样线程 | `storage/db.py` | 1min 快照 + 降采样（10min/30min → samples_downsampled） |
| 2a. 数据库保留 | `storage/db.py` | 定期 DELETE 超过 30 天的 samples + VACUUM |
| 2b. query_history 优化 | `storage/db.py` | 7d/30d 查询走降采样表；1d 查询限制结果行数 |
| 2c. 周期性 gc.collect | `web/backend.py` | 每小时调用 gc.collect() 缓解 pymalloc 碎片 |
| 3. start.sh | `packaging/start.sh` | 检查 root + BTF + 启动 |
| 4. PyInstaller 打包 | `packaging/pyinstaller.spec` | Python 运行时打包 |
| 5. tar.gz 组装 | — | 二进制 + .o + 前端 + 配置 |
| 6. README | `README.md` | 部署文档 |
| 7. 端到端验证 | 解压 → start.sh → 浏览器 | 全功能可用 |

**验证标准**：tar.gz 解压 → `./start.sh` → 浏览器打开 → 4 资源监控 + 告警 + 过滤全部工作

### M9-M13：迁移到 Go（~2-3 周）

| 里程碑 | 内容 | 关键点 |
|---|---|---|
| M9 | Go collector + IPC 协议设计 | unix socket + length-prefixed 二进制 |
| M10 | Go collector 实现 | cilium/ebpf 加载 .o + attach + ring buffer |
| M11 | Python 端替换 BCC | loader.py → socket reader，其余不变 |
| M12 | cgroup v2 支持 | 解析 v2 单行格式 |
| M13 | 生产打包 | `CGO_ENABLED=0 go build` 静态二进制 + tar.gz |

**迁移后架构**：
```
Go collector（静态二进制）──IPC──> Python 分析层（不变）──> Flask（不变）
```

---

## 十二、风险与规避

| 风险 | 阶段 | 规避 |
|---|---|---|
| BCC 运行时编译慢 | B1 | BCC 编译一次后缓存；或预编译 .o 用 `BPF(obj_file=)` |
| malloc 采样不精确 | B1 | 1/100 采样 + 统计放大（×100 估算总量） |
| free 无 size 参数 | B1 | 用 BPF hash map 存 ptr→size，free 时查 map |
| 高频事件淹没 Python | B1-B2 | 采样 + ring buffer 限长 + 背压丢弃 |
| stripped 二进制无符号 | B1 | 提示加载 debuginfo；退化为地址展示 |
| aarch64 PT_REGS 取值异常 | B1 | B0 先验证；用 `PT_REGS_PARM1` 宏而非硬编码 |
| cgroup v1 路径差异 | B3 | 固定用 `cpu` 控制器；M12 补 v2 |
| 正则匹配开销 | B3 | 30s 刷新 + 缓存匹配结果 |
| glibc 耦合 | B4 | MVP 依赖系统 bcc 包；M13 后消除 |
| IPC 协议成瓶颈 | M10 | length-prefixed 二进制，避免 JSON |

---

## 十三、文件结构（后端相关）

```
leakdetect/
├── bpf/
│   ├── common.h              # 共享定义（事件结构 + map + 过滤骨架）
│   ├── mem.bpf.c             # 内存 BPF
│   ├── threads.bpf.c         # 线程 BPF
│   ├── fd.bpf.c              # 句柄 BPF
│   └── compiled/             # 预编译 .o（M13 阶段）
│
├── core/
│   ├── loader.py             # BCC 加载 + attach + 事件读取
│   ├── ingest.py             # 事件解码 + 分发
│   ├── aggregator.py         # (PID, stack) 聚合
│   ├── filter_manager.py     # 黑白名单 + pid_filter_map
│   ├── cgroup_enum.py        # 容器枚举
│   └── config.py             # YAML 配置加载
│
├── analyzer/
│   ├── base.py               # 检测器基类
│   ├── memory.py             # 内存泄露检测
│   ├── threads.py            # 线程泄露检测
│   ├── handles.py            # 句柄泄露检测
│   └── cpu.py                # CPU /proc 轮询
│
├── symbolizer/
│   └── symbols.py            # 栈符号解析
│
├── storage/
│   ├── schema.sql            # SQLite 表结构（已有）
│   └── db.py                 # 读写 + 采样 + 降采样
│
├── logging/
│   └── alert_logger.py       # 告警本地日志
│
├── tests/
│   ├── b0/                   # 技术验证脚本
│   └── leak_programs/        # 合成泄露程序
│       ├── mem_leak.c
│       ├── thread_leak.c
│       └── fd_leak.c
│
├── web/                      # 已有（F1-F4），B1-B3 替换数据源
│   ├── app.py
│   ├── sockets.py            # 替换 mock → 真实分析层
│   ├── api.py                # 替换 stub → 真实 DB/cgroup
│   └── mock.py               # B2 后废弃
│
├── config/
│   └── default.yaml          # 阈值/采样率/路径（已有，B4 完善）
│
├── packaging/
│   ├── start.sh              # B4 实现
│   └── pyinstaller.spec      # B4 实现
│
└── tools/
    └── build_bpf.sh          # B1 实现（或用 BCC 运行时编译，不需要）
```

---

## 十四、附录

### 14.1 合成泄露程序

**mem_leak.c**（B1 验证用）：
```c
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

int main() {
    printf("Starting memory leak...\n");
    for (int i = 0; i < 10000; i++) {
        void *p = malloc(1024 * 1024);  // 1MB
        // 故意不 free → 泄露
        usleep(100000);  // 0.1s
    }
    return 0;
}
```

**thread_leak.c**（B2 验证用）：
```c
#include <pthread.h>
#include <unistd.h>
#include <stdio.h>

void* worker(void* arg) {
    // 线程不退出 → 泄露
    while (1) sleep(1);
    return NULL;
}

int main() {
    for (int i = 0; i < 100; i++) {
        pthread_t t;
        pthread_create(&t, NULL, worker, NULL);
        usleep(500000);  // 0.5s
    }
    sleep(300);  // 保持运行
    return 0;
}
```

**fd_leak.c**（B2 验证用）：
```c
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>

int main() {
    for (int i = 0; i < 1000; i++) {
        int fd = open("/dev/null", O_RDONLY);
        // 故意不 close → 泄露
        usleep(100000);
    }
    sleep(300);
    return 0;
}
```

### 14.2 后端启动流程（B4 完成后）

```bash
# 1. 检查 root
if [ "$(id -u)" != "0" ]; then echo "Need root"; exit 1; fi

# 2. 检查 BTF
if [ ! -f /sys/kernel/btf/vmlinux ]; then echo "No BTF"; exit 1; fi

# 3. 启动后端 + 前端
python3 web/app.py  # 内部启动 BPF loader + 分析层 + Flask
```

### 14.3 里程碑总览

| 里程碑 | 时长 | 状态 | 交付物 |
|---|---|---|---|
| F0-F4 | ~3 周 | ✅ 已完成 | 前端全部功能 |
| B0 | 1-2 天 | ⬜ 待实施 | eBPF 技术验证 |
| B1 | ~1.5 周 | ⬜ | 内存泄露检测端到端 |
| B2 | ~1.5 周 | ⬜ | 4 资源全真实数据 |
| B3 | 4-5 天 | ⬜ | 容器过滤 + 黑白名单 |
| B4 | ~1 周 | ⬜ | 打包发布 |
| M9-M13 | ~2-3 周 | ⬜ | 迁移到 Go，零依赖 |

### 14.4 B2 实施中发现的问题及 B4 改善计划

> 以下问题在 B2 实施及后续观察中发现，不影响核心功能，但会导致工具自身内存缓慢增长。计划在 B4 阶段统一改善。

#### 问题 1：SQLite 数据库无限增长

**现象**：`backend._sampler_loop` 每 60s 向 `samples` 表写入 4 资源 × 5 进程 = 20 行。每小时 1200 行，每天约 28800 行。无 `DELETE`，无 `VACUUM`，无保留策略 — 数据库文件无限增长。

**影响**：
- 磁盘：每天约增长 2-3MB，长期运行后数据库文件可达数百 MB
- SQLite 页缓存有界（默认 ~8MB），数据库文件增长不直接导致 Python RSS 增长
- 但 `query_history()` 加载结果行数随数据库增长而增加（见问题 2）

**B4 计划**：`storage/db.py` 新增定期保留任务：
```python
def cleanup_old_samples(self, retention_days=30):
    """删除超过保留期的采样数据 + 回收磁盘空间。"""
    cutoff = int(time.time()) - retention_days * 86400
    with self._lock:
        self.conn.execute("DELETE FROM samples WHERE timestamp < ?", (cutoff,))
        self.conn.execute("DELETE FROM samples_downsampled WHERE timestamp < ?", (cutoff,))
        self.conn.execute("VACUUM")
        self.conn.commit()
```
在 `backend._sampler_loop` 中每小时调用一次。

#### 问题 2：query_history() fetchall() 内存尖峰

**现象**：`db.py` 的 `query_history()` 使用 `fetchall()` 一次性加载所有匹配行到 Python 内存：

```python
series = [{"t": row[0], "v": row[1]} for row in cur.fetchall()]
```

前端打开时对 4 个资源各查询一次 "1d"。运行 1 天后，每资源约 7200 行（5 进程 × 1440 分钟），每行创建一个 Python dict：

| 运行时长 | 单资源行数 | 4 资源临时内存 | 
|---|---|---|
| 1 天 | ~7,200 | ~2.9 MB |
| 7 天 | ~50,400 | ~20 MB |
| 30 天 | ~216,000 | ~86 MB |

这些临时对象会被 GC 回收，但 **Python 的 pymalloc 不释放 arena**（256KB 内存块）。反复查询 → arena 逐渐积累 → RSS 缓慢上升。

**B4 计划**：
1. 实现 `downsample()` 方法，将 1min 采样聚合为 10min/30min 写入 `samples_downsampled` 表
2. `query_history()` 对 7d/30d 查询走降采样表（行数降至 ~1000/1440）
3. 1d 查询返回每资源聚合数据（每分钟一个点，而非每进程每分钟），限制结果行数

#### 问题 3：samples_downsampled 表未实现

**现状**：`storage/schema.sql` 已建表（第 21-32 行），后端设计 §8.1 规定了 10min/30min 降采样策略，但 `storage/db.py` 没有 `downsample()` 方法。7d/30d 查询直接查原始 `samples` 表，加载过多行到内存。

**B4 计划**：`storage/db.py` 新增降采样方法：

```python
def downsample(self):
    """定时任务：将 samples 聚合为 10min/30min 写入 samples_downsampled。"""
    now = int(time.time())
    # 10min 降采样（7d 视图）
    self._aggregate(now - 7 * 86400, 600, "7d")
    # 30min 降采样（30d 视图）
    self._aggregate(now - 30 * 86400, 1800, "30d")
```

在 `backend._sampler_loop` 中每小时调用一次。7d/30d 的 `query_history()` 改为查 `samples_downsampled` 表。

#### 问题 4：pymalloc arena 累积

**现象**：工具运行期间持续产生临时 Python 对象：
- 每 1s：`get_dashboard_update()` 创建 dict + per_process 列表 → GC → arena 不释放
- 每事件：`ct.cast(data, ct.POINTER(MemEvent)).contents` 创建 ctypes 对象 → GC → arena 不释放
- 每 5s：分析器循环创建 alert dict、history list → GC → arena 不释放
- 每 1s/5s：debug 打印字符串 → GC → arena 不释放

这是 Python 的固有行为：pymalloc 分配 256KB arena 管理小对象，对象被 GC 后 arena 保留在进程地址空间中供复用。arena 池满了才会向 OS 归还内存，此过程非常缓慢。

**影响**：RSS 缓慢上升，速率极低（每小时约几 MB），最终会稳定（arena 池足够大后不再增长）。

**B4 计划**：`web/backend.py` 的 `_sampler_loop` 中每小时调用一次 `gc.collect()`，帮助 Python 回收 pymalloc 碎片：

```python
import gc

def _sampler_loop(self):
    gc_count = 0
    while True:
        try:
            ...  # 既有采样逻辑
            gc_count += 1
            if gc_count % 60 == 0:  # 每小时（60min × 1次/min）
                gc.collect()
        except Exception as e:
            ...
        time.sleep(60)
```

#### 问题 5：leakdetect 自身内存增长为何不触发告警

**现象**：工具自身内存缓慢上升，但未触发内存泄露告警。

**根因**：泄露检测按 (PID, stack_id) 独立聚合，每个调用点单独判定 1MB 阈值。Python 进程的内存增长分散在 CPython 内部多个 malloc 调用点（pymalloc arena 分配、BCC 内部、SQLite、Flask/SocketIO 等），每个调用点的 outstanding 都低于 1MB 阈值。per-(PID, stack_id) 聚合无法捕获分散增长。

**结论**：这是 per-stack_id 聚合方式的固有特性，不是 bug。擅长定位"单一调用点持续泄露"，不擅长检测"多调用点分散增长"。上述问题 1-4 的改善（数据库保留、降采样、gc.collect）可缓解工具自身的缓慢增长。
