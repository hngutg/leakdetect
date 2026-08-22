# M9-M11 简化实施设计文档 — BCC → libbpf 迁移

> 文档版本：v1.0  
> 日期：2026-07-13  
> 状态：✅ 已实施  
> 关联文档：`leakdetect-plan.md` v1.5 §7.3（M9-M11 简化）、`leakdetect-backend-design.md` §十一

---

## 一、概述

### 1.1 迁移目标

将 BPF 加载层从 BCC Python 模块迁移到 libbpf + ctypes，消除对 BCC/LLVM（~300MB）的运行时依赖，实现无网络环境的自包含部署。

### 1.2 迁移范围

| 层 | 迁移前（BCC） | 迁移后（libbpf） |
|---|---|---|
| BPF 程序 | BCC 宏风格（`BPF_HASH`/`BPF_PERF_OUTPUT`） | libbpf SEC 风格（`SEC(".maps")`/`bpf_map_*`） |
| BPF 加载 | BCC `BPF(src_file=)` 运行时编译 | `clang -target bpf` 预编译 .o + libbpf 加载 |
| 事件传输 | BCC perf buffer（`perf_event_open`） | libbpf ring buffer（`ring_buffer__new`） |
| 符号解析 | BCC `bpf.sym()` | pyelftools 读 ELF 符号表 |
| 栈捕获 | BCC `get_stackid()` + BPF_STACK_TRACE map | `bpf_get_stack()` 直接拷贝地址到事件 |
| 打包 | 依赖系统 bcc 包（~300MB） | libbpf.so + libelf.so（~2MB）+ 纯 Python 包 |

### 1.3 与原始 M9-M11 的关系

原始 M9-M11 方案为 Go + cilium/ebpf + IPC（工期 2-3 周）。本方案用 Python ctypes + libbpf 替代（工期 ~3 天），消除了 BCC/LLVM 依赖，但未实现进程隔离。Go 方案保留为未来可选增强。

| | 原始 M9-M11（Go 方案） | 本方案（Python + libbpf） |
|---|---|---|
| 消除 BCC | ✅ Go + cilium/ebpf | ✅ Python + ctypes libbpf |
| 预编译 .o | ✅ | ✅ |
| ring buffer | ✅ cilium/ebpf | ✅ libbpf |
| 进程隔离 | ✅ Go collector 独立进程 | ❌ 同进程 |
| 零共享库依赖 | ✅ Go 静态二进制 | ❌ 需 libbpf.so（~2MB） |
| 代码量 | ~1000 行 Go + IPC 协议 | ~280 行 Python（loader.py） |
| 工期 | 2-3 周 | ~3 天 |

**取舍**：用"无进程隔离"换取"80% 更少的代码量"。监控工具非高可用服务，BPF 崩溃重启即可。

---

## 二、技术背景

### 2.1 BCC 方案的问题

| 问题 | 影响 |
|---|---|
| 运行时编译依赖 LLVM | 目标机需安装 bcc 包（~300MB 含 LLVM） |
| `perf_event_open` E2BIG | libbpf 用 `sizeof(perf_event_attr)` 设置 attr.size，系统头文件比内核新时返回 E2BIG |
| BCC 运行时编译慢 | 每次 `BPF(src_file=)` 都触发 clang 编译 |

### 2.2 libbpf 方案的优势

| 优势 | 说明 |
|---|---|
| 预编译 .o（CO-RE） | 构建时 `clang -target bpf` 编译，运行时直接加载 |
| libbpf.so 轻量 | ~1MB 共享库，替代 BCC 的 ~300MB LLVM |
| ring buffer 无 E2BIG | `BPF_MAP_TYPE_RINGBUF` 不调用 `perf_event_open`，无版本不匹配问题 |
| 栈地址直接在事件中 | `bpf_get_stack()` 拷贝地址到事件，不依赖 BPF_STACK_TRACE map（永不填满） |

### 2.3 三阶段演进路线

```
MVP（已完成）:    BCC Python → 运行时编译 → perf buffer → bpf.sym()
简化迁移（已实施）: libbpf ctypes → 预编译 .o → ring buffer → pyelftools
未来增强（可选）:  Go collector → 预编译 .o → ring buffer → 进程隔离
```

---

## 三、BPF 程序改造

### 3.1 common.h — 头文件和结构定义

#### 头文件变更

```c
// 修改前（BCC 风格）:
#include <uapi/linux/ptrace.h>

// 修改后（libbpf 风格）:
#include <linux/types.h>
#include <linux/bpf.h>        // BPF_MAP_TYPE_*, BPF_ANY, BPF_F_USER_STACK, BPF_F_CURRENT_CPU
#include <linux/ptrace.h>    // struct pt_regs 完整定义（PT_REGS_PARM1/RC 需要）
#include <bpf/bpf_helpers.h>  // __uint, __type, SEC, bpf_map_* helper 声明
#include <bpf/bpf_tracing.h>  // PT_REGS_PARM1, PT_REGS_RC 跨架构宏
```

**关键点**：
- `<linux/bpf.h>` 提供 `BPF_MAP_TYPE_*`、`BPF_ANY`、`BPF_F_USER_STACK`、`BPF_F_CURRENT_CPU` 等常量
- `<linux/ptrace.h>` 提供 `struct pt_regs` 完整定义（`bpf_tracing.h` 中的 `PT_REGS_*` 宏需要访问其字段）
- `<bpf/bpf_tracing.h>` 需要 `-D__TARGET_ARCH_x86`（x86_64）或 `-D__TARGET_ARCH_arm64`（aarch64）编译标志

#### 类型定义

```c
// BCC 提供 u32/u64 typedef，libbpf 不提供，需自定义:
typedef __u32 u32;
typedef __u64 u64;
typedef __s32 s32;
typedef __s64 s64;
```

#### 新增 tracepoint 通用参数结构

```c
/* sys_enter_* tracepoint 通用参数结构
 * 布局：common_header(8) + syscall_nr(8) + args[6](48)
 * 在 5.10+ 上跨架构稳定 */
struct sys_enter_args {
    u64 _common_header;
    s64 _syscall_nr;
    u64 args[6];      // args[0]=第1个syscall参数, args[1]=第2个, ...
};
```

BCC 的 `TRACEPOINT_PROBE` 自动从 tracepoint format 生成 `args` 结构体。libbpf 需要手动定义。`sys_enter_*` tracepoint 的布局在 5.10+ 上稳定。

#### 事件结构（不变，但栈捕获方式变化）

事件结构本身不变（`mem_event_t`/`thread_event_t`/`fd_event_t`），但 `int stack_id` 被替换为 `int stack_cnt` + `u64 stack_addrs[STACK_MAX_FRAMES]`（B2 变更 9 已完成）。

### 3.2 BPF 宏 → libbpf 对照表

| BCC 宏 | libbpf 等价 | 说明 |
|---|---|---|
| `BPF_PERF_OUTPUT(events)` | `struct { __uint(type, BPF_MAP_TYPE_RINGBUF); __uint(max_entries, 1024*1024); } events SEC(".maps");` | 事件输出 map（改为 ring buffer） |
| `BPF_HASH(allocs, u64, struct alloc_info_t, 100000)` | `struct { __uint(type, BPF_MAP_TYPE_HASH); __type(key, u64); __type(value, struct alloc_info_t); __uint(max_entries, 100000); } allocs SEC(".maps");` | hash map |
| `BPF_ARRAY(sampler, u64, 1)` | `struct { __uint(type, BPF_MAP_TYPE_ARRAY); __type(key, u32); __type(value, u64); __uint(max_entries, 1); } sampler SEC(".maps");` | array map |
| `events.perf_submit(ctx, &e, sz)` | `bpf_ringbuf_output(&events, &e, sz, 0)` | 事件提交（改为 ring buffer） |
| `allocs.lookup(&k)` | `bpf_map_lookup_elem(&allocs, &k)` | 查找 |
| `allocs.update(&k, &v)` | `bpf_map_update_elem(&allocs, &k, &v, BPF_ANY)` | 更新 |
| `entry_info.delete(&k)` | `bpf_map_delete_elem(&entry_info, &k)` | 删除 |
| `TRACEPOINT_PROBE(syscalls, sys_enter_clone)` | `SEC("tracepoint/syscalls/sys_enter_clone")` | tracepoint |
| `int trace_xxx(struct pt_regs *ctx)` | `SEC("uprobe") int trace_xxx(struct pt_regs *ctx)` | uprobe |
| — | `char _license[] SEC("license") = "GPL";` | GPL 许可（libbpf 必需） |

### 3.3 mem.bpf.c — 内存监控 BPF 程序

#### Map 定义变更

```c
// 修改前（BCC）:
BPF_PERF_OUTPUT(events);
BPF_ARRAY(sampler, u64, 1);
BPF_HASH(entry_info, u32, struct alloc_info_t, 10000);
BPF_HASH(allocs, u64, struct alloc_info_t, 100000);

// 修改后（libbpf + ring buffer）:
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1024 * 1024);  // 1MB
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, u32);
    __type(value, u64);
    __uint(max_entries, 1);
} sampler SEC(".maps");

// entry_info 和 allocs 同理改为 SEC(".maps") 风格
```

#### 事件输出变更

```c
// 修改前（BCC perf buffer）:
bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));

// 修改后（libbpf ring buffer）:
bpf_ringbuf_output(&events, &event, sizeof(event), 0);
```

**区别**：
- `bpf_perf_event_output` 需要 `ctx`（BPF 程序上下文）和 `BPF_F_CURRENT_CPU`（指定 CPU）
- `bpf_ringbuf_output` 只需 map 引用 + 数据 + 大小 + flags，不需要 ctx 和 CPU

#### 函数签名变更

```c
// 修改前（BCC 自动识别 uprobe）:
int trace_malloc_entry(struct pt_regs *ctx) { ... }

// 修改后（libbpf SEC 声明）:
SEC("uprobe")
int trace_malloc_entry(struct pt_regs *ctx) { ... }

SEC("uretprobe")  // return probe
int trace_malloc_return(struct pt_regs *ctx) { ... }
```

uprobe 的实际目标（libc 路径 + 函数偏移）在 Python 加载器中通过 `bpf_program__attach_uprobe()` 指定，不在 SEC 中声明。

#### Map 操作变更

```c
// 修改前（BCC 方法调用）:
u64 *cnt = sampler.lookup(&zero);
entry_info.update(&tid, &info);
allocs.lookup(&ptr);
entry_info.delete(&tid);

// 修改后（libbpf BPF helper）:
u64 *cnt = bpf_map_lookup_elem(&sampler, &zero);
bpf_map_update_elem(&entry_info, &tid, &info, BPF_ANY);
struct alloc_info_t *alloc = bpf_map_lookup_elem(&allocs, &ptr);
bpf_map_delete_elem(&entry_info, &tid);
```

### 3.4 threads.bpf.c — 线程监控 BPF 程序

#### Tracepoint 变更

```c
// 修改前（BCC TRACEPOINT_PROBE）:
TRACEPOINT_PROBE(syscalls, sys_enter_clone) {
    if (!(args->clone_flags & 0x10000)) return 0;
    ...
    bpf_perf_event_output(args, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    return 0;
}

// 修改后（libbpf SEC + sys_enter_args）:
SEC("tracepoint/syscalls/sys_enter_clone")
int trace_clone(struct sys_enter_args *ctx) {
    u64 clone_flags = ctx->args[0];  // args[0] = 第1个 syscall 参数
    if (!(clone_flags & 0x10000)) return 0;
    ...
    bpf_ringbuf_output(&events, &event, sizeof(event), 0);
    return 0;
}
```

**关键区别**：
- BCC 的 `TRACEPOINT_PROBE` 自动生成 `args` 结构体（从 tracepoint format）
- libbpf 用 `SEC("tracepoint/...")` + 手动定义的 `struct sys_enter_args *ctx`
- `ctx->args[0]` 访问第 1 个 syscall 参数（`clone_flags`），`ctx->args[1]` 访问第 2 个（`newfd`）

#### sched_process_exit

```c
// 修改后:
SEC("tracepoint/sched/sched_process_exit")
int trace_sched_exit(void *ctx) {
    // 不需要 tracepoint 参数，用 bpf_get_current_pid_tgid()
    ...
    bpf_ringbuf_output(&events, &event, sizeof(event), 0);
    return 0;
}
```

### 3.5 fd.bpf.c — 句柄监控 BPF 程序

#### Kprobe 变更

```c
// 修改后:
SEC("kprobe/fd_install")
int trace_fd_install(struct pt_regs *ctx) {
    unsigned int fd = PT_REGS_PARM1(ctx);  // fd_install 第1参数
    ...
    bpf_ringbuf_output(&events, &event, sizeof(event), 0);
    return 0;
}
```

#### close_range 移除

`close_range` syscall 在内核 5.11 引入，5.10 不存在。移除 `sys_enter_close_range` handler。影响极小（close_range 是批量关闭操作，使用场景少）。

#### Tracepoint 参数访问

```c
// close handler:
SEC("tracepoint/syscalls/sys_enter_close")
int trace_close(struct sys_enter_args *ctx) {
    int fd = (int)ctx->args[0];  // args[0] = fd 参数
    ...
}

// dup2 handler:
SEC("tracepoint/syscalls/sys_enter_dup2")
int trace_dup2(struct sys_enter_args *ctx) {
    int newfd = (int)ctx->args[1];  // args[1] = newfd 参数
    ...
}
```

---

## 四、事件传输改造（perf buffer → ring buffer）

### 4.1 问题：perf_event_open E2BIG

**现象**：libbpf 的 `perf_buffer__new_raw` 内部调用 `perf_event_open` 系统调用，内核返回 `E2BIG`。

**根因**：
- 运行内核版本：6.8.0-124-generic
- 系统头文件版本：6.8.0-134.134（比内核新 10 个版本）
- libbpf 1.3.0 用 `linux-libc-dev`（6.8.0-134）的头文件编译，`sizeof(perf_event_attr)` 包含 6.8.0-134 新增的字段
- 运行内核 6.8.0-124 不认识这些新字段 → `attr.size` 太大 → `E2BIG`
- libbpf 1.3.0 不自动重试更小的 `attr.size`

### 4.2 方案：BPF_MAP_TYPE_RINGBUF

Ring buffer 不调用 `perf_event_open`，从根本上消除 E2BIG 问题。

| | Perf Buffer | Ring Buffer |
|---|---|---|
| 内核 API | `perf_event_open` + `mmap` | `bpf_map_update_elem` + `mmap` |
| E2BIG 风险 | ✅ 有（attr.size 不匹配） | ❌ 无 |
| BPF helper | `bpf_perf_event_output(ctx, map, BPF_F_CURRENT_CPU, data, sz)` | `bpf_ringbuf_output(map, data, sz, 0)` |
| libbpf API | `perf_buffer__new_raw` + `perf_buffer__poll` | `ring_buffer__new` + `ring_buffer__poll` |
| 回调签名 | `void (*)(void *ctx, int cpu, void *data, __u32 data_sz)` | `int (*)(void *ctx, void *data, size_t size)` |
| 每 CPU 缓冲 | 是（需要 N 个 perf event） | 否（单个共享缓冲） |
| 最低内核 | 4.4 | 5.8（目标 5.10 ✅） |

### 4.3 BPF 侧改动

Map 定义：
```c
// 修改前:
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");

// 修改后:
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1024 * 1024);  // 1MB，必须 2^N 且页对齐
} events SEC(".maps");
```

事件输出：
```c
// 修改前:
bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));

// 修改后:
bpf_ringbuf_output(&events, &event, sizeof(event), 0);
```

改动位置（共 9 处输出调用）：

| 文件 | 输出调用数 | 位置 |
|---|---|---|
| `mem.bpf.c` | 2 | `trace_malloc_return`、`trace_free_entry` |
| `threads.bpf.c` | 3 | `trace_clone`、`trace_clone3`、`trace_sched_exit` |
| `fd.bpf.c` | 4 | `trace_fd_install`、`trace_close`、`trace_dup2`、`trace_dup3` |

### 4.4 Python 侧改动（loader.py）

回调类型变更：
```python
# 修改前（perf buffer 回调）:
PERF_CB = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.c_int,
                           ctypes.c_void_p, ctypes.c_int)
# void (*)(void *ctx, int cpu, void *data, __u32 data_sz)

# 修改后（ring buffer 回调）:
RING_CB = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p,
                           ctypes.c_void_p, ctypes.c_size_t)
# int (*)(void *ctx, void *data, size_t size)
# 返回 0 = 继续处理，非 0 = 停止
```

API 调用变更：
```python
# 修改前:
libbpf.perf_buffer__new_raw(map_fd, 512, ctypes.byref(opts))  # 创建
libbpf.perf_buffer__poll(pb, 50)                              # 轮询

# 修改后:
libbpf.ring_buffer__new(map_fd, cb, None, None)  # 创建
libbpf.ring_buffer__poll(rb, 50)                  # 轮询
```

回调包装适配：
```python
# ring buffer 回调无 cpu 参数，ingest 期望 (cpu, data, size)
# loader 包装层传 cpu=0 作 dummy
def _ring_cb(ctx, data, size):
    callback(0, data, size)  # 0 = dummy cpu
    return 0                  # 继续处理
```

**ingest.py 不需要改动**：回调签名 `(cpu, data, size)` 不变，loader 传 `cpu=0`。事件数据格式（`mem_event_t` 等）完全不变。

---

## 五、Python 加载器改造（core/loader.py）

### 5.1 整体架构

```
BCC 方案:
  from bcc import BPF
  self.bpf = BPF(src_file="mem.bpf.c", cflags=["-I..."])
  self.bpf.attach_uprobe(name="c", sym="malloc", fn_name="trace_malloc_entry")
  self.bpf["events"].open_perf_buffer(callback)
  self.bpf.perf_buffer_poll()

libbpf 方案:
  libbpf = ctypes.CDLL("libbpf.so.1")
  obj = libbpf.bpf_object__open_file("mem.o", None)
  libbpf.bpf_object__load(obj)
  prog = libbpf.bpf_object__find_program_by_name(obj, b"trace_malloc_entry")
  libbpf.bpf_program__attach_uprobe(prog, False, -1, libc_path, offset)
  libbpf.ring_buffer__new(map_fd, callback, None, None)
  libbpf.ring_buffer__poll(rb, 50)
```

### 5.2 libbpf 函数签名

```python
libbpf = ctypes.CDLL("libbpf.so.1")  # 或 "libbpf.so"

# 加载 .o 文件
libbpf.bpf_object__open_file.restype = ctypes.c_void_p
libbpf.bpf_object__open_file.argtypes = [ctypes.c_char_p, ctypes.c_void_p]
# → bpf_object*

libbpf.bpf_object__load.restype = ctypes.c_int
libbpf.bpf_object__load.argtypes = [ctypes.c_void_p]
# → 0=成功

# 查找程序
libbpf.bpf_object__find_program_by_name.restype = ctypes.c_void_p
libbpf.bpf_object__find_program_by_name.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
# → bpf_program*

# Attach 探针
libbpf.bpf_program__attach_kprobe.restype = ctypes.c_void_p
libbpf.bpf_program__attach_kprobe.argtypes = [ctypes.c_void_p, ctypes.c_bool, ctypes.c_char_p]
# → bpf_link*

libbpf.bpf_program__attach_uprobe.restype = ctypes.c_void_p
libbpf.bpf_program__attach_uprobe.argtypes = [ctypes.c_void_p, ctypes.c_bool,
                                              ctypes.c_int, ctypes.c_char_p, ctypes.c_size_t]
# 参数: prog, retprobe, pid(-1=all), binary_path, func_offset
# → bpf_link*

libbpf.bpf_program__attach_tracepoint.restype = ctypes.c_void_p
libbpf.bpf_program__attach_tracepoint.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]
# 参数: prog, category, event
# → bpf_link*

# Map 操作
libbpf.bpf_object__find_map_by_name.restype = ctypes.c_void_p
libbpf.bpf_object__find_map_by_name.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
# → bpf_map*

libbpf.bpf_map__fd.restype = ctypes.c_int
libbpf.bpf_map__fd.argtypes = [ctypes.c_void_p]
# → file descriptor

# Ring buffer
libbpf.ring_buffer__new.restype = ctypes.c_void_p
libbpf.ring_buffer__new.argtypes = [ctypes.c_int, ctypes.c_void_p,
                                     ctypes.c_void_p, ctypes.c_void_p]
# 参数: map_fd, callback, ctx, opts(NULL)
# → ring_buffer*

libbpf.ring_buffer__poll.restype = ctypes.c_int
libbpf.ring_buffer__poll.argtypes = [ctypes.c_void_p, ctypes.c_int]
# 参数: rb, timeout_ms
```

### 5.3 libc 路径自动检测 + 符号偏移查找

BCC 的 `attach_uprobe(name="c", sym="malloc")` 自动解析 libc 路径和函数偏移。libbpf 需要手动指定。

```python
_LIBC_PATHS = [
    "/lib64/libc.so.6",                              # EulerOS aarch64
    "/lib/aarch64-linux-gnu/libc.so.6",              # Ubuntu aarch64
    "/lib/x86_64-linux-gnu/libc.so.6",               # Ubuntu x86_64
    "/usr/lib64/libc.so.6",
    "/usr/lib/aarch64-linux-gnu/libc.so.6",
    "/usr/lib/x86_64-linux-gnu/libc.so.6",
]

def _find_libc():
    """查找 libc.so.6 路径。"""
    for p in _LIBC_PATHS:
        if os.path.exists(p):
            return p
    raise RuntimeError("libc not found")

def _find_symbol_offset(elf_path, symbol_name):
    """在 ELF 文件中查找函数符号的偏移地址（用 pyelftools）。"""
    with open(elf_path, "rb") as f:
        elf = ELFFile(f)
        for section in elf.iter_sections():
            if not hasattr(section, "iter_symbols"):
                continue
            for sym in section.iter_symbols():
                if sym.name == symbol_name and sym["st_value"] != 0:
                    return sym["st_value"]
    raise RuntimeError("Symbol not found")
```

### 5.4 多 BPF 对象管理

3 个 .o 文件（mem/threads/fd），各有独立的 `events` map 和 ring buffer：

```python
class BpfLoader:
    def __init__(self, config):
        self._objects = {}     # {resource: bpf_object*}
        self._rbs = []          # [ring_buffer*]
        self._cb_refs = []      # 持有回调引用，防止 GC

    def load_mem(self):
        self._load_obj("mem", "mem.o")
        self._attach_uprobe("mem", "trace_malloc_entry", "malloc", retprobe=False)
        self._attach_uprobe("mem", "trace_malloc_return", "malloc", retprobe=True)
        self._attach_uprobe("mem", "trace_free_entry", "free", retprobe=False)

    def load_threads(self):
        self._load_obj("threads", "threads.o")
        self._attach_tp("threads", "trace_clone", "syscalls", "sys_enter_clone")
        self._attach_tp("threads", "trace_clone3", "syscalls", "sys_enter_clone3")
        self._attach_tp("threads", "trace_sched_exit", "sched", "sched_process_exit")

    def load_fd(self):
        self._load_obj("fd", "fd.o")
        self._attach_kprobe("fd", "trace_fd_install", "fd_install")
        self._attach_tp("fd", "trace_close", "syscalls", "sys_enter_close")
        self._attach_tp("fd", "trace_dup2", "syscalls", "sys_enter_dup2")
        self._attach_tp("fd", "trace_dup3", "syscalls", "sys_enter_dup3")
```

### 5.5 单线程轮询

```python
def _poll_all(self):
    """单线程轮询所有 ring buffer，50ms timeout。"""
    while True:
        for rb in self._rbs:
            libbpf.ring_buffer__poll(rb, 50)
        time.sleep(0.001)
```

### 5.6 backend.py 适配

```python
# 修改前:
self.symbolizer = Symbolizer(self.loader.bpf_mem, self.loader.bpf_threads, self.loader.bpf_fd)

# 修改后:
self.symbolizer = Symbolizer()  # pyelftools 不需要 BPF 对象
```

---

## 六、符号解析改造（symbolizer/symbols.py）

### 6.1 BCC bpf.sym() → pyelftools

BCC 的 `bpf.sym(addr, pid, show_module=True, show_offset=True)` 自动读进程的 ELF 并解析符号。libbpf 不提供此功能，用 pyelftools 替代。

### 6.2 实现流程

```
1. 读 /proc/[pid]/maps → 找到地址所属库
2. 计算库内偏移: elf_addr = addr - map_start + map_offset
3. 打开库的 ELF 文件 → 遍历符号表 → 找到 elf_addr 所在的函数
4. 返回 "函数名+偏移"
```

### 6.3 代码结构

```python
class Symbolizer:
    def __init__(self, bpf_mem=None, bpf_threads=None, bpf_fd=None):
        """参数保留以兼容 backend.py 调用，实际不使用。"""
        self._elf_cache = {}  # {elf_path: [(st_value, st_size, name), ...]}

    def resolve(self, resource, stack_addrs, stack_cnt, pid):
        # 1. 解析 /proc/[pid]/maps
        # 2. 对每个地址找到所属库
        # 3. 在库的 ELF 符号表中查找
        ...

    def _get_symbols(self, elf_path):
        """获取 ELF 函数符号列表（带缓存）。"""
        if elf_path in self._elf_cache:
            return self._elf_cache[elf_path]
        # 用 pyelftools 解析 ELF，缓存结果
        ...
```

### 6.4 性能优化

libc (~2MB ELF) 的符号表解析需要几十毫秒。用缓存避免重复解析：

```python
_elf_cache = {}  # {elf_path: [(st_value, st_size, name), ...]}
# 首次解析后缓存，后续直接查表
```

---

## 七、构建流程

### 7.1 tools/build_bpf.sh — 预编译脚本

```bash
#!/bin/bash
# build_bpf.sh - 预编译 BPF 程序为 CO-RE .o 文件
# 用法：./tools/build_bpf.sh
# 产出：bpf/compiled/{mem,threads,fd}.o
# 要求：clang（支持 -target bpf），libbpf-dev（提供 bpf/bpf_helpers.h 等头文件）
set -e

DIR="$(cd "$(dirname "$0")/.." && pwd)"
BPF_DIR="$DIR/bpf"
OUT_DIR="$DIR/bpf/compiled"

mkdir -p "$OUT_DIR"

# 架构检测
ARCH=$(uname -m)
case "$ARCH" in
    x86_64)  BPF_ARCH="x86" ;;
    aarch64) BPF_ARCH="arm64" ;;
    *) echo "Unsupported arch: $ARCH"; exit 1 ;;
esac

# multiarch include 路径检测
MULTIARCH=$(dpkg-architecture -qDEB_HOST_MULTIARCH 2>/dev/null || echo "$ARCH-linux-gnu")
INCLUDE_PATH="/usr/include/${MULTIARCH}"

if [ ! -d "$INCLUDE_PATH/asm" ]; then
    echo "WARNING: asm headers not found at $INCLUDE_PATH"
    echo "  Try: apt install linux-libc-dev (Debian/Ubuntu)"
    echo "  Or:  yum install kernel-headers (RHEL/EulerOS)"
fi

CFLAGS="-target bpf -D__TARGET_ARCH_${BPF_ARCH} -g -O2 -I${INCLUDE_PATH} -I${BPF_DIR}"

echo "Building BPF programs (arch=$ARCH, target=$BPF_ARCH)..."
clang $CFLAGS -c "$BPF_DIR/mem.bpf.c" -o "$OUT_DIR/mem.o"
clang $CFLAGS -c "$BPF_DIR/threads.bpf.c" -o "$OUT_DIR/threads.o"
clang $CFLAGS -c "$BPF_DIR/fd.bpf.c" -o "$OUT_DIR/fd.o"

echo "Done: mem.o threads.o fd.o"
ls -la "$OUT_DIR"/*.o
```

### 7.2 编译标志说明

| 标志 | 作用 | 缺失时的错误 |
|---|---|---|
| `-target bpf` | 生成 BPF 字节码（CO-RE） | 生成 x86 机器码，内核拒绝加载 |
| `-D__TARGET_ARCH_x86` | 告诉 `bpf_tracing.h` 架构（x86_64 → RDI，aarch64 → X0） | `Must specify a BPF target arch via __TARGET_ARCH_xxx` |
| `-g` | 生成 DWARF 调试信息（CO-RE 依赖） | CO-RE 重定位失败 |
| `-O2` | 优化（消除死代码，减小 .o 体积） | — |
| `-I/usr/include/${MULTIARCH}` | 提供 `asm/types.h` 等架构相关头文件 | `fatal error: 'asm/types.h' file not found` |
| `-I${BPF_DIR}` | 提供 `common.h` | `fatal error: 'common.h' file not found` |

### 7.3 常见编译错误及解决

| 错误 | 原因 | 解决 |
|---|---|---|
| `'asm/types.h' file not found` | 缺少 multiarch 头文件 | `apt install linux-libc-dev`，用 `-I/usr/include/$(dpkg-architecture -qDEB_HOST_MULTIARCH)` |
| `Must specify a BPF target arch` | `bpf_tracing.h` 需要架构宏 | 加 `-D__TARGET_ARCH_x86`（x86_64）或 `-D__TARGET_ARCH_arm64`（aarch64） |
| `incomplete definition of type 'struct pt_regs'` | 只有前向声明，缺完整定义 | 加 `#include <linux/ptrace.h>` |
| `use of undeclared identifier 'BPF_MAP_TYPE_*'` | 缺 BPF 常量定义 | 加 `#include <linux/bpf.h>` |

### 7.4 CO-RE .o 的架构无关性

BPF 字节码是架构无关的中间表示。同一个 `.o` 文件可在不同架构的内核上运行，前提是：
- 内核支持 BTF（5.10+ ✅）
- BPF 程序不直接使用内核类型（本程序使用自定义结构 ✅）
- `PT_REGS_*` 宏在编译时已展开为具体架构的寄存器访问（x86_64 和 aarch64 的 .o 不同，但同一架构跨内核版本通用）

> **注意**：x86_64 和 aarch64 需要分别编译 .o（因为 `PT_REGS_*` 宏展开不同）。打包时需包含目标架构的 .o。

---

## 八、打包方案

### 8.1 包结构

```
leakdetect-{arch}.tar.gz (~25MB)
├── bpf/compiled/           # 预编译 CO-RE .o
│   ├── mem.o
│   ├── threads.o
│   └── fd.o
├── lib/                     # 目标架构共享库
│   ├── libbpf.so.1         # ~1MB
│   └── libelf.so.1         # ~0.1MB
├── py-packages/             # 纯 Python 包（架构无关）
│   ├── flask/
│   ├── flask_socketio/
│   ├── engineio/
│   ├── yaml/
│   ├── elftools/
│   └── ... (依赖)
├── core/                    # 项目 Python 源码
├── analyzer/
├── symbolizer/
├── storage/
├── alert_logging/
├── web/
│   └── static/             # 前端静态资源（vendor + js + css + index.html）
├── config/
│   └── default.yaml
├── tests/leak_programs/    # 验证程序（.c 源码）
│   ├── mem_leak.c
│   ├── thread_leak.c
│   └── fd_leak.c
├── data/                   # 运行时数据（SQLite + 日志，空目录）
├── requirements.txt
└── start.sh                # 启动脚本（已去 BOM + chmod +x）
```

### 8.2 纯 Python 包获取

```bash
# 在 x86_64 构建机上
pip download -d py-packages/ flask flask-socketio pyyaml pyelftools

# .whl 文件解压后，纯 Python 代码架构无关
# C 扩展（pyyaml/markupsafe）的 .so 在 aarch64 上无法加载
# Python 自动回退到纯 Python实现（慢但功能正确）

# 解压 .whl：
for f in *.whl; do unzip -oq "$f" && rm "$f"; done
```

**C 扩展回退机制**：`.whl` 文件同时包含 `.so`（C 扩展）和 `.py`（纯 Python 回退）。在 aarch64 上：
- Python 的 import 机制按平台标签查找 `.so`：`_speedups.cpython-311-x86_64_linux_gnu.so` → 不匹配 aarch64 → 跳过
- 回退到纯 Python 实现：`markupsafe/_native.py`、`yaml/` 纯 Python 解析器
- 功能不受影响，只是稍慢

### 8.3 目标架构共享库获取

| 场景 | 方法 | 命令 |
|---|---|---|
| 同架构打包 | 从系统复制 | `cp /usr/lib/.../libbpf.so.1 lib/` |
| x86_64 → aarch64 | 从 aarch64 deb 包提取 | `apt download libbpf1:arm64` → `dpkg-deb -x` |
| 无 deb 包的系统 | 交叉编译 | `aarch64-linux-gnu-gcc` 从 libbpf 源码编译 |

**glibc 兼容性**：libbpf.so 依赖 glibc 的基础函数（open/read/mmap 等），这些在 glibc 2.0+ 都有。
风险主要来自 libbpf.so 是否引用了较新 glibc 的版本符号。验证方法：
```bash
objdump -T libbpf.so.1 | grep GLIBC | sort -t_ -k2 -V
# 最高版本应 <= 目标系统的 glibc 版本
```

### 8.4 start.sh — 启动脚本

```bash
#!/bin/bash
# start.sh - LeakDetect 启动脚本（自包含打包版）
# 用法：./start.sh
# 前置：root 权限，BTF 可用，Python 3 已安装
set -e

DIR="$(cd "$(dirname "$0")" && pwd)"

# 1. 检查 root
if [ "$(id -u)" != "0" ]; then
    echo "ERROR: Need root (eBPF requires root)"
    exit 1
fi

# 2. 检查 BTF
if [ ! -f /sys/kernel/btf/vmlinux ]; then
    echo "ERROR: BTF not found (/sys/kernel/btf/vmlinux)"
    echo "Kernel 5.10+ with CONFIG_DEBUG_INFO_BTF required"
    exit 1
fi

# 3. 检查 Python 3
if ! command -v python3 >/dev/null 2>&1; then
    echo "ERROR: python3 not found"
    exit 1
fi

# 4. 设置环境变量
export LD_LIBRARY_PATH="$DIR/lib:$LD_LIBRARY_PATH"
export PYTHONPATH="$DIR/py-packages:$DIR:$PYTHONPATH"

echo "LeakDetect starting..."
echo "  Dir: $DIR"
echo "  Python: $(python3 --version)"
echo "  BTF: OK"
echo "  libbpf: $(ls $DIR/lib/libbpf* 2>/dev/null || echo 'not found')"
echo ""

cd "$DIR"
exec python3 web/app.py
```

### 8.5 tools/package.sh — 打包脚本

```bash
#!/bin/bash
# package.sh - 打包 LeakDetect 为自包含 tar.gz
# 用法：./tools/package.sh [target_arch]
#   target_arch: x86_64 或 aarch64（默认：当前架构）
# 产出：dist/leakdetect-{arch}.tar.gz
#
# 前置：
#   - clang + libbpf-dev（编译 BPF .o）
#   - pip（下载 Python 包）
#   - 对于 aarch64 目标：需要能获取 aarch64 libbpf.so
set -e

DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$DIR"

TARGET_ARCH="${1:-$(uname -m)}"
PKG_NAME="leakdetect-${TARGET_ARCH}"
PKG_DIR="dist/$PKG_NAME"

echo "=== Packaging LeakDetect for $TARGET_ARCH ==="

# 1. 预编译 BPF .o（使用当前机器的 clang）
echo "[1/5] Building BPF .o files..."
./tools/build_bpf.sh

# 2. 准备目录结构
echo "[2/5] Assembling package structure..."
rm -rf "$PKG_DIR"
mkdir -p "$PKG_DIR"/{bpf/compiled,lib,py-packages,config,tests/leak_programs,data}

# 拷贝项目源码
cp -r core analyzer symbolizer storage alert_logging web "$PKG_DIR/"
cp -r bpf/compiled/*.o "$PKG_DIR/bpf/compiled/"
cp config/default.yaml "$PKG_DIR/config/"
cp -r tests/leak_programs/*.c "$PKG_DIR/tests/leak_programs/"
cp packaging/start.sh "$PKG_DIR/"
cp requirements.txt "$PKG_DIR/"

# 3. 下载纯 Python 包
echo "[3/5] Downloading Python packages..."
pip download -d "$PKG_DIR/py-packages/" \
    flask flask-socketio pyyaml pyelftools \
    2>/dev/null || true

# 解压 .whl 文件（纯 Python 代码架构无关，C 扩展会回退到纯 Python）
cd "$PKG_DIR/py-packages/"
for f in *.whl; do
    [ -f "$f" ] && unzip -oq "$f" && rm "$f"
done
cd "$DIR"

# 4. 获取目标架构的共享库
echo "[4/5] Fetching $TARGET_ARCH shared libraries..."
if [ "$TARGET_ARCH" = "$(uname -m)" ]; then
    # 当前架构：从系统复制
    LIBBPF=$(find /usr/lib* -name "libbpf.so.1" 2>/dev/null | head -1)
    LIBELF=$(find /usr/lib* -name "libelf.so.1" 2>/dev/null | head -1)
    if [ -n "$LIBBPF" ]; then cp "$LIBBPF" "$PKG_DIR/lib/"; fi
    if [ -n "$LIBELF" ]; then cp "$LIBELF" "$PKG_DIR/lib/"; fi
else
    # 交叉架构：从 deb 包提取
    echo "  Downloading $TARGET_ARCH packages..."
    apt download "libbpf1:${TARGET_ARCH/amd64/x86_64}" \
        "libelf1:${TARGET_ARCH/amd64/x86_64}" \
        -d /tmp/leakdetect-debs 2>/dev/null || true
    mkdir -p /tmp/leakdetect-extract
    for deb in /tmp/leakdetect-debs/*.deb; do
        [ -f "$deb" ] && dpkg-deb -x "$deb" /tmp/leakdetect-extract/
    done
    find /tmp/leakdetect-extract -name "libbpf.so*" \
        -exec cp {} "$PKG_DIR/lib/" \; 2>/dev/null || true
    find /tmp/leakdetect-extract -name "libelf.so*" \
        -exec cp {} "$PKG_DIR/lib/" \; 2>/dev/null || true
    rm -rf /tmp/leakdetect-debs /tmp/leakdetect-extract
fi

if [ -z "$(ls "$PKG_DIR/lib/"libbpf* 2>/dev/null)" ]; then
    echo "  WARNING: libbpf.so not found for $TARGET_ARCH"
    echo "  For aarch64: apt download libbpf1:arm64 libelf1:arm64"
fi

# 5. 打包
echo "[5/5] Creating tar.gz..."
# 去除 .sh 文件的 BOM（Windows 创建的 .sh 有 UTF-8 BOM）
sed -i '1s/^\xEF\xBB\xBF//' "$PKG_DIR/start.sh" 2>/dev/null || true
chmod +x "$PKG_DIR/start.sh"

cd dist
tar czf "${PKG_NAME}.tar.gz" "$PKG_NAME"
cd "$DIR"

echo ""
echo "=== Done ==="
echo "Package: dist/${PKG_NAME}.tar.gz"
echo "Size: $(du -sh dist/${PKG_NAME}.tar.gz | cut -f1)"
echo ""
echo "Deploy:"
echo "  tar xzf dist/${PKG_NAME}.tar.gz"
echo "  cd $PKG_NAME"
echo "  ./start.sh"
```

### 8.6 打包步骤说明

| 步骤 | 命令 | 说明 |
|---|---|---|
| 1. 预编译 .o | `./tools/build_bpf.sh` | clang -target bpf 生成 CO-RE .o（架构无关字节码，但 PT_REGS 宏按编译机架构展开） |
| 2. 组装目录 | `cp -r core/ analyzer/ ...` | 拷贝项目源码 + .o + config + tests + start.sh + requirements.txt |
| 3. 下载 Python 包 | `pip download` + `unzip` | 下载 .whl 并解压；纯 Python 代码架构无关；C 扩展回退 |
| 4. 获取 .so | `find` / `apt download` + `dpkg-deb -x` | 同架构从系统复制；跨架构从 deb 包提取 |
| 5. 打包 | `sed` 去 BOM + `chmod +x` + `tar czf` | start.sh 去 BOM 后才能在 Linux 执行 |

### 8.7 BOM 问题

在 Windows 上创建的 .sh 文件包含 UTF-8 BOM（`EF BB BF`），Linux bash 无法识别带 BOM 的 shebang：

```
#!/bin/bash → /bin/bash: No such file or directory
```

**解决**：`package.sh` 步骤 5 中自动用 `sed` 去除 start.sh 的 BOM。`build_bpf.sh` 和 `package.sh` 本身在传输到 Linux 后也需要去 BOM：

```bash
sed -i '1s/^\xEF\xBB\xBF//' tools/build_bpf.sh tools/package.sh packaging/start.sh
chmod +x tools/build_bpf.sh tools/package.sh packaging/start.sh
```

### 8.8 部署流程

```bash
# 在 x86_64 构建机上（有网络）
cd ~/workspace/leakdetect
# 去除 BOM
sed -i '1s/^\xEF\xBB\xBF//' tools/build_bpf.sh tools/package.sh packaging/start.sh
chmod +x tools/build_bpf.sh tools/package.sh packaging/start.sh
# 打包（aarch64 目标）
./tools/package.sh aarch64

# 传输到 aarch64 目标机（无网络）
scp dist/leakdetect-aarch64.tar.gz target:~/

# 在 aarch64 目标机上
tar xzf leakdetect-aarch64.tar.gz
cd leakdetect-aarch64
./start.sh
```

---

## 九、跨环境兼容性

### 9.1 内核版本兼容性

| 特性 | 最低内核版本 | 5.10 支持 | 说明 |
|---|---|---|---|
| `bpf_get_stack()` | 4.18 | ✅ | 栈地址直接拷贝到事件 |
| `BPF_MAP_TYPE_RINGBUF` | 5.8 | ✅ | ring buffer，不调用 perf_event_open |
| `fd_install` kprobe | 核心函数 | ✅ | 所有内核版本可用 |
| `bpf_ringbuf_output` | 5.8 | ✅ | ring buffer 事件输出 |
| `bpf_map_*` helpers | 4.6 | ✅ | map 操作 |
| 有界循环 | 5.3 | ✅ | `for (i = 0; i < 8; i++)` |
| `CLONE_THREAD` (0x10000) | 内核常量 | ✅ | 所有架构相同 |
| BTF 支持 | 5.10+ | ✅ | CO-RE 依赖 |

### 9.2 架构兼容性

| 特性 | x86_64 | aarch64 | 适配方式 |
|---|---|---|---|
| `PT_REGS_PARM1(ctx)` | → RDI | → X0 | `<bpf/bpf_tracing.h>` + `-D__TARGET_ARCH_x86/arm64` |
| `PT_REGS_RC(ctx)` | → RAX | → X0 | 同上 |
| libc 路径 | `/lib/x86_64-linux-gnu/libc.so.6` | `/lib64/libc.so.6` | `_find_libc()` 自动检测 |
| `bpf_get_stack()` | ✅ | ✅ | 内核 helper，架构无关 |
| `bpf_get_current_pid_tgid()` | ✅ | ✅ | 内核 helper，架构无关 |
| .o 文件 | x86_64 专用 | aarch64 专用 | `PT_REGS_*` 宏编译时展开不同 |

### 9.3 Python 兼容性

- 代码使用 `%` 格式化（非 f-string），兼容 Python 3.6+
- `ctypes`、`threading`、`os`、`time` 等标准库在所有 Python 3 版本可用
- pyelftools 兼容 Python 3.5+
- flask/flask-socketio 需选择与目标 Python 版本兼容的版本

### 9.4 已知限制

| 限制 | 原因 | 影响 |
|---|---|---|
| close_range handler 移除 | 内核 5.10 无此 tracepoint | 极少量 close 事件不追踪 |
| dup2/dup3 open 侧不追踪 | `do_dup2` 不调用 `fd_install` | 既有问题，close 侧已改善 |
| libbpf.so glibc 兼容 | 共享库可能依赖较新 glibc | 从 glibc 2.28 的发行版提取 |
| x86_64 和 aarch64 .o 不同 | `PT_REGS_*` 宏编译时展开 | 打包时需含目标架构的 .o |
| 无进程隔离 | 同进程 ctypes 调用 | BPF 崩溃影响整个 Python 进程 |

---

## 十、修改文件清单

| 文件 | 操作 | 关键变更 |
|---|---|---|
| `bpf/common.h` | **重写** | BCC `#include <uapi/linux/ptrace.h>` → `<linux/types.h>` + `<linux/bpf.h>` + `<linux/ptrace.h>` + `<bpf/bpf_helpers.h>` + `<bpf/bpf_tracing.h>`；新增 `sys_enter_args` 结构；`STACK_MAX_FRAMES` 宏 |
| `bpf/mem.bpf.c` | **重写** | BCC 宏 → libbpf `SEC(".maps")` + `bpf_map_*` + `bpf_ringbuf_output`；`SEC("uprobe/uretprobe")` |
| `bpf/threads.bpf.c` | **重写** | `TRACEPOINT_PROBE` → `SEC("tracepoint/...")` + `struct sys_enter_args *ctx` |
| `bpf/fd.bpf.c` | **重写** | 同上 + `SEC("kprobe/fd_install")` + 移除 close_range |
| `core/loader.py` | **重写** | BCC API → ctypes 调用 libbpf.so：open_file/load/attach_*/ring_buffer__new/poll；libc 自动检测 + pyelftools 偏移查找 |
| `symbolizer/symbols.py` | **重写** | BCC `bpf.sym()` → pyelftools 读 `/proc/[pid]/maps` + ELF 符号表 + 缓存 |
| `web/backend.py` | **修改** | `Symbolizer(bpf_mem, ...)` → `Symbolizer()` |
| `tools/build_bpf.sh` | **实现** | `clang -target bpf -D__TARGET_ARCH_* -g -O2` 预编译 |
| `packaging/start.sh` | **实现** | 检查 root/BTF/Python3 + LD_LIBRARY_PATH + PYTHONPATH |
| `requirements.txt` | **修改** | 新增 `pyelftools`；移除 BCC 注释 |

### 不修改的文件

| 文件 | 原因 |
|---|---|
| `core/ingest.py` | 事件解码逻辑不变（ctypes 结构 + 回调签名） |
| `core/aggregator.py` | 收到 event dict 格式不变 |
| `core/config.py` | 不涉及 BPF |
| `analyzer/*` | 分析逻辑不变 |
| `storage/*` | 不涉及 BPF |
| `alert_logging/*` | 不涉及 BPF |
| `web/app.py` | 不涉及 BPF（fallback 到 mock 逻辑不变） |
| `web/sockets.py` | 不涉及 BPF |
| `web/api.py` | 不涉及 BPF |
| `web/mock.py` | 不涉及 BPF |
| `web/static/*` | 前端不变 |

---

## 十一、验证记录

### 11.1 x86_64 Ubuntu 24.04 内核 6.8 验证

| 验证项 | 结果 | 关键日志 |
|---|---|---|
| BPF .o 编译 | ✅ | `clang -target bpf -D__TARGET_ARCH_x86` 编译成功 |
| BPF .o 加载 | ✅ | `[loader] mem loaded` / `threads loaded` / `fd loaded` |
| uprobe 挂载 | ✅ | `[loader] uprobe trace_malloc_entry:malloc attached at /lib/.../libc.so.6+0xad670` |
| kprobe 挂载 | ✅ | `[loader] kprobe trace_fd_install:fd_install attached` |
| tracepoint 挂载 | ✅ | `[loader] tracepoint trace_clone:syscalls/sys_enter_clone attached` |
| ring buffer 创建 | ✅ | `[loader] ring buffer opened for mem/threads/fd`（无 E2BIG） |
| 事件到达 | ✅ | `[ingest] mem event #1: pid=... stack_cnt=8` |
| 栈展示 | ✅ | pyelftools 解析出函数名 |

### 11.2 关键验证点

| 验证点 | BCC 版本 | libbpf 版本 | 结果 |
|---|---|---|---|
| BPF 编译 | BCC 运行时编译 | clang -target bpf 预编译 | ✅ 一致 |
| BPF 加载 | `BPF(src_file=)` | `bpf_object__open_file + load` | ✅ 一致 |
| uprobe | `attach_uprobe(name="c")` | `bpf_program__attach_uprobe` + pyelftools 偏移 | ✅ 一致 |
| 事件传输 | perf buffer | ring buffer | ✅ 一致（无 E2BIG） |
| 栈解析 | `bpf.sym()` | pyelftools | ✅ 一致 |
| 4 资源监控 | mem/thread/fd/cpu | 同 | ✅ 一致 |
| 泄露检测 | 双条件 + 状态机 | 同 | ✅ 一致 |

---

## 十二、与原始 M9-M11（Go 方案）对比

### 12.1 技术对照

| 维度 | 原始 M9-M11（Go） | 本方案（Python + libbpf） |
|---|---|---|
| 加载层语言 | Go | Python（ctypes） |
| BPF 加载 | cilium/ebpf | libbpf.so（ctypes 调用） |
| 进程模型 | 独立 Go 进程 | 同进程（Python 内 ctypes） |
| 通信 | unix socket + 二进制协议 | 无（同进程函数调用） |
| 事件传输 | ring buffer | ring buffer（相同） |
| 符号解析 | Go 内 ELF 解析 | pyelftools |
| 打包 | Go 静态二进制 + PyInstaller | libbpf.so + 纯 Python 包 + .o |
| 依赖 | 0（Go 静态二进制） | libbpf.so ~2MB + 系统 Python 3 |
| 进程隔离 | ✅ | ❌ |

### 12.2 取舍分析

**选择 Python + libbpf 的理由**：
1. 监控工具非高可用服务，不需要进程隔离
2. 代码量减少 80%（280 行 vs ~1000 行 + IPC 协议）
3. 工期缩短 85%（3 天 vs 2-3 周）
4. Python 分析层（ingest/aggregator/analyzer）零改动

**保留 Go 方案的条件**：
- 需要 7×24 不间断运行（BPF 崩溃不影响 Web UI）
- 目标环境无 Python 3（罕见）
- 需要零共享库依赖（libbpf.so 也不需要）
- 需要高频率事件处理（Go 比 Python 快）

---

## 十三、附录

### 13.1 BCC 宏 → libbpf 完整对照

| BCC | libbpf | 说明 |
|---|---|---|
| `BPF_PERF_OUTPUT(name)` | `struct { __uint(type, BPF_MAP_TYPE_RINGBUF); __uint(max_entries, N); } name SEC(".maps");` | 事件输出（ring buffer） |
| `BPF_HASH(name, key_t, val_t, max)` | `struct { __uint(type, BPF_MAP_TYPE_HASH); __type(key, key_t); __type(value, val_t); __uint(max_entries, max); } name SEC(".maps");` | hash map |
| `BPF_ARRAY(name, val_t, max)` | `struct { __uint(type, BPF_MAP_TYPE_ARRAY); __type(key, u32); __type(value, val_t); __uint(max_entries, max); } name SEC(".maps");` | array map |
| `BPF_STACK_TRACE(name, max)` | 不需要（用 `bpf_get_stack()` 替代） | 栈追踪（已移除） |
| `name.lookup(&k)` | `bpf_map_lookup_elem(&name, &k)` | 查找 |
| `name.update(&k, &v)` | `bpf_map_update_elem(&name, &k, &v, BPF_ANY)` | 更新 |
| `name.delete(&k)` | `bpf_map_delete_elem(&name, &k)` | 删除 |
| `events.perf_submit(ctx, &e, sz)` | `bpf_ringbuf_output(&events, &e, sz, 0)` | 事件提交 |
| `TRACEPOINT_PROBE(cat, evt)` | `SEC("tracepoint/cat/evt")` | tracepoint |
| `attach_uprobe(name="c", sym="malloc")` | `bpf_program__attach_uprobe(prog, false, -1, libc_path, offset)` | uprobe（BCC 自动找 libc，libbpf 手动） |
| `attach_kprobe(event="fn", fn_name="handler")` | `bpf_program__attach_kprobe(prog, false, "fn")` | kprobe |
| `bpf["events"].open_perf_buffer(cb)` | `ring_buffer__new(map_fd, cb, None, None)` | 事件缓冲 |
| `bpf.perf_buffer_poll()` | `ring_buffer__poll(rb, 50)` | 轮询 |
| `bpf.sym(addr, pid, ...)` | pyelftools 读 ELF 符号表 | 符号解析 |
| `bpf["stack_traces"].walk(id)` | 不需要（地址直接在事件中） | 栈地址获取 |
| — | `char _license[] SEC("license") = "GPL";` | GPL 许可（libbpf 必需） |

### 13.2 ring buffer 回调签名对比

```c
// Perf buffer 回调:
void perf_buffer_event_fn(void *ctx, int cpu, void *data, __u32 data_sz);
//                                           ↑ CPU 编号          ↑ 32位大小

// Ring buffer 回调:
int ring_buffer_sample_fn(void *ctx, void *data, size_t size);
//  ↑ 返回值(0=继续)                     ↑ 无 CPU    ↑ 64位大小
```

### 13.3 参考链接

- libbpf 文档: https://libbpf.readthedocs.io/
- libbpf GitHub: https://github.com/libbpf/libbpf
- BPF CO-RE: https://facebookmicrosites.github.io/bpf/blog/2020/02/19/bpf-portability-and-co-re.html
- ring buffer 介绍: https://facebookmicrosites.github.io/bpf/blog/2020/02/19/bpf-ringbuf.html
- pyelftools: https://github.com/eliben/pyelftools
