# B0 里程碑设计文档 — eBPF 技术验证

> 文档版本：v1.0  
> 日期：2026-07-08  
> 状态：⬜ 待实施  
> 关联文档：`D:\leakdetect-plan.md` §7.2 B0

---

## 一、B0 目标

通过 4 个独立测试脚本，验证 eBPF + BCC 在目标环境的核心能力是否可用。**B0 不构建功能代码**，仅做技术验证，确认 B1 可以安全开发。

| # | 测试 | 验证什么 | B1 依赖 |
|---|---|---|---|
| 1 | Hello BPF | BCC 运行时编译 + tracepoint 挂载 + 事件读取 | B1 基础 |
| 2 | uprobe malloc | uprobe 挂载到 libc + PT_REGS_PARM1 抓参数 + perf buffer | B1 malloc 追踪 |
| 3 | cgroup_id | bpf_get_current_cgroup_id() 获取 + Python 读出 | B3 容器过滤 |
| 4 | stack trace | BPF_STACK_TRACE + get_stackid + Python 符号解析 | B1 栈定位 |

---

## 二、前置条件

| 条件 | 状态 | 验证命令 |
|---|---|---|
| 内核 >= 5.10 | ✅ 6.8.0 | `uname -r` |
| BTF 存在 | ✅ | `ls /sys/kernel/btf/vmlinux` |
| BCC 可用 | ✅ | `python3 -c "from bcc import BPF; print('BCC OK')"` |
| root 权限 | 必须 | `sudo -s` |
| 内核 headers | ✅ | `dpkg -l \| grep linux-headers` |

> 所有 B0 脚本必须以 root 运行（eBPF 要求）。

---

## 三、架构兼容性说明（重要）

### 设计原则

B0 全部 4 个测试代码 **架构无关**，在 x86_64 和 aarch64 上无需修改即可运行。

### 唯一的架构差异点：uprobe 参数寄存器

malloc/free 等用户态函数的参数在不同架构下位于不同寄存器：

| 架构 | 第一个参数（malloc 的 size） | 第二个参数 |
|---|---|---|
| x86_64 | RDI | RSI |
| aarch64 | X0 | X1 |

**解决方案**：代码中使用 BCC 提供的 `PT_REGS_PARM1(ctx)` 宏，**编译时自动按目标架构选择正确寄存器**：

```c
// 代码里这样写（一处，跨架构）
int trace_malloc(struct pt_regs *ctx) {
    event.size = PT_REGS_PARM1(ctx);  // BCC 自动展开
    ...
}
```

BCC 编译时展开：
- x86_64：`PT_REGS_PARM1(ctx)` → `ctx->di`（读 RDI）
- aarch64：`PT_REGS_PARM1(ctx)` → `ctx->regs[0]`（读 X0）

**代码完全不用改，BCC 替你选寄存器。**

### libc 路径自动解析

uprobe 挂载时使用 `attach_uprobe(name="c", sym="malloc")`，BCC 内部调用 `find_library("c")` 自动返回当前架构的 libc 路径：

| 架构 | BCC 解析结果 |
|---|---|
| x86_64 (Ubuntu) | `/lib/x86_64-linux-gnu/libc.so.6` |
| aarch64 (EulerOS) | `/lib64/libc.so.6` |

**代码中不硬编码 libc 路径，由 BCC 自动解析。**

### 逐测试兼容性确认

| 测试 | 涉及架构的地方 | 兼容方式 |
|---|---|---|
| Test 1 Hello BPF | 无架构相关代码 | tracepoint 名 + bpf helpers 全部跨架构 |
| Test 2 uprobe malloc | `PT_REGS_PARM1(ctx)` | 宏自动选择寄存器（RDI/X0） |
| Test 2 libc 路径 | `attach_uprobe(name="c")` | BCC `find_library("c")` 自动解析 |
| Test 3 cgroup_id | 无架构相关代码 | `bpf_get_current_cgroup_id()` 跨架构 |
| Test 4 stack trace | `BPF_F_USER_STACK` + `b.sym()` | 栈回溯和符号解析均为架构无关的 BPF helper |

### 验证策略

```
x86_64 开发服务器（Ubuntu 24.04）     aarch64 生产环境（EulerOS v2r15）
┌──────────────────────────┐         ┌──────────────────────────┐
│ B0 Test 1-4 全部通过     │         │ B0 Test 1-4 预期同样通过  │
│ 验证 eBPF 核心能力       │ ──代码不改──> │ 验证架构兼容性           │
└──────────────────────────┘         └──────────────────────────┘
```

- **x86_64 上先验证**：确认 eBPF + BCC 基础链路通
- **aarch64 上再验证**：确认 `PT_REGS_PARM1` 宏在 ARM 上取值正确（malloc size 值合理）
- 两次验证代码完全相同，无需任何修改

---

## 四、文件结构

```
leakdetect/
├── tests/
│   └── b0/
│       ├── test1_hello_bpf.py      # tracepoint + trace_printk
│       ├── test2_uprobe_malloc.py  # uprobe malloc + perf buffer
│       ├── test3_cgroup_id.py      # cgroup_id 获取
│       ├── test4_stack_trace.py    # 栈回溯 + 符号解析
│       └── README.md               # 运行说明
```

每个脚本是独立的 Python 文件，可单独运行：
```bash
sudo python3 tests/b0/test1_hello_bpf.py
```

---

## 五、Test 1：Hello BPF

**验证**：BCC 运行时编译 BPF C 代码 → 挂载 tracepoint → 读取事件。

**BPF 程序**：挂载 `syscalls:sys_enter_openat` tracepoint，每次有进程调用 `openat()` 时打印 PID。

```python
#!/usr/bin/env python3
"""B0-1: Hello BPF — 验证 BCC 能加载 BPF 程序并捕获事件。"""

from bcc import BPF

bpf_text = r"""
TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    bpf_trace_printk("openat called by PID %d\n", pid);
    return 0;
}
"""

b = BPF(text=bpf_text)
print("Tracing openat syscalls... Ctrl+C to stop.")
print("-" * 50)
b.trace_print()
```

**技术要点**：

| 点 | 说明 | 架构无关 |
|---|---|---|
| `TRACEPOINT_PROBE` | BCC 宏，自动挂载到 tracepoint，无需手动 attach | ✅ |
| `bpf_get_current_pid_tgid() >> 32` | 获取进程 PID（高 32 位是 tgid） | ✅ |
| `bpf_trace_printk()` | BPF 内核打印，写入 `/sys/kernel/debug/tracing/trace_pipe` | ✅ |
| `b.trace_print()` | Python 端读取 trace pipe，逐行打印 | ✅ |

**预期输出**：
```
Tracing openat syscalls... Ctrl+C to stop.
--------------------------------------------------
         <...>-1234  [000] 12345.678: openat called by PID 1234
         bash-5678  [001] 12345.679: openat called by PID 5678
         ...
```

**验证标准**：能看到持续滚动的 PID 输出（系统每秒有大量 openat 调用）。

---

## 六、Test 2：uprobe malloc

**验证**：uprobe 挂载到 libc malloc → PT_REGS_PARM1 抓 size 参数 → perf buffer 传事件到 Python。

```python
#!/usr/bin/env python3
"""B0-2: uprobe malloc — 验证 uprobe 挂载 + 参数抓取 + perf buffer。"""

from bcc import BPF

bpf_text = r"""
#include <uapi/linux/ptrace.h>

struct event_t {
    u32 pid;
    u64 size;
    char comm[16];
};

BPF_PERF_OUTPUT(events);

int trace_malloc(struct pt_regs *ctx) {
    struct event_t event = {};
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.size = PT_REGS_PARM1(ctx);
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}
"""

b = BPF(text=bpf_text)
b.attach_uprobe(name="c", sym="malloc", fn_name="trace_malloc")

def print_event(cpu, data, size):
    event = b["events"].event(data)
    print("malloc: PID=%-6d comm=%-16s size=%d" % (
        event.pid,
        event.comm.decode('utf-8', errors='replace'),
        event.size
    ))

print("Tracing malloc... Ctrl+C to stop.")
print("-" * 60)
b["events"].open_perf_buffer(print_event)

while True:
    b.perf_buffer_poll()
```

**技术要点**：

| 点 | 说明 | 架构无关 |
|---|---|---|
| `attach_uprobe(name="c", sym="malloc")` | BCC 自动定位 libc（x86_64: `/lib/x86_64-linux-gnu/libc.so.6`；aarch64: `/lib64/libc.so.6`） | ✅ BCC 自动解析 |
| `PT_REGS_PARM1(ctx)` | 跨架构宏取第一个参数（x86_64→RDI，aarch64→X0）。malloc 的第一个参数是 size | ✅ 宏自动适配 |
| `BPF_PERF_OUTPUT(events)` | 声明 perf buffer map | ✅ |
| `events.perf_submit(ctx, &event, sizeof(event))` | BPF 端提交事件到 perf buffer | ✅ |
| `open_perf_buffer(callback)` | Python 端注册回调 | ✅ |
| `perf_buffer_poll()` | 轮询 perf buffer，有事件时调回调 | ✅ |

**预期输出**：
```
Tracing malloc... Ctrl+C to stop.
------------------------------------------------------------
malloc: PID=1234  comm=bash             size=1024
malloc: PID=5678  comm=python3          size=4096
malloc: PID=1234  comm=bash             size=256
...
```

**验证标准**：
1. 能看到 malloc 事件持续输出
2. size 值合理（非 0、非负）—— **aarch64 验证时重点确认 size 值正确**（验证 PT_REGS_PARM1 在 ARM 上取值无误）
3. 不同进程的 PID/comm 正确

> **触发 malloc**：在另一个终端运行 `ls`、`cat`、`python3 -c "import time; time.sleep(1)"` 等命令会产生大量 malloc 调用。

> **架构验证要点**：在 x86_64 上 size 应为合理值（如 1024、4096）。迁移到 aarch64 后，如果 size 值仍然合理，说明 `PT_REGS_PARM1` 宏在 ARM 上工作正常。如果 size 值异常（0 或超大），说明寄存器映射有问题，需要排查 BCC 版本和内核配置。

---

## 七、Test 3：cgroup_id

**验证**：BPF 程序内调用 `bpf_get_current_cgroup_id()` 获取当前进程的 cgroup ID。

```python
#!/usr/bin/env python3
"""B0-3: cgroup_id — 验证 BPF 能获取进程的 cgroup_id。"""

from bcc import BPF

bpf_text = r"""
TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 cgid = bpf_get_current_cgroup_id();
    bpf_trace_printk("openat PID=%d cgid=%llu\n", pid, cgid);
    return 0;
}
"""

b = BPF(text=bpf_text)
print("Tracing cgroup_id... Ctrl+C to stop.")
print("-" * 60)
b.trace_print()
```

**技术要点**：

| 点 | 说明 | 架构无关 |
|---|---|---|
| `bpf_get_current_cgroup_id()` | 内核 4.18+ 提供，返回当前进程的 cgroup v1/v2 ID | ✅ |
| 同一进程的 cgid 应一致 | 不同进程的 cgid 可能不同（不同 cgroup） | ✅ |
| cgid 是内核分配的 64 位整数 | 与 `/proc/[pid]/cgroup` 的路径对应 | ✅ |

**预期输出**：
```
Tracing cgroup_id... Ctrl+C to stop.
------------------------------------------------------------
         bash-1234  [000] ...: openat PID=1234 cgid=1234567890
         python-5678 [001] ...: openat PID=5678 cgid=1234567890
```

**验证标准**：
1. cgid 值非 0
2. 同一进程多次调用的 cgid 一致
3. 不同进程的 cgid 可能相同（同一 cgroup）或不同（不同 cgroup）

**补充验证**：在另一个终端运行 Docker 容器，观察容器内进程的 cgid 是否与宿主机进程不同：
```bash
docker run --rm -it ubuntu bash -c "ls /"
# 容器内进程的 cgid 应不同于宿主机 bash 的 cgid
```

---

## 八、Test 4：stack trace

**验证**：BPF 捕获用户态调用栈 → Python 解析符号。

```python
#!/usr/bin/env python3
"""B0-4: Stack trace — 验证 bpf_get_stackid + Python 符号解析。"""

from bcc import BPF

bpf_text = r"""
#include <uapi/linux/ptrace.h>

struct event_t {
    u32 pid;
    int stack_id;
    char comm[16];
};

BPF_STACK_TRACE(stack_traces);
BPF_PERF_OUTPUT(events);

int trace_malloc(struct pt_regs *ctx) {
    struct event_t event = {};
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}
"""

b = BPF(text=bpf_text)
b.attach_uprobe(name="c", sym="malloc", fn_name="trace_malloc")

def print_event(cpu, data, size):
    event = b["events"].event(data)
    print("\nmalloc: PID=%d comm=%s" % (
        event.pid,
        event.comm.decode('utf-8', errors='replace')
    ))
    if event.stack_id >= 0:
        for addr in b["stack_traces"].walk(event.stack_id):
            try:
                sym = b.sym(addr, event.pid, show_module=True, show_offset=True)
                print("    %s" % sym.decode('utf-8', errors='replace'))
            except Exception:
                print("    0x%x" % addr)
    else:
        print("    (no stack available)")

print("Tracing malloc with stack... Ctrl+C to stop.")
print("-" * 60)
b["events"].open_perf_buffer(print_event)

while True:
    b.perf_buffer_poll()
```

**技术要点**：

| 点 | 说明 | 架构无关 |
|---|---|---|
| `BPF_STACK_TRACE(stack_traces)` | 声明栈追踪 map（存储帧地址） | ✅ |
| `get_stackid(ctx, BPF_F_USER_STACK)` | 捕获用户态调用栈，返回 stack_id（-1 表示失败） | ✅ |
| `BPF_F_USER_STACK` | 标志：抓用户空间栈（非内核栈） | ✅ |
| `b["stack_traces"].walk(stack_id)` | Python 端遍历栈帧地址 | ✅ |
| `b.sym(addr, pid, show_module=True, show_offset=True)` | 解析用户态地址为 `函数名+偏移 (模块)` | ✅ 读 ELF 符号表，架构无关 |

**预期输出**：
```
Tracing malloc with stack... Ctrl+C to stop.
------------------------------------------------------------

malloc: PID=1234 comm=bash
    __libc_malloc+0x0 (libc-2.31.so)
    xmalloc+0x20 (bash)
    execute_command+0x80 (bash)
    main+0x100 (bash)
```

**验证标准**：
1. stack_id >= 0（栈捕获成功）
2. 能解析出函数名（如 `__libc_malloc`）
3. 栈帧有层级关系（malloc → 调用者 → 更上层）
4. 如果进程的二进制是 stripped 的，可能只显示地址——这是正常的，B1 阶段会加 debuginfo 支持

> **架构说明**：栈回溯机制（stack unwinding）在不同架构下实现不同（x86_64 用 frame pointer 或 DWARF，aarch64 也有自己的方式），但 BPF 的 `get_stackid` 和 `BPF_F_USER_STACK` 对上层透明，代码无需区分架构。如果 aarch64 上 stack_id 返回 -1，可能是内核的 unwinder 配置问题（需要 `CONFIG_UNWINDER_FRAME_POINTER=y`），可退化为地址展示。

---

## 九、验证汇总

| # | 测试 | 通过标准 | B1 影响 | 架构无关 |
|---|---|---|---|---|
| 1 | Hello BPF | trace_print 持续输出 PID | B1 可用 BCC 加载 BPF | ✅ |
| 2 | uprobe malloc | malloc 事件 + size 值合理 | B1 可追踪 malloc 分配 | ✅ PT_REGS_PARM1 |
| 3 | cgroup_id | cgid 非 0 且进程间有差异 | B3 可按容器过滤 | ✅ |
| 4 | stack trace | 栈帧解析出函数名 | B1 可定位泄露调用栈 | ✅ |

**4 项全部通过 = eBPF 技术验证完成，B1 可安全开发。**

**架构验证要点**：在 aarch64 上运行 Test 2 时，重点确认 `PT_REGS_PARM1` 取到的 malloc size 值合理。这是唯一与架构相关的验证点，通过后说明跨架构代码可行。

---

## 十、已知风险与规避

| 风险 | 概率 | 规避 |
|---|---|---|
| `TRACEPOINT_PROBE` 找不到 tracepoint | 低 | `syscalls:sys_enter_openat` 在 5.x+ 内核稳定存在 |
| `attach_uprobe(name="c")` 找不到 libc | 低 | BCC 内部调 `find_library("c")`，Ubuntu/EulerOS 均支持 |
| `PT_REGS_PARM1` 取值不对（aarch64） | 中 | 先在 x86_64 验证逻辑正确；aarch64 上重点确认 size 值；若异常检查 BCC 版本 |
| stack_id 返回 -1 | 中 | 可能是内核配置 `CONFIG_UNWINDER_FRAME_POINTER` 未开，退化为地址展示 |
| 符号解析失败（stripped binary） | 高 | 正常现象，B1 阶段加 debuginfo 支持 |
| trace_print 无输出 | 低 | 确认 debugfs 已挂载：`mount \| grep debugfs` |

---

## 十一、实施步骤

| 步骤 | 操作 | 耗时 |
|---|---|---|
| 1 | 创建 `tests/b0/` 目录 | 1 分钟 |
| 2 | 编写 test1_hello_bpf.py | 5 分钟 |
| 3 | 运行 test1，验证输出 | 5 分钟 |
| 4 | 编写 test2_uprobe_malloc.py | 10 分钟 |
| 5 | 运行 test2，验证 malloc 事件 + size 值 | 5 分钟 |
| 6 | 编写 test3_cgroup_id.py | 5 分钟 |
| 7 | 运行 test3，验证 cgid | 5 分钟 |
| 8 | 编写 test4_stack_trace.py | 10 分钟 |
| 9 | 运行 test4，验证栈解析 | 10 分钟 |
| 10 | 编写 README.md | 5 分钟 |

**预计总耗时：1-2 小时**

---

## 十二、B0 完成后的下一步

B0 全部通过后，进入 **B1（内存抓取 + 分析）**：

| B1 内容 | 依赖 B0 的哪项 |
|---|---|
| mem.bpf.c（malloc/free uprobe） | Test 2 uprobe + Test 4 stack |
| BCC 加载 + ring buffer 读取 | Test 1 BCC 加载 + Test 2 perf buffer |
| 符号解析 | Test 4 b.sym |
| 内存泄露趋势检测 | Test 2 size 参数采集 |
| 替换 mock.py 为真实数据 | Test 1-4 全部通过 |

B0 是 B1 的技术基础，确保 eBPF 核心能力可用后再投入 B1 开发。B0 代码架构无关，x86_64 验证通过后 aarch64 上无需改代码即可运行。
