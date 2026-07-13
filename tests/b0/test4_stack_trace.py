#!/usr/bin/env python3
"""B0-4: Stack trace — 验证 bpf_get_stackid + Python 符号解析。

对应文档：leakdetect-b0-design.md §八
架构无关：get_stackid + BPF_F_USER_STACK + b.sym() 均跨架构。

运行方式：
    sudo python3 tests/b0/test4_stack_trace.py
    # 在另一个终端运行命令触发 malloc：
    ls; cat /dev/null; python3 -c "pass"

预期输出：
    malloc: PID=1234 comm=bash
        __libc_malloc+0x0 (libc-2.31.so)
        xmalloc+0x20 (bash)
        execute_command+0x80 (bash)
        main+0x100 (bash)

验证要点：
    - stack_id >= 0（栈捕获成功）
    - 能解析出函数名（如 __libc_malloc）
    - 栈帧有层级关系（malloc → 调用者 → 更上层）
    - stripped 二进制可能只显示地址——正常，B1 阶段加 debuginfo

架构说明：
    栈回溯机制在不同架构下实现不同，但 BPF 的 get_stackid 对上层透明。
    如果 aarch64 上 stack_id 返回 -1，可能是内核 CONFIG_UNWINDER_FRAME_POINTER 未开。
"""

from bcc import BPF

bpf_text = r"""
#include <uapi/linux/ptrace.h>

struct event_t {
    u32 pid;
    int stack_id;
    char comm[16];
};

BPF_STACK_TRACE(stack_traces, 16384);
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

print("=" * 60)
print("B0-4: Stack trace")
print("Tracing malloc with stack... Ctrl+C to stop.")
print("Run commands in another terminal: ls, cat, etc.")
print("=" * 60)

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
                sym = b.sym(addr, event.pid,
                            show_module=True, show_offset=True)
                print("    %s" % sym.decode('utf-8', errors='replace'))
            except Exception:
                print("    0x%x" % addr)
    else:
        print("    (no stack available, stack_id=%d)" % event.stack_id)


b["events"].open_perf_buffer(print_event)

while True:
    b.perf_buffer_poll()
