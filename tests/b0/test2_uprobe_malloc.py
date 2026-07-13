#!/usr/bin/env python3
"""B0-2: uprobe malloc — 验证 uprobe 挂载 + PT_REGS_PARM1 抓参数 + perf buffer。

对应文档：leakdetect-b0-design.md §六
架构无关：PT_REGS_PARM1 宏自动选 RDI(x86)/X0(ARM)；
         attach_uprobe(name="c") BCC 自动解析 libc 路径。

运行方式：
    sudo python3 tests/b0/test2_uprobe_malloc.py
    # 在另一个终端运行命令触发 malloc：
    ls; cat /dev/null; python3 -c "pass"

预期输出：
    malloc: PID=1234  comm=bash             size=1024
    malloc: PID=5678  comm=python3          size=4096
    ...

验证要点：
    - size 值应合理（非 0、非负）
    - aarch64 上重点确认 size 值正确（验证 PT_REGS_PARM1 宏在 ARM 上取值无误）
"""

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

print("=" * 60)
print("B0-2: uprobe malloc")
print("Tracing malloc... Ctrl+C to stop.")
print("Run commands in another terminal to trigger malloc: ls, cat, etc.")
print("=" * 60)

b = BPF(text=bpf_text)
b.attach_uprobe(name="c", sym="malloc", fn_name="trace_malloc")


def print_event(cpu, data, size):
    event = b["events"].event(data)
    print("malloc: PID=%-6d comm=%-16s size=%d" % (
        event.pid,
        event.comm.decode('utf-8', errors='replace'),
        event.size
    ))


b["events"].open_perf_buffer(print_event)

while True:
    b.perf_buffer_poll()
