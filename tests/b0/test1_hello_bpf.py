#!/usr/bin/env python3
"""B0-1: Hello BPF — 验证 BCC 能加载 BPF 程序并捕获事件。

对应文档：leakdetect-b0-design.md §五
架构无关：TRACEPOINT_PROBE + bpf_trace_printk 均跨架构。

运行方式：
    sudo python3 tests/b0/test1_hello_bpf.py

预期输出：
    持续滚动的 PID 输出（系统每秒有大量 openat 调用）
"""

from bcc import BPF

bpf_text = r"""
TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    bpf_trace_printk("openat called by PID %d\n", pid);
    return 0;
}
"""

print("=" * 50)
print("B0-1: Hello BPF")
print("Tracing openat syscalls... Ctrl+C to stop.")
print("=" * 50)

b = BPF(text=bpf_text)
b.trace_print()
