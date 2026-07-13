#!/usr/bin/env python3
"""B0-3: cgroup_id — 验证 BPF 能获取进程的 cgroup_id。

对应文档：leakdetect-b0-design.md §七
架构无关：bpf_get_current_cgroup_id() 跨架构。

运行方式：
    sudo python3 tests/b0/test3_cgroup_id.py

预期输出：
    openat PID=1234 cgid=1234567890
    openat PID=5678 cgid=1234567890
    ...

验证要点：
    - cgid 值非 0
    - 同一进程多次调用的 cgid 一致
    - 不同进程的 cgid 可能相同（同一 cgroup）或不同（不同 cgroup）

补充验证（如有 Docker）：
    docker run --rm -it ubuntu bash -c "ls /"
    # 容器内进程的 cgid 应不同于宿主机进程的 cgid
"""

from bcc import BPF

bpf_text = r"""
TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 cgid = bpf_get_current_cgroup_id();
    bpf_trace_printk("openat PID=%d cgid=%llu\n", pid, cgid);
    return 0;
}
"""

print("=" * 60)
print("B0-3: cgroup_id")
print("Tracing cgroup_id... Ctrl+C to stop.")
print("=" * 60)

b = BPF(text=bpf_text)
b.trace_print()
