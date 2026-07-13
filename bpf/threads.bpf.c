/* threads.bpf.c - 线程泄露检测 BPF 程序（libbpf 风格）
 *
 * Hook: tracepoint clone/clone3/sched_process_exit
 * 采样: 全量
 * 栈捕获: bpf_get_stack() 直接拷贝地址到事件
 * CLONE_THREAD 过滤：只追踪线程创建（pthread_create），跳过 fork/vfork
 */

#include "common.h"

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1024 * 1024);
} events SEC(".maps");

/* clone: 线程创建（只追踪 CLONE_THREAD=线程，跳过 fork/vfork=进程） */
SEC("tracepoint/syscalls/sys_enter_clone")
int trace_clone(struct sys_enter_args *ctx) {
    u64 clone_flags = ctx->args[0];
    if (!(clone_flags & 0x10000)) return 0;

    struct thread_event_t event = {};
    event.pid = bpf_get_current_pid_tgid() >> 32;
    int ret = bpf_get_stack(ctx, event.stack_addrs,
                             sizeof(event.stack_addrs), BPF_F_USER_STACK);
    event.stack_cnt = (ret >= 0) ? ret / (int)sizeof(u64) : 0;
    if (event.stack_cnt > STACK_MAX_FRAMES) event.stack_cnt = STACK_MAX_FRAMES;
    event.op = 'c';
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_ringbuf_output(&events, &event, sizeof(event), 0);
    return 0;
}

/* clone3: 线程创建（从用户空间 struct clone_args 读 flags） */
SEC("tracepoint/syscalls/sys_enter_clone3")
int trace_clone3(struct sys_enter_args *ctx) {
    u64 uargs_ptr = ctx->args[0];
    u64 flags;
    bpf_probe_read(&flags, sizeof(flags), (void *)uargs_ptr);
    if (!(flags & 0x10000)) return 0;

    struct thread_event_t event = {};
    event.pid = bpf_get_current_pid_tgid() >> 32;
    int ret = bpf_get_stack(ctx, event.stack_addrs,
                             sizeof(event.stack_addrs), BPF_F_USER_STACK);
    event.stack_cnt = (ret >= 0) ? ret / (int)sizeof(u64) : 0;
    if (event.stack_cnt > STACK_MAX_FRAMES) event.stack_cnt = STACK_MAX_FRAMES;
    event.op = 'c';
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_ringbuf_output(&events, &event, sizeof(event), 0);
    return 0;
}

/* 线程退出（只计线程退出 tid!=pid，不计进程退出；无栈） */
SEC("tracepoint/sched/sched_process_exit")
int trace_sched_exit(void *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;

    if (tid == pid) return 0;

    struct thread_event_t event = {};
    event.pid = pid;
    event.tid = tid;
    event.stack_cnt = 0;
    event.op = 'e';
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_ringbuf_output(&events, &event, sizeof(event), 0);
    return 0;
}

char _license[] SEC("license") = "GPL";
