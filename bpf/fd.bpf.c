/* fd.bpf.c - 句柄泄露检测 BPF 程序（file_close_fd + filp_close 方案）
 *
 * 方案：kprobe fd_install + kprobe file_close_fd + kprobe filp_close
 * 原理：fd_install（fs/file_table.c）→ open_count++（所有 fd 创建）
 *       file_close_fd（fs/file.c）→ close_count++（sys_close 路径，ftrace 确认 sys_close 调此函数）
 *       filp_close（fs/open.c）→ close_count++（close_range/exec/dup2 路径，从 fs/file.c 调用，跨编译单元不内联）
 *       进程退出 → 死 pid 清理器删条目
 *       epoll 清理 → 调 fput 不调 file_close_fd/filp_close → 不影响计数
 *       filp_close 在 fs/open.c 内被 sys_close 内联 → 不触发（file_close_fd 负责该路径）
 *       file_close_fd 不调 filp_close → 无 double-count（ftrace 确认）
 *
 * 聚合: fd_count_map[{pid}] = {open_count, close_count, comm, stack}（atomic add only）
 * outstanding = open_count - close_count ≈ /proc/pid/fd
 */

#include "common.h"

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct fd_count_key_t);
    __type(value, struct fd_count_val_t);
    __uint(max_entries, 1000000);
} fd_count_map SEC(".maps");

SEC("kprobe/fd_install")
int trace_fd_install(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    u64 stack_addrs[STACK_MAX_FRAMES];
    int ret = bpf_get_stack(ctx, stack_addrs, sizeof(stack_addrs), BPF_F_USER_STACK);
    int stack_cnt = (ret >= 0) ? ret / (int)sizeof(u64) : 0;
    if (stack_cnt > STACK_MAX_FRAMES) stack_cnt = STACK_MAX_FRAMES;

    struct fd_count_key_t ckey = {.pid = (u64)pid};
    struct fd_count_val_t *cval = bpf_map_lookup_elem(&fd_count_map, &ckey);
    if (!cval) {
        struct fd_count_val_t zero = {};
        bpf_map_update_elem(&fd_count_map, &ckey, &zero, BPF_ANY);
        cval = bpf_map_lookup_elem(&fd_count_map, &ckey);
    }
    if (cval) {
        __sync_fetch_and_add(&cval->open_count, 1);
        bpf_get_current_comm(cval->comm, sizeof(cval->comm));
        cval->stack_cnt = stack_cnt;
        int j;
        for (j = 0; j < STACK_MAX_FRAMES; j++)
            cval->stack_addrs[j] = stack_addrs[j];
    }
    return 0;
}

SEC("kprobe/file_close_fd")
int trace_file_close_fd(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct fd_count_key_t ckey = {.pid = (u64)pid};
    struct fd_count_val_t *cval = bpf_map_lookup_elem(&fd_count_map, &ckey);
    if (cval) {
        __sync_fetch_and_add(&cval->close_count, 1);
    }
    return 0;
}

SEC("kprobe/filp_close")
int trace_filp_close(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct fd_count_key_t ckey = {.pid = (u64)pid};
    struct fd_count_val_t *cval = bpf_map_lookup_elem(&fd_count_map, &ckey);
    if (cval) {
        __sync_fetch_and_add(&cval->close_count, 1);
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_close")
int trace_close_syscall(struct sys_enter_args *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct fd_count_key_t ckey = {.pid = (u64)pid};
    struct fd_count_val_t *cval = bpf_map_lookup_elem(&fd_count_map, &ckey);
    if (cval) {
        __sync_fetch_and_add(&cval->close_count, 1);
    }
    return 0;
}

char _license[] SEC("license") = "GPL";
