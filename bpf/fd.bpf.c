/* fd.bpf.c - 句柄泄露检测 BPF 程序（libbpf 风格，map 聚合版）
 *
 * B 方案：删 events ring，改用 fd_count_map（per-pid 聚合，Python 定期读）。
 * Hook: kprobe fd_install + tracepoint close/dup2/dup3
 * 追踪: fd_map[{pid,fd}] = {refcount, stack}（配对+栈，驱逐）
 * 聚合: fd_count_map[{pid}] = {open_count, close_count, comm, stack}（atomic add only，无 sub → 无 u64 回绕窗口）
 */

#include "common.h"

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct fd_key_t);
    __type(value, struct fd_value_t);
    __uint(max_entries, 1000000);
} fd_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct fd_count_key_t);
    __type(value, struct fd_count_val_t);
    __uint(max_entries, 1000000);
} fd_count_map SEC(".maps");

static __always_inline void decrement_fd_count(u32 pid)
{
    struct fd_count_key_t ckey = {};
    ckey.pid = (u64)pid;
    struct fd_count_val_t *cval = bpf_map_lookup_elem(&fd_count_map, &ckey);
    if (cval) {
        __sync_fetch_and_add(&cval->close_count, 1);
    }
}

SEC("kprobe/fd_install")
int trace_fd_install(struct pt_regs *ctx) {
    unsigned int fd = PT_REGS_PARM1(ctx);
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    u64 stack_addrs[STACK_MAX_FRAMES];
    int ret = bpf_get_stack(ctx, stack_addrs, sizeof(stack_addrs), BPF_F_USER_STACK);
    int stack_cnt = (ret >= 0) ? ret / (int)sizeof(u64) : 0;
    if (stack_cnt > STACK_MAX_FRAMES) stack_cnt = STACK_MAX_FRAMES;

    struct fd_key_t key = {.pid = pid, .fd = (int)fd};
    struct fd_value_t *val = bpf_map_lookup_elem(&fd_map, &key);
    if (!val) {
        struct fd_value_t zero = {};
        bpf_map_update_elem(&fd_map, &key, &zero, BPF_ANY);
        val = bpf_map_lookup_elem(&fd_map, &key);
    }
    if (val) {
        __sync_fetch_and_add(&val->refcount, 1);
        val->stack_cnt = stack_cnt;
        int i;
        for (i = 0; i < STACK_MAX_FRAMES; i++) {
            val->stack_addrs[i] = stack_addrs[i];
        }
    }

    struct fd_count_key_t ckey = {};
    ckey.pid = (u64)pid;
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
        for (j = 0; j < STACK_MAX_FRAMES; j++) {
            cval->stack_addrs[j] = stack_addrs[j];
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_close")
int trace_close(struct sys_enter_args *ctx) {
    int fd = (int)ctx->args[0];
    if (fd < 0) return 0;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct fd_key_t key = {.pid = pid, .fd = fd};
    struct fd_value_t *val = bpf_map_lookup_elem(&fd_map, &key);
    if (val) {
        decrement_fd_count(pid);
        u64 old = __sync_fetch_and_sub(&val->refcount, 1);
        if (old > 0) {
            if (old == 1 && val->refcount == 0) {
                bpf_map_delete_elem(&fd_map, &key);
            }
        } else {
            __sync_fetch_and_add(&val->refcount, 1);
        }
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_dup2")
int trace_dup2(struct sys_enter_args *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    int newfd = (int)ctx->args[1];
    struct fd_key_t key = {.pid = pid, .fd = newfd};
    struct fd_value_t *val = bpf_map_lookup_elem(&fd_map, &key);
    if (val) {
        decrement_fd_count(pid);
        u64 old = __sync_fetch_and_sub(&val->refcount, 1);
        if (old > 0) {
            if (old == 1 && val->refcount == 0) {
                bpf_map_delete_elem(&fd_map, &key);
            }
        } else {
            __sync_fetch_and_add(&val->refcount, 1);
        }
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_dup3")
int trace_dup3(struct sys_enter_args *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    int newfd = (int)ctx->args[1];
    struct fd_key_t key = {.pid = pid, .fd = newfd};
    struct fd_value_t *val = bpf_map_lookup_elem(&fd_map, &key);
    if (val) {
        decrement_fd_count(pid);
        u64 old = __sync_fetch_and_sub(&val->refcount, 1);
        if (old > 0) {
            if (old == 1 && val->refcount == 0) {
                bpf_map_delete_elem(&fd_map, &key);
            }
        } else {
            __sync_fetch_and_add(&val->refcount, 1);
        }
    }
    return 0;
}

char _license[] SEC("license") = "GPL";
