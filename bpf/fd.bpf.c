/* fd.bpf.c - 句柄泄露检测 BPF 程序（libbpf 风格）
 *
 * Hook: kprobe fd_install（所有 fd 创建的内核汇聚点）
 *       tracepoint sys_enter_close/dup2/dup3（close 侧）
 * 采样: 全量
 * 追踪方式: fd_map 引用计数（refcount→0 即驱逐，原子操作，无 TOCTOU 竞态）
 * 栈捕获: bpf_get_stack() 直接拷贝地址到事件
 *
 * 已知限制：
 *   - dup2/dup3 的 open 侧不经过 fd_install，不被追踪
 *   - close_range 已移除（内核 5.10 无此 tracepoint）
 */

#include "common.h"

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1024 * 1024);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct fd_key_t);
    __type(value, struct fd_value_t);
    __uint(max_entries, 100000);
} fd_map SEC(".maps");

/* fd_install kprobe: 所有 fd 创建的内核汇聚点
 * 函数签名: fd_install(unsigned int fd, struct file *file)
 * PT_REGS_PARM1(ctx) = fd */
SEC("kprobe/fd_install")
int trace_fd_install(struct pt_regs *ctx) {
    unsigned int fd = PT_REGS_PARM1(ctx);
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    struct fd_event_t event = {};
    event.pid = pid;
    event.fd = (int)fd;
    event.fd_type = 0;
    int ret = bpf_get_stack(ctx, event.stack_addrs,
                            sizeof(event.stack_addrs), BPF_F_USER_STACK);
    event.stack_cnt = (ret >= 0) ? ret / (int)sizeof(u64) : 0;
    if (event.stack_cnt > STACK_MAX_FRAMES) event.stack_cnt = STACK_MAX_FRAMES;
    event.op = 'o';

    /* 查找或创建 fd_map 条目（refcount 方式） */
    struct fd_key_t key = {.pid = pid, .fd = (int)fd};
    struct fd_value_t *val = bpf_map_lookup_elem(&fd_map, &key);
    if (!val) {
        struct fd_value_t zero = {};
        bpf_map_update_elem(&fd_map, &key, &zero, BPF_ANY);
        val = bpf_map_lookup_elem(&fd_map, &key);
    }
    if (val) {
        __sync_fetch_and_add(&val->refcount, 1);
        val->stack_cnt = event.stack_cnt;
        int i;
        for (i = 0; i < STACK_MAX_FRAMES; i++) {
            val->stack_addrs[i] = event.stack_addrs[i];
        }
    }

    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_ringbuf_output(&events, &event, sizeof(event), 0);
    return 0;
}

/* close: 仅在匹配时发包 */
SEC("tracepoint/syscalls/sys_enter_close")
int trace_close(struct sys_enter_args *ctx) {
    int fd = (int)ctx->args[0];
    if (fd < 0) return 0;

    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct fd_key_t key = {.pid = pid, .fd = fd};
    struct fd_value_t *val = bpf_map_lookup_elem(&fd_map, &key);

    if (val) {
        int stack_cnt = val->stack_cnt;
        u64 stack_addrs[STACK_MAX_FRAMES];
        int i;
        for (i = 0; i < STACK_MAX_FRAMES; i++) {
            stack_addrs[i] = val->stack_addrs[i];
        }

        u64 old = __sync_fetch_and_sub(&val->refcount, 1);
        if (old > 0) {
            /* 驱逐：refcount→0 删条目，防 fd_map 饱和导致稳态进程伪增长。
             * 重读 refcount==0 守卫：并发 fd_install 复用同 fd 已 +1 则不删。 */
            if (old == 1 && val->refcount == 0) {
                bpf_map_delete_elem(&fd_map, &key);
            }
            struct fd_event_t event = {};
            event.pid = pid;
            event.fd = fd;
            event.op = 'c';
            event.stack_cnt = stack_cnt;
            int j;
            for (j = 0; j < STACK_MAX_FRAMES; j++) {
                event.stack_addrs[j] = stack_addrs[j];
            }
            bpf_get_current_comm(&event.comm, sizeof(event.comm));
            bpf_ringbuf_output(&events, &event, sizeof(event), 0);
        } else {
            __sync_fetch_and_add(&val->refcount, 1);
        }
    }
    return 0;
}

/* dup2: 静默关闭 newfd（如果已追踪） */
SEC("tracepoint/syscalls/sys_enter_dup2")
int trace_dup2(struct sys_enter_args *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    int newfd = (int)ctx->args[1];
    struct fd_key_t key = {.pid = pid, .fd = newfd};
    struct fd_value_t *val = bpf_map_lookup_elem(&fd_map, &key);
    if (val) {
        int stack_cnt = val->stack_cnt;
        u64 stack_addrs[STACK_MAX_FRAMES];
        int i;
        for (i = 0; i < STACK_MAX_FRAMES; i++) {
            stack_addrs[i] = val->stack_addrs[i];
        }

        u64 old = __sync_fetch_and_sub(&val->refcount, 1);
        if (old > 0) {
            if (old == 1 && val->refcount == 0) {
                bpf_map_delete_elem(&fd_map, &key);
            }
            struct fd_event_t event = {};
            event.pid = pid;
            event.fd = newfd;
            event.op = 'c';
            event.stack_cnt = stack_cnt;
            int j;
            for (j = 0; j < STACK_MAX_FRAMES; j++) {
                event.stack_addrs[j] = stack_addrs[j];
            }
            bpf_get_current_comm(&event.comm, sizeof(event.comm));
            bpf_ringbuf_output(&events, &event, sizeof(event), 0);
        } else {
            __sync_fetch_and_add(&val->refcount, 1);
        }
    }
    return 0;
}

/* dup3: 同 dup2 */
SEC("tracepoint/syscalls/sys_enter_dup3")
int trace_dup3(struct sys_enter_args *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    int newfd = (int)ctx->args[1];
    struct fd_key_t key = {.pid = pid, .fd = newfd};
    struct fd_value_t *val = bpf_map_lookup_elem(&fd_map, &key);
    if (val) {
        int stack_cnt = val->stack_cnt;
        u64 stack_addrs[STACK_MAX_FRAMES];
        int i;
        for (i = 0; i < STACK_MAX_FRAMES; i++) {
            stack_addrs[i] = val->stack_addrs[i];
        }

        u64 old = __sync_fetch_and_sub(&val->refcount, 1);
        if (old > 0) {
            if (old == 1 && val->refcount == 0) {
                bpf_map_delete_elem(&fd_map, &key);
            }
            struct fd_event_t event = {};
            event.pid = pid;
            event.fd = newfd;
            event.op = 'c';
            event.stack_cnt = stack_cnt;
            int j;
            for (j = 0; j < STACK_MAX_FRAMES; j++) {
                event.stack_addrs[j] = stack_addrs[j];
            }
            bpf_get_current_comm(&event.comm, sizeof(event.comm));
            bpf_ringbuf_output(&events, &event, sizeof(event), 0);
        } else {
            __sync_fetch_and_add(&val->refcount, 1);
        }
    }
    return 0;
}

char _license[] SEC("license") = "GPL";
