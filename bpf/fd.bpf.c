/* fd.bpf.c - 句柄泄露检测 BPF 程序（libbpf 风格，file 指针追踪版）
 *
 * 方案：kprobe fd_install + kprobe fput（替代旧的 close/dup2/dup3 tracepoint）
 * 原因：sys_enter_close 漏掉 close_range/exec CLOEXEC/进程退出 等内核内部关闭
 *       fput 是所有 fd 关闭的最终路径，捕获全部
 *
 * 追踪: fd_file_map[{file指针}] = {opener_pid, fd, stack}（全局 key，跨进程 fork 继承）
 * 聚合: fd_count_map[{pid}] = {open_count, close_count, comm, stack}（atomic add only）
 *
 * fd_install: 仅新 file 时 open_count++（dup 不重复计，BPF_NOEXIST）
 * fput: f_count==1（最后一次关闭）→ close_count++ + 删除 fd_file_map 条目
 */

#include "common.h"

/* 最小 struct file 定义（___o 后缀避免名字冲突，CO-RE 按 field name 匹配内核 BTF） */
struct file___o {
    struct {
        long counter;
    } f_count;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64);
    __type(value, struct fd_file_val_t);
    __uint(max_entries, 1000000);
} fd_file_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct fd_count_key_t);
    __type(value, struct fd_count_val_t);
    __uint(max_entries, 1000000);
} fd_count_map SEC(".maps");

SEC("kprobe/fd_install")
int trace_fd_install(struct pt_regs *ctx) {
    unsigned int fd = PT_REGS_PARM1(ctx);
    struct file___o *file = (struct file___o *)PT_REGS_PARM2(ctx);
    u64 fkey = (u64)file;
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    u64 stack_addrs[STACK_MAX_FRAMES];
    int ret = bpf_get_stack(ctx, stack_addrs, sizeof(stack_addrs), BPF_F_USER_STACK);
    int stack_cnt = (ret >= 0) ? ret / (int)sizeof(u64) : 0;
    if (stack_cnt > STACK_MAX_FRAMES) stack_cnt = STACK_MAX_FRAMES;

    struct fd_file_val_t val = {};
    val.opener_pid = pid;
    val.fd = (int)fd;
    val.stack_cnt = stack_cnt;
    int j;
    for (j = 0; j < STACK_MAX_FRAMES; j++)
        val.stack_addrs[j] = stack_addrs[j];

    long rc = bpf_map_update_elem(&fd_file_map, &fkey, &val, BPF_NOEXIST);
    if (rc) return 0;

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
        for (j = 0; j < STACK_MAX_FRAMES; j++)
            cval->stack_addrs[j] = stack_addrs[j];
    }
    return 0;
}

SEC("kprobe/fput")
int trace_fput(struct pt_regs *ctx) {
    struct file___o *file = (struct file___o *)PT_REGS_PARM1(ctx);
    u64 fkey = (u64)file;

    long f_count = 0;
    bpf_core_read(&f_count, sizeof(f_count), &file->f_count);
    if (f_count != 1) return 0;

    struct fd_file_val_t *val = bpf_map_lookup_elem(&fd_file_map, &fkey);
    if (!val) return 0;

    struct fd_count_key_t ckey = {.pid = (u64)val->opener_pid};
    struct fd_count_val_t *cval = bpf_map_lookup_elem(&fd_count_map, &ckey);
    if (cval) {
        __sync_fetch_and_add(&cval->close_count, 1);
    }
    bpf_map_delete_elem(&fd_file_map, &fkey);
    return 0;
}

char _license[] SEC("license") = "GPL";
