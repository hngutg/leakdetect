/* mem.bpf.c - 内存泄露检测 BPF 程序（libbpf 风格）
 *
 * Hook: uprobe malloc entry/return + uprobe free entry
 * 采样: 1/100（sampler map 计数）
 * 配对追踪: allocs[ptr] = {refcount, size, stack_cnt, stack_addrs}（refcount 原子操作）
 * 栈捕获: bpf_get_stack() 直接拷贝地址到事件
 */

#include "common.h"

/* BPF Maps（libbpf SEC 风格，替代 BCC 宏） */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1024 * 1024);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, u32);
    __type(value, u64);
    __uint(max_entries, 1);
} sampler SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, struct alloc_info_t);
    __uint(max_entries, 10000);
} entry_info SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64);
    __type(value, struct alloc_info_t);
    __uint(max_entries, 100000);
} allocs SEC(".maps");

/* malloc entry: 采样 + 记录 size + 捕获栈 */
SEC("uprobe")
int trace_malloc_entry(struct pt_regs *ctx) {
    u32 zero = 0;
    u64 *cnt = bpf_map_lookup_elem(&sampler, &zero);
    if (cnt) {
        *cnt += 1;
        if (*cnt % 100 != 0) {
            return 0;
        }
    }

    u32 tid = (u32)bpf_get_current_pid_tgid();
    struct alloc_info_t info = {};
    info.size = PT_REGS_PARM1(ctx);
    int ret = bpf_get_stack(ctx, info.stack_addrs,
                            sizeof(info.stack_addrs), BPF_F_USER_STACK);
    info.stack_cnt = (ret >= 0) ? ret / (int)sizeof(u64) : 0;
    if (info.stack_cnt > STACK_MAX_FRAMES) info.stack_cnt = STACK_MAX_FRAMES;
    bpf_map_update_elem(&entry_info, &tid, &info, BPF_ANY);
    return 0;
}

/* malloc return: 取 ptr + 存 allocs map + 发 alloc 事件 */
SEC("uretprobe")
int trace_malloc_return(struct pt_regs *ctx) {
    u64 ptr = PT_REGS_RC(ctx);
    if (ptr == 0) {
        return 0;
    }

    u32 tid = (u32)bpf_get_current_pid_tgid();
    struct alloc_info_t *info = bpf_map_lookup_elem(&entry_info, &tid);
    if (!info) {
        return 0;
    }

    /* 存入 allocs 追踪 map（refcount 方式） */
    struct alloc_info_t *alloc = bpf_map_lookup_elem(&allocs, &ptr);
    if (!alloc) {
        struct alloc_info_t zero = {};
        bpf_map_update_elem(&allocs, &ptr, &zero, BPF_ANY);
        alloc = bpf_map_lookup_elem(&allocs, &ptr);
    }
    if (alloc) {
        __sync_fetch_and_add(&alloc->refcount, 1);
        alloc->size = info->size;
        alloc->stack_cnt = info->stack_cnt;
        int i;
        for (i = 0; i < STACK_MAX_FRAMES; i++) {
            alloc->stack_addrs[i] = info->stack_addrs[i];
        }
    }

    /* 发 alloc 事件 */
    struct mem_event_t event = {};
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.tid = tid;
    event.size = info->size;
    event.ptr = ptr;
    event.stack_cnt = info->stack_cnt;
    int j;
    for (j = 0; j < STACK_MAX_FRAMES; j++) {
        event.stack_addrs[j] = info->stack_addrs[j];
    }
    event.op = 'a';
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_ringbuf_output(&events, &event, sizeof(event), 0);

    bpf_map_delete_elem(&entry_info, &tid);
    return 0;
}

/* free entry: 原子递减 refcount + 局部变量拷贝 */
SEC("uprobe")
int trace_free_entry(struct pt_regs *ctx) {
    u64 ptr = PT_REGS_PARM1(ctx);
    struct alloc_info_t *info = bpf_map_lookup_elem(&allocs, &ptr);
    if (!info) {
        return 0;
    }

    u64 size = info->size;
    int stack_cnt = info->stack_cnt;
    u64 stack_addrs[STACK_MAX_FRAMES];
    int i;
    for (i = 0; i < STACK_MAX_FRAMES; i++) {
        stack_addrs[i] = info->stack_addrs[i];
    }

    u64 old = __sync_fetch_and_sub(&info->refcount, 1);
    if (old > 0) {
        struct mem_event_t event = {};
        event.pid = bpf_get_current_pid_tgid() >> 32;
        event.tid = (u32)bpf_get_current_pid_tgid();
        event.size = size;
        event.ptr = ptr;
        event.stack_cnt = stack_cnt;
        int j;
        for (j = 0; j < STACK_MAX_FRAMES; j++) {
            event.stack_addrs[j] = stack_addrs[j];
        }
        event.op = 'f';
        bpf_get_current_comm(&event.comm, sizeof(event.comm));
        bpf_ringbuf_output(&events, &event, sizeof(event), 0);
    } else {
        __sync_fetch_and_add(&info->refcount, 1);
    }
    return 0;
}

char _license[] SEC("license") = "GPL";
