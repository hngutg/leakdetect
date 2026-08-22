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

    /* 方案 B：捕获叶子返回地址 [RSP]。内核 walker 用 RBP 链回溯，在 malloc 入口
     * 会跳过 [RSP] 里的 return-to-caller（main 等），导致叶子调用者丢失。
     * 读 [RSP] 插入到 stack_addrs[1]（frame 0 = malloc RIP 保留），walker 帧后移一位。
     * 含去重：若 walker 已含 ra（某些内核不跳过叶子），不插，避免重复帧。 */
    u64 ra = 0;
    if (bpf_probe_read_user(&ra, sizeof(ra), (void *)PT_REGS_SP(ctx)) == 0 && ra != 0) {
        int scnt = info.stack_cnt;
        if (scnt > STACK_MAX_FRAMES) scnt = STACK_MAX_FRAMES;
        int dup = 0;
        int i;
        for (i = 0; i < scnt; i++) {
            if (info.stack_addrs[i] == ra) { dup = 1; break; }
        }
        if (!dup) {
            if (scnt == 0) {
                info.stack_addrs[0] = ra;
                info.stack_cnt = 1;
            } else {
                int new_cnt = scnt + 1;
                if (new_cnt > STACK_MAX_FRAMES) new_cnt = STACK_MAX_FRAMES;
                for (i = STACK_MAX_FRAMES - 1; i >= 2; i--) {
                    if (i < new_cnt) {
                        info.stack_addrs[i] = info.stack_addrs[i - 1];
                    }
                }
                info.stack_addrs[1] = ra;
                info.stack_cnt = new_cnt;
            }
        }
    }

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
        /* 驱逐：refcount→0 删条目，防 allocs map 饱和导致稳态进程伪增长。
         * 重读 refcount==0 守卫：并发 alloc（libc 复用同地址）已 +1 则不删，
         * 把"删-增"竞态窗口压到 1 条 load 指令；残余概率极低且每次仅 +1（有界）。 */
        if (old == 1 && info->refcount == 0) {
            bpf_map_delete_elem(&allocs, &ptr);
        }
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
