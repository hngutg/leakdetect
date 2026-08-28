/* mem.bpf.c - 内存泄露检测 BPF 程序（libbpf 风格，map 聚合版）
 *
 * B 方案：删 events ring，改用 outstanding_map（per-(pid,stack) 聚合，Python 定期读）。
 * Hook: uprobe malloc entry/return + uprobe free entry
 * 采样: 1/100（sampler map 计数）
 * 配对追踪: allocs[ptr] = {refcount, size, stack}（refcount 原子操作，驱逐）
 * 聚合: outstanding_map[{pid, stack}] = {alloc_bytes, free_bytes, comm, stack_cnt}（atomic add only，无 sub → 无 u64 回绕窗口）
 * 栈捕获: bpf_get_stack() 直接拷贝地址到 entry_info/outstanding_map key
 */

#include "common.h"

/* BPF Maps（libbpf SEC 风格） */
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
    __uint(max_entries, 1000000);
} allocs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct outstanding_key_t);
    __type(value, struct outstanding_val_t);
    __uint(max_entries, 1000000);
} outstanding_map SEC(".maps");

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

/* malloc return: 取 ptr + 存 allocs map + 更新 outstanding_map */
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

    u64 pid = bpf_get_current_pid_tgid() >> 32;

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
        alloc->pid = (u32)pid;
        int i;
        for (i = 0; i < STACK_MAX_FRAMES; i++) {
            alloc->stack_addrs[i] = info->stack_addrs[i];
        }
    }

    struct outstanding_key_t okey = {};
    okey.pid = pid;
    int j;
    for (j = 0; j < STACK_MAX_FRAMES; j++) {
        okey.stack_addrs[j] = info->stack_addrs[j];
    }
    struct outstanding_val_t *oval = bpf_map_lookup_elem(&outstanding_map, &okey);
    if (!oval) {
        struct outstanding_val_t zero = {};
        bpf_map_update_elem(&outstanding_map, &okey, &zero, BPF_ANY);
        oval = bpf_map_lookup_elem(&outstanding_map, &okey);
    }
    if (oval) {
        __sync_fetch_and_add(&oval->alloc_bytes, info->size);
        bpf_get_current_comm(oval->comm, sizeof(oval->comm));
        oval->stack_cnt = info->stack_cnt;
    }

    bpf_map_delete_elem(&entry_info, &tid);
    return 0;
}

/* free entry: outstanding_map free_bytes add + allocs refcount sub + 驱逐 */
SEC("uprobe")
int trace_free_entry(struct pt_regs *ctx) {
    u64 ptr = PT_REGS_PARM1(ctx);
    struct alloc_info_t *info = bpf_map_lookup_elem(&allocs, &ptr);
    if (!info) {
        return 0;
    }

    u64 size = info->size;

    u64 pid = (u64)(bpf_get_current_pid_tgid() >> 32);
    struct outstanding_key_t okey = {};
    okey.pid = pid;
    int j;
    for (j = 0; j < STACK_MAX_FRAMES; j++) {
        okey.stack_addrs[j] = info->stack_addrs[j];
    }
    struct outstanding_val_t *oval = bpf_map_lookup_elem(&outstanding_map, &okey);
    if (oval) {
        __sync_fetch_and_add(&oval->free_bytes, size);
    }

    u64 old = __sync_fetch_and_sub(&info->refcount, 1);
    if (old > 0) {
        if (old == 1 && info->refcount == 0) {
            bpf_map_delete_elem(&allocs, &ptr);
        }
    } else {
        __sync_fetch_and_add(&info->refcount, 1);
    }
    return 0;
}

char _license[] SEC("license") = "GPL";
