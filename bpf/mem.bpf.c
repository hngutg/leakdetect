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

/* mmap per-(pid,stack) 分配追踪（复用 outstanding_key_t/outstanding_val_t） */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct outstanding_key_t);
    __type(value, struct outstanding_val_t);
    __uint(max_entries, 1000000);
} mmap_outstanding_map SEC(".maps");

/* mmap per-PID 释放计数（munmap 无匹配栈） */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct mmap_free_key_t);
    __type(value, struct mmap_free_val_t);
    __uint(max_entries, 1000000);
} mmap_free_map SEC(".maps");

/* mmap 地址→栈反查（munmap 时按地址匹配到原始 mmap 的栈） */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct mmap_addr_key_t);
    __type(value, struct mmap_addr_val_t);
    __uint(max_entries, 1000000);
} mmap_addr_map SEC(".maps");

/* mmap entry→return 暂存 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, struct mmap_entry_info_t);
    __uint(max_entries, 10000);
} mmap_entry_info SEC(".maps");

/* Python PID 集合（libc malloc/free 跳过这些 PID，由 PyObject_Malloc/Free 追踪） */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, u8);
    __uint(max_entries, 65536);
} python_pids SEC(".maps");

/* malloc entry: 采样 + 记录 size + 捕获栈 */
SEC("uprobe")
int trace_malloc_entry(struct pt_regs *ctx) {
    /* Python 进程跳过（由 PyObject_Malloc 探针追踪） */
    u32 mpid = bpf_get_current_pid_tgid() >> 32;
    u8 *is_py = bpf_map_lookup_elem(&python_pids, &mpid);
    if (is_py) return 0;

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
    fixup_return_addr(ctx, info.stack_addrs, &info.stack_cnt);

    bpf_map_update_elem(&entry_info, &tid, &info, BPF_ANY);
    return 0;
}

/* malloc return: 取 ptr + 存 allocs map + 更新 outstanding_map
 * Python PID 跳过：由 trace_pymalloc_return 处理 PyObject_Malloc 返回，
 * 避免 trace_malloc_return 为 Python 创建 allocs[libc_ptr]（arena/大对象），
 * 这些 ptr 被 libc free 释放时 trace_free_entry 跳过 → stale → double-count */
SEC("uretprobe")
int trace_malloc_return(struct pt_regs *ctx) {
    /* Python 进程跳过（由 trace_pymalloc_return 处理） */
    u32 mpid = bpf_get_current_pid_tgid() >> 32;
    u8 *is_py = bpf_map_lookup_elem(&python_pids, &mpid);
    if (is_py) return 0;

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

        /* outstanding_map 更新移入 if(alloc) 内，防止 allocs 创建失败时 ghost */
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
    }

    bpf_map_delete_elem(&entry_info, &tid);
    return 0;
}

/* free entry: outstanding_map free_bytes add + allocs refcount sub + 驱逐 */
SEC("uprobe")
int trace_free_entry(struct pt_regs *ctx) {
    /* Python 进程跳过（由 PyObject_Free 探针追踪） */
    u32 mpid = bpf_get_current_pid_tgid() >> 32;
    u8 *is_py = bpf_map_lookup_elem(&python_pids, &mpid);
    if (is_py) return 0;

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

/* ======== PyObject_Malloc/Free 追踪（Python 进程专用，复用 allocs/outstanding_map）======== */

/* PyObject_Malloc entry: 采样 + 记录 size + 捕获栈（逻辑同 trace_malloc_entry） */
SEC("uprobe")
int trace_pymalloc_entry(struct pt_regs *ctx) {
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

    fixup_return_addr(ctx, info.stack_addrs, &info.stack_cnt);

    bpf_map_update_elem(&entry_info, &tid, &info, BPF_ANY);
    return 0;
}

/* PyObject_Malloc return: 取 ptr + 存 allocs + 更新 outstanding_map
 * 处理 stale 条目：ptr 被 libc free 释放（PyObject_Realloc 内部 / arena 释放）
 * 但 allocs[ptr] 因 trace_free_entry 跳过 Python PID 而未删除 → 补记 free + 删除重建 */
SEC("uretprobe")
int trace_pymalloc_return(struct pt_regs *ctx) {
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

    /* 检查 stale 条目：ptr 被 libc free 释放但 allocs[ptr] 未删除 */
    struct alloc_info_t *alloc = bpf_map_lookup_elem(&allocs, &ptr);
    if (alloc) {
        /* 补记 free_bytes 到旧栈，清除旧 alloc 的 outstanding */
        struct outstanding_key_t old_okey = {};
        old_okey.pid = pid;
        int j;
        for (j = 0; j < STACK_MAX_FRAMES; j++)
            old_okey.stack_addrs[j] = alloc->stack_addrs[j];
        struct outstanding_val_t *old_oval = bpf_map_lookup_elem(&outstanding_map, &old_okey);
        if (old_oval)
            __sync_fetch_and_add(&old_oval->free_bytes, alloc->size);
        /* 删除 stale 条目，下面重新创建 */
        bpf_map_delete_elem(&allocs, &ptr);
        alloc = NULL;
    }

    /* 创建新条目 */
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

        /* outstanding_map 更新在 if(alloc) 内，防止创建失败时 ghost */
        struct outstanding_key_t okey = {};
        okey.pid = pid;
        int k;
        for (k = 0; k < STACK_MAX_FRAMES; k++) {
            okey.stack_addrs[k] = info->stack_addrs[k];
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
    }

    bpf_map_delete_elem(&entry_info, &tid);
    return 0;
}

/* PyObject_Free entry: outstanding_map free_bytes + allocs refcount 驱逐（逻辑同 trace_free_entry） */
SEC("uprobe")
int trace_pyfree_entry(struct pt_regs *ctx) {
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

/* ======== mmap/munmap/mremap 追踪（全量，不采样）======== */

SEC("uprobe")
int trace_mmap_entry(struct pt_regs *ctx) {
    u64 flags = PT_REGS_PARM4(ctx);
    if (!(flags & MAP_ANONYMOUS_)) return 0;
    u32 tid = (u32)bpf_get_current_pid_tgid();
    struct mmap_entry_info_t info = {};
    info.length = PT_REGS_PARM2(ctx);
    info.pid = (u32)(bpf_get_current_pid_tgid() >> 32);
    int ret = bpf_get_stack(ctx, info.stack_addrs, sizeof(info.stack_addrs), BPF_F_USER_STACK);
    info.stack_cnt = (ret >= 0) ? ret / (int)sizeof(u64) : 0;
    if (info.stack_cnt > STACK_MAX_FRAMES) info.stack_cnt = STACK_MAX_FRAMES;
    fixup_return_addr(ctx, info.stack_addrs, &info.stack_cnt);
    bpf_map_update_elem(&mmap_entry_info, &tid, &info, BPF_ANY);
    return 0;
}

SEC("uretprobe")
int trace_mmap_return(struct pt_regs *ctx) {
    u64 ptr = PT_REGS_RC(ctx);
    if (ptr == (u64)-1) {
        u32 tid = (u32)bpf_get_current_pid_tgid();
        bpf_map_delete_elem(&mmap_entry_info, &tid);
        return 0;
    }
    u32 tid = (u32)bpf_get_current_pid_tgid();
    struct mmap_entry_info_t *info = bpf_map_lookup_elem(&mmap_entry_info, &tid);
    if (!info) return 0;
    u64 pid = bpf_get_current_pid_tgid() >> 32;
    struct outstanding_key_t key = {};
    key.pid = pid;
    int j;
    for (j = 0; j < STACK_MAX_FRAMES; j++) key.stack_addrs[j] = info->stack_addrs[j];
    struct outstanding_val_t *val = bpf_map_lookup_elem(&mmap_outstanding_map, &key);
    if (!val) {
        struct outstanding_val_t zero = {};
        bpf_map_update_elem(&mmap_outstanding_map, &key, &zero, BPF_ANY);
        val = bpf_map_lookup_elem(&mmap_outstanding_map, &key);
    }
    if (val) {
        __sync_fetch_and_add(&val->alloc_bytes, info->length);
        bpf_get_current_comm(val->comm, sizeof(val->comm));
        val->stack_cnt = info->stack_cnt;
    }
    /* 存 {pid, addr → stack} 供 munmap 反查 */
    struct mmap_addr_key_t akey = {};
    akey.pid = pid;
    akey.addr = ptr;
    struct mmap_addr_val_t aval = {};
    for (j = 0; j < STACK_MAX_FRAMES; j++) aval.stack_addrs[j] = info->stack_addrs[j];
    bpf_map_update_elem(&mmap_addr_map, &akey, &aval, BPF_ANY);
    bpf_map_delete_elem(&mmap_entry_info, &tid);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_munmap")
int trace_munmap_entry(struct sys_enter_args *ctx) {
    u64 addr = ctx->args[0];
    u64 length = ctx->args[1];
    u64 pid = bpf_get_current_pid_tgid() >> 32;

    /* 尝试按地址匹配到原始 mmap 的栈 */
    struct mmap_addr_key_t akey = {};
    akey.pid = pid;
    akey.addr = addr;
    struct mmap_addr_val_t *aval = bpf_map_lookup_elem(&mmap_addr_map, &akey);
    if (aval) {
        /* 精确匹配：归因到栈 */
        struct outstanding_key_t okey = {};
        okey.pid = pid;
        int j;
        for (j = 0; j < STACK_MAX_FRAMES; j++) okey.stack_addrs[j] = aval->stack_addrs[j];
        struct outstanding_val_t *oval = bpf_map_lookup_elem(&mmap_outstanding_map, &okey);
        if (oval) {
            __sync_fetch_and_add(&oval->free_bytes, length);
        }
        bpf_map_delete_elem(&mmap_addr_map, &akey);
    } else {
        /* 回退：per-PID free（部分 munmap/mremap 移动/启动前 mmap） */
        struct mmap_free_key_t fkey = {.pid = pid};
        struct mmap_free_val_t *fval = bpf_map_lookup_elem(&mmap_free_map, &fkey);
        if (!fval) {
            struct mmap_free_val_t zero = {};
            bpf_map_update_elem(&mmap_free_map, &fkey, &zero, BPF_ANY);
            fval = bpf_map_lookup_elem(&mmap_free_map, &fkey);
        }
        if (fval) {
            __sync_fetch_and_add(&fval->free_bytes, length);
        }
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_mremap")
int trace_mremap_entry(struct sys_enter_args *ctx) {
    u64 old_size = ctx->args[1];
    u64 new_size = ctx->args[2];
    u64 pid = bpf_get_current_pid_tgid() >> 32;
    if (new_size > old_size) {
        u64 delta = new_size - old_size;
        struct outstanding_key_t key = {};
        key.pid = pid;
        int ret = bpf_get_stack(ctx, key.stack_addrs, sizeof(key.stack_addrs), BPF_F_USER_STACK);
        int scnt = (ret >= 0) ? ret / (int)sizeof(u64) : 0;
        if (scnt > STACK_MAX_FRAMES) scnt = STACK_MAX_FRAMES;
        struct outstanding_val_t *val = bpf_map_lookup_elem(&mmap_outstanding_map, &key);
        if (!val) {
            struct outstanding_val_t zero = {};
            bpf_map_update_elem(&mmap_outstanding_map, &key, &zero, BPF_ANY);
            val = bpf_map_lookup_elem(&mmap_outstanding_map, &key);
        }
        if (val) {
            __sync_fetch_and_add(&val->alloc_bytes, delta);
            bpf_get_current_comm(val->comm, sizeof(val->comm));
            val->stack_cnt = scnt;
        }
    } else if (old_size > new_size) {
        u64 delta = old_size - new_size;
        struct mmap_free_key_t fkey = {};
        fkey.pid = pid;
        struct mmap_free_val_t *fval = bpf_map_lookup_elem(&mmap_free_map, &fkey);
        if (!fval) {
            struct mmap_free_val_t zero = {};
            bpf_map_update_elem(&mmap_free_map, &fkey, &zero, BPF_ANY);
            fval = bpf_map_lookup_elem(&mmap_free_map, &fkey);
        }
        if (fval) {
            __sync_fetch_and_add(&fval->free_bytes, delta);
        }
    }
    return 0;
}

char _license[] SEC("license") = "GPL";
