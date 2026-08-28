/* common.h - 共享定义（事件结构 + 常量）
 * libbpf 风格：不依赖 BCC，用标准 BPF 头文件
 * 栈捕获方式：bpf_get_stack() 直接拷贝地址到事件，不依赖 BPF_STACK_TRACE map
 */
#ifndef __COMMON_H
#define __COMMON_H

#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

typedef __u32 u32;
typedef __u64 u64;
typedef __s32 s32;
typedef __s64 s64;

#define STACK_MAX_FRAMES 8

/* sys_enter_* tracepoint 通用参数结构
 * 布局：common_header(8) + syscall_nr(8) + args[6](48)
 * 在 5.10+ 上跨架构稳定 */
struct sys_enter_args {
    u64 _common_header;
    s64 _syscall_nr;
    u64 args[6];
};

/* 内存事件结构（perf buffer 传输） */
struct mem_event_t {
    u32 pid;
    u32 tid;
    u64 size;
    u64 ptr;
    int stack_cnt;
    u64 stack_addrs[STACK_MAX_FRAMES];
    char op;
    char comm[16];
};

/* 内存 entry probe 暂存信息 + allocs map value */
struct alloc_info_t {
    u64 refcount;
    u64 size;
    int stack_cnt;
    u64 stack_addrs[STACK_MAX_FRAMES];
    u32 pid;                    /* 死 pid 清理用 */
};

/* 线程事件结构 */
struct thread_event_t {
    u32 pid;
    u32 tid;
    int stack_cnt;
    u64 stack_addrs[STACK_MAX_FRAMES];
    char op;
    char comm[16];
};

/* 句柄事件结构 */
struct fd_event_t {
    u32 pid;
    int fd;
    int fd_type;
    int stack_cnt;
    u64 stack_addrs[STACK_MAX_FRAMES];
    char op;
    char comm[16];
};

/* fd 配对追踪的 key */
struct fd_key_t {
    u32 pid;
    int fd;
};

/* fd_map 的 value：引用计数 + 栈地址 */
struct fd_value_t {
    u64 refcount;
    int stack_cnt;
    u64 stack_addrs[STACK_MAX_FRAMES];
};

/* outstanding_map 的 key：per-(pid,stack) 内存聚合 */
struct outstanding_key_t {
    u64 pid;
    u64 stack_addrs[STACK_MAX_FRAMES];
};

/* outstanding_map 的 value：双计数器（add only，无 sub → 无 u64 回绕窗口）+ comm + stack_cnt */
struct outstanding_val_t {
    u64 alloc_bytes;
    u64 free_bytes;
    char comm[16];
    int stack_cnt;
};

/* fd_count_map 的 key：per-pid fd 计数 */
struct fd_count_key_t {
    u64 pid;
};

/* fd_count_map 的 value：双计数器（add only，无 sub → 无 u64 回绕窗口）+ comm + 栈（last open）*/
struct fd_count_val_t {
    u64 open_count;
    u64 close_count;
    u64 stack_addrs[STACK_MAX_FRAMES];
    char comm[16];
    int stack_cnt;
};

#endif /* __COMMON_H */
