"""P3 验证脚本：值算法一致性（get_total_* vs get_per_process_*）。

无需 root/eBPF，纯算法验证。验证 get_total_outstanding/thread_count/fd_count
与 get_per_process_mem/thread/fd 的求和结果一致（per-sid/per-entry clamp）。

运行：python3 tests/verify_p3.py
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.aggregator import Aggregator

ALL_PASS = True


def check(name, total, sum_per_proc):
    """断言 get_total_* == sum(get_per_process_* values)。"""
    global ALL_PASS
    ok = (total == sum_per_proc)
    status = "PASS" if ok else "FAIL"
    if not ok:
        ALL_PASS = False
    print("  [%s] total=%d  sum(per_proc)=%d  %s" % (name, total, sum_per_proc, status))


def make_agg(mem_stats=None, thread_stats=None, fd_stats=None):
    agg = Aggregator()
    if mem_stats is not None:
        agg.mem_stats = mem_stats
    if thread_stats is not None:
        agg.thread_stats = thread_stats
    if fd_stats is not None:
        agg.fd_stats = fd_stats
    return agg


print("=== P3 内存一致性验证 ===")

# 场景1: 混合正负 sid（bug 场景，churn 进程）
agg = make_agg({
    100: {
        "sid_a": {"alloc_bytes": 5000000, "free_bytes": 0, "comm": "app"},
        "sid_b": {"alloc_bytes": 0, "free_bytes": 1500000, "comm": "app"},
    },
})
check("混合正负 sid", agg.get_total_outstanding(),
      sum(p["value"] for p in agg.get_per_process_mem()))

# 场景2: 全正 sid
agg = make_agg({
    100: {"sid_a": {"alloc_bytes": 3000000, "free_bytes": 1000000, "comm": "app"}},
    200: {"sid_b": {"alloc_bytes": 2000000, "free_bytes": 500000, "comm": "svc"}},
})
check("全正 sid", agg.get_total_outstanding(),
      sum(p["value"] for p in agg.get_per_process_mem()))

# 场景3: 全负 sid
agg = make_agg({
    100: {"sid_a": {"alloc_bytes": 0, "free_bytes": 1000000, "comm": "app"}},
})
check("全负 sid", agg.get_total_outstanding(),
      sum(p["value"] for p in agg.get_per_process_mem()))

# 场景4: 空 stats
agg = make_agg({})
check("空 stats", agg.get_total_outstanding(),
      sum(p["value"] for p in agg.get_per_process_mem()))

# 场景5: 多进程混合（一个正一个负）
agg = make_agg({
    100: {"sid_a": {"alloc_bytes": 5000000, "free_bytes": 0, "comm": "app"}},
    200: {"sid_b": {"alloc_bytes": 0, "free_bytes": 2000000, "comm": "svc"}},
})
check("多进程混合", agg.get_total_outstanding(),
      sum(p["value"] for p in agg.get_per_process_mem()))

print("=== P3 线程一致性验证 ===")

# 混合正负（一个进程 created>exited，另一个 exited>created）
agg = make_agg(thread_stats={
    100: {"created": 10, "exited": 3, "comm": "app"},
    200: {"created": 2, "exited": 5, "comm": "svc"},
})
check("线程混合", agg.get_total_thread_count(),
      sum(p["value"] for p in agg.get_per_process_thread()))

# 全正
agg = make_agg(thread_stats={
    100: {"created": 10, "exited": 3, "comm": "app"},
    200: {"created": 5, "exited": 2, "comm": "svc"},
})
check("线程全正", agg.get_total_thread_count(),
      sum(p["value"] for p in agg.get_per_process_thread()))

# 空
agg = make_agg(thread_stats={})
check("线程空", agg.get_total_thread_count(),
      sum(p["value"] for p in agg.get_per_process_thread()))

print("=== P3 句柄一致性验证 ===")

# 混合正负
agg = make_agg(fd_stats={
    100: {"open_count": 50, "close_count": 20, "comm": "app"},
    200: {"open_count": 5, "close_count": 10, "comm": "svc"},
})
check("句柄混合", agg.get_total_fd_count(),
      sum(p["value"] for p in agg.get_per_process_fd()))

# 全正
agg = make_agg(fd_stats={
    100: {"open_count": 50, "close_count": 20, "comm": "app"},
    200: {"open_count": 30, "close_count": 10, "comm": "svc"},
})
check("句柄全正", agg.get_total_fd_count(),
      sum(p["value"] for p in agg.get_per_process_fd()))

# 空
agg = make_agg(fd_stats={})
check("句柄空", agg.get_total_fd_count(),
      sum(p["value"] for p in agg.get_per_process_fd()))

print("=== 数值对照（改前 sum-then-clamp 会被低估的场景）===")
agg = make_agg({
    100: {
        "sid_a": {"alloc_bytes": 5000000, "free_bytes": 0, "comm": "app"},
        "sid_b": {"alloc_bytes": 0, "free_bytes": 1500000, "comm": "app"},
    },
})
old_algo = max(0, 5000000 - 0 + 0 - 1500000) * 100
new_algo = agg.get_total_outstanding()
print("  混合 sid: 改前(sum-then-clamp)=%d  改后(per-sid-clamp)=%d  差额=%d" % (
    old_algo, new_algo, new_algo - old_algo))

agg = make_agg(thread_stats={
    100: {"created": 10, "exited": 3, "comm": "app"},
    200: {"created": 2, "exited": 5, "comm": "svc"},
})
old_algo = max(0, (10 - 3) + (2 - 5))
new_algo = agg.get_total_thread_count()
print("  线程混合: 改前(sum-then-clamp)=%d  改后(per-entry-clamp)=%d  差额=%d" % (
    old_algo, new_algo, new_algo - old_algo))

print("")
if ALL_PASS:
    print("=== 全部 PASS ===")
else:
    print("=== 有 FAIL，请检查 ===")
    sys.exit(1)
