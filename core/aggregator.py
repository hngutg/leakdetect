"""按 (PID, stack_addrs) 聚合事件，维护 outstanding/count 指标。

对应里程碑：B1 + B2
对应文档：leakdetect-b1-design.md §6.3、leakdetect-b2-design.md §8.3
线程安全：threading.Lock 保护所有 stats

聚合 key：内存按 (pid, tuple(stack_addrs))，线程/句柄按 pid。
stack_addrs 来自 bpf_get_stack 直接拷贝，不依赖 BPF_STACK_TRACE map。
"""

import os
import threading


class Aggregator:
    """聚合内存/线程/句柄事件。"""

    def __init__(self):
        self._lock = threading.Lock()
        # 内存: {pid: {stack_key: {alloc_bytes, alloc_count, free_bytes, free_count, comm, stack_addrs, stack_cnt}}}
        self.mem_stats = {}
        # 线程: {pid: {created, exited, comm, stack_addrs, stack_cnt}}
        self.thread_stats = {}
        # 句柄: {pid: {open_count, close_count, comm, stack_addrs, stack_cnt}}
        self.fd_stats = {}

    # ========== 内存（B1） ==========

    def set_mem_stats(self, stats):
        """B 方案：整体替换 mem_stats（由 loader.read_outstanding_map 设置）。"""
        with self._lock:
            self.mem_stats = stats

    def get_total_outstanding(self):
        with self._lock:
            total = sum(max(0, s["alloc_bytes"] - s["free_bytes"])
                    for stacks in self.mem_stats.values()
                    for s in stacks.values())
        return total * 100

    def get_per_process_mem(self):
        result = []
        with self._lock:
            for pid, stacks in self.mem_stats.items():
                total = sum(max(0, s["alloc_bytes"] - s["free_bytes"])
                            for s in stacks.values())
                comm = next(iter(stacks.values()))["comm"] if stacks else ""
                result.append({"pid": pid, "name": comm,
                               "value": total * 100, "delta_60s": 0})
        return sorted(result, key=lambda x: x["value"], reverse=True)

    # ========== 线程（B2） ==========

    def on_thread_event(self, event):
        pid = event["pid"]
        with self._lock:
            if pid not in self.thread_stats:
                self.thread_stats[pid] = {
                    "created": 0, "exited": 0,
                    "comm": event["comm"],
                    "stack_addrs": [],
                    "stack_cnt": 0,
                }
            if event["op"] == 'c':
                self.thread_stats[pid]["created"] += 1
                self.thread_stats[pid]["stack_addrs"] = event.get("stack_addrs", [])
                self.thread_stats[pid]["stack_cnt"] = event.get("stack_cnt", 0)
            elif event["op"] == 'e':
                if self.thread_stats[pid]["created"] > 0:
                    self.thread_stats[pid]["exited"] += 1

    def get_total_thread_count(self):
        with self._lock:
            return sum(max(0, s["created"] - s["exited"])
                      for s in self.thread_stats.values())

    def get_per_process_thread(self):
        result = []
        with self._lock:
            for pid, s in self.thread_stats.items():
                count = max(0, s["created"] - s["exited"])
                result.append({"pid": pid, "name": s["comm"], "value": count})
        return sorted(result, key=lambda x: x["value"], reverse=True)

    # ========== 句柄（B2，per-PID 计数，与线程相同模式） ==========

    def set_fd_stats(self, stats):
        """B 方案：整体替换 fd_stats（由 loader.read_fd_count_map 设置）。"""
        with self._lock:
            self.fd_stats = stats

    def get_total_fd_count(self):
        with self._lock:
            return sum(max(0, s["open_count"] - s["close_count"])
                      for s in self.fd_stats.values())

    def get_per_process_fd(self):
        result = []
        with self._lock:
            for pid, s in self.fd_stats.items():
                count = max(0, s["open_count"] - s["close_count"])
                result.append({"pid": pid, "name": s["comm"], "value": count})
        return sorted(result, key=lambda x: x["value"], reverse=True)

    # ========== 通用 ==========

    def get_snapshot(self):
        return self.get_per_process_mem()

    def cleanup_dead(self):
        """清理已退出进程的所有统计。"""
        with self._lock:
            all_pids = set(self.mem_stats.keys())
            all_pids.update(self.thread_stats.keys())
            all_pids.update(self.fd_stats.keys())
            dead = [pid for pid in all_pids
                    if not os.path.exists("/proc/%d" % pid)]
            for pid in dead:
                self.mem_stats.pop(pid, None)
                self.thread_stats.pop(pid, None)
                self.fd_stats.pop(pid, None)
