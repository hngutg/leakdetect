"""mmap 泄露检测器：mmap outstanding 趋势检测（全量追踪，无采样）。

复用 TrendLeakDetector 基类的 OLS 斜率 + 显著性 + 状态生命周期。
per-PID 聚合：total = Σ mmap_alloc - Σ per-stack free - per-PID free。
栈归因：per-stack outstanding（alloc - free per stack）最大的栈。

Python 进程：值用 VmRSS（/proc/pid/status），消除 pymalloc arena 缓存导致的误报。
栈仍用 BPF mmap 调用栈（VmRSS 不提供栈信息，eBPF 提供）。
"""

import os

from analyzer.base import TrendLeakDetector


class MmapLeakDetector(TrendLeakDetector):
    """mmap 泄露检测：mmap outstanding 趋势检测（无 ×100，全量精确值）。
    Python 进程值用 VmRSS，C/C++ 进程值用 BPF outstanding。"""

    def __init__(self, config):
        cfg = config["thresholds"]["mmap"]
        super().__init__(
            config=config,
            resource="mmap",
            threshold=cfg.get("outstanding_delta_bytes", 10240),
            observe_seconds=cfg.get("observe_seconds", 30),
            leak_seconds=cfg.get("leak_seconds", 60),
            clear_ratio=cfg.get("clear_ratio", 0.5),
            clear_seconds=cfg.get("clear_seconds", 30),
            resolve_seconds=cfg.get("resolve_seconds", 60),
            stabilize_seconds=cfg.get("stabilize_seconds", 300),
            significance_z=cfg.get("significance_z", 3.0),
            grace_seconds=cfg.get("grace_seconds", 120),
            confirm_seconds=cfg.get("confirm_seconds", 240),
        )
        self._python_cache = {}

    def _is_python(self, pid):
        """检查进程是否为 Python（缓存结果）。"""
        if pid not in self._python_cache:
            try:
                exe = os.readlink("/proc/%d/exe" % pid)
                self._python_cache[pid] = "python" in exe.lower()
            except Exception:
                self._python_cache[pid] = False
        return self._python_cache[pid]

    def _read_vmrss(self, pid):
        """读 /proc/pid/status 的 VmRSS（返回字节）。"""
        try:
            with open("/proc/%d/status" % pid) as f:
                for line in f:
                    if line.startswith("VmRSS:"):
                        return int(line.split()[1]) * 1024
        except Exception:
            pass
        return 0

    def _iter_stats(self, aggregator):
        """迭代 mmap 聚合数据：yield (key, value, comm, stack_addrs, stack_cnt, pid)
        per-PID 聚合：total = Σ alloc - Σ per-stack free - per-PID free。
        栈归因：per-stack outstanding（alloc - per-stack free）最大的栈。
        Python 进程：值用 VmRSS（消除 pymalloc 误报），栈仍用 BPF。"""
        with aggregator._lock:
            data = []
            for pid, stacks in aggregator.mmap_stats.items():
                free_bytes = aggregator.mmap_free_stats.get(pid, 0)
                total_alloc = sum(s["alloc_bytes"] for s in stacks.values())
                total_per_stack_free = sum(s.get("free_bytes", 0) for s in stacks.values())
                total_outstanding = max(0, total_alloc - total_per_stack_free - free_bytes)

                # Python 进程：值用 VmRSS（消除 pymalloc arena 缓存误报）
                if self._is_python(pid):
                    value = self._read_vmrss(pid)
                else:
                    value = total_outstanding

                # 栈归因：per-stack outstanding（alloc - per-stack free）最大的栈
                best = max(stacks.values(),
                           key=lambda s: max(0, s["alloc_bytes"] - s.get("free_bytes", 0))) if stacks else {}
                data.append((pid, value, best.get("comm", ""),
                            best.get("stack_addrs", []),
                            best.get("stack_cnt", 0), pid))
        for item in data:
            yield item
