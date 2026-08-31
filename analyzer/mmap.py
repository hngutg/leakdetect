"""mmap 泄露检测器：mmap outstanding 趋势检测（全量追踪，无采样）。

复用 TrendLeakDetector 基类的 OLS 斜率 + 显著性 + 状态生命周期。
per-PID 聚合：total = Σ mmap_alloc - mmap_free（per-PID）。
栈归因：取 alloc_bytes 最大的调用点。
"""

from analyzer.base import TrendLeakDetector


class MmapLeakDetector(TrendLeakDetector):
    """mmap 泄露检测：mmap outstanding 趋势检测（无 ×100，全量精确值）。"""

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

    def _iter_stats(self, aggregator):
        """迭代 mmap 聚合数据：yield (key, value, comm, stack_addrs, stack_cnt, pid)
        per-PID 聚合：total = Σ alloc_bytes - free_bytes（per-PID）。
        栈归因：取 alloc_bytes 最大的调用点。"""
        with aggregator._lock:
            data = []
            for pid, stacks in aggregator.mmap_stats.items():
                free_bytes = aggregator.mmap_free_stats.get(pid, 0)
                total_alloc = sum(s["alloc_bytes"] for s in stacks.values())
                total = max(0, total_alloc - free_bytes)
                best = max(stacks.values(), key=lambda s: s["alloc_bytes"]) if stacks else {}
                data.append((pid, total, best.get("comm", ""),
                            best.get("stack_addrs", []),
                            best.get("stack_cnt", 0), pid))
        for item in data:
            yield item
