"""句柄泄露检测器：open - close 趋势检测。

对应里程碑：B2
复用 TrendLeakDetector 基类的双条件 + 状态生命周期。
"""

from analyzer.base import TrendLeakDetector


class HandleLeakDetector(TrendLeakDetector):
    """句柄泄露检测：fd_count = open - close 趋势检测。"""

    def __init__(self, config):
        cfg = config["thresholds"]["fd"]
        super().__init__(
            config=config,
            resource="fd",
            threshold=cfg.get("delta_threshold", 10),
            observe_seconds=cfg.get("observe_seconds", 30),
            leak_seconds=cfg.get("leak_seconds", 120),
            clear_ratio=cfg.get("clear_ratio", 0.5),
            clear_seconds=cfg.get("clear_seconds", 30),
            resolve_seconds=cfg.get("resolve_seconds", 60),
            stabilize_seconds=cfg.get("stabilize_seconds", 300),
        )

    def _iter_stats(self, aggregator):
        """迭代句柄聚合数据：yield (key, value, comm, stack_addrs, stack_cnt, pid)
        per-PID 计数（与线程相同），锁内拷贝，锁外 yield。"""
        with aggregator._lock:
            data = []
            for pid, stats in aggregator.fd_stats.items():
                fd_count = max(0, stats["open_count"] - stats["close_count"])
                key = pid
                data.append((key, fd_count, stats["comm"],
                            stats.get("stack_addrs", []),
                            stats.get("stack_cnt", 0), pid))
        for item in data:
            yield item
