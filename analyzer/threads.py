"""线程泄露检测器：created - exited 趋势检测。

对应里程碑：B2
复用 TrendLeakDetector 基类的双条件 + 状态生命周期。
"""

from analyzer.base import TrendLeakDetector


class ThreadLeakDetector(TrendLeakDetector):
    """线程泄露检测：thread_count = created - exited 趋势检测。"""

    def __init__(self, config):
        cfg = config["thresholds"]["thread"]
        super().__init__(
            config=config,
            resource="thread",
            threshold=cfg.get("delta_threshold", 5),
            observe_seconds=cfg.get("observe_seconds", 30),
            leak_seconds=cfg.get("leak_seconds", 120),
            clear_ratio=cfg.get("clear_ratio", 0.5),
            clear_seconds=cfg.get("clear_seconds", 30),
            resolve_seconds=cfg.get("resolve_seconds", 60),
            stabilize_seconds=cfg.get("stabilize_seconds", 300),
        )

    def _iter_stats(self, aggregator):
        """迭代线程聚合数据：yield (key, value, comm, stack_addrs, stack_cnt, pid)
        锁内拷贝，锁外 yield，避免阻塞 BPF 回调。"""
        with aggregator._lock:
            data = []
            for pid, stats in aggregator.thread_stats.items():
                thread_count = max(0, stats["created"] - stats["exited"])
                key = pid
                data.append((key, thread_count, stats["comm"],
                            stats.get("stack_addrs", []),
                            stats.get("stack_cnt", 0), pid))
        for item in data:
            yield item
