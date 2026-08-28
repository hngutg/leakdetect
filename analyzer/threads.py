"""线程泄露检测器：created - exited 趋势检测。

对应里程碑：B2
复用 TrendLeakDetector 基类的 OLS 斜率 + 显著性 + 状态生命周期。
精度专项：阈值语义 delta→斜率（threads/sec，默认 0.1）。
"""

from analyzer.base import TrendLeakDetector


class ThreadLeakDetector(TrendLeakDetector):
    """线程泄露检测：thread_count = created - exited 趋势检测。"""

    def __init__(self, config):
        cfg = config["thresholds"]["thread"]
        super().__init__(
            config=config,
            resource="thread",
            threshold=cfg.get("delta_threshold", 0.1),   # 斜率地板 threads/sec
            observe_seconds=cfg.get("observe_seconds", 30),
            leak_seconds=cfg.get("leak_seconds", 120),
            clear_ratio=cfg.get("clear_ratio", 0.5),
            clear_seconds=cfg.get("clear_seconds", 30),
            resolve_seconds=cfg.get("resolve_seconds", 60),
            stabilize_seconds=cfg.get("stabilize_seconds", 300),
            significance_z=cfg.get("significance_z", 3.0),
            grace_seconds=cfg.get("grace_seconds", 120),
            confirm_seconds=cfg.get("confirm_seconds", 240),
        )

    def _iter_stats(self, aggregator):
        """迭代线程聚合数据：yield (key, value, comm, stack_addrs, stack_cnt, pid)
        per-PID 计数（本就 per-PID）；锁内拷贝，锁外 yield。"""
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
