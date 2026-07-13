"""内存泄露检测器：双条件判定 + 状态生命周期 + 防抖。

对应里程碑：B1 + B2（B2 重构为继承 TrendLeakDetector）
"""

from analyzer.base import TrendLeakDetector


class MemoryLeakDetector(TrendLeakDetector):
    """内存泄露检测：outstanding_bytes 趋势检测。"""

    def __init__(self, config):
        cfg = config["thresholds"]["mem"]
        super().__init__(
            config=config,
            resource="mem",
            threshold=cfg["outstanding_delta_bytes"],
            observe_seconds=cfg.get("observe_seconds", 30),
            leak_seconds=cfg.get("leak_seconds", 60),
            clear_ratio=cfg.get("clear_ratio", 0.5),
            clear_seconds=cfg.get("clear_seconds", 30),
            resolve_seconds=cfg.get("resolve_seconds", 60),
            stabilize_seconds=cfg.get("stabilize_seconds", 300),
        )

    def _iter_stats(self, aggregator):
        """迭代内存聚合数据：yield (key, value, comm, stack_addrs, stack_cnt, pid)
        锁内拷贝，锁外 yield，避免阻塞 BPF 回调。"""
        with aggregator._lock:
            data = []
            for pid, stacks in aggregator.mem_stats.items():
                for sid, stats in stacks.items():
                    outstanding = max(0, stats["alloc_bytes"] - stats["free_bytes"])
                    outstanding_est = outstanding * 100
                    key = (pid, sid)
                    data.append((key, outstanding_est, stats["comm"],
                                stats.get("stack_addrs", []),
                                stats.get("stack_cnt", 0), pid))
        for item in data:
            yield item
