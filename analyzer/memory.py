"""内存泄露检测器：OLS 斜率 + 显著性 + 状态生命周期 + 防抖。

对应里程碑：B1 + B2（B2 重构为继承 TrendLeakDetector）
精度专项：per-PID 聚合（key=pid，跨栈求和）+ 增长 sid 栈归因 + 排自身 PID。
"""

import os

from analyzer.base import TrendLeakDetector


class MemoryLeakDetector(TrendLeakDetector):
    """内存泄露检测：outstanding_bytes 趋势检测。"""

    def __init__(self, config):
        cfg = config["thresholds"]["mem"]
        super().__init__(
            config=config,
            resource="mem",
            threshold=cfg["outstanding_delta_bytes"],   # 复用为斜率地板（bytes/sec）
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
        # per-sid outstanding 快照，用于告警栈归因（选 Δ 最大的 sid = 在涨的调用点）
        self._sid_snapshot = {}

    def _iter_stats(self, aggregator):
        """迭代内存聚合数据：yield (key, value, comm, stack_addrs, stack_cnt, pid)
        per-PID 聚合：跨栈求和 ×100（无偏估计）；key=pid → 每进程 1 状态机/1 告警。
        栈归因：取 Δ outstanding 最大的 sid（增长调用点）；无增长则取最大 outstanding sid。
        锁内拷贝，锁外 yield，避免阻塞 BPF 回调。"""
        my_pid = os.getpid()
        with aggregator._lock:
            data = []
            live = set()
            for pid, stacks in aggregator.mem_stats.items():
                if pid == my_pid:
                    continue                        # 排自身（leakdetect 不告自己）
                total = 0
                best_sid = None
                best_delta = 0
                fb_sid = None
                fb_val = -1
                for sid, s in stacks.items():
                    cur = s["alloc_bytes"] - s["free_bytes"]
                    live.add((pid, sid))
                    prev = self._sid_snapshot.get((pid, sid), cur)  # 新 sid: prev=cur → Δ0
                    self._sid_snapshot[(pid, sid)] = cur
                    if cur > fb_val:
                        fb_val = cur
                        fb_sid = sid
                    d = cur - prev
                    if d > best_delta:
                        best_delta = d
                        best_sid = sid
                    if cur > 0:
                        total += cur
                chosen = best_sid if best_delta > 0 else fb_sid
                top = stacks.get(chosen, {}) if chosen is not None else {}
                data.append((pid, total * 100, top.get("comm", ""),
                            top.get("stack_addrs", []),
                            top.get("stack_cnt", 0), pid))
            # 修剪已退出 pid 的快照，防 _sid_snapshot 无界增长
            self._sid_snapshot = {k: v for k, v in self._sid_snapshot.items()
                                   if k in live}
        for item in data:
            yield item
