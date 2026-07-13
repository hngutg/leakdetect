"""泄露检测器基类。

对应里程碑：B1 + B2
"""

import time
import os
import threading

STATE_NORMAL = "normal"
STATE_OBSERVING = "observing"
STATE_LEAK = "leak_suspected"
STATE_RESOLVED = "resolved"


class StackSiteState:
    """单个监控点（PID 或 PID+stack_addrs）的状态追踪。"""

    def __init__(self):
        self.state = STATE_NORMAL
        self.history = []
        self.peak_outstanding = 0
        self.peak_time = 0
        self.state_since = 0
        self.last_check_outstanding = 0


class TrendLeakDetector:
    """通用趋势泄露检测器基类。

    子类需实现：
      - _iter_stats(aggregator): 迭代聚合数据，yield (key, value, comm, stack_addrs, stack_cnt, pid)
      - resource: 资源名（"mem"/"thread"/"fd"）
    """

    def __init__(self, config, resource, threshold, observe_seconds=30,
                 leak_seconds=60, clear_ratio=0.5, clear_seconds=30,
                 resolve_seconds=60, stabilize_seconds=300):
        self.resource = resource
        self.threshold = threshold
        self.observe_seconds = observe_seconds
        self.leak_seconds = leak_seconds
        self.clear_ratio = clear_ratio
        self.clear_seconds = clear_seconds
        self.resolve_seconds = resolve_seconds
        self.stabilize_seconds = stabilize_seconds
        self._lock = threading.Lock()
        self.states = {}
        self.active_alerts = []

    def _iter_stats(self, aggregator):
        """子类实现：迭代聚合数据。yield (key, value, comm, stack_addrs, stack_cnt, pid)"""
        raise NotImplementedError

    def cleanup_dead_states(self):
        """清理已退出进程的状态条目（与 aggregator.cleanup_dead 对应）。"""
        with self._lock:
            pids = set()
            for key in self.states:
                pids.add(key[0] if isinstance(key, tuple) else key)
            dead_pids = {pid for pid in pids
                         if not os.path.exists("/proc/%d" % pid)}
            if dead_pids:
                self.states = {
                    k: v for k, v in self.states.items()
                    if (k[0] if isinstance(k, tuple) else k) not in dead_pids
                }

    def check(self, aggregator, symbolizer):
        """周期调用：检查所有聚合数据，更新状态 + 告警。"""
        now = time.time()
        new_alerts = []

        with self._lock:
            for key, value, comm, stack_addrs, stack_cnt, pid in self._iter_stats(aggregator):
                if key not in self.states:
                    self.states[key] = StackSiteState()
                st = self.states[key]

                st.history.append((now, value))
                cutoff = now - self.leak_seconds * 2
                st.history = [(t, v) for t, v in st.history if t >= cutoff]

                self._update_state(st, now, value, pid)

                if st.state == STATE_LEAK:
                    stack = symbolizer.resolve(self.resource, stack_addrs, stack_cnt, pid)
                    new_alerts.append({
                        "id": "%s-%s" % (self.resource, str(key).replace(" ", "-")),
                        "resource": self.resource,
                        "pid": pid,
                        "process_name": comm,
                        "severity": "leak",
                        "detail": "+%d in %ds" % (value, int(now - st.state_since)),
                        "timestamp": int(now),
                        "stack": stack,
                    })
                elif st.state == STATE_RESOLVED:
                    stack = symbolizer.resolve(self.resource, stack_addrs, stack_cnt, pid)
                    new_alerts.append({
                        "id": "%s-%s" % (self.resource, str(key).replace(" ", "-")),
                        "resource": self.resource,
                        "pid": pid,
                        "process_name": comm,
                        "severity": "resolved",
                        "detail": "resolved: %d (peak %d)" % (value, st.peak_outstanding),
                        "timestamp": int(now),
                        "stack": stack,
                    })

            self.active_alerts = new_alerts
        return new_alerts

    def _update_state(self, st, now, value, pid):
        """状态机流转逻辑。"""
        elapsed = now - st.state_since

        if st.state == STATE_NORMAL:
            if len(st.history) >= 2 and value > st.last_check_outstanding:
                if self._is_growing(st.history, self.observe_seconds):
                    st.state = STATE_OBSERVING
                    st.state_since = now

        elif st.state == STATE_OBSERVING:
            if self._is_leaking(st.history):
                st.state = STATE_LEAK
                st.state_since = now
                st.peak_outstanding = value
                st.peak_time = now
            elif not self._is_growing(st.history, self.observe_seconds):
                st.state = STATE_NORMAL
                st.state_since = now

        elif st.state == STATE_LEAK:
            if not os.path.exists("/proc/%d" % pid):
                st.state = STATE_RESOLVED
                st.state_since = now
                return

            if value > st.peak_outstanding:
                st.peak_outstanding = value
                st.peak_time = now
            if (value < st.peak_outstanding * self.clear_ratio
                    and elapsed > self.clear_seconds):
                st.state = STATE_RESOLVED
                st.state_since = now
            elif now - st.peak_time > self.stabilize_seconds:
                st.state = STATE_RESOLVED
                st.state_since = now

        elif st.state == STATE_RESOLVED:
            if elapsed > self.resolve_seconds:
                st.state = STATE_NORMAL
                st.state_since = now
                st.history = []
                st.peak_outstanding = 0
                st.peak_time = 0

        st.last_check_outstanding = value

    def _is_growing(self, history, duration):
        if len(history) < 2:
            return False
        cutoff = history[-1][0] - duration
        recent = [(t, v) for t, v in history if t >= cutoff]
        if len(recent) < 2:
            return False
        return recent[-1][1] > recent[0][1]

    def _is_leaking(self, history):
        if len(history) < 10:
            return False
        first_t, _ = history[0]
        last_t, _ = history[-1]
        if last_t - first_t < self.leak_seconds:
            return False

        increasing = sum(1 for i in range(1, len(history))
                         if history[i][1] >= history[i - 1][1])
        cond_a = (increasing >= len(history) * 0.8 and
                  history[-1][1] - history[0][1] > self.threshold)

        n = min(5, len(history) // 2)
        first_avg = sum(v for _, v in history[:n]) / n
        last_avg = sum(v for _, v in history[-n:]) / n
        cond_b = (last_avg - first_avg > self.threshold)

        return cond_a or cond_b

    def get_active_alerts(self):
        with self._lock:
            return list(self.active_alerts)
