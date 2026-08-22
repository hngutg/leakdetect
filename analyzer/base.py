"""泄露检测器基类。

对应里程碑：B1 + B2
精度专项（2026-08-21）：_is_leaking 改为 OLS 斜率 + 显著性（噪声鲁棒），
  新增启动宽限 grace_seconds；阈值语义从 delta 字节/计数 → 斜率（单位/秒）。
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
        self.first_seen = 0   # 首次见到该 key 的时间（启动宽限用）
        self.confirmed = False   # 疑似→确认：LEAK 持续 confirm_seconds 且仍 leaking


class TrendLeakDetector:
    """通用趋势泄露检测器基类。

    子类需实现：
      - _iter_stats(aggregator): 迭代聚合数据，yield (key, value, comm, stack_addrs, stack_cnt, pid)
      - resource: 资源名（"mem"/"thread"/"fd"）

    泄漏判定（精度专项）：在 history 窗口（2×leak_seconds）上做 OLS 线性回归，
    斜率 > threshold（幅度地板，单位/秒，可配）且斜率/SE > significance_z（显著性）才算泄露。
    对稳态噪声：斜率期望≈0、SE 大 → 不显著 → 不误报；对真实泄露：斜率稳定为正、
    t 极大 → 命中。×100 采样补偿对 t 统计量尺度无关（斜率与 SE 同比缩放）。
    """

    def __init__(self, config, resource, threshold, observe_seconds=30,
                 leak_seconds=60, clear_ratio=0.5, clear_seconds=30,
                 resolve_seconds=60, stabilize_seconds=300,
                 significance_z=3.0, grace_seconds=120, confirm_seconds=240):
        self.resource = resource
        self.threshold = threshold                  # 斜率地板（单位/秒）
        self.observe_seconds = observe_seconds
        self.leak_seconds = leak_seconds
        self.clear_ratio = clear_ratio
        self.clear_seconds = clear_seconds
        self.resolve_seconds = resolve_seconds
        self.stabilize_seconds = stabilize_seconds
        self.significance_z = significance_z
        self.grace_seconds = grace_seconds
        self.confirm_seconds = confirm_seconds      # 疑似→确认：LEAK 持续此时长且仍 leaking 才升 confirmed
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
                    st = StackSiteState()
                    st.first_seen = now
                    self.states[key] = st
                else:
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
                        "severity": "confirmed" if st.confirmed else "suspected",
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
            # 启动宽限：新进程前 grace_seconds 只攒历史不判定，防启动爬坡误报。
            # 不 early-return：末行 last_check_outstanding 照常更新。
            if now - st.first_seen >= self.grace_seconds:
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

            # 疑似→确认：LEAK 持续 confirm_seconds 且 _is_leaking 仍 true（spurious 数据已老化出窗口）
            # 才升 confirmed。随机游走伪信号此时 _is_leaking 已转 false → 不升确认，维持疑似→stabilize 消除。
            if not st.confirmed and now - st.state_since >= self.confirm_seconds and self._is_leaking(st.history):
                st.confirmed = True

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
                st.confirmed = False

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
        """OLS 线性回归斜率 + 显著性判定（噪声鲁棒）。

        - 幅度地板：slope > threshold（单位/秒，可配），滤掉微小漂移。
        - 显著性：slope/SE > significance_z，滤掉噪声驱动的虚假斜率。
          自相关会使 t 虚高 ~1.4×，故 z 默认 3.0（实效≈2.1）。
        - 原始 history，不平滑（EWMA+t 检验统计不一致，会放大显著性→反效果）。
        """
        if len(history) < 6:
            return False
        first_t = history[0][0]
        last_t = history[-1][0]
        if last_t - first_t < self.leak_seconds:
            return False

        xs = [t - first_t for t, _ in history]
        ys = [v for _, v in history]
        n = len(xs)
        xbar = sum(xs) / n
        ybar = sum(ys) / n
        Sxx = sum((x - xbar) ** 2 for x in xs)
        Sxy = sum((xs[i] - xbar) * (ys[i] - ybar) for i in range(n))
        if Sxx == 0:
            return False
        slope = Sxy / Sxx

        # 残差方差 + 斜率标准误（n≥6 保证 n-2≥4）
        s2 = sum((ys[i] - (ybar + slope * (xs[i] - xbar))) ** 2
                 for i in range(n)) / (n - 2)
        SE = (s2 / Sxx) ** 0.5
        sig = (SE == 0) or (slope / SE > self.significance_z)

        return slope > self.threshold and sig

    def get_active_alerts(self):
        with self._lock:
            return list(self.active_alerts)
