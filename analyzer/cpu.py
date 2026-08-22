"""CPU 监控：/proc/[pid]/stat 轮询 + CPU% 计算。

对应里程碑：B2
对应文档：leakdetect-b2-design.md §8.7-8.8

CPU 监控不用 BPF，直接轮询 /proc：
  - 每 1s 读 /proc/[pid]/stat 的 utime/stime
  - 与上次差值算 CPU%
  - 返回 top-5 进程

CPU 无泄露检测，仅监控占用率。
"""

import os
import time


class CpuMonitor:
    """轮询 /proc/[pid]/stat 计算 CPU%。"""

    def __init__(self, interval=1):
        self.interval = interval
        self._clk_tck = os.sysconf('SC_CLK_TCK')
        self._last = {}

    def poll(self):
        """返回 [{pid, name, value(cpu%)}] top-5。"""
        now = time.time()
        result = []
        for entry in os.listdir("/proc"):
            if not entry.isdigit():
                continue
            pid = int(entry)
            try:
                with open("/proc/%d/stat" % pid) as f:
                    fields = f.read().split()
                utime = int(fields[13])
                stime = int(fields[14])
                comm = fields[1].strip("()")

                if pid in self._last:
                    old_ut, old_st, old_t = self._last[pid]
                    dt = now - old_t
                    if dt > 0:
                        delta_ticks = (utime + stime) - (old_ut + old_st)
                        cpu_pct = (delta_ticks / self._clk_tck) / dt * 100
                        result.append({
                            "pid": pid,
                            "name": comm,
                            "value": round(cpu_pct, 1)
                        })
                self._last[pid] = (utime, stime, now)
            except (IOError, IndexError):
                continue

        self._last = {pid: v for pid, v in self._last.items()
                      if os.path.exists("/proc/%d" % pid)}
        return sorted(result, key=lambda x: x["value"], reverse=True)
