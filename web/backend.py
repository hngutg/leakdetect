"""后端集成层：初始化所有后端模块，启动后台线程。

对应里程碑：B1 + B2
对应文档：leakdetect-b1-design.md §6.8、leakdetect-b2-design.md §九

B2 变更：4 资源全真实数据（mem + thread + fd + cpu）
Phase 1 变更：cgroup_enum 容器枚举 + display_target 显示过滤（capture all, filter at display）
"""

import os
import sys
import time
import threading

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from core.loader import BpfLoader
from core.ingest import IngestManager
from core.aggregator import Aggregator
from core.config import load_config
from core.cgroup_enum import CgroupEnum
from symbolizer.symbols import Symbolizer
from analyzer.memory import MemoryLeakDetector
from analyzer.threads import ThreadLeakDetector
from analyzer.handles import HandleLeakDetector
from analyzer.mmap import MmapLeakDetector
from analyzer.cpu import CpuMonitor
from storage.db import Database
from alert_logging.alert_logger import AlertLogger


class Backend:
    """后端集成层，替代 mock.py。"""

    def __init__(self, config):
        self.config = config
        self.loader = BpfLoader(config)
        self.aggregator = Aggregator()
        self.symbolizer = None
        self.analyzer_mem = MemoryLeakDetector(config)
        self.analyzer_threads = ThreadLeakDetector(config)
        self.analyzer_fd = HandleLeakDetector(config)
        self.analyzer_mmap = MmapLeakDetector(config)
        self.db = Database(config["storage"]["sqlite_path"])
        self.logger = AlertLogger(config["logging"]["alert_log"])
        self.cpu_monitor = CpuMonitor(config["sampling"]["cpu_interval"])
        self.cpu_stats = []
        self.cgroup_enum = CgroupEnum(refresh_interval=30)
        self.display_target = None
        self._started = False

    def start(self):
        if self._started:
            return

        print("[backend] Loading BPF programs...")
        self.loader.load_mem()
        print("[backend] mem.bpf loaded")
        self.loader.load_threads()
        print("[backend] threads.bpf loaded")
        self.loader.load_fd()
        print("[backend] fd.bpf loaded")

        self.symbolizer = Symbolizer()

        ingest = IngestManager(self.aggregator, self.symbolizer)
        self._ingest = ingest
        self.loader.start_event_loop({
            "threads": ingest.on_thread_event,
        })

        threading.Thread(target=self._map_reader_loop, daemon=True).start()
        threading.Thread(target=self._analyzer_loop, daemon=True).start()
        threading.Thread(target=self._cpu_loop, daemon=True).start()
        threading.Thread(target=self._sampler_loop, daemon=True).start()
        threading.Thread(target=self._dead_pid_cleaner_loop, daemon=True).start()

        self.cgroup_enum.start()
        self._started = True
        print("[backend] All components started.")

    def set_display_target(self, cid):
        """设置显示过滤目标：None=宿主 / cid=容器（仅影响显示，不影响采集存储）。"""
        self.display_target = cid

    def _map_reader_loop(self):
        """B 方案：1s 读 BPF map → set aggregator.mem_stats/fd_stats。"""
        while True:
            try:
                self.aggregator.set_mem_stats(self.loader.read_outstanding_map())
                self.aggregator.set_fd_stats(self.loader.read_fd_count_map())
                self.aggregator.set_mmap_stats(*self.loader.read_mmap_outstanding_map())
            except Exception as e:
                print("[backend] map_reader error: %s" % e)
            time.sleep(1)

    def _dead_pid_cleaner_loop(self):
        """每 60s 清理 allocs 中已退出进程的条目。"""
        while True:
            try:
                n1 = self.loader.clean_dead_pid_allocs()
                n3 = self.loader.clean_dead_tid_mmap_entry_info()
                if n1 + n3 > 0:
                    print("[backend] cleaned %d allocs + %d mmap_entry dead entries" % (n1, n3))
            except Exception as e:
                print("[backend] dead pid cleaner error: %s" % e)
            time.sleep(60)

    def _analyzer_loop(self):
        while True:
            try:
                self.aggregator.cleanup_dead()
                self.analyzer_mem.cleanup_dead_states()
                self.analyzer_threads.cleanup_dead_states()
                self.analyzer_fd.cleanup_dead_states()
                self.analyzer_mmap.cleanup_dead_states()
                alerts = []
                alerts += self.analyzer_mem.check(self.aggregator, self.symbolizer)
                alerts += self.analyzer_mmap.check(self.aggregator, self.symbolizer)
                alerts += self.analyzer_threads.check(self.aggregator, self.symbolizer)
                alerts += self.analyzer_fd.check(self.aggregator, self.symbolizer)
                for a in alerts:
                    a["process_name"] = self.cgroup_enum.pid_cmdline(a["pid"]) or a["process_name"]
                    self.logger.log(a)
                    self.db.write_alert(a)
            except Exception as e:
                print("[backend] analyzer error: %s" % e)
            time.sleep(5)

    def _cpu_loop(self):
        while True:
            try:
                self.cpu_stats = self.cpu_monitor.poll()
            except Exception as e:
                print("[backend] cpu poll error: %s" % e)
            time.sleep(1)

    def _sampler_loop(self):
        while True:
            try:
                for p in self.aggregator.get_per_process_mem()[:5]:
                    self.db.write_sample("mem", p["pid"], p["value"])
                for p in self.aggregator.get_per_process_mmap()[:5]:
                    self.db.write_sample("mmap", p["pid"], p["value"])
                for p in self.aggregator.get_per_process_thread()[:5]:
                    self.db.write_sample("thread", p["pid"], p["value"])
                for p in self.aggregator.get_per_process_fd()[:5]:
                    self.db.write_sample("fd", p["pid"], p["value"])
                for p in self.cpu_stats[:5]:
                    self.db.write_sample("cpu", p["pid"], p["value"])
            except Exception as e:
                print("[backend] sampler error: %s" % e)
            time.sleep(60)

    def get_dashboard_update(self):
        now = int(time.time())
        tpids = self.cgroup_enum.target_pids(self.display_target)
        if self.display_target is not None and not tpids:
            print("[backend] target %s not found (stopped?), showing empty" % self.display_target)
        mem_all = self.aggregator.get_per_process_mem()
        mmap_all = self.aggregator.get_per_process_mmap()
        thr_all = self.aggregator.get_per_process_thread()
        fd_all = self.aggregator.get_per_process_fd()
        cpu_all = self.cpu_stats

        def _top5(pp):
            f = [p for p in pp if p["pid"] in tpids]
            result = sorted(f, key=lambda x: x["value"], reverse=True)[:5]
            for p in result:
                p["name"] = self.cgroup_enum.pid_cmdline(p["pid"]) or p["name"]
            return result

        alerts = [a for a in (self.analyzer_mem.get_active_alerts()
                  + self.analyzer_mmap.get_active_alerts()
                  + self.analyzer_threads.get_active_alerts()
                  + self.analyzer_fd.get_active_alerts()) if a["pid"] in tpids]
        _mem = sum(p["value"] for p in mem_all if p["pid"] in tpids)
        _mmap = sum(p["value"] for p in mmap_all if p["pid"] in tpids)
        _thread = sum(p["value"] for p in thr_all if p["pid"] in tpids)
        _fd = sum(p["value"] for p in fd_all if p["pid"] in tpids)
        _cpu = sum(p["value"] for p in cpu_all if p["pid"] in tpids)
        print("[debug] target=%s mem=%d mmap=%d thread=%d fd=%d cpu=%d" % (
            self.display_target or "host", _mem, _mmap, _thread, _fd, _cpu))
        return {
            "type": "dashboard_update",
            "timestamp": now,
            "filter": {"container_id": self.display_target, "pid": None},
            "latest_points": {
                "mem": {"t": now, "v": _mem},
                "mmap": {"t": now, "v": _mmap},
                "thread": {"t": now, "v": _thread},
                "fd": {"t": now, "v": _fd},
                "cpu": {"t": now, "v": _cpu},
            },
            "per_process": {
                "mem": _top5(mem_all),
                "mmap": _top5(mmap_all),
                "thread": _top5(thr_all),
                "fd": _top5(fd_all),
                "cpu": _top5(cpu_all),
            },
            "alerts": alerts,
            "containers": self.cgroup_enum.enumerate(),
        }

    def get_history(self, resource, range_tag):
        return self.db.query_history(resource, range_tag)

    def get_alerts(self, range_tag):
        return self.db.query_alerts(range_tag)

    def get_monitoring_config(self):
        """返回当前监控参数（从分析器实例属性读取）。"""
        return {
            "mem": {
                "outstanding_delta_bytes": self.analyzer_mem.threshold,
                "observe_seconds": self.analyzer_mem.observe_seconds,
                "leak_seconds": self.analyzer_mem.leak_seconds,
                "clear_ratio": self.analyzer_mem.clear_ratio,
                "clear_seconds": self.analyzer_mem.clear_seconds,
                "resolve_seconds": self.analyzer_mem.resolve_seconds,
                "stabilize_seconds": self.analyzer_mem.stabilize_seconds,
                "grace_seconds": self.analyzer_mem.grace_seconds,
                "confirm_seconds": self.analyzer_mem.confirm_seconds,
            },
            "thread": {
                "delta_threshold": self.analyzer_threads.threshold,
                "observe_seconds": self.analyzer_threads.observe_seconds,
                "leak_seconds": self.analyzer_threads.leak_seconds,
                "clear_ratio": self.analyzer_threads.clear_ratio,
                "clear_seconds": self.analyzer_threads.clear_seconds,
                "resolve_seconds": self.analyzer_threads.resolve_seconds,
                "stabilize_seconds": self.analyzer_threads.stabilize_seconds,
                "grace_seconds": self.analyzer_threads.grace_seconds,
                "confirm_seconds": self.analyzer_threads.confirm_seconds,
            },
            "fd": {
                "delta_threshold": self.analyzer_fd.threshold,
                "observe_seconds": self.analyzer_fd.observe_seconds,
                "leak_seconds": self.analyzer_fd.leak_seconds,
                "clear_ratio": self.analyzer_fd.clear_ratio,
                "clear_seconds": self.analyzer_fd.clear_seconds,
                "resolve_seconds": self.analyzer_fd.resolve_seconds,
                "stabilize_seconds": self.analyzer_fd.stabilize_seconds,
                "grace_seconds": self.analyzer_fd.grace_seconds,
                "confirm_seconds": self.analyzer_fd.confirm_seconds,
            },
            "mmap": {
                "outstanding_delta_bytes": self.analyzer_mmap.threshold,
                "observe_seconds": self.analyzer_mmap.observe_seconds,
                "leak_seconds": self.analyzer_mmap.leak_seconds,
                "clear_ratio": self.analyzer_mmap.clear_ratio,
                "clear_seconds": self.analyzer_mmap.clear_seconds,
                "resolve_seconds": self.analyzer_mmap.resolve_seconds,
                "stabilize_seconds": self.analyzer_mmap.stabilize_seconds,
                "grace_seconds": self.analyzer_mmap.grace_seconds,
                "confirm_seconds": self.analyzer_mmap.confirm_seconds,
            },
            "cpu": {"cpu_interval": self.cpu_monitor.interval},
            "sampling_rate": self.config["sampling"]["mem"],
        }

    def update_monitoring_config(self, data):
        """运行时更新监控参数（更新分析器实例属性，下次 check() 立即生效）。"""
        resource_map = {
            "mem": self.analyzer_mem,
            "thread": self.analyzer_threads,
            "fd": self.analyzer_fd,
            "mmap": self.analyzer_mmap,
        }
        param_map = {
            "outstanding_delta_bytes": "threshold",
            "delta_threshold": "threshold",
            "observe_seconds": "observe_seconds",
            "leak_seconds": "leak_seconds",
            "clear_ratio": "clear_ratio",
            "clear_seconds": "clear_seconds",
            "resolve_seconds": "resolve_seconds",
            "stabilize_seconds": "stabilize_seconds",
            "grace_seconds": "grace_seconds",
            "confirm_seconds": "confirm_seconds",
        }
        for resource, analyzer in resource_map.items():
            if resource not in data:
                continue
            d = data[resource]
            for key, attr in param_map.items():
                if key in d:
                    val = d[key]
                    if isinstance(val, (int, float)):
                        setattr(analyzer, attr, val)
                    else:
                        try:
                            val = float(val) if attr == "clear_ratio" else int(float(val))
                            setattr(analyzer, attr, val)
                        except (TypeError, ValueError):
                            pass
        if "cpu" in data and "cpu_interval" in data["cpu"]:
            val = data["cpu"]["cpu_interval"]
            if isinstance(val, (int, float)):
                self.cpu_monitor.interval = val
            else:
                try:
                    self.cpu_monitor.interval = int(float(val))
                except (TypeError, ValueError):
                    pass
        print("[backend] monitoring config updated")


backend = None
