"""后端集成层：初始化所有后端模块，启动后台线程。

对应里程碑：B1 + B2
对应文档：leakdetect-b1-design.md §6.8、leakdetect-b2-design.md §九

B2 变更：4 资源全真实数据（mem + thread + fd + cpu）
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
from symbolizer.symbols import Symbolizer
from analyzer.memory import MemoryLeakDetector
from analyzer.threads import ThreadLeakDetector
from analyzer.handles import HandleLeakDetector
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
        self.db = Database(config["storage"]["sqlite_path"])
        self.logger = AlertLogger(config["logging"]["alert_log"])
        self.cpu_monitor = CpuMonitor(config["sampling"]["cpu_interval"])
        self.cpu_stats = []
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
            "mem": ingest.on_mem_event,
            "threads": ingest.on_thread_event,
            "fd": ingest.on_fd_event,
        })

        threading.Thread(target=self._analyzer_loop, daemon=True).start()
        threading.Thread(target=self._cpu_loop, daemon=True).start()
        threading.Thread(target=self._sampler_loop, daemon=True).start()

        self._started = True
        print("[backend] All components started.")

    def _analyzer_loop(self):
        while True:
            try:
                self.aggregator.cleanup_dead()
                self.analyzer_mem.cleanup_dead_states()
                self.analyzer_threads.cleanup_dead_states()
                self.analyzer_fd.cleanup_dead_states()
                alerts = []
                alerts += self.analyzer_mem.check(self.aggregator, self.symbolizer)
                alerts += self.analyzer_threads.check(self.aggregator, self.symbolizer)
                alerts += self.analyzer_fd.check(self.aggregator, self.symbolizer)
                for a in alerts:
                    self.logger.log(a)
                    self.db.write_alert(a)
                if hasattr(self, '_ingest'):
                    ing = self._ingest
                    print("[debug] fd_stats: open=%d close_matched=%d close_unmatched=%d" % (
                        ing._fd_open_total, ing._fd_close_matched, ing._fd_close_unmatched))
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
                for p in self.aggregator.get_per_process_mem():
                    self.db.write_sample("mem", p["pid"], p["value"])
                for p in self.aggregator.get_per_process_thread():
                    self.db.write_sample("thread", p["pid"], p["value"])
                for p in self.aggregator.get_per_process_fd():
                    self.db.write_sample("fd", p["pid"], p["value"])
                for p in self.cpu_stats:
                    self.db.write_sample("cpu", p["pid"], p["value"])
            except Exception as e:
                print("[backend] sampler error: %s" % e)
            time.sleep(60)

    def get_dashboard_update(self):
        now = int(time.time())
        alerts = (self.analyzer_mem.get_active_alerts() +
                  self.analyzer_threads.get_active_alerts() +
                  self.analyzer_fd.get_active_alerts())
        _mem = self.aggregator.get_total_outstanding()
        _thread = self.aggregator.get_total_thread_count()
        _fd = self.aggregator.get_total_fd_count()
        _cpu = sum(p["value"] for p in self.cpu_stats)
        _mem_pids = len(self.aggregator.mem_stats)
        _thread_pids = len(self.aggregator.thread_stats)
        _fd_pids = len(self.aggregator.fd_stats)
        print("[debug] mem=%d(%dpids) thread=%d(%dpids) fd=%d(%dpids) cpu=%d" % (
            _mem, _mem_pids, _thread, _thread_pids, _fd, _fd_pids, _cpu))
        return {
            "type": "dashboard_update",
            "timestamp": now,
            "filter": {"container_id": None, "pid": None},
            "latest_points": {
                "mem": {"t": now, "v": _mem},
                "thread": {"t": now, "v": _thread},
                "fd": {"t": now, "v": _fd},
                "cpu": {"t": now, "v": _cpu},
            },
            "per_process": {
                "mem": self.aggregator.get_per_process_mem(),
                "thread": self.aggregator.get_per_process_thread(),
                "fd": self.aggregator.get_per_process_fd(),
                "cpu": self.cpu_stats,
            },
            "alerts": alerts,
            "containers": [],
        }

    def get_history(self, resource, range_tag):
        return self.db.query_history(resource, range_tag)


backend = None
