"""SQLite 读写：周期采样 + 告警存储 + 历史查询。

对应里程碑：B1
对应文档：leakdetect-b1-design.md §6.6
线程安全：threading.Lock 保护 SQLite 连接
"""

import os
import time
import sqlite3
import threading


class Database:
    """SQLite 存储管理。"""

    def __init__(self, path):
        self.path = path
        self._lock = threading.Lock()

        dir_path = os.path.dirname(path)
        if dir_path and not os.path.exists(dir_path):
            os.makedirs(dir_path)

        self.conn = sqlite3.connect(path, check_same_thread=False)
        self._init_schema()

    def _init_schema(self):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        schema_path = os.path.join(root, "storage", "schema.sql")
        with open(schema_path) as f:
            self.conn.executescript(f.read())
            self.conn.commit()

    def write_sample(self, resource, pid, value, container_id=None):
        """写入采样数据（每 60s 调用）。"""
        with self._lock:
            self.conn.execute(
                "INSERT INTO samples (timestamp, resource, pid, value, container_id) "
                "VALUES (?, ?, ?, ?, ?)",
                (int(time.time()), resource, pid, value, container_id)
            )
            self.conn.commit()

    def write_alert(self, alert):
        """写入告警记录。"""
        import json
        with self._lock:
            self.conn.execute(
                "INSERT OR REPLACE INTO alerts (id, timestamp, resource, pid, "
                "process_name, severity, detail, stack_json) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (alert["id"], alert["timestamp"], alert["resource"],
                 alert["pid"], alert.get("process_name", ""),
                 alert["severity"], alert["detail"],
                 json.dumps(alert.get("stack", [])))
            )
            self.conn.commit()

    def query_history(self, resource, range_tag):
        """查询历史时序数据（REST /api/history 调用）。"""
        ranges = {"1d": 86400, "7d": 604800, "30d": 2592000}
        duration = ranges.get(range_tag, 86400)
        cutoff = int(time.time()) - duration
        with self._lock:
            cur = self.conn.execute(
                "SELECT timestamp, value FROM samples "
                "WHERE resource=? AND timestamp>=? ORDER BY timestamp",
                (resource, cutoff)
            )
            series = [{"t": row[0], "v": row[1]} for row in cur.fetchall()]
        return {"range": range_tag, "series": series}

    def query_alerts(self, range_tag):
        """查询历史告警（REST /api/alerts 调用）。"""
        import json
        ranges = {"24h": 86400, "1d": 86400, "7d": 604800, "30d": 2592000}
        duration = ranges.get(range_tag, 86400)
        cutoff = int(time.time()) - duration
        with self._lock:
            cur = self.conn.execute(
                "SELECT id, timestamp, resource, pid, process_name, "
                "severity, detail, stack_json FROM alerts "
                "WHERE timestamp >= ? ORDER BY timestamp DESC",
                (cutoff,)
            )
            alerts = []
            for row in cur.fetchall():
                try:
                    stack = json.loads(row[7]) if row[7] else []
                except (ValueError, TypeError):
                    stack = []
                alerts.append({
                    "id": row[0],
                    "timestamp": row[1],
                    "resource": row[2],
                    "pid": row[3],
                    "process_name": row[4],
                    "severity": row[5],
                    "detail": row[6],
                    "stack": stack,
                })
        return alerts
