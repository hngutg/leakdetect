"""mock 数据生产者（F1 阶段替代真实后端）。

对应里程碑：F1 + F2
对应文档：frontend-design.md §十 mock 数据策略

生成符合 dashboard_update 契约的 mock 数据：
- 内存/句柄缓慢增长（模拟泄露，触发告警）
- 线程/CPU 波动（正常状态）
- 告警在超阈值时生成（含伪造栈帧）
- 容器列表固定
- 历史数据末尾与实时数据当前值平滑衔接
"""

import time
import random
import math


class MockProducer:
    """生成 mock dashboard_update 数据。"""

    def __init__(self):
        self.start_time = time.time()
        self.containers = [
            {"id": "a3f4b2c1d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0", "name": "nginx-server", "pid_count": 5},
            {"id": "b4e5c3d2e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1", "name": "mysql-db", "pid_count": 3},
            {"id": "c5f6d4e3f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2", "name": "app-worker", "pid_count": 4},
            {"id": "d6a7e5f4a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3", "name": "redis-cache", "pid_count": 2},
        ]
        self.mem_base = 64 * 1024 * 1024
        self.thread_base = 20
        self.fd_base = 80
        self.cpu_base = 15.0
        self.base_values = {
            "mem": self.mem_base,
            "thread": self.thread_base,
            "fd": self.fd_base,
            "cpu": self.cpu_base,
        }
        self.processes = [
            {"pid": 1234, "name": "nginx"},
            {"pid": 5678, "name": "mysql"},
            {"pid": 9012, "name": "app-worker"},
            {"pid": 3456, "name": "redis-server"},
            {"pid": 7890, "name": "sshd"},
            {"pid": 1111, "name": "systemd"},
            {"pid": 2222, "name": "kthreadd"},
        ]
        self.filter_config = {
            "mode": "disabled",
            "name_regex": "",
            "pid_list": [],
        }
        self.selected_container = None
        self.container_pids = {
            "a3f4b2c1d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0": [1234],
            "b4e5c3d2e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1": [5678],
            "c5f6d4e3f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2": [9012],
            "d6a7e5f4a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3": [3456],
        }

    def set_selected_container(self, cid):
        """设置当前选中的容器（None=全部）。"""
        self.selected_container = cid

    def _get_current_value(self, resource):
        """根据运行时间计算当前值（历史末尾和实时数据共用，保证衔接）。"""
        elapsed = time.time() - self.start_time
        if resource == "mem":
            return self.mem_base + elapsed * 2 * 1024 * 1024 / 60
        elif resource == "fd":
            return self.fd_base + elapsed * 0.5 / 60
        else:
            return self.base_values[resource]

    def _is_filtered(self, pid, name):
        """检查进程是否应被过滤掉（True=过滤掉，不展示）。"""
        mode = self.filter_config["mode"]
        if mode == "disabled":
            return False
        name_regex = self.filter_config["name_regex"]
        pid_list = self.filter_config["pid_list"]
        name_match = False
        pid_match = False
        if name_regex:
            import re
            try:
                if re.search(name_regex, name):
                    name_match = True
            except re.error:
                pass
        if pid in pid_list:
            pid_match = True
        matched = name_match or pid_match
        if mode == "whitelist":
            return not matched
        if mode == "blacklist":
            return matched
        return False

    def get_dashboard_update(self):
        elapsed = time.time() - self.start_time
        now = int(time.time())

        mem_current = int(self._get_current_value("mem"))
        mem_current += random.randint(-524288, 524288)

        thread_current = self.thread_base + int(5 * math.sin(elapsed / 30)) + random.randint(-1, 1)
        thread_current = max(1, thread_current)

        fd_current = int(self._get_current_value("fd"))
        fd_current += random.randint(-2, 2)
        fd_current = max(1, fd_current)

        cpu_current = self.cpu_base + 8 * math.sin(elapsed / 10) + random.uniform(-2, 2)
        cpu_current = max(0.1, cpu_current)

        alerts = self._generate_alerts(elapsed, now, mem_current, fd_current)

        per_process = {
            "mem": [
                {"pid": 1234, "name": "nginx", "value": mem_current // 2, "delta_60s": 2097152},
                {"pid": 5678, "name": "mysql", "value": mem_current // 4, "delta_60s": 0},
            ],
            "thread": [
                {"pid": 5678, "name": "mysql", "value": thread_current // 2},
                {"pid": 9012, "name": "app", "value": thread_current // 3},
            ],
            "fd": [
                {"pid": 9012, "name": "app", "value": fd_current // 2, "delta_60s": 12},
                {"pid": 1234, "name": "nginx", "value": fd_current // 4, "delta_60s": 0},
            ],
            "cpu": [
                {"pid": 1234, "name": "nginx", "value": round(cpu_current, 1)},
                {"pid": 5678, "name": "mysql", "value": round(cpu_current * 0.7, 1)},
            ],
        }

        for resource in per_process:
            per_process[resource] = [
                p for p in per_process[resource]
                if not self._is_filtered(p["pid"], p["name"])
            ]

        alerts = [
            a for a in alerts
            if not self._is_filtered(a["pid"], a["process_name"])
        ]

        if self.selected_container:
            allowed_pids = self.container_pids.get(self.selected_container, [])
            for resource in per_process:
                per_process[resource] = [
                    p for p in per_process[resource]
                    if p["pid"] in allowed_pids
                ]
            alerts = [
                a for a in alerts
                if a["pid"] in allowed_pids
            ]

        return {
            "type": "dashboard_update",
            "timestamp": now,
            "filter": {"container_id": None, "pid": None},
            "latest_points": {
                "mem": {"t": now, "v": mem_current},
                "thread": {"t": now, "v": thread_current},
                "fd": {"t": now, "v": fd_current},
                "cpu": {"t": now, "v": round(cpu_current, 1)},
            },
            "per_process": per_process,
            "alerts": alerts,
            "containers": self.containers,
        }

    def _generate_alerts(self, elapsed, now, mem_current, fd_current):
        alerts = []
        if elapsed > 30:
            delta_mb = (mem_current - self.mem_base) // (1024 * 1024)
            alerts.append({
                "id": "mock-mem-001",
                "resource": "mem",
                "pid": 1234,
                "process_name": "nginx",
                "severity": "leak",
                "detail": "outstanding +%dMB in %ds" % (delta_mb, int(elapsed)),
                "timestamp": now,
                "stack": [
                    {"func": "main()", "addr": "0x401000"},
                    {"func": "start_worker()", "addr": "0x4012a0"},
                    {"func": "handle_request()", "addr": "0x401580"},
                    {"func": "malloc()", "addr": "0x401800"},
                ],
            })
        if elapsed > 60:
            delta_fd = fd_current - self.fd_base
            alerts.append({
                "id": "mock-fd-001",
                "resource": "fd",
                "pid": 9012,
                "process_name": "app",
                "severity": "leak",
                "detail": "+%d FD in %ds" % (delta_fd, int(elapsed)),
                "timestamp": now,
                "stack": [
                    {"func": "main()", "addr": "0x402000"},
                    {"func": "process_loop()", "addr": "0x4022a0"},
                    {"func": "open()", "addr": "0x402580"},
                ],
            })
        return alerts

    def get_history(self, resource, range_tag="1d"):
        now = int(time.time())
        ranges = {"1d": (86400, 60), "7d": (604800, 600), "30d": (2592000, 1800)}
        duration, interval = ranges.get(range_tag, ranges["1d"])
        count = min(duration // interval, 1440)

        base = self.base_values[resource]
        current = self._get_current_value(resource)
        is_leak = resource in ("mem", "fd")

        series = []
        for i in range(count):
            t = now - (count - 1 - i) * interval
            if is_leak:
                progress = i / max(count - 1, 1)
                v = base + (current - base) * progress
                noise = random.uniform(-0.03, 0.03) * v
                v += noise
            else:
                v = base + 8 * math.sin(i * interval / 600) + random.uniform(-2, 2)

            if resource == "mem":
                series.append({"t": t, "v": int(v)})
            else:
                series.append({"t": t, "v": round(v, 1)})

        if series and is_leak:
            if resource == "mem":
                series[-1]["v"] = int(current)
            else:
                series[-1]["v"] = round(current, 1)

        return {
            "range": range_tag,
            "interval": "%ds" % interval,
            "series": series,
            "per_process": [{"pid": 1234, "name": "nginx", "value": int(base * 0.6)}],
        }

    def get_alerts(self, range_tag="24h"):
        """生成 mock 历史告警。"""
        now = int(time.time())
        history = []
        for i in range(5):
            t = now - random.randint(3600, 86400)
            resource = random.choice(["mem", "fd", "thread"])
            pid = random.choice([1234, 5678, 9012])
            pname = random.choice(["nginx", "mysql", "app"])
            alloc_fn = "malloc()" if resource == "mem" else ("open()" if resource == "fd" else "clone()")
            history.append({
                "id": "hist-%03d" % i,
                "resource": resource,
                "pid": pid,
                "process_name": pname,
                "severity": "leak",
                "detail": "outstanding +%d%s in 60s" % (
                    random.randint(1, 10),
                    "MB" if resource == "mem" else " FD" if resource == "fd" else " threads",
                ),
                "timestamp": t,
                "stack": [
                    {"func": "main()", "addr": "0x%06x" % random.randint(0x400000, 0x410000)},
                    {"func": "worker_loop()", "addr": "0x%06x" % random.randint(0x400000, 0x410000)},
                    {"func": alloc_fn, "addr": "0x%06x" % random.randint(0x400000, 0x410000)},
                ],
            })
        history.sort(key=lambda a: a["timestamp"], reverse=True)
        return history

    def get_filter_config(self):
        return dict(self.filter_config)

    def save_filter_config(self, config):
        self.filter_config = {
            "mode": config.get("mode", "disabled"),
            "name_regex": config.get("name_regex", ""),
            "pid_list": config.get("pid_list", []),
        }
        pid_str = ",".join(str(p) for p in self.filter_config["pid_list"])
        preview = self.preview_filter(self.filter_config["name_regex"], pid_str)
        return {
            "status": "applied",
            "matched_pids": [p["pid"] for p in preview["matched"]],
        }

    def preview_filter(self, name_regex, pid_list_str):
        import re
        matched = []
        unmatched = []
        pids = []
        if pid_list_str:
            for s in pid_list_str.split(","):
                s = s.strip()
                if s.isdigit():
                    pids.append(int(s))
        for p in self.processes:
            name_match = False
            pid_match = False
            if name_regex:
                try:
                    if re.search(name_regex, p["name"]):
                        name_match = True
                except re.error:
                    pass
            if p["pid"] in pids:
                pid_match = True
            if name_match or pid_match:
                matched.append(p)
            else:
                unmatched.append(p)
        return {"matched": matched, "unmatched": unmatched}


producer = MockProducer()
