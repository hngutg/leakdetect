"""容器枚举 + cgroup 映射。

对应里程碑：B3
对应文档：plan.md §5.2、§十一.2

遍历 /proc/*/cgroup 解析容器（/kubepods/、/docker/、/lxc/），
按 container_id 聚合 PID；docker ps 取容器名；后台 30s 刷新。
供：前端下拉框（enumerate）+ 后端显示过滤（target_pids）。
"""

import os
import subprocess
import threading
import time


_CONTAINER_PREFIXES = ("/kubepods/", "/docker/", "/lxc/")


class CgroupEnum:
    """枚举节点上的容器，维护 PID↔容器 映射（后台 30s 刷新）。"""

    def __init__(self, refresh_interval=30):
        self._lock = threading.Lock()
        self._containers = []      # [{id, id_short, name, image, pids(set), cgroup_path}]
        self._host_pids = set()
        self._pid_cmdline = {}     # {pid: cmdline}（ps -ef CMD 风格，30s 刷新）
        self._refresh_interval = refresh_interval
        self._stop = threading.Event()
        self._thread = None

    def start(self):
        """启动后台刷新线程；初始建一次（失败不抛，避免拖垮 backend）。"""
        try:
            self._refresh()
        except Exception as e:
            print("[cgroup_enum] initial refresh err: %s" % e)
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def _loop(self):
        while not self._stop.is_set():
            time.sleep(self._refresh_interval)
            try:
                self._refresh()
            except Exception as e:
                print("[cgroup_enum] refresh err: %s" % e)

    def enumerate(self):
        """供前端下拉：返回无 pids 列表（避免每秒推大 pid 数组）。"""
        with self._lock:
            return [{
                "id": c["id"],
                "id_short": c["id_short"],
                "name": c["name"],
                "image": c["image"],
                "pid_count": len(c["pids"]),
            } for c in self._containers]

    def target_pids(self, cid):
        """cid=None → 宿主 PID 集；cid=X → 该容器 PID 集（找不到返回空集）。"""
        with self._lock:
            if cid is None:
                return set(self._host_pids)
            for c in self._containers:
                if c["id"] == cid:
                    return set(c["pids"])
            return set()

    def _refresh(self):
        cid_pids = {}      # {cid: set(pids)}
        all_pids = []
        pid_cmdline = {}   # {pid: cmdline}（全 pid，含宿主+容器）
        for pid_s in os.listdir("/proc"):
            if not pid_s.isdigit():
                continue
            pid = int(pid_s)
            all_pids.append(pid)
            # cmdline（全 pid；内核线程/异常 → None，调用方回退 comm）
            cl = self._read_cmdline(pid)
            if cl:
                pid_cmdline[pid] = cl
            try:
                cgpath = self._read_container_cgroup(pid)
            except Exception:
                cgpath = None
            if cgpath is None:
                continue
            cid = cgpath.split("/")[-1]      # basename = 容器 ID
            if not cid:
                continue
            cid_pids.setdefault(cid, set()).add(pid)
        host_pids = set(all_pids) - {p for ps in cid_pids.values() for p in ps}
        name_map = self._docker_names()     # cid → (name, image)
        containers = [{
            "id": cid,
            "id_short": cid[:12],
            "name": name_map.get(cid, (cid[:12], ""))[0],
            "image": name_map.get(cid, (cid[:12], ""))[1],
            "pids": pids,
            "cgroup_path": "",
        } for cid, pids in cid_pids.items()]
        with self._lock:
            self._containers = containers
            self._host_pids = host_pids
            self._pid_cmdline = pid_cmdline

    def _read_container_cgroup(self, pid):
        """读 /proc/[pid]/cgroup，返回第一条含容器前缀的 cgroup path（已去尾斜杠）。"""
        for line in open("/proc/%d/cgroup" % pid):
            parts = line.strip().split(":", 2)
            if len(parts) < 3:
                continue
            path = parts[2]
            if any(p in path for p in _CONTAINER_PREFIXES):
                return path.rstrip("/")
        return None

    def _docker_names(self):
        """docker ps 取 cid → (name, image)；不可用返回空 dict。"""
        m = {}
        try:
            out = subprocess.run(
                ["docker", "ps", "--no-trunc", "--format",
                 "{{.ID}}\t{{.Names}}\t{{.Image}}"],
                capture_output=True, text=True, timeout=2,
            )
            for line in out.stdout.splitlines():
                f = line.split("\t")
                if len(f) >= 3:
                    m[f[0]] = (f[1], f[2])
        except Exception:
            pass
        return m

    def _read_cmdline(self, pid):
        """读 /proc/[pid]/cmdline（ps -ef CMD 风格）：\\0 分隔 → 空格 join。
        内核线程/异常/空 → None（调用方回退 comm）。"""
        try:
            with open("/proc/%d/cmdline" % pid, "rb") as f:
                data = f.read()
            if not data:
                return None
            parts = [p for p in data.split(b"\x00") if p]
            if not parts:
                return None
            return " ".join(p.decode("utf-8", "replace") for p in parts)
        except Exception:
            return None

    def pid_cmdline(self, pid):
        """返回 pid 的 cmdline（30s 缓存）；无则 None（调用方回退 BPF comm）。"""
        with self._lock:
            return self._pid_cmdline.get(pid)

    def stop(self):
        self._stop.set()
