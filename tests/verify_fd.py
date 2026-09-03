#!/usr/bin/env python3
"""verify_fd.py - 对比 BPF fd_count_map 与 /proc/pid/fd 真实值

用法: sudo python3 tests/verify_fd.py [pid] [interval秒]
默认: pid=1 (systemd), interval=5

依赖: libbpf.so (首选) 或 bpftool (备选)
"""
import os
import sys
import time
import json
import re
import subprocess
import ctypes


# ---------- 结构体定义（与 loader.py / common.h 一致） ----------

class FdCountKey(ctypes.Structure):
    _fields_ = [("pid", ctypes.c_ulonglong)]


class FdCountVal(ctypes.Structure):
    _fields_ = [
        ("open_count", ctypes.c_ulonglong),
        ("close_count", ctypes.c_ulonglong),
        ("stack_addrs", ctypes.c_ulonglong * 8),
        ("comm", ctypes.c_char * 16),
        ("stack_cnt", ctypes.c_int),
    ]


# ---------- libbpf 加载（与 loader.py _load_libbpf 一致） ----------

def _load_libbpf():
    for name in ("libbpf.so.1", "libbpf.so.0", "libbpf.so"):
        try:
            return ctypes.CDLL(name)
        except OSError:
            continue
    return None


libbpf = _load_libbpf()
HAS_LIBBPF = False

if libbpf:
    try:
        libbpf.bpf_map_get_next_key.restype = ctypes.c_int
        libbpf.bpf_map_get_next_key.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p]
        libbpf.bpf_map_lookup_elem.restype = ctypes.c_int
        libbpf.bpf_map_lookup_elem.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p]
        libbpf.bpf_map_get_fd_by_id.restype = ctypes.c_int
        libbpf.bpf_map_get_fd_by_id.argtypes = [ctypes.c_uint32]
        HAS_LIBBPF = True
    except AttributeError:
        HAS_LIBBPF = False


# ---------- bpftool 辅助 ----------

def get_map_id():
    """通过 bpftool 找到 fd_count_map 的 ID"""
    try:
        r = subprocess.run(["bpftool", "map", "list", "-j"],
                           capture_output=True, text=True, timeout=5)
        for m in json.loads(r.stdout or "[]"):
            if m.get("name") == "fd_count_map":
                return m["id"]
    except Exception:
        pass
    try:
        r = subprocess.run(["bpftool", "map", "list"],
                           capture_output=True, text=True, timeout=5)
        for line in r.stdout.splitlines():
            if "fd_count_map" in line:
                m = re.search(r'(\d+):', line)
                if m:
                    return int(m.group(1))
    except Exception:
        pass
    return None


def parse_hex(data):
    """bpftool JSON hex -> bytes（兼容 list 和 string 格式）"""
    if isinstance(data, list):
        return bytes(int(h, 16) for h in data)
    if isinstance(data, str):
        return bytes.fromhex(data.replace(" ", ""))
    return b""


# ---------- 方式 1: libbpf ctypes（首选，与 loader.py 逻辑一致） ----------

def get_bpf_fd_stats_libbpf():
    map_id = get_map_id()
    if map_id is None:
        return None
    fd = libbpf.bpf_map_get_fd_by_id(map_id)
    if fd < 0:
        return None
    try:
        stats = {}
        key = FdCountKey()
        next_key = FdCountKey()
        val = FdCountVal()
        ret = libbpf.bpf_map_get_next_key(fd, None, ctypes.byref(next_key))
        while ret == 0:
            ctypes.memmove(ctypes.byref(key), ctypes.byref(next_key),
                           ctypes.sizeof(FdCountKey))
            r = libbpf.bpf_map_lookup_elem(fd, ctypes.byref(key), ctypes.byref(val))
            if r == 0:
                pid = int(key.pid)
                stats[pid] = (int(val.open_count), int(val.close_count))
            ret = libbpf.bpf_map_get_next_key(fd, ctypes.byref(key),
                                              ctypes.byref(next_key))
        return stats
    finally:
        os.close(fd)


# ---------- 方式 2: bpftool JSON（备选） ----------

def get_bpf_fd_stats_bpftool():
    map_id = get_map_id()
    if map_id is None:
        return None
    try:
        r = subprocess.run(
            ["bpftool", "map", "dump", "id", str(map_id), "-j"],
            capture_output=True, text=True, timeout=10)
        entries = json.loads(r.stdout or "[]")
    except Exception:
        return None
    stats = {}
    for e in entries:
        key_bytes = parse_hex(e.get("key", []))
        val_bytes = parse_hex(e.get("value", []))
        if len(key_bytes) >= 8 and len(val_bytes) >= 16:
            pid = int.from_bytes(key_bytes[:8], "little")
            oc = int.from_bytes(val_bytes[:8], "little")
            cc = int.from_bytes(val_bytes[8:16], "little")
            stats[pid] = (oc, cc)
    return stats


# ---------- 统一接口 ----------

def get_bpf_fd_stats():
    if HAS_LIBBPF:
        stats = get_bpf_fd_stats_libbpf()
        if stats is not None:
            return stats
    stats = get_bpf_fd_stats_bpftool()
    return stats if stats is not None else {}


def get_real_fd(pid):
    try:
        return len(os.listdir("/proc/%d/fd" % pid))
    except OSError:
        return -1


# ---------- 主循环 ----------

def main():
    pid = int(sys.argv[1]) if len(sys.argv) > 1 else 1
    interval = int(sys.argv[2]) if len(sys.argv) > 2 else 5

    method = "libbpf" if HAS_LIBBPF else "bpftool"
    print("=" * 72)
    print("  对比 PID %d fd 计数 (BPF fd_count_map vs /proc/%d/fd)" % (pid, pid))
    print("  读取方式: %s, 间隔 %d 秒, Ctrl+C 退出" % (method, interval))
    print("=" * 72)
    print("%-10s %12s %12s %12s %10s %8s" % (
        "时间", "BPF_open", "BPF_close", "BPF_out", "real_fd", "diff"))
    print("-" * 72)

    while True:
        stats = get_bpf_fd_stats()
        real = get_real_fd(pid)

        if pid in stats:
            oc, cc = stats[pid]
            out = max(0, oc - cc)
            diff = out - real
            if abs(diff) <= 5:
                mark = "  OK"
            elif abs(diff) <= 30:
                mark = "  WARN"
            else:
                mark = "  DIFF"
            print("%-10s %12d %12d %12d %10d %8d%s" % (
                time.strftime("%H:%M:%S"), oc, cc, out, real, diff, mark))
        else:
            print("%-10s %52s %10d" % (
                time.strftime("%H:%M:%S"),
                "(PID %d 不在 map 中)" % pid, real))

        sys.stdout.flush()
        time.sleep(interval)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n退出")
