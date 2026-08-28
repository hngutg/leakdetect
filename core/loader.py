"""libbpf 加载器：用 ctypes 调用 libbpf.so 加载预编译 .o 文件 + attach 探针 + ring buffer 轮询。

替代 BCC 的 BPF(src_file=) 运行时编译方案。
不需要 clang/LLVM，只需 libbpf.so (~1MB)。

功能：
- 加载预编译 CO-RE .o 文件
- attach uprobe（malloc/free，自动查找 libc 路径和函数偏移）
- attach kprobe（fd_install）
- attach tracepoint（clone/clone3/sched_process_exit/close/dup2/dup3）
- 打开 ring buffer，单线程轮询所有 BPF 对象的事件

使用 BPF_MAP_TYPE_RINGBUF（内核 5.8+）替代 BPF_MAP_TYPE_PERF_EVENT_ARRAY，
不调用 perf_event_open，避免内核/头文件版本不匹配导致的 E2BIG 错误。
"""

import os
import time
import ctypes
import threading

from elftools.elf.elffile import ELFFile


# ========== libbpf 加载 ==========

def _load_libbpf():
    """加载 libbpf 共享库（libbpf.so.1 → libbpf.so.0 → libbpf.so）。"""
    for name in ("libbpf.so.1", "libbpf.so.0", "libbpf.so"):
        try:
            return ctypes.CDLL(name)
        except OSError:
            continue
    raise RuntimeError("libbpf not found. Install libbpf or set LD_LIBRARY_PATH.")


libbpf = _load_libbpf()

# ========== 函数签名 ==========

libbpf.bpf_object__open_file.restype = ctypes.c_void_p
libbpf.bpf_object__open_file.argtypes = [ctypes.c_char_p, ctypes.c_void_p]

libbpf.bpf_object__load.restype = ctypes.c_int
libbpf.bpf_object__load.argtypes = [ctypes.c_void_p]

libbpf.bpf_object__find_program_by_name.restype = ctypes.c_void_p
libbpf.bpf_object__find_program_by_name.argtypes = [ctypes.c_void_p, ctypes.c_char_p]

libbpf.bpf_program__attach_kprobe.restype = ctypes.c_void_p
libbpf.bpf_program__attach_kprobe.argtypes = [ctypes.c_void_p, ctypes.c_bool, ctypes.c_char_p]

libbpf.bpf_program__attach_uprobe.restype = ctypes.c_void_p
libbpf.bpf_program__attach_uprobe.argtypes = [ctypes.c_void_p, ctypes.c_bool,
                                              ctypes.c_int, ctypes.c_char_p, ctypes.c_size_t]

libbpf.bpf_program__attach_tracepoint.restype = ctypes.c_void_p
libbpf.bpf_program__attach_tracepoint.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]

libbpf.bpf_object__find_map_by_name.restype = ctypes.c_void_p
libbpf.bpf_object__find_map_by_name.argtypes = [ctypes.c_void_p, ctypes.c_char_p]

libbpf.bpf_map__fd.restype = ctypes.c_int
libbpf.bpf_map__fd.argtypes = [ctypes.c_void_p]

libbpf.ring_buffer__new.restype = ctypes.c_void_p
libbpf.ring_buffer__new.argtypes = [ctypes.c_int, ctypes.c_void_p,
                                     ctypes.c_void_p, ctypes.c_void_p]

libbpf.ring_buffer__poll.restype = ctypes.c_int
libbpf.ring_buffer__poll.argtypes = [ctypes.c_void_p, ctypes.c_int]

libbpf.bpf_map_get_next_key.restype = ctypes.c_int
libbpf.bpf_map_get_next_key.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p]

libbpf.bpf_map_lookup_elem.restype = ctypes.c_int
libbpf.bpf_map_lookup_elem.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p]

libbpf.bpf_map_delete_elem.restype = ctypes.c_int
libbpf.bpf_map_delete_elem.argtypes = [ctypes.c_int, ctypes.c_void_p]

# ring buffer 回调类型: int (*)(void *ctx, void *data, size_t size)
# 返回 0 = 继续处理，非 0 = 停止
RING_CB = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p,
                           ctypes.c_void_p, ctypes.c_size_t)

STACK_MAX = 8


class OutstandingKey(ctypes.Structure):
    _fields_ = [
        ("pid", ctypes.c_ulonglong),
        ("stack_addrs", ctypes.c_ulonglong * STACK_MAX),
    ]


class OutstandingVal(ctypes.Structure):
    _fields_ = [
        ("alloc_bytes", ctypes.c_ulonglong),
        ("free_bytes", ctypes.c_ulonglong),
        ("comm", ctypes.c_char * 16),
        ("stack_cnt", ctypes.c_int),
    ]


class FdCountKey(ctypes.Structure):
    _fields_ = [
        ("pid", ctypes.c_ulonglong),
    ]


class FdCountVal(ctypes.Structure):
    _fields_ = [
        ("open_count", ctypes.c_ulonglong),
        ("close_count", ctypes.c_ulonglong),
        ("stack_addrs", ctypes.c_ulonglong * STACK_MAX),
        ("comm", ctypes.c_char * 16),
        ("stack_cnt", ctypes.c_int),
    ]


class AllocsKey(ctypes.Structure):
    _fields_ = [("ptr", ctypes.c_ulonglong)]


class AllocsVal(ctypes.Structure):
    _fields_ = [
        ("refcount", ctypes.c_ulonglong),
        ("size", ctypes.c_ulonglong),
        ("stack_cnt", ctypes.c_int),
        ("stack_addrs", ctypes.c_ulonglong * STACK_MAX),
        ("pid", ctypes.c_uint32),
    ]


class FdKey(ctypes.Structure):
    _fields_ = [
        ("pid", ctypes.c_uint32),
        ("fd", ctypes.c_int32),
    ]


class FdVal(ctypes.Structure):
    _fields_ = [
        ("refcount", ctypes.c_ulonglong),
        ("stack_cnt", ctypes.c_int),
        ("stack_addrs", ctypes.c_ulonglong * STACK_MAX),
    ]


# ========== ELF 符号查找 ==========

_LIBC_PATHS = [
    "/lib64/libc.so.6",
    "/lib/aarch64-linux-gnu/libc.so.6",
    "/lib/x86_64-linux-gnu/libc.so.6",
    "/usr/lib64/libc.so.6",
    "/usr/lib/aarch64-linux-gnu/libc.so.6",
    "/usr/lib/x86_64-linux-gnu/libc.so.6",
]


def _find_libc():
    """查找 libc.so.6 路径。"""
    for p in _LIBC_PATHS:
        if os.path.exists(p):
            return p
    raise RuntimeError("libc not found in common paths")


def _find_symbol_offset(elf_path, symbol_name):
    """在 ELF 文件中查找函数符号的偏移地址。"""
    with open(elf_path, "rb") as f:
        elf = ELFFile(f)
        for section in elf.iter_sections():
            if not hasattr(section, "iter_symbols"):
                continue
            for sym in section.iter_symbols():
                if sym.name == symbol_name and sym["st_value"] != 0:
                    return sym["st_value"]
    raise RuntimeError("Symbol '%s' not found in %s" % (symbol_name, elf_path))


# ========== BpfLoader ==========

class BpfLoader:
    """加载预编译 BPF .o 文件并管理事件读取。"""

    def __init__(self, config):
        self.config = config
        self._objects = {}     # {resource: bpf_object*}
        self._rbs = []          # [ring_buffer*]
        self._cb_refs = []      # 持有回调引用，防止 GC
        self._bpf_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "bpf", "compiled"
        )

    def _load_obj(self, resource, obj_name):
        """加载一个 .o 文件。"""
        obj_path = os.path.join(self._bpf_dir, obj_name)
        if not os.path.exists(obj_path):
            raise RuntimeError("BPF object not found: %s" % obj_path)
        obj = libbpf.bpf_object__open_file(obj_path.encode("utf-8"), None)
        if not obj:
            raise RuntimeError("Failed to open BPF object: %s" % obj_path)
        ret = libbpf.bpf_object__load(obj)
        if ret < 0:
            raise RuntimeError("Failed to load BPF object: %s (ret=%d)" % (obj_path, ret))
        self._objects[resource] = obj
        print("[loader] %s loaded (%s)" % (resource, obj_path))
        return obj

    def _find_prog(self, resource, prog_name):
        """查找 BPF 程序。"""
        obj = self._objects[resource]
        prog = libbpf.bpf_object__find_program_by_name(obj, prog_name.encode("utf-8"))
        if not prog:
            raise RuntimeError("Program '%s' not found in %s" % (prog_name, resource))
        return prog

    def _attach_uprobe(self, resource, prog_name, sym_name, retprobe=False):
        """attach uprobe（自动查找 libc 路径和函数偏移）。"""
        libc_path = _find_libc()
        offset = _find_symbol_offset(libc_path, sym_name)
        prog = self._find_prog(resource, prog_name)
        link = libbpf.bpf_program__attach_uprobe(
            prog, retprobe, -1, libc_path.encode("utf-8"), offset)
        if not link:
            raise RuntimeError("Failed to attach uprobe %s:%s" % (prog_name, sym_name))
        print("[loader] uprobe %s:%s attached at %s+0x%x" % (
            prog_name, sym_name, libc_path, offset))

    def _attach_kprobe(self, resource, prog_name, func_name):
        """attach kprobe。"""
        prog = self._find_prog(resource, prog_name)
        link = libbpf.bpf_program__attach_kprobe(
            prog, False, func_name.encode("utf-8"))
        if not link:
            raise RuntimeError("Failed to attach kprobe %s:%s" % (prog_name, func_name))
        print("[loader] kprobe %s:%s attached" % (prog_name, func_name))

    def _attach_tp(self, resource, prog_name, category, event, optional=False):
        """attach tracepoint。optional=True 时失败只 warning 不 raise。"""
        prog = self._find_prog(resource, prog_name)
        link = libbpf.bpf_program__attach_tracepoint(
            prog, category.encode("utf-8"), event.encode("utf-8"))
        if not link:
            if optional:
                print("[loader] WARNING: tracepoint %s:%s/%s not available, skipping" % (
                    prog_name, category, event))
                return
            raise RuntimeError("Failed to attach tracepoint %s:%s/%s" % (
                prog_name, category, event))
        print("[loader] tracepoint %s:%s/%s attached" % (prog_name, category, event))

    def _open_ring_buffer(self, resource, callback):
        """打开 ring buffer 并注册回调。"""
        obj = self._objects[resource]
        map_obj = libbpf.bpf_object__find_map_by_name(obj, b"events")
        if not map_obj:
            raise RuntimeError("events map not found in %s" % resource)
        fd = libbpf.bpf_map__fd(map_obj)
        if fd < 0:
            raise RuntimeError("Failed to get events map fd for %s" % resource)

        # 创建回调包装（ring buffer 回调无 cpu 参数，传 0 作 dummy）
        def _ring_cb(ctx, data, size):
            callback(0, data, size)
            return 0

        cb = RING_CB(_ring_cb)
        self._cb_refs.append(cb)
        rb = libbpf.ring_buffer__new(fd, cb, None, None)
        if not rb:
            raise RuntimeError("Failed to create ring buffer for %s" % resource)
        self._rbs.append(rb)
        print("[loader] ring buffer opened for %s" % resource)

    def load_mem(self):
        """加载内存 BPF 程序。"""
        self._load_obj("mem", "mem.o")
        self._attach_uprobe("mem", "trace_malloc_entry", "malloc", retprobe=False)
        self._attach_uprobe("mem", "trace_malloc_return", "malloc", retprobe=True)
        self._attach_uprobe("mem", "trace_free_entry", "free", retprobe=False)
        print("[loader] mem probes attached")

    def load_threads(self):
        """加载线程 BPF 程序。"""
        self._load_obj("threads", "threads.o")
        self._attach_tp("threads", "trace_clone", "syscalls", "sys_enter_clone")
        self._attach_tp("threads", "trace_clone3", "syscalls", "sys_enter_clone3")
        self._attach_tp("threads", "trace_sched_exit", "sched", "sched_process_exit")
        print("[loader] threads tracepoints attached")

    def load_fd(self):
        """加载句柄 BPF 程序。"""
        self._load_obj("fd", "fd.o")
        self._attach_kprobe("fd", "trace_fd_install", "fd_install")
        self._attach_tp("fd", "trace_close", "syscalls", "sys_enter_close")
        self._attach_tp("fd", "trace_dup2", "syscalls", "sys_enter_dup2", optional=True)
        self._attach_tp("fd", "trace_dup3", "syscalls", "sys_enter_dup3", optional=True)
        print("[loader] fd kprobe + tracepoints attached")

    def start_event_loop(self, callbacks):
        """启动 ring buffer 轮询（B 方案：仅 threads ring，mem/fd 用 map 聚合）。

        Args:
            callbacks: {"threads": on_thread_event}
        """
        for resource, cb in callbacks.items():
            self._open_ring_buffer(resource, cb)
        threading.Thread(target=self._poll_all, daemon=True).start()
        print("[loader] event loop started")

    def _poll_all(self):
        """单线程轮询所有 ring buffer，50ms timeout。"""
        count = 0
        while True:
            try:
                for rb in self._rbs:
                    libbpf.ring_buffer__poll(rb, 50)
            except Exception as e:
                print("[loader] poll error: %s" % e)
            count += 1
            if count % 1000 == 0:
                print("[loader] _poll_all cycle %d" % count)
            time.sleep(0.001)

    def _get_map_fd(self, resource, map_name):
        obj = self._objects.get(resource)
        if not obj:
            return -1
        if isinstance(map_name, str):
            map_name = map_name.encode("utf-8")
        map_obj = libbpf.bpf_object__find_map_by_name(obj, map_name)
        if not map_obj:
            return -1
        return libbpf.bpf_map__fd(map_obj)

    def iter_map(self, resource, map_name, key_cls, val_cls):
        fd = self._get_map_fd(resource, map_name)
        if fd < 0:
            return
        key = key_cls()
        next_key = key_cls()
        val = val_cls()
        ret = libbpf.bpf_map_get_next_key(fd, None, ctypes.byref(next_key))
        while ret == 0:
            ctypes.memmove(ctypes.byref(key), ctypes.byref(next_key), ctypes.sizeof(key_cls))
            r = libbpf.bpf_map_lookup_elem(fd, ctypes.byref(key), ctypes.byref(val))
            if r == 0:
                yield key, val
            ret = libbpf.bpf_map_get_next_key(fd, ctypes.byref(key), ctypes.byref(next_key))

    def read_outstanding_map(self):
        fd = self._get_map_fd("mem", b"outstanding_map")
        if fd < 0:
            return {}
        key = OutstandingKey()
        next_key = OutstandingKey()
        val = OutstandingVal()
        stats = {}
        dead_keys = []
        ret = libbpf.bpf_map_get_next_key(fd, None, ctypes.byref(next_key))
        while ret == 0:
            ctypes.memmove(ctypes.byref(key), ctypes.byref(next_key), ctypes.sizeof(OutstandingKey))
            r = libbpf.bpf_map_lookup_elem(fd, ctypes.byref(key), ctypes.byref(val))
            if r == 0:
                pid = int(key.pid)
                if os.path.exists("/proc/%d" % pid):
                    scnt = min(int(val.stack_cnt), STACK_MAX) if val.stack_cnt > 0 else 0
                    sid = tuple(int(key.stack_addrs[i]) for i in range(scnt)) if scnt > 0 else ()
                    addrs = [int(key.stack_addrs[i]) for i in range(scnt)]
                    if pid not in stats:
                        stats[pid] = {}
                    stats[pid][sid] = {
                        "alloc_bytes": int(val.alloc_bytes),
                        "free_bytes": int(val.free_bytes),
                        "comm": val.comm.decode("utf-8", errors="replace"),
                        "stack_addrs": addrs,
                        "stack_cnt": scnt,
                    }
                else:
                    dk = OutstandingKey()
                    ctypes.memmove(ctypes.byref(dk), ctypes.byref(key), ctypes.sizeof(OutstandingKey))
                    dead_keys.append(dk)
            ret = libbpf.bpf_map_get_next_key(fd, ctypes.byref(key), ctypes.byref(next_key))
        for dk in dead_keys:
            libbpf.bpf_map_delete_elem(fd, ctypes.byref(dk))
        return stats

    def read_fd_count_map(self):
        fd = self._get_map_fd("fd", b"fd_count_map")
        if fd < 0:
            return {}
        key = FdCountKey()
        next_key = FdCountKey()
        val = FdCountVal()
        stats = {}
        dead_keys = []
        ret = libbpf.bpf_map_get_next_key(fd, None, ctypes.byref(next_key))
        while ret == 0:
            ctypes.memmove(ctypes.byref(key), ctypes.byref(next_key), ctypes.sizeof(FdCountKey))
            r = libbpf.bpf_map_lookup_elem(fd, ctypes.byref(key), ctypes.byref(val))
            if r == 0:
                pid = int(key.pid)
                if os.path.exists("/proc/%d" % pid):
                    scnt = min(int(val.stack_cnt), STACK_MAX) if val.stack_cnt > 0 else 0
                    addrs = [int(val.stack_addrs[i]) for i in range(scnt)]
                    stats[pid] = {
                        "open_count": int(val.open_count),
                        "close_count": int(val.close_count),
                        "comm": val.comm.decode("utf-8", errors="replace"),
                        "stack_addrs": addrs,
                        "stack_cnt": scnt,
                    }
                else:
                    dk = FdCountKey()
                    ctypes.memmove(ctypes.byref(dk), ctypes.byref(key), ctypes.sizeof(FdCountKey))
                    dead_keys.append(dk)
            ret = libbpf.bpf_map_get_next_key(fd, ctypes.byref(key), ctypes.byref(next_key))
        for dk in dead_keys:
            libbpf.bpf_map_delete_elem(fd, ctypes.byref(dk))
        return stats

    def clean_dead_pid_allocs(self):
        """清理 allocs map 中已退出进程的条目。"""
        fd = self._get_map_fd("mem", b"allocs")
        if fd < 0:
            return 0
        key = AllocsKey()
        next_key = AllocsKey()
        val = AllocsVal()
        dead_keys = []
        ret = libbpf.bpf_map_get_next_key(fd, None, ctypes.byref(next_key))
        while ret == 0:
            ctypes.memmove(ctypes.byref(key), ctypes.byref(next_key), ctypes.sizeof(AllocsKey))
            r = libbpf.bpf_map_lookup_elem(fd, ctypes.byref(key), ctypes.byref(val))
            if r == 0:
                pid = int(val.pid)
                if pid > 0 and not os.path.exists("/proc/%d" % pid):
                    dk = AllocsKey()
                    ctypes.memmove(ctypes.byref(dk), ctypes.byref(key), ctypes.sizeof(AllocsKey))
                    dead_keys.append(dk)
            ret = libbpf.bpf_map_get_next_key(fd, ctypes.byref(key), ctypes.byref(next_key))
        for dk in dead_keys:
            libbpf.bpf_map_delete_elem(fd, ctypes.byref(dk))
        return len(dead_keys)

    def clean_dead_pid_fd_map(self):
        """清理 fd_map 中已退出进程的条目。"""
        fd = self._get_map_fd("fd", b"fd_map")
        if fd < 0:
            return 0
        key = FdKey()
        next_key = FdKey()
        val = FdVal()
        dead_keys = []
        ret = libbpf.bpf_map_get_next_key(fd, None, ctypes.byref(next_key))
        while ret == 0:
            ctypes.memmove(ctypes.byref(key), ctypes.byref(next_key), ctypes.sizeof(FdKey))
            r = libbpf.bpf_map_lookup_elem(fd, ctypes.byref(key), ctypes.byref(val))
            if r == 0:
                pid = int(key.pid)
                if pid > 0 and not os.path.exists("/proc/%d" % pid):
                    dk = FdKey()
                    ctypes.memmove(ctypes.byref(dk), ctypes.byref(key), ctypes.sizeof(FdKey))
                    dead_keys.append(dk)
            ret = libbpf.bpf_map_get_next_key(fd, ctypes.byref(key), ctypes.byref(next_key))
        for dk in dead_keys:
            libbpf.bpf_map_delete_elem(fd, ctypes.byref(dk))
        return len(dead_keys)

    def cleanup(self):
        """清理 BPF 对象。"""
        self._rbs = []
        self._cb_refs = []
        self._objects = {}
