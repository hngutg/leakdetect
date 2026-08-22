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

# ring buffer 回调类型: int (*)(void *ctx, void *data, size_t size)
# 返回 0 = 继续处理，非 0 = 停止
RING_CB = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p,
                           ctypes.c_void_p, ctypes.c_size_t)


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
        """启动 ring buffer 轮询（单线程轮询所有 BPF 对象）。

        Args:
            callbacks: {"mem": on_mem_event, "threads": on_thread_event, "fd": on_fd_event}
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

    def cleanup(self):
        """清理 BPF 对象。"""
        self._rbs = []
        self._cb_refs = []
        self._objects = {}
