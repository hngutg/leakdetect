"""事件解码 + 分发到聚合器。

对应里程碑：B1 + B2
对应文档：leakdetect-b1-design.md §6.2、leakdetect-b2-design.md §8.2

栈捕获方式：bpf_get_stack 直接拷贝地址到事件，不依赖 BPF_STACK_TRACE map
"""

import ctypes as ct

STACK_MAX_FRAMES = 8


class MemEvent(ct.Structure):
    """与 BPF C struct mem_event_t 对应。"""
    _fields_ = [
        ("pid", ct.c_uint),
        ("tid", ct.c_uint),
        ("size", ct.c_ulonglong),
        ("ptr", ct.c_ulonglong),
        ("stack_cnt", ct.c_int),
        ("stack_addrs", ct.c_ulonglong * STACK_MAX_FRAMES),
        ("op", ct.c_char),
        ("comm", ct.c_char * 16),
    ]


class ThreadEvent(ct.Structure):
    """与 BPF C struct thread_event_t 对应。"""
    _fields_ = [
        ("pid", ct.c_uint),
        ("tid", ct.c_uint),
        ("stack_cnt", ct.c_int),
        ("stack_addrs", ct.c_ulonglong * STACK_MAX_FRAMES),
        ("op", ct.c_char),
        ("comm", ct.c_char * 16),
    ]


class FdEvent(ct.Structure):
    """与 BPF C struct fd_event_t 对应。"""
    _fields_ = [
        ("pid", ct.c_uint),
        ("fd", ct.c_int),
        ("fd_type", ct.c_int),
        ("stack_cnt", ct.c_int),
        ("stack_addrs", ct.c_ulonglong * STACK_MAX_FRAMES),
        ("op", ct.c_char),
        ("comm", ct.c_char * 16),
    ]


def _decode_op(raw):
    """安全解码 op 字段。"""
    if isinstance(raw, bytes):
        return chr(raw[0]) if raw else '?'
    return chr(raw)


def _extract_addrs(array, cnt):
    """从 ctypes 数组提取有效地址列表。"""
    if cnt <= 0:
        return []
    n = min(cnt, STACK_MAX_FRAMES)
    return [array[i] for i in range(n)]


class IngestManager:
    """接收 perf buffer 事件，解码并分发到聚合器。"""

    def __init__(self, aggregator, symbolizer=None):
        self.aggregator = aggregator
        self.symbolizer = symbolizer
        self._mem_count = 0
        self._thread_count = 0
        self._fd_count = 0
        self._fd_open_total = 0
        self._fd_close_matched = 0
        self._fd_close_unmatched = 0

    def on_mem_event(self, cpu, data, size):
        """B1：内存事件。"""
        event = ct.cast(data, ct.POINTER(MemEvent)).contents
        self._mem_count += 1
        if self._mem_count % 100 == 1:
            print("[ingest] mem event #%d: pid=%d op=%s size=%d stack_cnt=%d" % (
                self._mem_count, event.pid,
                _decode_op(event.op), event.size, event.stack_cnt))
        self.aggregator.on_mem_event({
            "pid": event.pid,
            "tid": event.tid,
            "size": event.size,
            "ptr": event.ptr,
            "stack_cnt": event.stack_cnt,
            "stack_addrs": _extract_addrs(event.stack_addrs, event.stack_cnt),
            "op": _decode_op(event.op),
            "comm": event.comm.decode('utf-8', errors='replace'),
        })

    def on_thread_event(self, cpu, data, size):
        """B2：线程事件。"""
        event = ct.cast(data, ct.POINTER(ThreadEvent)).contents
        self._thread_count += 1
        print("[ingest] thread event #%d: pid=%d op=%s" % (
            self._thread_count, event.pid, _decode_op(event.op)))
        self.aggregator.on_thread_event({
            "pid": event.pid,
            "tid": event.tid,
            "stack_cnt": event.stack_cnt,
            "stack_addrs": _extract_addrs(event.stack_addrs, event.stack_cnt),
            "op": _decode_op(event.op),
            "comm": event.comm.decode('utf-8', errors='replace'),
        })

    def on_fd_event(self, cpu, data, size):
        """B2：句柄事件。"""
        event = ct.cast(data, ct.POINTER(FdEvent)).contents
        self._fd_count += 1
        op = _decode_op(event.op)
        if op == 'o':
            self._fd_open_total += 1
        elif op == 'c':
            if event.stack_cnt > 0:
                self._fd_close_matched += 1
            else:
                self._fd_close_unmatched += 1
        if self._fd_count % 100 == 1:
            print("[ingest] fd event #%d: pid=%d op=%s fd=%d stack_cnt=%d" % (
                self._fd_count, event.pid, op, event.fd, event.stack_cnt))
        self.aggregator.on_fd_event({
            "pid": event.pid,
            "fd": event.fd,
            "fd_type": event.fd_type,
            "stack_cnt": event.stack_cnt,
            "stack_addrs": _extract_addrs(event.stack_addrs, event.stack_cnt),
            "op": op,
            "comm": event.comm.decode('utf-8', errors='replace'),
        })
