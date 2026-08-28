"""事件解码 + 分发到聚合器（B 方案：仅 threads，mem/fd 改用 map 聚合）。

对应里程碑：B1 + B2（B 方案重构）
mem/fd 不再走 ring buffer → Python per-event；改用 BPF map + loader 定期读。
threads 保持 ring buffer（低率，不溢出）。
"""

import ctypes as ct

STACK_MAX_FRAMES = 8


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


def _decode_op(raw):
    if isinstance(raw, bytes):
        return chr(raw[0]) if raw else '?'
    return chr(raw)


def _extract_addrs(array, cnt):
    if cnt <= 0:
        return []
    n = min(cnt, STACK_MAX_FRAMES)
    return [array[i] for i in range(n)]


class IngestManager:
    """接收 threads ring buffer 事件，解码并分发到聚合器。
    mem/fd 由 loader.read_outstanding_map/read_fd_count_map 定期读取（不走本类）。"""

    def __init__(self, aggregator, symbolizer=None):
        self.aggregator = aggregator
        self.symbolizer = symbolizer
        self._thread_count = 0

    def on_thread_event(self, cpu, data, size):
        """线程事件（clone/exit）。"""
        event = ct.cast(data, ct.POINTER(ThreadEvent)).contents
        self._thread_count += 1
        if self._thread_count % 100 == 1:
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
