#!/usr/bin/env python3
"""Python 内存泄露测试脚本

通过 ctypes 直接调用 libc malloc，绕过 pymalloc，
让 BPF uprobe 抓到真实的 malloc 调用且不 free。

用法：python3 tests/leak_programs/py_leak.py
预期：leakdetect 触发告警，栈含 python3 C 层函数名
前提：已装 python3-dbg（栈帧才能解析 CPython 内部函数）
"""

import ctypes
import time

libc = ctypes.CDLL("libc.so.6")
libc.malloc.restype = ctypes.c_void_p

leaked = []
print("[py_leak] Starting: 4KB malloc every 0.1s, no free")
print("[py_leak] Expected: LeakDetect alert after ~125s (grace 120 + window)")

for i in range(10000):
    ptr = libc.malloc(4096)
    if ptr:
        leaked.append(ptr)
    time.sleep(0.1)

print("[py_leak] Done allocating. Keeping alive.")
time.sleep(600)
