"""栈符号解析：栈地址列表 → 函数名。

用 pyelftools 读 ELF 符号表替代 BCC 的 bpf.sym()。
通过 /proc/[pid]/maps 查找地址所属库，再在库的 ELF 中解析符号。
带缓存避免重复解析大型 ELF（如 libc ~2MB）。
"""


class Symbolizer:
    """解析用户态栈地址为函数名列表。"""

    def __init__(self, bpf_mem=None, bpf_threads=None, bpf_fd=None):
        """不再需要 BPF 对象（pyelftools 直接读 ELF 文件）。
        参数保留以兼容 backend.py 调用。"""
        self._elf_cache = {}  # {elf_path: [(st_value, st_size, name), ...]}

    def resolve(self, resource, stack_addrs, stack_cnt, pid):
        """解析栈地址列表为 [{func, addr}] 列表。

        Args:
            resource: 资源名（忽略，兼容旧接口）
            stack_addrs: 地址列表 [u64, ...]
            stack_cnt: 有效帧数
            pid: 进程 PID

        Returns:
            [{"func": "main+0x10", "addr": "0x401000"}, ...]
        """
        if not stack_addrs or stack_cnt <= 0:
            return []
        frames = []
        maps = None
        for i in range(min(stack_cnt, len(stack_addrs))):
            addr = stack_addrs[i]
            if maps is None:
                maps = self._parse_maps(pid)
            sym = self._resolve_addr(addr, maps)
            if sym:
                frames.append({"func": sym, "addr": "0x%x" % addr})
            else:
                frames.append({"func": "[unknown]", "addr": "0x%x" % addr})
        return frames

    def _parse_maps(self, pid):
        """读 /proc/[pid]/maps，返回 [(start, end, offset, path), ...]。"""
        result = []
        try:
            with open("/proc/%d/maps" % pid) as f:
                for line in f:
                    parts = line.split()
                    if len(parts) < 6 or not parts[5].startswith("/"):
                        continue
                    addr_range = parts[0].split("-")
                    start = int(addr_range[0], 16)
                    end = int(addr_range[1], 16)
                    offset = int(parts[2], 16)
                    path = parts[5]
                    result.append((start, end, offset, path))
        except (IOError, ValueError):
            pass
        return result

    def _resolve_addr(self, addr, maps):
        """在进程的内存映射中解析地址。"""
        for start, end, offset, path in maps:
            if start <= addr < end:
                elf_addr = addr - start + offset
                return self._lookup_elf(elf_addr, path)
        return None

    def _lookup_elf(self, addr, elf_path):
        """在 ELF 文件中查找地址对应的符号。"""
        symbols = self._get_symbols(elf_path)
        if not symbols:
            return None
        for st_value, st_size, name in symbols:
            if st_size > 0 and st_value <= addr < st_value + st_size:
                off = addr - st_value
                if off > 0:
                    return "%s+0x%x" % (name, off)
                return name
        return None

    def _get_symbols(self, elf_path):
        """获取 ELF 文件的函数符号列表（带缓存）。"""
        if elf_path in self._elf_cache:
            return self._elf_cache[elf_path]

        symbols = []
        try:
            from elftools.elf.elffile import ELFFile
            with open(elf_path, "rb") as f:
                elf = ELFFile(f)
                for section in elf.iter_sections():
                    if not hasattr(section, "iter_symbols"):
                        continue
                    for sym in section.iter_symbols():
                        try:
                            if sym["st_info"]["type"] != "STT_FUNC":
                                continue
                            if sym["st_value"] == 0 or sym["st_size"] == 0:
                                continue
                            name = sym.name
                            if isinstance(name, bytes):
                                name = name.decode("utf-8", errors="replace")
                            symbols.append((sym["st_value"], sym["st_size"], name))
                        except Exception:
                            continue
        except Exception as e:
            print("[symbolizer] read %s failed: %s" % (elf_path, e))
        else:
            if not symbols:
                print("[symbolizer] no STT_FUNC symbols in %s" % elf_path)

        self._elf_cache[elf_path] = symbols
        return symbols
