"""栈符号解析：栈地址列表 → 函数名。

用 pyelftools 读 ELF 符号表替代 BCC 的 bpf.sym()。
通过 /proc/[pid]/maps 查找地址所属库，再在库的 ELF 中解析符号。
带缓存避免重复解析大型 ELF（如 libc ~2MB）。
Tier 1：stripped binary 回退读 debuginfo 文件（/usr/lib/debug 或 .gnu_debuglink）。
"""

import os
import bisect


class Symbolizer:
    """解析用户态栈地址为函数名列表。"""

    def __init__(self, bpf_mem=None, bpf_threads=None, bpf_fd=None):
        """不再需要 BPF 对象（pyelftools 直接读 ELF 文件）。
        参数保留以兼容 backend.py 调用。"""
        self._elf_cache = {}  # {elf_path: [(st_value, st_size, name), ...]}
        self._dwarf_cache = {}  # {elf_path: [(addr, filename, line), ...]}

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
                    if not os.path.exists(path):
                        root_path = "/proc/%d/root%s" % (pid, path)
                        if os.path.exists(root_path):
                            path = root_path
                    result.append((start, end, offset, path))
        except (IOError, ValueError):
            pass
        return result

    def _resolve_addr(self, addr, maps):
        """在进程的内存映射中解析地址。"""
        for start, end, offset, path in maps:
            if start <= addr < end:
                elf_addr = addr - start + offset
                sym = self._lookup_elf(elf_addr, path)
                if sym:
                    return sym
                return "%s+0x%x" % (os.path.basename(path), elf_addr)
        return None

    def _lookup_elf(self, addr, elf_path):
        """在 ELF 文件中查找地址对应的符号。"""
        symbols = self._get_symbols(elf_path)
        if not symbols:
            return None
        for st_value, st_size, name in symbols:
            if st_size > 0 and st_value <= addr < st_value + st_size:
                off = addr - st_value
                base = "%s+0x%x" % (name, off) if off > 0 else name
                src = self._lookup_dwarf_line(elf_path, addr)
                if src:
                    return "%s (%s:%d)" % (base, src[0], src[1])
                return base
        return None

    def _get_symbols(self, elf_path):
        """获取 ELF 函数符号列表（带缓存 + debuginfo 回退）。"""
        if elf_path in self._elf_cache:
            return self._elf_cache[elf_path]

        symbols = self._read_elf_symbols(elf_path)

        debug_path = self._find_debuginfo(elf_path)
        if debug_path:
            debug_symbols = self._read_elf_symbols(debug_path)
            if len(debug_symbols) > len(symbols):
                symbols = debug_symbols
                print("[symbolizer] using debuginfo %s for %s (%d > %d symbols)"
                      % (debug_path, elf_path, len(debug_symbols), len(symbols)))

        if not symbols:
            print("[symbolizer] no symbols in %s (stripped, no debuginfo)" % elf_path)

        self._elf_cache[elf_path] = symbols
        return symbols

    def _read_elf_symbols(self, elf_path):
        """读 ELF STT_FUNC 符号（无缓存，无回退）。"""
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
        return symbols

    def _find_debuginfo(self, elf_path):
        """搜索 debuginfo 文件（stripped binary 回退）。"""
        real_path = os.path.realpath(elf_path)

        for base in ("/usr/lib/debug" + elf_path, "/usr/lib/debug" + real_path):
            if os.path.exists(base):
                return base

        try:
            from elftools.elf.elffile import ELFFile
            with open(elf_path, "rb") as f:
                elf = ELFFile(f)
                section = elf.get_section_by_name(".gnu_debuglink")
                if section:
                    data = section.data()
                    null_pos = data.index(b'\x00')
                    dbg_name = data[:null_pos].decode("utf-8", errors="replace")
                    for dirname in (os.path.dirname(elf_path),
                                    os.path.dirname(real_path)):
                        for c in (os.path.join(dirname, dbg_name),
                                  os.path.join(dirname, ".debug", dbg_name),
                                  os.path.join("/usr/lib/debug", dirname, dbg_name)):
                            if os.path.exists(c) and os.path.realpath(c) != real_path:
                                return c

                section = elf.get_section_by_name(".note.gnu.build-id")
                if section:
                    for note in section.iter_notes():
                        name = note.n_name
                        if isinstance(name, bytes):
                            name = name.rstrip(b'\x00').decode("utf-8", errors="replace")
                        if name == "GNU":
                            build_id = note.n_desc
                            if isinstance(build_id, bytes):
                                build_id_hex = build_id.hex()
                            else:
                                build_id_hex = build_id
                            debug_file = "/usr/lib/debug/.build-id/%s/%s.debug" % (
                                build_id_hex[:2], build_id_hex[2:])
                            if os.path.exists(debug_file):
                                return debug_file
        except Exception:
            pass
        return None

    def _get_dwarf_lines(self, elf_path):
        """读 DWARF .debug_line，返回 [(addr, filename, line)] 排序列表（cached）。"""
        if elf_path in self._dwarf_cache:
            return self._dwarf_cache[elf_path]

        lines = []
        try:
            from elftools.elf.elffile import ELFFile
            with open(elf_path, "rb") as f:
                elf = ELFFile(f)
                if elf.has_dwarf_info():
                    lines = self._read_dwarf_lines(elf)
            debug_path = self._find_debuginfo(elf_path)
            if debug_path:
                with open(debug_path, "rb") as df:
                    delf = ELFFile(df)
                    if delf.has_dwarf_info():
                        debug_lines = self._read_dwarf_lines(delf)
                        if len(debug_lines) > len(lines):
                            lines = debug_lines
        except Exception as e:
            print("[symbolizer] DWARF line read %s failed: %s" % (elf_path, e))

        lines.sort(key=lambda x: x[0])
        self._dwarf_cache[elf_path] = lines
        return lines

    def _read_dwarf_lines(self, elf):
        """从 ELFFile 对象读 .debug_line 行表。"""
        lines = []
        dwarfinfo = elf.get_dwarf_info()
        for CU in dwarfinfo.iter_CUs():
            lineprog = dwarfinfo.line_program_for_CU(CU)
            if not lineprog:
                continue
            file_entries = lineprog.header.file_entry
            for entry in lineprog.get_entries():
                if entry.state is None or entry.state.end_sequence:
                    continue
                addr = entry.state.address
                file_idx = entry.state.file
                line_no = entry.state.line
                fname = "?"
                if 1 <= file_idx <= len(file_entries):
                    fname = file_entries[file_idx - 1].name
                elif 0 <= file_idx < len(file_entries):
                    fname = file_entries[file_idx].name
                if isinstance(fname, bytes):
                    fname = fname.decode("utf-8", errors="replace")
                lines.append((addr, os.path.basename(fname), line_no))
        return lines

    def _lookup_dwarf_line(self, elf_path, addr):
        """二分查找 addr 对应的源码行号，返回 (filename, line) 或 None。"""
        lines = self._get_dwarf_lines(elf_path)
        if not lines:
            return None
        addrs = [l[0] for l in lines]
        idx = bisect.bisect_right(addrs, addr) - 1
        if idx >= 0:
            return (lines[idx][1], lines[idx][2])
        return None
