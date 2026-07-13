# B0: eBPF 技术验证

## 前置条件

- root 权限
- BCC 已安装：`python3 -c "from bcc import BPF; print('BCC OK')`
- 内核 >= 5.10，BTF 可用

## 运行方式

所有脚本必须以 root 运行：

```bash
cd ~/leakdetect

# Test 1: Hello BPF（最简单，验证 BCC 加载 + 事件读取）
sudo python3 tests/b0/test1_hello_bpf.py

# Test 2: uprobe malloc（验证 uprobe + PT_REGS_PARM1 + perf buffer）
sudo python3 tests/b0/test2_uprobe_malloc.py

# Test 3: cgroup_id（验证 cgroup ID 获取）
sudo python3 tests/b0/test3_cgroup_id.py

# Test 4: stack trace（验证栈回溯 + 符号解析）
sudo python3 tests/b0/test4_stack_trace.py
```

## 触发事件

Test 2 和 Test 4 需要 malloc 调用。在**另一个终端**运行命令：

```bash
ls
cat /dev/null
python3 -c "import time; time.sleep(1)"
```

## 验证标准

| # | 测试 | 通过标准 |
|---|---|---|
| 1 | Hello BPF | trace_print 持续输出 PID |
| 2 | uprobe malloc | malloc 事件 + size 值合理（非 0、非负） |
| 3 | cgroup_id | cgid 非 0，同一进程 cgid 一致 |
| 4 | stack trace | stack_id >= 0，能解析出函数名 |

4 项全部通过 = eBPF 技术验证完成，B1 可安全开发。

## 架构兼容性

全部 4 个脚本**架构无关**：
- `PT_REGS_PARM1` 宏自动选 RDI(x86_64)/X0(aarch64)
- `attach_uprobe(name="c")` BCC 自动解析 libc 路径
- 所有 BPF helper 跨架构

在 x86_64 上验证通过后，aarch64 上无需改代码即可运行。
重点确认 Test 2 的 size 值在 aarch64 上仍然合理。
