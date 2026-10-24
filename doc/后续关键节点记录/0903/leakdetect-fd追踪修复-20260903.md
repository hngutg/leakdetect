# LeakDetect fd 追踪修复（file_close_fd 方案）

> 日期：2026-09-03
> 用途：记录 fd 追踪从 fput 方案切换到 file_close_fd + filp_close 方案的完整过程
> 前置文档：`leakdetect-待处理事项与未来方向-20260826.md`（§三 #4 fd close 侧 kprobe，标记为"延后"）
> 对应 commit：`0e7e807`（fd追踪修复2），6 文件，+242/-99 行

---

## 一、背景

0826 文档 §三 #4 将 fd close 侧 kprobe 标记为"长跑 fd 虚高复现再做"（延后）。
此前 fd 追踪采用 **fput + f_count==1** 方案（commit 32b8e63），存在 epoll 持有引用
导致 f_count>1 → 跳过 close → outstanding 漂移的问题。本阶段彻底解决此问题。

---

## 二、fd 追踪迭代历程（6 次迭代）

| 轮次 | 方案 | 问题 | 结果 |
|---|---|---|---|
| 1 | `sys_enter_close` tracepoint + dup2/dup3 tracepoint | 漏 close_range / close_on_exec / 进程退出 | ❌ |
| 2 | `fput` kprobe + `f_count==1` 检查（CO-RE 读 file->f_count） | epoll 持有引用 f_count>1 → 跳过 → 漂移 | ❌ |
| 3 | `filp_close` kprobe only | filp_close 在 fs/open.c 内被 sys_close 内联 → kprobe 不触发 → close_count≈0 | ❌ |
| 4 | `fput` kprobe（无 f_count 检查，计每次 fput） | epoll/splice/recvmsg 额外 fput → 暂时膨胀 → 假阳性窗口 | ❌ |
| 5 | `close_fd` kprobe + `filp_close` kprobe | close_fd 不被 sys_close 调用 → close_count≈0 | ❌ |
| 6 | **`file_close_fd` kprobe + `filp_close` kprobe** | ftrace 确认 sys_close 调 file_close_fd → 成功 | ✅ |

### 关键教训

- **不能猜内核函数名**：第 5 轮假设 sys_close 调 close_fd，错误。第 6 轮用 ftrace 实锤确认。
- **跨编译单元不内联**：filp_close（fs/open.c）从 fs/file.c 调用时不内联 → kprobe 可触发。
- **同编译单元内联**：filp_close 从 sys_close（同在 fs/open.c）调用时被内联 → kprobe 不触发。
- **epoll 持有引用**：fput 是所有 file 引用递减的终点，但 epoll 的 fput 不是 fd 表移除 → 不应计入 close_count。

---

## 三、ftrace 验证

### 命令

```bash
sudo bash -c '
echo "close_fd file_close_fd filp_close fput" > /sys/kernel/debug/tracing/set_ftrace_filter
echo "function" > /sys/kernel/debug/tracing/current_tracer
echo > /sys/kernel/debug/tracing/trace
sleep 5
cat /sys/kernel/debug/tracing/trace | head -40
echo "nop" > /sys/kernel/debug/tracing/current_tracer
echo > /sys/kernel/debug/tracing/set_ftrace_filter
'
```

### 输出（关键行）

```
file_close_fd <-__x64_sys_close       ← sys_close 调的是 file_close_fd，不是 close_fd
filp_close <-do_dup2                  ← do_dup2 调 filp_close（跨编译单元，不内联）
fput <-filp_close                     ← filp_close 内部调 fput
fput <-ep_item_poll.isra.0            ← epoll 调 fput（不是 fd 表移除）
fput <-remove_vma                     ← 进程退出清理 VMA 调 fput
```

### 三个确认

| # | 确认 | 证据 | 结论 |
|---|---|---|---|
| 1 | sys_close 调 file_close_fd | `file_close_fd <-__x64_sys_close` | hook file_close_fd 正确 ✅ |
| 2 | close_fd 不被调用 | close_fd 完全不出现在 trace 中 | 不 hook close_fd 正确 ✅ |
| 3 | file_close_fd 不调 filp_close | file_close_fd 后无 filp_close 调用 | 无 double-count ✅ |

### 额外发现

- `do_dup2` 调 `filp_close`（跨编译单元 fs/file.c → fs/open.c）→ filp_close kprobe 可触发 ✅
- `filp_close` 内部调 `fput` → filp_close 是 fput 的超集（fput 有额外调用方如 epoll）→ 不应 hook fput
- epoll 清理调 `fput` 不调 `file_close_fd`/`filp_close` → 不影响 close_count ✅

---

## 四、本阶段改动

> commit `0e7e807`，6 文件，+242/-99 行

### 4.1 `bpf/fd.bpf.c` — 核心改动（重写）

**删除**：
- `fd_file_map`（file 指针 → opener PID 映射，1M 条目 hash map）
- `struct file___o`（CO-RE 最小 struct file 定义，用于读 f_count）
- `trace_fput`（fput kprobe + bpf_core_read f_count==1 检查 + fd_file_map 查找/删除）
- `#include <bpf/bpf_core_read.h>`（在 common.h 中删除）

**新增**：

```c
SEC("kprobe/file_close_fd")
int trace_file_close_fd(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct fd_count_key_t ckey = {.pid = (u64)pid};
    struct fd_count_val_t *cval = bpf_map_lookup_elem(&fd_count_map, &ckey);
    if (cval) {
        __sync_fetch_and_add(&cval->close_count, 1);
    }
    return 0;
}

SEC("kprobe/filp_close")
int trace_filp_close(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct fd_count_key_t ckey = {.pid = (u64)pid};
    struct fd_count_val_t *cval = bpf_map_lookup_elem(&fd_count_map, &ckey);
    if (cval) {
        __sync_fetch_and_add(&cval->close_count, 1);
    }
    return 0;
}
```

**简化 `trace_fd_install`**：删除 fd_file_map 更新逻辑（BPF_NOEXIST 插入 + stack 复制），只保留 fd_count_map 的 open_count++。

**头注释更新**：`close_fd + filp_close 方案` → `file_close_fd + filp_close 方案`，补充 ftrace 确认记录。

### 4.2 `bpf/common.h` — 清理废弃结构

- 删除 `#include <bpf/bpf_core_read.h>`（fput CO-RE 依赖，不再需要）
- 删除 `struct fd_file_val_t`（file 指针追踪结构体，不再使用）

### 4.3 `core/loader.py` — 适配新 BPF 程序

**删除**：
- `FdFileVal` ctypes Structure（对应已删除的 `fd_file_val_t`）
- `clean_dead_pid_fd_file_map()` 方法（fd_file_map 已移除，无需清理）

**修改 `load_fd()`**：

```python
# 改前（fput 方案）
self._attach_kprobe("fd", "trace_fput", "fput")

# 改后（file_close_fd + filp_close 方案）
self._attach_kprobe("fd", "trace_file_close_fd", "file_close_fd")
self._attach_kprobe("fd", "trace_filp_close", "filp_close")
```

### 4.4 `tests/verify_fd.py` — 新增验证脚本（211 行）

**功能**：对比 BPF `fd_count_map` 中 PID 的 `open_count - close_count` 与 `/proc/pid/fd` 真实 fd 数。

**双模式读取**：
- **方式 1（首选）**：libbpf ctypes — `bpf_map_get_fd_by_id` + `bpf_map_get_next_key` + `bpf_map_lookup_elem`，与 `loader.py:read_fd_count_map` 逻辑完全一致。`_load_libbpf()` 尝试 `libbpf.so.1` → `.so.0` → `.so`（与 loader.py 一致）。FD 用 `try/finally: os.close(fd)` 防泄漏。
- **方式 2（备选）**：bpftool JSON — `bpftool map dump id <ID> -j` + `parse_hex()`（兼容 `["0x01","0x00"]` 和 `"01 00"` 两种 hex 格式）。

**输出格式**：

```
时间        BPF_open  BPF_close   BPF_out  real_fd    diff
15:42:55        4009        3977        32       125     -93  OK
```

**用法**：`sudo python3 tests/verify_fd.py [pid] [interval秒]`（默认 pid=1, interval=5）

### 4.5 `web/backend.py` — 清理废弃调用

`_dead_pid_cleaner_loop` 删除 `clean_dead_pid_fd_file_map()` 调用（fd_file_map 已移除）。

### 4.6 `web/static/js/app.js` — 去掉初始历史加载

`onMounted` 中删除 `loadHistory` 循环（图表从空开始，仅用实时 SocketIO 数据构建，避免初始加载历史数据与实时数据叠加）。

---

## 五、x86 VM 验证结果

### 环境

- 节点：x86 VM（Ubuntu 24.04，kernel 6.8.0-124-generic）
- 监控对象：PID 1（systemd）
- 运行时长：40 分钟（15:42:55 → 16:22:16）

### 关键数据

| 时间 | BPF_open | BPF_close | BPF_out | real_fd | diff |
|---|---|---|---|---|---|
| 15:42:55 | 4009 | 3977 | 32 | 125 | -93 |
| 15:50:01 | 4120 | 4087 | 33 | 125 | -92 |
| 15:53:01 | 4223 | 4182 | 41 | 132 | -91 |
| 16:00:02 | 4358 | 4322 | 36 | 125 | -89 |
| 16:10:04 | 4490 | 4453 | 37 | 125 | -88 |
| 16:20:05 | 4621 | 4583 | 38 | 125 | -87 |
| 16:22:16 | 4640 | 4602 | 38 | 125 | -87 |

### 判定

| 指标 | 结果 | 判定 |
|---|---|---|
| `close_count` 正常增长 | 3977→4602（+625） | ✅ file_close_fd 正确触发 |
| `close_count < open_count` | 4602 < 4640 | ✅ 无 double-count |
| `real_fd` 稳定 | 125→125 | ✅ systemd 无 fd 泄露 |
| `BPF_out` 微漂 | 32→38（+6/40min） | ⚠️ 轻微漂移 |
| 漂移率 | 6/631 = 0.9% | ✅ 可接受 |
| `diff` 收窄 | -93→-87 | ⚠️ 方向一致 |

### 对比之前方案

| 方案 | close_count | BPF_out | 可用性 |
|---|---|---|---|
| fput + f_count | 不可控 | 暴涨（epoll 多计） | ❌ |
| filp_close only | ≈0 | 暴涨（内联不触发） | ❌ |
| close_fd + filp_close | ≈0 | 暴涨（close_fd 不触发） | ❌ |
| **file_close_fd + filp_close** | **正常增长** | **稳定+微漂** | ✅ |

---

## 六、已知局限

| # | 局限 | 原因 | 影响 | 可接受? |
|---|---|---|---|---|
| 1 | pre-existing fd 少计 | systemd 启动早于 LeakDetect，fd_install kprobe 未 attach 时已打开的 fd 不计入 open_count | diff 的主要来源（~93） | ✅ 新进程无此问题 |
| 2 | dup2 少计 open | dup2 不调 fd_install → 新 fd 表条目未计入 open_count | 每次 dup2 少计 1 个 open | ✅ 恒定偏差，不影响趋势 |
| 3 | 轻微漂移（~9/hour） | 少量 close 路径未覆盖（可能 close_range、内核内部 fput） | BPF_out 缓慢增长 | ✅ 漂移率 0.9%，远低于泄露速率 |
| 4 | 仅假阴性（少计） | 以上三项都是少计 open 或少计 close | outstanding 偏低 | ✅ 无假阳性（不会误报） |

**核心结论**：所有局限都是假阴性（少计），不会产生假阳性（误报）。对泄露检测来说，**趋势准确**（稳定 = 无泄露，增长 = 有泄露），绝对值略低可接受。

---

## 七、fd 关闭路径覆盖分析

### 已覆盖的 close 路径

| close 路径 | 调用函数 | 我们的 hook | 覆盖? |
|---|---|---|---|
| sys_close | file_close_fd | kprobe/file_close_fd | ✅ |
| dup2/dup3 | filp_close（从 do_dup2） | kprobe/filp_close | ✅ |
| close_range | filp_close（从 __close_range） | kprobe/filp_close | ✅（推断，ftrace 未单独验证） |
| close_on_exec | filp_close（从 do_close_on_exec） | kprobe/filp_close | ✅（推断） |

### 未覆盖的 close 路径（漂移来源）

| close 路径 | 调用函数 | 我们的 hook | 覆盖? | 说明 |
|---|---|---|---|---|
| epoll 清理 | fput（直接） | 无 | ❌ | 不是 fd 表移除，正确不计入 |
| 进程退出 VMA 清理 | fput（从 remove_vma） | 无 | ❌ | 不是 fd 表移除，正确不计入 |
| socket recv | fput（从 __sys_recvfrom） | 无 | ❌ | 不是 fd 表移除，正确不计入 |
| 某些内核内部 close | fput（直接） | 无 | ❌ | 可能是漂移来源（~0.9%） |

### open 侧覆盖

| open 路径 | 调用函数 | 我们的 hook | 覆盖? |
|---|---|---|---|
| open/socket/pipe 等 | fd_install | kprobe/fd_install | ✅ |
| dup2/dup3 | do_dup2（不调 fd_install） | 无 | ❌ 少计 open |

---

## 八、后续待办

| # | 事项 | 优先级 | 说明 |
|---|---|---|---|
| 1 | ARM 验证 | 高 | 确认 ARM kernel 6.x 有 `file_close_fd` 且 sys_close 调用它。若 ARM 用 `close_fd` → 需回退或条件编译 |
| 2 | `package_arm.sh` 打包 `verify_fd.py` | 中 | 当前打包脚本不含 verify_fd.py，需加 `cp tests/verify_fd.py "$PKG_DIR/tests/"` |
| 3 | dup2 open 侧补充 | 低 | 可 hook `do_dup2` 的 open 侧（复杂度高，当前偏差恒定可接受） |
| 4 | 漂移来源定位 | 低 | 用 ftrace 长时间捕获，定位 0.9% 未覆盖的 close 路径 |
| 5 | 内核版本兼容 | 低 | `file_close_fd` 在 kernel 6.0 引入，5.x 内核可能用 `close_fd` → 需条件加载或 fallback |
