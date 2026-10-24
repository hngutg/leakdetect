# LeakDetect 现阶段进展总结

> 日期：2026-09-03
> 用途：记录截至 2026-09-03 的整体进展、当前缺陷、待解决事项和验证覆盖情况
> 前置文档：`leakdetect-待处理事项与未来方向-20260826.md` + `leakdetect-fd追踪修复-20260903.md`

---

## 一、已完成工作（按时间线）

| 阶段 | 日期 | 内容 | 验证状态 |
|---|---|---|---|
| 初期 | 2026-07 | F0-F4 前端 + B0-B4 后端 + M9-M11 libbpf 迁移 | ✅ |
| REST + 容器 | 08-15 | C1/C2 REST 接线 + 符号修复 + Phase 1 容器选择 + 打包兼容 | ✅ x86+ARM |
| 精度专项 | 08-21 | OLS + per-PID + 驱逐 + 疑似/确认 + B 方案 map 聚合 + 双计数器 | ✅ x86+ARM |
| 栈符号 | 08-26 | Tier 1 debuginfo + Tier 2 DWARF 行号 + 兜底库名+偏移 + 栈展示修复 | ✅ x86+ARM |
| 采样修复 | 08-26 | sampler HASH→ARRAY + 死 pid 清理器 + ARM K8s 验证 | ✅ x86+ARM |
| P3 值算法 | 08-27 | sum-then-clamp → per-sid clamp（3 处） | ✅ 11 场景 PASS |
| P4 alerts 接 DB | 08-28 | query_alerts + get_alerts + api.py 连接 | ✅ 608 条→API |
| P2 libc uprobe | 08-29 | 全 libc 发现 + inode 去重 + PIE 偏移修正 + 容器路径 | ✅ ARM 17 libc |
| mmap 追踪 | 08-29 | 3 map + 4 BPF 程序 + munmap/mremap tracepoint + analyzer | ✅ x86 |
| fd 追踪修复 | 09-03 | fput → file_close_fd + filp_close（ftrace 确认）+ verify_fd.py | ✅ x86 40min |

---

## 二、当前缺陷与局限

### 2.1 fd 追踪（当前方案：file_close_fd + filp_close）

| # | 缺陷 | 原因 | 影响 | 性质 |
|---|---|---|---|---|
| 1 | pre-existing fd 少计（~93） | systemd 启动早于 LeakDetect，fd_install kprobe 未 attach 时已打开的 fd 不计入 open_count | diff 主要来源 | 假阴性 |
| 2 | dup2 少计 open | dup2 不调 fd_install → 新 fd 表条目未计入 open_count | 恒定偏差 | 假阴性 |
| 3 | 轻微漂移（~9/hour，0.9%） | 少量 close 路径未覆盖（可能 close_range、内核内部 fput） | BPF_out 缓慢增长 | 假阴性 |
| 4 | ARM 未验证 | file_close_fd 可能在 ARM 内核不存在或 sys_close 不调用它 | 未知 | 风险 |

**关键**：缺陷 1-3 都是假阴性（少计），无假阳性（不会误报）。对泄露检测来说，**趋势准确**（稳定 = 无泄露，增长 = 有泄露），绝对值略低可接受。

### 2.2 代码/仓库卫生问题

| # | 问题 | 状态 | 说明 |
|---|---|---|---|
| 1 | README 过时 | ❌ 未修 | 仍写"MVP 加载层 BCC"（实际 libbpf ctypes）；项目结构写 `logging/`（实际 `alert_logging/`） |
| 2 | `packaging/start.sh` DIR bug | ❌ 未修 | `DIR` 指向 `packaging/` 而非仓库根，源码树用 `sudo python3 web/app.py` 绕过 |
| 3 | `data/leakdetect.db` + `.log` 被 git 跟踪 | ✅ 已修 | .gitignore 已忽略，git 不跟踪 |
| 4 | 测试二进制（mem_leak 等 ELF）被 git 跟踪 | ❌ 未修 | `tests/leak_programs/mem_leak`、`fd_leak`、`thread_leak` 仍在 git 中 |
| 5 | `core/filter_manager.py` 仍是 stub | ❌ 未实现 | 6 行 TODO，黑白名单功能缺失 |
| 6 | 3 个 filter REST 端点返回硬编码空数据 | ❌ 未实现 | `/api/config/filter` GET/POST + `/api/config/filter/preview` 返回固定空响应 |

### 2.3 loader link 指针未保存（非功能性，代码卫生）

> 核实日期：2026-09-05
> 性质：代码一致性 / 认知误导，**非功能性 bug**，不影响运行

**现象**：`core/loader.py` 的 `_attach_kprobe`(:252)/`_attach_tp`(:261)/`_attach_uprobe`(:240) 三个 helper 调 `bpf_program__attach_*` 拿到 link 指针后判空即丢弃，不存入 `self._links`；仅 `_attach_all_libc_uprobes`(:371) 存。导致 8 个探针 link 未保存：fd 的 3 个 kprobe（fd_install/file_close_fd/filp_close）、threads 的 3 个 tracepoint（clone/clone3/sched_process_exit）、mem 的 2 个 tracepoint（munmap/mremap）。

**原因**：`__init__`(:210) 注释写「持有 uprobe link 指针，防 GC 导致 detach」，但这是对 libbpf+ctypes 语义的误解。`bpf_program__attach_*` 返回 `struct bpf_link *`，ctypes `c_void_p` 只是个整数，Python GC 回收的是该整数对象，不触发任何 C 侧析构；link 在内核侧已 attach（LINK_CREATE 完成、持有内核 link fd），丢掉 Python 引用不会 detach。三个 helper 未遵循自己的注释。

**libbpf 语义**：探针保持 attach 直到以下任一发生：显式 `bpf_link__destroy()`/`bpf_link__detach()`、关闭 link fd、`bpf_object__close()`、进程退出。本仓库未声明 `bpf_link__destroy`/`bpf_object__close` 符号（函数签名 :41-85 无），`cleanup()`(:639-643) 只置空 `self._objects`，从不调 close —— 存与不存 link，运行期行为一致。

**影响（不改动会出什么问题）**：

| 项 | 影响 |
|---|---|
| 探针是否失效 | ❌ 不会，8 个探针全程工作（fd/threads/munmap/mremap 全部生效）|
| 内存泄漏 | bpf_link 结构体未显式 free，~8×几十字节，进程退出回收，可忽略 |
| fd 泄漏 | ~8 个内核 link fd，daemon 本身 fd 上百，无感 |
| 认知误导 | ❌ 注释与代码自相矛盾，后人易误判「threads/fd 探针悬空未生效」而浪费排查 |
| 未来加优雅关闭 | 若将来实现 `cleanup` 调 `bpf_link__destroy`，需先补全 link 收集（3 行）|

**结论**：不修不影响任何功能；修只是 3 行一致性改动（三个 helper 末尾各加 `self._links.append(link)`）+ 修正 `__init__` 注释。**优先级 P2（代码卫生）**，不阻塞任何功能与 ARM 验证。

---

## 三、待解决事项（按优先级）

### 3.1 高优先级

| # | 事项 | 工作量 | 依赖 | 说明 |
|---|---|---|---|---|
| 1 | ARM 验证 fd 追踪 | 小（~1h） | 无 | 确认 ARM kernel 6.x 有 `file_close_fd` 且 sys_close 调用它。若 ARM 用 `close_fd` → 需回退或条件编译 |
| 2 | `package_arm.sh` 打包 `verify_fd.py` | 极小（1 行） | 无 | 加 `cp tests/verify_fd.py "$PKG_DIR/tests/"` |

### 3.2 中优先级

| # | 事项 | 工作量 | 依赖 | 说明 |
|---|---|---|---|---|
| 3 | P1 持久化专项 | 大（1-2 周） | 无 | D1: sampler 写全量 PID + 填 container_id；D2: db.py 加按 pid/容器/时间查询；D3: 激活降采样；D4: retention purge；D5: 索引优化；D6: alerts 填 container_id |
| 4 | P5 黑白名单 | 中（2-3 天） | 无 | filter_manager.py 实现 name_regex → PID → BPF pid_filter_map + 3 个 REST 端点接线 |
| 5 | P6 导出功能 | 小-中 | 无 | 导出告警进程信息（Excel）+ 按进程导出泄露信息 |
| 6 | README 更新 | 小 | 无 | 改 BCC→libbpf、`logging/`→`alert_logging/`、补启动步骤 |
| 7 | start.sh DIR 修复 | 极小 | 无 | `dirname "$0"` → `dirname "$0")/.."` |
| 8 | 测试二进制从 git 移除 | 极小 | 无 | .gitignore 加 `tests/leak_programs/mem_leak` 等 + `git rm --cached` |

### 3.3 低优先级/可选

| # | 事项 | 说明 |
|---|---|---|
| 9 | P7 打包 debuginfo | 阻塞（需 EulerOS 内部渠道获取 .debug 文件；代码仅 2 行 + 打包 3 行） |
| 10 | Werkzeug WS 修复 | cosmetic（`async_mode="threading"` 不支持 WS 升级 → 500，回退 long-polling 正常；装 eventlet 或 `allow_upgrades=False`） |
| 11 | Tier 3 PIE 偏移修正 | `_resolve_addr` 在极少数 ELF（`p_vaddr ≠ p_offset`）时偏移算错 → 走兜底，影响面极小 |
| 12 | cgroup v2 支持 | 解析 v2 单行格式 |
| 13 | CPU 火焰图 | 用户需求，可选 |
| 14 | 内存 perf 图 | 用户需求，可选 |
| 15 | dup2 open 侧补充 | hook `do_dup2` 的 open 侧（复杂度高，当前偏差恒定可接受） |
| 16 | 漂移来源定位 | ftrace 长时间捕获，定位 0.9% 未覆盖的 close 路径 |
| 17 | 内核版本兼容 | `file_close_fd` 在 kernel 6.0 引入，5.x 内核可能用 `close_fd` → 需条件加载或 fallback |
| 18 | BPF_ATOMIC 5.10 兼容 | 设为环境需求（内核 ≥5.12），不做条件编译 |

---

## 四、验证覆盖矩阵

| 功能 | x86 VM | ARM dfx-syn01 | ARM cscf-dfx-syn02 |
|---|---|---|---|
| mem (malloc) 追踪 | ✅ 验证 | ✅ 验证 | ⬜ 未验证（最新代码） |
| mmap 追踪 | ✅ 验证 | ⬜ 未验证 | ⬜ 未验证 |
| thread 追踪 | ✅ 验证 | ✅ 验证 | ⬜ 未验证 |
| fd 追踪 (file_close_fd) | ✅ 40min 长跑 | ⬜ 未验证 | ⬜ 未验证 |
| P2 全 libc uprobe | ✅ 验证 | ✅ 17 libc 挂载 | ✅ 验证 |
| P3 值算法 | ✅ 11 场景 PASS | ⬜ | ⬜ |
| P4 /api/alerts | ✅ 608 条→API | ⬜ | ⬜ |
| 栈符号解析 | ✅ debuginfo | ✅ 兜底（库名+偏移） | ⬜ |

---

## 五、当前架构能力边界

| 能力 | 状态 | 说明 |
|---|---|---|
| 内存泄露检测（malloc） | ✅ 可用 | 1/100 采样 ×100 补偿，含栈归因 |
| 映射内存泄露检测（mmap） | ✅ 可用 | 全量追踪，含栈归因 |
| 线程泄露检测 | ✅ 可用 | 全量追踪 |
| fd 泄露检测 | ✅ 可用 | file_close_fd + filp_close，漂移率 0.9% |
| CPU 监控 | ✅ 可用 | /proc 采样，无泄露检测 |
| 容器内存监控 | ✅ 可用 | 全 libc uprobe + 容器路径 |
| 历史趋势 | ⚠️ 部分 | sampler 写 DB 但只 top-5，无 per-pid 全量历史 |
| 告警查看 | ✅ 可用 | /api/alerts 接 DB |
| 黑白名单 | ❌ 未实现 | stub + 硬编码 REST |
| 导出 | ❌ 未实现 | |
| 慢泄露检测（RSS 长基线） | ❌ 未实现 | 依赖 P1 持久化 |

---

## 六、建议实施顺序

```
fd 追踪 ARM 验证（高, ~1h）+ package_arm.sh 含 verify_fd.py（高, 1 行）
    ↓
代码卫生修复（README + start.sh + git rm 测试二进制, 各极小）
    ↓
持久化专项 P1（中, 1-2 周）
    ↓ （有 per-pid RSS 全量历史）
Tier-2 慢泄露检测（RSS 长基线 delta）
    ↓
黑白名单 P5（2-3 天）/ 导出 P6（小-中）
    ↓
可选增强（CPU 火焰图 / 内存 perf 图 / cgroup v2 等）
```
