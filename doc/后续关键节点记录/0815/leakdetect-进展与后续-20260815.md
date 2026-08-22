# LeakDetect 进展总结与后续关键节点

> 文档版本：v1.0
> 日期：2026-08-15
> 用途：记录当前工程进展、已知的不足与遗留问题、后续开发方向与专项规划。
> 目标读者：开发人员（回顾已完成工作、指导后续开发）。

---

## 一、项目概述

LeakDetect 是基于 eBPF 的资源监控与泄露检测工具，对四种资源（内存、线程、句柄、CPU）实现实时监控与泄露检测，通过 Web 前端实时展示。

- **eBPF 框架**：libbpf + CO-RE（预编译 .o，Python ctypes 加载）
- **分析层**：Python（泄露判定、聚合、告警）
- **前端**：Flask + Flask-SocketIO + Vue 3 (CDN) + Chart.js
- **存储**：SQLite
- **打包**：tar.gz 自包含（.o + libbpf.so + py-packages + start.sh）

---

## 二、已完成的代码改动

### 2.1 REST 路由接线（C1）

**问题**：`web/app.py` 未调用 `api.set_backend(backend)`，导致 8 条 REST 路由的 `if _backend is not None` 分支恒为 False，全部走 mock。

**修复**：
- `web/app.py`：`from api import api, set_backend`；成功分支 `set_backend(backend)`；mock 回退分支 `set_backend(None)`。
- `web/backend.py`：`update_monitoring_config` 加 `isinstance` 类型硬化（防空串/None 致 `check()` TypeError）。

**验证**：`curl /api/containers` 返回诚实空 `[]`（原 4 个假容器）；`/api/history`、`/api/config/monitoring` 走真后端。

### 2.2 host/port 从 config + IPv6（C2）

**问题**：`app.py` 硬编码 `127.0.0.1:8080`，忽略 config；不支持 IPv6。

**修复**：
- `config/default.yaml`：`host: "::"` + 三种地址注释。
- `web/app.py`：从 config 读 host/port + IPv6 URL 打印 `http://[%s]:%d` + try/except OSError 回退 `0.0.0.0`（`::` 绑不了时）+ docstring 更新。
- `web/app.py`：werkzeug 条件传参（`_wz_major >= 3` 时传 `allow_unsafe_werkzeug=True`，werkzeug 2.x 不传 → 不 TypeError）。

**验证**：启动日志 `http://[::]:8080` + werkzeug `Running on all addresses (::)`。

### 2.3 符号解析 per-symbol 容错

**问题**：`symbolizer/symbols.py` 的 `_get_symbols` 用 `except Exception: pass` 吞掉 `.gnu.version` 段条目的 `KeyError('st_info')` → 整个 ELF 缓存空 → mem_leak 全帧 `[unknown]`。

**修复**：`_get_symbols`：except 从"整个 ELF"收窄到"单符号"（per-symbol try/except 跳过坏条目）+ 外层 try/except/else 告警（读失败/0 符号不再静默）。

**验证**：mem_leak 栈 `_start` 从 `[unknown]` → `_start+0x25`。

### 2.4 mem [RSP] 叶子帧补帧

**问题**：`bpf_get_stack(BPF_F_USER_STACK)` 用 RBP 链回溯，在 malloc 入口跳过 `[RSP]` 里的 return-to-caller → main 等叶子帧丢失。

**修复**：`bpf/mem.bpf.c` `trace_malloc_entry`：`bpf_probe_read_user` 读 `[RSP]` → 去重 → 后移插入 frame 1（保留 frame 0 = malloc RIP）。含去重（若 walker 已含 ra 则不插）。

**验证**：mem_leak 栈 `malloc → main+0x4c → [unknown] → __libc_start_main+0x8b → _start+0x25`（main 现身）。

### 2.5 Phase 1 容器选择（7 文件）

**目标**：下拉框选"宿主机"或某容器 → 看板只显示对应进程。后台全量采集存储（capture all），显示层按 target 过滤（filter at display）。

| 文件 | 改动 |
|---|---|
| `core/cgroup_enum.py` | 桩（6 行）→ 完整实现（~130 行）：遍历 `/proc/*/cgroup` 解析 `/kubepods/`、`/docker/`、`/lxc/`；按 cid 聚 PID 集；`docker ps` 取容器名；后台 30s 刷新；`rstrip("/")` 防尾斜杠；`start()` 初始 `_refresh` 包 try/except |
| `core/aggregator.py` | `get_per_process_mem/thread/fd` 去 `[:5]` 返回全量 |
| `analyzer/cpu.py` | `poll()` 去 `[:5]` 返回全量 |
| `web/backend.py` | 整体重写：`import CgroupEnum` + `display_target`（None=宿主 / cid=容器）+ `set_display_target()` + `get_dashboard_update()` 按 `target_pids` 过滤 per_process/latest_points/alerts + `_top5()` + sampler 全 `[:5]`（DB 不增长）+ 选中容器消失 warning + debug 带 target；保留 C1 的 `update_monitoring_config` 硬化 |
| `web/sockets.py` | `select_container`：`pass` → `backend.set_display_target(cid)` |
| `web/api.py` | `/api/containers`：`{"containers": []}` → `_backend.cgroup_enum.enumerate()` |
| `web/static/index.html` | 默认项 `全部容器` → `宿主机`；option 文案 `c.name` → `c.name + (c.id_short ? ...)` |

**设计要点**：
- `cgroup_enum` 后台线程 30s 刷新（`docker ps` + `/proc/*/cgroup` 解析），不阻塞 pusher。
- `enumerate()` 返回前端友好格式（无 pids 列表，有 `pid_count`），避免每秒推大数组。
- `target_pids(cid)`：cid=None → 宿主 PID 集（不在任何容器 cgroup）；cid=X → 该容器 PID 集。
- sampler 全 `[:5]`：DB 写入量不变（top-5），不引爆增长。实时显示用 aggregator 内存态（全量），不依赖 samples 表。
- chart（历史曲线）仍读 samples（全局 top-5），不按 target 过滤——"历史延后"已知限制。

**验证**：arm64/glibc 2.38/Python 3.11 节点（dfx-syn01-csp-c-arm-0）→ `/api/containers` 返回 50+ 容器（K8s 全名 + pid_count）+ 浏览器可访问 + 下拉选容器切换视图正确。

### 2.6 fd 虚高文档订正

**问题**：`b2-fd-issue-summary.md` v1.0 描述 fd 虚高未解决，但实际代码已用 `kprobe/fd_install`（open 侧 100% 覆盖），主根因已消除。

**修复**：`b2-fd-issue-summary.md` 升 v2.0：
- fd_install kprobe 已实施（open 侧 100% 覆盖）→ 虚高主根因消除。
- mem 负数未复现（防御性 refcount 生效）。
- 符号解析：per-symbol ✅ 已修 / 方案 B（[RSP]）✅ 已验证 / 方案 A（libunwind）⬜ 遗留。

---

## 三、打包兼容性修复

### 3.1 Python 3.9 兼容（`--python-version` + `--only-binary`）

**问题**：`pip download` 在 Python 3.12 构建机上解析依赖为 latest → wsproto 1.3.x（`>=3.10`，用 `bytes | bytearray` 语法）+ pyelftools 0.33（`>=3.10`）→ Python 3.9 上 SyntaxError/TypeError。

**修复**：
- `tools/package_arm.sh` L85：`pip download --python-version "$TARGET_PY" --only-binary :all:`
- `tools/package.sh` L61：同上
- `--python-version 3.9` → pip 按 3.9 解析（跳过 >=3.10 版本）→ wsproto 1.2.0 + pyelftools 0.32
- `--only-binary :all:` → 强制只下 wheel（不 build sdist，避免 3.12 机器无法为 3.9 构建）

**验证**：包里 wsproto 1.2.0（不是 1.3.x）、pyelftools 0.32（不是 0.33）、markupsafe/pyyaml cp39 wheel。Python 3.9.9 节点无 SyntaxError/TypeError。

### 3.2 libelf1t64 回退（Ubuntu noble time64 重命名）

**问题**：Ubuntu 24.04 (noble) 把 `libelf1` 重命名为 `libelf1t64`（time64 迁移）→ `apt-get download libelf1:arm64` 无候选 → 整条 `apt-get download libbpf1:arm64 libelf1:arm64` 失败 → libbpf 也没下到。

**修复**：`tools/package_arm.sh` + `tools/package.sh`：
- 拆分 `apt-get download libbpf1:arm64 libelf1:arm64` 为两条独立命令（libelf 失败不拖垮 libbpf）。
- libelf 回退：`apt-get download libelf1:arm64 || apt-get download libelf1t64:arm64`。
- glob 匹配：`libelf1*_*arm64.deb`（匹配 libelf1 + libelf1t64）。

### 3.3 libelf 不再 bundle（LD_LIBRARY_PATH 毒化修复）

**问题**：包的 `lib/` 里 bundle 了 noble 的 `libelf.so.1`（glibc 2.38）。在 glibc 2.34 节点上，`LD_LIBRARY_PATH=lib` 让系统 libbpf.so.0（0.8.1, glibc 2.34）的依赖 libelf.so.1 被解析到 noble 版（glibc 2.38）→ 加载失败 → "libbpf not found"。

**修复**：`tools/package_arm.sh`：删除 libelf 的下载/提取/复制/清理（4 处）→ `lib/` 只有 libbpf.so* → 系统提供 libelf.so.1（各节点 glibc 匹配）。

**验证**：glibc 2.34 节点 libbpf.so.0 + 系统 libelf 加载成功（不再 "libbpf not found"）。

### 3.4 werkzeug 条件传参

**问题**：`app.py` 固定传 `allow_unsafe_werkzeug=True` → werkzeug 2.x（pinned for 3.9）的 `run_simple` 不接受此参数 → TypeError。

**修复**：`web/app.py`：`import werkzeug` → `_wz_major = int(werkzeug.__version__.split(".")[0])` → `if _wz_major >= 3: _run_kwargs["allow_unsafe_werkzeug"] = True` → `socketio.run(app, ..., **_run_kwargs)`。

**验证**：werkzeug 2.x（syn02, Python 3.9）+ 3.x（VM, Python 3.12）都不 TypeError。

### 3.5 libbpf.so.0 回退（glibc 2.34 兼容）

**问题**：bundled `libbpf.so.1`（noble, glibc 2.38）在 glibc 2.34 节点加载失败（GLIBC_2.38 not found）。系统有 `libbpf.so.0`（0.8.1, glibc 2.34）但 loader 不找 `.so.0`。

**修复**：`core/loader.py` `_load_libbpf()`：尝试列表从 `("libbpf.so.1", "libbpf.so")` 改为 `("libbpf.so.1", "libbpf.so.0", "libbpf.so")`。

**验证**：glibc 2.34 节点 libbpf.so.1（bundled, glibc 2.38）失败 → libbpf.so.0（系统 0.8.1, glibc 2.34）加载成功。glibc 2.38 节点 libbpf.so.1 先成功 → 不走 .so.0 → 行为不变。

---

## 四、文档更新

| 文档 | 更新内容 |
|---|---|
| `leakdetect-plan.md` §十一 | 实施进展 + 问题修复表（5 项）+ 容器监控设计（Phase 1/2/3 分期）+ 状态汇总 |
| `b2-fd-issue-summary.md` v2.0 | fd_install 已解决虚高主根因 / mem 负数未复现 / 符号 §8.5：per-symbol ✅、mem [RSP] ✅、方案 A ⬜ 遗留 |
| `leakdetect-进展与后续-20260815.md`（本文档） | 全量进展 + 打包修复 + 环境需求 + 已知限制 + 两个专项立项 |

---

## 五、验证状态

| 节点 | 架构 | Python | glibc | 内核 | 结果 |
|---|---|---|---|---|---|
| VM-0-10-ubuntu | x86_64 | 3.12 | 2.38+ | 6.x | C1/C2/符号/mem [RSP] 全验证 ✅ |
| dfx-syn01-csp-c-arm-0 | aarch64 | 3.11.6 | 2.38 | 6.x | **Phase 1 全通过**：Backend 真起 + BPF 加载 + 50+ 容器 + REST 真数据 + 浏览器可访问 ✅ |
| syn02-service-vdu-2 | aarch64 | 3.9.9 | 2.34 | 5.10 | Python 3.9 兼容 ✅ + libbpf.so.0 回退 ✅ + libelf 毒化消除 ✅。**但 BPF 程序加载失败**（5.10 不支持 BPF_ATOMIC）❌ |

---

## 六、环境需求（最终确定）

| 需求 | 值 | 原因 |
|---|---|---|
| 权限 | root | eBPF 内核能力 |
| 内核 | ≥ 5.12 | BPF_ATOMIC 指令支持（`__sync_fetch_and_sub` 编译为 BPF_ATOMIC） |
| BTF | `/sys/kernel/btf/vmlinux` 存在 | CO-RE 依赖 |
| Python | 3.9 - 3.12 | pinned 依赖兼容（flask 2.2.5 + click 8.0.4 + werkzeug 2.3.8） |
| glibc | ≥ 2.34 | libbpf.so.0 回退（系统 0.8.1）或 ≥ 2.38（bundled .so.1） |
| 系统 libelf | `libelf.so.1` 存在 | libbpf 依赖（不再 bundle，由系统提供） |
| 系统 libz | `libz.so.1` 存在 | libbpf 依赖（不 bundle） |

---

## 七、已知限制

| # | 限制 | 原因 | 影响 | 修复方向 |
|---|---|---|---|---|
| 1 | **内核 ≥ 5.12** | BPF 程序用 `__sync_fetch_and_sub`（BPF_ATOMIC），5.10 不支持 | EulerOS 5.10 节点无法运行 | 条件编译两套 .o（原子/非原子）→ 待需要时立项 |
| 2 | **容器 mem=0** | uprobe 只挂宿主 libc，容器自带 libc 不被追踪 | 容器模式 mem 卡片为空 | Phase 2（全 libc uprobe） |
| 3 | **栈 `[unknown]`**（部分） | symbolizer 缺 kallsyms + 用户态 PIE 解析不全 | 泄露栈定位不完整 | 方案 A（libunwind）或装 debuginfo |
| 4 | **内存值 `*100` 高估** | 1/100 采样 ×100 修正，少量大块分配被放大 100 倍 | 显示值不准（7.5GB 实际 ~75MB）→ 大量误报 | 内存检测精度专项（5 根因已分析） |
| 5 | **自监控误报** | leakdetect 的 python3 自身 malloc 被监控 → 自己告自己 | "+13 python3" 假告警 | 内存检测精度专项（排除自身 PID） |
| 6 | **per-stack 粒度告警** | 每个 (pid, stack) 独立状态机 → 一个进程 N 个栈 → N 个告警 | 告警数量膨胀 | 内存检测精度专项（按 PID 聚合） |
| 7 | **chart 不按 target 过滤** | sampler 写全局 top-5，不按容器 | 历史曲线不匹配选定容器 | 持久化专项 |
| 8 | **libelf 不自包含** | noble libelf 毒化 glibc 2.34 → 改为系统提供 | 目标需有系统 libelf.so.1 | 从源码编 glibc 兼容的 libelf bundle（复杂，暂不做） |
| 9 | **dup2 tracepoint 缺失**（arm64） | arm64 内核无 `sys_enter_dup2` tracepoint | dup2 静默关闭不被追踪 | 已优雅跳过（`optional=True`），dup3 覆盖 |
| 10 | **package.sh 交叉架构名 bug** | `${TARGET_ARCH/amd64/x86_64}` 生成 `aarch64`（apt 要 `arm64`） | package.sh 交叉路径不通 | 不阻塞（用 package_arm.sh）；待需要时修 |
| 11 | **无 retention purge** | db.py 无 DELETE 逻辑 | samples 无限累积 | 持久化专项 |

---

## 八、未完成/待做

| # | 内容 | 状态 | 依赖/备注 |
|---|---|---|---|
| 1 | **内存检测精度专项** | ⬜ 待立项 | 5 根因 + 5 修复已分析（见 §九.1） |
| 2 | **持久化专项** | ⬜ 待立项 | 历史查询 + 泄露点定位（见 §九.2） |
| 3 | **Phase 2：mem 全 libc uprobe** | ⬜ 待实施 | 给节点所有 libc 挂 uprobe + symbolizer `/proc/[pid]/root` |
| 4 | **Phase 3：历史/存储** | ⬜ 延后 | 已并入持久化专项 |
| 5 | **黑白名单**（原 B3 另一半） | ⬜ 延后 | pid_filter_map + 进程名正则 + filter API |
| 6 | **方案 A libunwind** | ⬜ 遗留 | kprobe/tracepoint 栈全栈回溯 |
| 7 | **fd close 侧 close_fd kprobe** | ⬜ 延后 | 长跑虚高复现再做 |
| 8 | **BPF_ATOMIC 5.10 兼容** | ⬜ 不做（设为环境需求） | 条件编译两套 .o → 复杂度高 |
| 9 | **文档同步** | ⬜ 待更新 | 打包/werkzeug/loader/libelf/BPF_ATOMIC 环境需求 + 两个专项 未记入 `leakdetect-plan.md` §十一 |
| 10 | **glibc 2.34 + 内核 ≥ 5.12 节点完整验证** | ⚠️ 待找节点 | syn02-service-vdu-2 是 5.10（不支持 BPF_ATOMIC）；需找 glibc 2.34 + 内核 ≥ 5.12 的节点验证 |

---

## 九、专项立项

### 9.1 内存检测精度专项

**问题现象**：arm64/K8s 节点上大量内存泄露告警（疑似误报）；`/api/history` 显示 7.5GB 增长但环境长稳无问题 → 测量不准。

**5 个根因**：

| # | 根因 | 代码位置 | 影响 |
|---|---|---|---|
| 1 | `*100` 采样高估 | `aggregator.py:59,69` + `memory.py:34` | 少量大块分配被 1/100 采样 → ×100 放大 100 倍 |
| 2 | 自监控（python3 自己告自己） | `memory.py` `_iter_stats` 无自身 PID 排除 | leakdetect 自身的 malloc 被监控 |
| 3 | 按 (pid,stack) 粒度追踪 | `memory.py:35` `key=(pid,sid)` | 一个进程 N 个栈 → N 个告警 |
| 4 | 阈值对 *100 太低（1MB） | `config/default.yaml` | 几乎所有活跃进程都超阈值 |
| 5 | 启动期增长无法区分 | `base.py` 状态机 | 启动分配 → 瞬态告警 |

**5 个修复**：

| # | 修复 | 文件 | 要点 |
|---|---|---|---|
| F1 | 去掉 `*100` | `aggregator.py` + `memory.py` | 显示原始采样值，趋势不变 |
| F2 | 排除自身 PID | `memory.py` `_iter_stats` | `if pid == os.getpid(): continue` |
| F3 | 按 PID 聚合 | `memory.py` `_iter_stats` | 每进程一个状态机 + 一个告警（栈保留在告警详情） |
| F4 | 阈值调整 | `config/default.yaml` 或 UI | 去掉 ×100 后调低（10KB 量级） |
| F5 | 启动宽限期 | `config/default.yaml` 或 UI | `observe_seconds` 30→120 |

**不引入新问题**：去掉 ×100 后趋势检测不变（常数倍不改变方向）；排除自身 PID 不影响其他进程监控；按 PID 聚合减少告警数但保留栈定位。

### 9.2 持久化专项

**目标**：用户能**选一个进程 + 选一段时间 → 看资源趋势（是否泄露）+ 看告警 + 栈（泄露在哪）**。

**数据层改动**：

| # | 改动 | 文件 | 要点 |
|---|---|---|---|
| D1 | sampler 写全量 PID + 填 container_id | `backend.py` `_sampler_loop` | 从 cgroup_enum 取 pid→cid；写全量（不再 `[:5]`） |
| D2 | db.py 加按 pid/容器/时间查询 | `db.py` | `query_process_history(pid, resource, start, end)` / `query_container_history(cid, ...)` / `query_alerts_by_pid` / `query_alerts_by_container` |
| D3 | 激活降采样 | `db.py` + `backend.py` | 定时聚合 `samples` → `samples_downsampled`（7d→10min, 30d→1h） |
| D4 | retention purge | `db.py` + `backend.py` | 定时 `DELETE FROM samples WHERE timestamp < cutoff`；retention 可配 |
| D5 | 索引优化 | `schema.sql` | 加 `idx_alerts_pid_ts` 等 |
| D6 | alerts 填 container_id | `backend.py` `_analyzer_loop` | 写 alert 时从 cgroup_enum 取 pid→cid |

**REST API**：

| 端点 | 用途 |
|---|---|
| `GET /api/history?resource=mem&range=1d&pid=12345` | 按进程查资源趋势 |
| `GET /api/history?resource=mem&range=7d&container=<cid>` | 按容器查资源趋势 |
| `GET /api/alerts?range=24h&pid=12345` | 按进程查告警（含栈） |
| `GET /api/alerts?range=24h&container=<cid>` | 按容器查告警 |
| `GET /api/processes?range=1d` | 列出有数据的进程（pid+name+last_value） |

**前端**：
- 进程选择器（搜索/下拉）+ 时间范围（1d/7d/30d）+ 资源趋势图（Chart.js）+ 告警列表 + 栈展开。

**DB 容量**：全量 200 PID × 4 资源 × 1440/min ≈ 115 万行/天；降采样后 ~2 万行；retention 30 天后 purge 原始 → 稳定。

---

## 十、未来开发方向与建议顺序

### 10.1 依赖关系

```
内存精度专项（修 *100 / 自监控 / per-stack）
    ↓ （值准确后才值得存历史）
持久化专项（存全量 + 按 pid/时间查）
    ↓ （容器 mem 有值才完整）
Phase 2（全 libc uprobe）
```

### 10.2 建议实施顺序

| 优先 | 专项/Phase | 理由 |
|---|---|---|
| 1 | **内存检测精度专项** | 当前大量误报 → 工具不可信 → 必须先修 |
| 2 | **Phase 2（全 libc uprobe）** | 容器 mem=0 是最大功能缺口 |
| 3 | **持久化专项** | 依赖精度（存准的值）+ Phase 2（容器 mem 有值） |

### 10.3 其他待做（非阻塞，可并行）

- 黑白名单（pid_filter_map + 进程名正则）
- 方案 A libunwind（栈全栈回溯）
- fd close 侧 close_fd kprobe（长跑虚高复现再做）
- BPF_ATOMIC 5.10 兼容（条件编译，待需要时）
- package.sh 架构名修复
- 文档同步（§十一 补充打包/环境需求/专项）

---

## 十一、文件变更全览

### 代码文件（本次会话改动的）

| 文件 | 改动 |
|---|---|
| `web/app.py` | C1 set_backend + C2 host/port/IPv6/werkzeug 条件传参 |
| `web/backend.py` | C1 类型硬化 + Phase 1 整体重写（cgroup_enum + display_target + 显示过滤 + sampler [:5]） |
| `web/api.py` | Phase 1 /api/containers → cgroup_enum.enumerate() |
| `web/sockets.py` | Phase 1 select_container → set_display_target |
| `web/static/index.html` | Phase 1 宿主机 + option 文案 |
| `core/cgroup_enum.py` | Phase 1 桩 → 完整实现 |
| `core/aggregator.py` | Phase 1 get_per_process_* 返回全量 |
| `analyzer/cpu.py` | Phase 1 poll() 返回全量 |
| `symbolizer/symbols.py` | per-symbol try/except + 告警 |
| `bpf/mem.bpf.c` | mem [RSP] 叶子帧补帧 |
| `core/loader.py` | libbpf.so.0 回退 |
| `tools/package_arm.sh` | --python-version + --only-binary + libelf1t64 回退 + 去掉 libelf bundle |
| `tools/package.sh` | --python-version + --only-binary + libelf1t64 回退 |
| `config/default.yaml` | C2 host "::"

### 文档文件

| 文档 | 更新 |
|---|---|
| `leakdetect-plan.md` §十一 | 实施进展 + 问题修复 + 容器监控设计 + 分期 |
| `b2-fd-issue-summary.md` v2.0 | fd_install / mem 负数 / 符号方案 B / 方案 A 遗留 |
| `leakdetect-进展与后续-20260815.md`（本文档） | 全量进展 + 打包修复 + 环境需求 + 已知限制 + 两个专项立项 |

---

## 十二、附录：验证命令速查

```bash
# 启动
sudo ./start.sh

# REST 验证
curl -s http://127.0.0.1:8080/api/containers
curl -s 'http://127.0.0.1:8080/api/history?resource=mem&range=1d'
curl -s http://127.0.0.1:8080/api/config/monitoring

# 浏览器（SSH 隧道）
ssh -L 8080:127.0.0.1:8080 <user>@<node>
# 浏览器 http://127.0.0.1:8080

# 包验证
ls dist/leakdetect-aarch64-py3.9/lib/              # libbpf.so.1（无 libelf）
ls dist/leakdetect-aarch64-py3.9/py-packages/ | grep wsproto  # 1.2.0
ls dist/leakdetect-aarch64-py3.9/py-packages/ | grep elftools  # 0.32
grep "_wz_major" dist/leakdetect-aarch64-py3.9/web/app.py

# 环境检查
uname -r               # ≥ 5.12
python3 --version      # 3.9-3.12
ls /usr/lib*/libelf.so.1  # 系统有 libelf
ls /sys/kernel/btf/vmlinux  # BTF
```
