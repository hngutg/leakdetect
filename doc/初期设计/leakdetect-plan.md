# 内存泄露检测工具 — 方案总结

> 文档版本：v1.4  
> 日期：2026-07-07  
> 状态：方案已收敛，待开工  
> 变更：v1.4 黑白名单功能纳入 F3/F4/B3；§5.4 新增三层过滤架构；项目结构增 filter_manager.py + filter-config.js；风险表新增正则开销  
> 变更：v1.3 前端技术定为 Vue 3 (CDN) + Chart.js；实现顺序改为前台先行；里程碑重构为 F0-F4/B0-B4/M9-M13；新增决策 15-18 项  
> 变更：v1.2 cgroup 过滤新增"配置文件预指定容器"触发方式；M6 范围扩展  
> 变更：v1.1 部署形态从"observer 容器"简化为"host root 进程直接跑"，cgroup 过滤降级为可选

---

## 一、项目概述

### 1.1 项目目标

构建一个基于 eBPF 的资源监控与泄露检测工具，对四种资源实现实时监控与泄露检测，并通过 Web 前端实时告知用户当前资源使用情况及泄露告警。

### 1.2 监控资源范围

| 资源 | 实时监控 | 泄露检测 | 说明 |
|---|:---:|:---:|---|
| 内存 | ✅ | ✅ | malloc/free + mmap/munmap 配对追踪，定位到分配栈 |
| 线程 | ✅ | ✅ | clone/exit 配对，检测长期不退出的线程 |
| 句柄 | ✅ | ✅ | open/close 等配对，按调用栈聚合未关闭 FD |
| CPU | ✅ | ❌ | 仅监控占用率，不做泄露检测 |

### 1.3 最终交付形态

- **形式**：tar.gz 压缩包，解压即用
- **部署**：宿主机 root 进程直接运行（无需容器）
- **目标 OS**：EulerOS（内核 5.10+）
- **运行权限**：root（eBPF 内核能力要求，不可绕过）

---

## 二、关键技术决策总览

| # | 维度 | MVP 阶段（当前） | 迁移阶段（未来） | 决策理由 |
|---|---|---|---|---|
| 1 | 内核版本 | EulerOS 5.10+ | 不变 | BTF 支持，CO-RE 可用 |
| 2 | eBPF 框架 | BCC Python 模块（B2 前期）→ libbpf + ctypes（B2 后期，✅ 已实施） | Go + cilium/ebpf（可选） | BCC 快速验证；libbpf 消除 LLVM 依赖；Go 可选增强 |
| 3 | BPF 程序语言 | C（clang -target bpf 预编译 .o） | 不变 | BPF 字节码事实标准 |
| 4 | 前端 | Flask + Flask-SocketIO + Vue 3 (CDN) + Chart.js | 不变 | 响应式绑定，无构建链，实时推送 |
| 5 | CPU 检测策略 | /proc 轮询，仅监控 | 不变（可选 on-CPU 火焰图） | 量小、实现简单 |
| 6 | 监控范围 | 默认全量进程，可选按 cgroup 过滤容器 | 不变 | 灵活、按需聚焦 |
| 7 | 免安装边界 | BCC 阶段依赖系统 bcc 包 → libbpf 阶段仅依赖 libbpf.so（~2MB，打包内置） | Go 静态二进制（零依赖，可选） | 逐步减依赖：BCC(300MB) → libbpf(2MB) → Go(0) |
| 8 | 部署形态 | host root 进程直接跑 | 不变 | 已有 host root，无需容器层 |
| 9 | 容器枚举 | 可选功能，支持 Web 切换 + 配置文件预指定 | 不变 | 双触发方式，灵活 |
| 10 | 发布形式 | 仅 tar.gz | 不变 | 解压即跑 ./start.sh |
| 11 | 告警方式 | 界面弹窗 + 本地日志文件 | 不变 | 即时可见 + 可追溯 |
| 12 | 进程过滤 | 进程名正则 + PID 黑/白名单，前台可配置，BPF map 过滤，定时刷新 | 不变 | 抓取层减开销，UI 可改，预览防误配 |
| 13 | cgroup 版本 | 仅 v1（可选功能启用时） | 补 v2 支持 | EulerOS 5.10 默认 v1，先跑通 |
| 14 | 容器指定方式 | Web 切换 + 配置文件预指定 | 不变 | 双触发，灵活 |
| 15 | 实现顺序 | 前台先行（路径 X：契约优先 + 前台 mock + 后端按契约接上） | 不变 | 最早可见界面；契约隔离前后端 |
| 16 | 页面结构 | 单页 + 面板切换 | 不变 | 监控类工具常见，跳转少 |
| 17 | 前端技术 | Vue 3 (CDN, 本地 vendor) + Chart.js | 不变 | 响应式、无构建链、契合免安装、中文资料丰富 |
| 18 | 主题 | 暗色主题 | 不变 | 监控类工具常见，长时间看不刺眼 |

---

## 三、当前采用方案（MVP 阶段）

### 3.1 技术栈

| 层 | 选型 | 说明 |
|---|---|---|
| BPF 程序 | C + clang 预编译为 CO-RE .o | build 期完成，目标机无需编译器 |
| eBPF 加载/管理 | libbpf + Python ctypes（预编译 CO-RE .o 加载） | 不依赖 BCC/LLVM；libbpf.so ~2MB 打包内置 |
| 分析层 | Python | 泄露判定、聚合、告警 |
| 存储 | SQLite（零配置）+ 内存实时态 | 历史趋势 + 当前快照 |
| 前端 | Flask + Flask-SocketIO + Vue 3 (CDN, 本地 vendor) + Chart.js | WebSocket 实时推送；Vue 响应式绑定；无构建链 |
| 打包 | tar.gz（源码 + .o + libbpf.so + 纯 Python 包 + start.sh） | 系统 Python 3 + LD_LIBRARY_PATH + PYTHONPATH |

### 3.2 整体架构

```
┌──────────────── 宿主机（root）────────────────┐
│                                               │
│  ┌─容器A─┐ ┌─容器B─┐  ← 业务容器（可选监控）   │
│  │ 应用A │ │ 应用B │                          │
│  └───────┘ └───────┘                          │
│       ▲            ▲                          │
│       │ cgroup_id  │ (可选过滤)               │
│  ┌────┴────────────┴──────────────────┐       │
│  │  leakdetect（root 进程，直接跑 host）│       │
│  │                                      │       │
│  │  ┌──── BPF 程序 (.o × 3) ──────┐    │       │
│  │  │  mem.bpf.o  threads.bpf.o   │    │       │
│  │  │  fd.bpf.o   (cpu 走 /proc)  │    │       │
│  │  │  每个 .o 内置可选 cgroup 过滤│    │       │
│  │  └──────────┬──────────────────┘    │       │
│  │             │ ring buffer            │       │
│  │             ▼                        │       │
│  │  ┌──── BCC 加载层（MVP）────────┐   │       │
│  │  │  加载 .o + attach + 读 ring  │   │       │
│  │  └──────────┬──────────────────┘   │       │
│  │             ▼                       │       │
│  │  ┌──── Python 核心层 ───────────┐  │       │
│  │  │  ingest (采样: malloc 1/100)  │  │       │
│  │  │  aggregator (PID+stack 聚合)  │  │       │
│  │  │  symbolizer (kallsyms+ELF)    │  │       │
│  │  │  4 个泄露分析器               │  │       │
│  │  │  cgroup 枚举器 (可选)         │  │       │
│  │  │  SQLite + 日志                │  │       │
│  │  └──────────┬──────────────────┘  │       │
│  │             ▼                       │       │
│  │  ┌──── Flask + SocketIO + 前端 ──┐ │       │
│  │  │  顶部: 容器下拉框(可选，默认全部)│       │
│  │  │  实时看板: 4 资源当前状态      │ │       │
│  │  │  告警弹窗: 泄露事件 + 栈定位   │ │       │
│  │  │  历史曲线: SQLite 查询         │ │       │
│  │  └────────────────────────────────┘ │       │
│  └──────────────────────────────────────┘       │
│         ▲                                       │
│      内核 eBPF（5.10+）                         │
│   直接访问 /proc /sys/fs/bpf /sys/kernel/tracing │
└─────────────────────────────────────────────────┘
```

### 3.3 数据流

```
BPF 事件 ──ring buffer──> BCC Python ──> ingest(采样)
                                          │
                                          ▼
                                      aggregator
                                       │   │   │
                                       ▼   ▼   ▼
                                    分析器 SQLite 日志
                                       │
                                       ▼
                                  Flask-SocketIO
                                       │
                                       ▼
                                    浏览器
```

### 3.4 BPF 程序设计

**通用 cgroup 过滤骨架（每个 .o 都有，可选启用）**

```c
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);    // cgroup_id
    __type(value, __u8);   // 1 = 监控
    __uint(max_entries, 1024);
} target_cgroups SEC(".maps");

static __always_inline int should_track() {
    // 默认 target_cgroups 为空 → 全量（不过滤）
    // 用户在 Web 选择容器后 → Python 写入 cgroup_id → 只放行该容器
    __u64 cgid = bpf_get_current_cgroup_id();
    __u8 *v = bpf_map_lookup_elem(&target_cgroups, &cgid);
    if (!v) return 1;  // map 为空时全量放行
    return *v;
}
```

**各 BPF 程序 Hook 点**

| 程序 | Hook 类型 | 采集字段 | 采样 |
|---|---|---|---|
| `mem.bpf.c` | uprobe `malloc`(entry, size=RDI)<br>uretprobe `malloc`(ptr=RAX)<br>uprobe `free`(ptr=RDI)<br>tracepoint `mmap`/`munmap` | PID, TID, stack_id, size, op | 1/100 |
| `threads.bpf.c` | tracepoint `clone`/`clone3`<br>tracepoint `sched_process_exit`<br>uprobe `pthread_create` | PID, TID, stack_id, op | 全量 |
| `fd.bpf.c` | tracepoint `openat`/`openat2`<br>`socket`/`pipe2`/`dup`/`eventfd2`<br>`close` | PID, FD, type, stack_id, op | 全量 |
| CPU（无 BPF） | 轮询 `/proc/[pid]/stat` | CPU% | 1s 间隔 |

### 3.5 项目结构

```
leakdetect/
├── bpf/
│   ├── common.h              # 共享 cgroup 过滤骨架
│   ├── mem.bpf.c
│   ├── threads.bpf.c
│   ├── fd.bpf.c
│   └── compiled/             # .o 编译产物
├── core/
│   ├── loader.py             # BCC 加载 .o + attach
│   ├── ingest.py             # ring buffer 读取 + 采样
│   ├── aggregator.py         # 按 (PID, stack) 聚合
│   ├── cgroup_enum.py        # 容器枚举（可选功能）
│   ├── filter_manager.py     # 黑白名单解析 + BPF map 更新 + 定时刷新
│   └── config.py             # YAML 配置加载
├── analyzer/
│   ├── base.py
│   ├── memory.py
│   ├── threads.py
│   ├── handles.py
│   └── cpu.py                # /proc 轮询
├── symbolizer/
│   └── symbols.py            # 内核+用户态符号解析
├── storage/
│   ├── schema.sql
│   └── db.py                 # SQLite 读写
├── web/
│   ├── app.py                # Flask + SocketIO
│   ├── sockets.py            # WebSocket 推送 Contract 2
│   ├── api.py                # REST: 容器列表/历史查询
│   ├── static/
│   │   ├── vendor/
│   │   │   ├── vue.global.prod.js   # Vue 3 本地存（无需 CDN 联网）
│   │   │   └── chart.umd.min.js     # Chart.js 本地存
│   │   ├── css/
│   │   │   └── style.css     # 暗色主题
│   │   ├── js/
│   │   │   ├── app.js        # Vue 主应用（createApp + setup）
│   │   │   ├── api.js        # WebSocket + REST 封装
│   │   │   └── components/
│   │   │       ├── resource-card.js   # 资源卡片组件
│   │   │       ├── alert-popup.js     # 告警弹窗组件
│   │   │       ├── container-select.js # 容器下拉框
│   │   │       ├── filter-config.js    # 监控配置弹窗（黑白名单）
│   │   │       └── stack-table.js     # 栈表格组件
│   │   └── index.html        # 单页入口
│   └── templates/
├── logging/
│   └── alert_logger.py       # 告警本地日志
├── config/
│   └── default.yaml          # 阈值/采样率/过滤
├── tests/
│   └── leak_programs/        # 合成泄露程序
│       ├── mem_leak.c
│       ├── thread_leak.c
│       └── fd_leak.c
├── packaging/
│   ├── start.sh              # 启动脚本（检查 root + BTF）
│   └── pyinstaller.spec
├── tools/
│   └── build_bpf.sh
├── requirements.txt
└── README.md
```

---

## 四、未来补全/替换内容（迁移阶段）

### 4.1 替换项

> **三阶段演进**：MVP（BCC）→ 简化迁移（libbpf，✅ 已实施）→ 未来增强（Go，可选）

| 模块 | MVP（BCC，已完成） | 简化迁移（✅ 已实施） | 未来增强（可选） |
|---|---|---|---|
| eBPF 加载层 | BCC Python 模块（运行时编译） | libbpf.so + ctypes（预编译 .o 加载） | Go 静态二进制（cilium/ebpf） |
| 进程模型 | 同进程 Python ↔ BCC | 同进程 Python ↔ libbpf | 跨进程 IPC（Go collector） |
| 事件传输 | BCC perf buffer | libbpf ring buffer | length-prefixed 二进制 |
| 符号解析 | BCC `bpf.sym()` | pyelftools 读 ELF 符号表 | Go collector 内解析 |
| BPF 程序 | BCC 宏风格（`BPF_HASH` 等） | libbpf SEC 风格（CO-RE .o） | 不变（CO-RE .o 跨框架） |
| 打包依赖 | 系统 bcc 包（~300MB LLVM） | libbpf.so + libelf.so（~2MB） | Go 静态二进制（0 依赖） |
| 打包方式 | PyInstaller + 系统 bcc | 系统 Python 3 + PYTHONPATH + LD_LIBRARY_PATH | PyInstaller + Go 二进制 |

**简化迁移的取舍**：用"无进程隔离"换取"80% 更少的代码量"。监控工具非高可用服务，
BPF 崩溃重启即可。Go 方案保留为未来需要进程隔离或零依赖时的可选增强。

### 4.2 补全项

| 项 | MVP 状态 | 迁移阶段补全 |
|---|---|---|
| cgroup v2 支持 | 仅 v1（可选功能） | 补 v2 单行格式解析 |
| CPU on-CPU 火焰图 | 仅 /proc 占用率 | 可选加 sched_switch BPF |
| 容器名友好展示 | 仅 container_id | Docker inspect / kubelet API 取名字 |
| 远程告警 | 仅界面+本地日志 | 可选 webhook（钉钉/飞书） |
| 多 observer 聚合 | 单进程 | 可选集群模式 |

### 4.3 保留不变项

- 所有 BPF 程序源码（.bpf.c）—— clang 编译 .o，框架无关
- Python 分析层（ingest/aggregator/analyzer/symbolizer/storage/web）—— 仅 loader.py 换数据源
- 配置格式（YAML）
- SQLite schema
- 前端静态资源

### 4.4 迁移阶段架构对比

```
MVP（已完成）:
  [BCC Python] ──同进程──> [Python 分析层] ──> [Flask 前端]
  (运行时编译，依赖 LLVM ~300MB)

简化迁移（✅ 已实施）:
  [libbpf + ctypes] ──同进程──> [Python 分析层] ──> [Flask 前端]
  (预编译 .o + ring buffer，依赖 libbpf.so ~2MB)

未来增强（可选）:
  [Go collector] ──IPC──> [Python 分析层] ──> [Flask 前端]
  (静态二进制，零依赖)         (进程隔离)
```

---

## 五、部署形态

### 5.1 部署方式：host root 进程直接运行

工具作为 root 进程直接在宿主机上运行，**不部署在容器内**，业务容器完全不受影响。

```
┌──────────────── 宿主机（root）────────────────┐
│                                               │
│  ┌─容器A─┐ ┌─容器B─┐  ← 业务容器（完全不动）   │
│  │ 应用A │ │ 应用B │                          │
│  └───────┘ └───────┘                          │
│       ▲            ▲                          │
│       │ cgroup_id  │ (可选过滤)               │
│  ┌────┴────────────┴──────────────────┐       │
│  │  leakdetect（root 进程）            │       │
│  │  直接访问：                         │       │
│  │    /proc                            │       │  ← 原生路径，无需挂载
│  │    /sys/fs/bpf                      │       │
│  │    /sys/kernel/tracing              │       │
│  │  Web UI: 0.0.0.0:8080 或 127.0.0.1  │       │
│  └────────────────────────────────────┘        │
│         ▲                                     │
│      内核 eBPF（5.10+，BTF 可用）              │
└───────────────────────────────────────────────┘
```

**部署优势**
- 无需 observer 容器、无需 Dockerfile、无需挂载
- 无需特权容器审批（已是 root）
- 路径直接（`/proc` 而非 `/host_proc`）
- 启动一行：`./start.sh`

**前置条件**
| 项 | 要求 |
|---|---|
| 权限 | root |
| 内核 | 5.10+ |
| BTF | `/sys/kernel/btf/vmlinux` 存在 |
| MVP 额外 | 系统装 bcc 包（`yum install bcc-python3`） |
| 迁移后额外 | 无（Go 静态二进制 + PyInstaller Python） |

### 5.2 cgroup 过滤（可选功能）

业务应用混合部署（部分在容器、部分在 host），cgroup 过滤作为**可选功能**：

- **默认**：全量监控所有进程（host + 容器）
- **启用**：用户在 Web 下拉框选择某容器 → 仅展示该容器内进程的事件

**容器枚举流程（Docker/K8s 通用，仅在启用时执行）**

```
遍历 /proc/*/cgroup
    │
    ▼
解析 v1 格式: "4:cpu:/docker/<cid>" 或 ".../pod<uid>/<cid>"
    │
    ▼
提取 container_id（Docker 64位 hex / K8s 从 pod 路径解析）
    │
    ▼
对每个 PID 取 bpf_get_current_cgroup_id()（BPF 端获取）
    │
    ▼
建立映射: {container_id, pod_uid?, cgroup_id, pid_list}
    │
    ▼
Web 下拉框展示，用户切换时更新 BPF map（target_cgroups）
```

**注意**：cgroup 过滤仅对在容器内运行的应用有意义。直接跑在 host 上的应用不归属任何容器，默认始终可见。

### 5.3 配置文件预指定容器（启动即聚焦）

除 Web 动态切换外，支持在 `config/default.yaml` 启动时预指定目标容器：

```yaml
# config/default.yaml
monitoring:
  # 默认 null = 全量监控
  # 填 container_id 则启动即聚焦该容器（Web 仍可动态切换覆盖）
  target_container_id: null
```

**行为规则**

| 场景 | 行为 |
|---|---|
| 配置为 null | 启动后全量，Web 可随时切换 |
| 配置了 container_id 且容器存在 | 启动即聚焦，Web 可切换到其他或"全部" |
| 配置了 container_id 但容器不存在 | 启动告警 + 回退全量，提示用户 Web 切换 |
| Web 切换 | 运行时覆盖配置（不修改配置文件） |

**优先级**：Web 运行时切换 > 配置文件预指定 > 默认全量

### 5.4 黑白名单过滤架构

黑白名单是**抓取层过滤**，与容器下拉/PID 输入（显示层过滤）正交，三层共存：

| 过滤维度 | 作用层 | 何时生效 | 持久性 | 示例 |
|---|---|---|---|---|
| 黑/白名单 | 抓取层（eBPF） | 事件采集前，减少数据量 | 持久化配置 | "不监控 systemd/kthreadd" |
| 容器下拉 | 显示层 | 查看时过滤 | 会话级 | "只看容器A" |
| PID 输入 | 显示层 | 查看时过滤 | 会话级 | "只看 PID 1234" |

**配置流程**

```
用户在前台"监控配置"弹窗保存
    │
    ▼
Python 后端收到 POST /api/config/filter
    │
    ├─ 1. 解析 name_regex → 遍历 /proc/[pid]/comm 匹配 → PID 集合 A
    ├─ 2. 合并用户 pid_list → PID 集合 B = A ∪ pid_list
    ├─ 3. 写入 BPF pid_filter_map：白名单→加入 B；黑名单→加入 B
    ├─ 4. 持久化到 config/runtime.yaml
    └─ 5. 启动定时任务：每 30s 重新解析 name_regex（进程启停，PID 变化）
```

**BPF 侧过滤**（复用已有 map 模式）

```c
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);    // PID
    __type(value, __u8);   // 1 = 在列表里
    __uint(max_entries, 65536);
} pid_filter_map SEC(".maps");

// 每个事件处理函数开头
__u32 pid = bpf_get_current_pid_tgid() >> 32;
__u8 *in_list = bpf_map_lookup_elem(&pid_filter_map, &pid);
if (mode == WHITELIST && !in_list) return 0;  // 白名单：不在列表→跳过
if (mode == BLACKLIST && in_list) return 0;   // 黑名单：在列表→跳过
```

**前台 UI**：顶部栏"监控配置"按钮 → 弹窗含模式选择（全部/白名单/黑名单）、进程名正则、PID 列表、保存前预览匹配进程。

---

## 六、泄露检测算法

### 6.1 算法总览

| 资源 | 主信号 | 默认判定条件 | 阈值可配 |
|---|---|---|---|
| 内存 | 调用栈 outstanding_bytes | 单调增长 > 60s 且增量 > 1MB | ✅ |
| 内存 | alloc_count - free_count | 差值 > 10000 持续 > 60s | ✅ |
| 线程 | created - exited | 单调增长持续 > 120s | ✅ |
| 句柄 | open_count - close_count | 单调增长持续 > 120s | ✅ |

### 6.2 栈定位流程

```
BPF: bpf_get_stackid(ctx, stack_map)
        │
        ▼
BCC: stack_map[stack_id] → 帧地址列表
        │
        ▼
symbolizer:
    ├─ 内核帧 → /proc/kallsyms 解析
    └─ 用户帧 → /proc/[pid]/root + ELF 符号表
        │
        ▼
函数名 + 偏移量（stripped 二进制则提示加载 debuginfo）
```

---

## 七、里程碑与工期

> v1.3 调整：实现顺序改为"前台先行"，里程碑重构为前台阶段（F0-F4）、后端阶段（B0-B4）、迁移阶段（M9-M13）。

### 7.1 前台阶段（前台先行）

| # | 里程碑 | 时长 | 交付物 |
|---|---|---|---|
| F0 | 契约定义 | 1-2 天 | DashboardUpdate schema、WebSocket 协议、REST API 规格（F0 产出，写入项目文档） |
| F1 | 骨架 + mock 数据 | 3-4 天 | Flask+SocketIO+Vue 起服务；mock 推 Contract 2 数据；暗色主题基础布局；浏览器看 mock 实时刷新 |
| F2 | 四资源看板 | 4-5 天 | 内存/线程/句柄/CPU 面板；top-N 栈表；Chart.js 曲线 |
| F3 | 告警 + 历史 | 4-5 天 | 告警弹窗+栈展示；告警历史列表；REST 历史查询；**+监控配置弹窗（模式/正则/PID/预览）** |
| F4 | 打磨 | 3-4 天 | 容器下拉框（mock 容器列表）；样式优化；响应式；**+配置预览功能** |

**前台阶段总工期：约 3 周**

### 7.2 后端阶段（前台完成后按契约接上）

| # | 里程碑 | 时长 | 交付物 |
|---|---|---|---|
| B0 | 技术验证 | 1-2 天 | BTF 可用；BCC 加载 hello .o；cgroup_id 能取到 |
| B1 | 内存抓取 + 分析 | ~1.5 周 | mem.bpf.c + BCC 加载 + 分析器按契约产出数据；替换 mock，前台接真数据 |
| B2 | 线程 + 句柄 + CPU | ~1.5 周 | threads.bpf.c + fd.bpf.c + CPU /proc 轮询；4 资源全真数据 |
| B3 | cgroup 过滤 + 黑白名单 | 4-5 天 | 容器枚举 + 前台下拉框联动；配置文件预指定；**+filter API、pid_filter_map BPF、定时刷新** |
| B4 | 配置 + 打包 | ~1 周 | tar.gz + start.sh（检查 root + BTF）+ 文档 |

**后端阶段总工期：约 2.5-3 周**

### 7.3 迁移阶段（生产可用后）

> **简化实施说明**：M9-M11 原始方案为 Go + cilium/ebpf + IPC（工期 2-3 周）。
> 实际用 Python ctypes + libbpf.so 替代（工期 ~3 天），消除了 BCC/LLVM 依赖。
> Go 方案保留为未来可选增强（进程隔离 + 零依赖），当前监控工具场景不需要。

| # | 里程碑 | 原始方案 | 简化实施 | 状态 |
|---|---|---|---|---|
| M9 | 设计 collector + IPC 协议 | Go + unix socket + 二进制协议 | Python ctypes 调用 libbpf.so（同进程，无需 IPC） | ✅ 已简化 |
| M10 | 实现 collector | Go + cilium/ebpf 加载 .o + ring buffer | libbpf 加载预编译 .o + ring buffer 事件传输 | ✅ 已实施 |
| M11 | Python 端替换 BCC | Python loader.py 改为 IPC 客户端 | Python loader.py 改为 ctypes libbpf（分析层零改动） | ✅ 已实施 |
| M12 | 补 cgroup v2 支持 | 解析 /proc/[pid]/cgroup v2 单行格式 | — | ⬜ 未开始 |
| M13 | 生产打包 | CGO_ENABLED=0 go build + PyInstaller + tar.gz | libbpf.so + 纯 Python 包 + .o + start.sh（tar.gz 自包含） | ✅ 已简化 |

> **M12 仍需实施**（cgroup v2 支持），与加载层无关。

> **未来可选增强（Go 方案）**：如果需要进程隔离（BPF 崩溃不影响 Web UI）或零共享库依赖
>（不依赖系统 Python 3 和 libbpf.so），可实施原始 Go 方案。工期 2-3 周。
> 当前方案对于监控工具场景（非高可用服务）已足够。

### 7.4 总工期路线图

```
F0──F1──F2──F3──F4 │ B0──B1──────B2──────B3──B4 │ M9-M11(简化)──M12──M13(简化)
└──前台(已完成)───┘ └──后端(已完成)──────────┘ └──迁移(已实施)─────────┘
                                                          │
                                                          ▼
                                                   跨环境可用版本
                                                   （Go 增强可选，未来）
```

---

## 八、技术风险与规避

| 风险 | 影响阶段 | 影响 | 规避措施 |
|---|---|---|---|
| BCC `BPF(obj_file=...)` 旧版支持差 | B0 | 卡住 | 先验证 bcc ≥ 0.16，必要时自编 |
| uprobe libc 路径定位 | B1 | 探针挂不上 | 启动探测 `/lib64/libc.so.6`，配置可覆盖 |
| `bpf_get_current_cgroup_id()` v1 含义模糊 | B3 | 过滤不准 | 固定用 `cpu` 控制器 cgroup 路径对齐 |
| 高频 malloc 事件淹没 Python | B1 | 性能崩 | 1/100 采样 + ring buffer 限长 + 丢弃计数 |
| glibc 耦合（MVP 不打包 .so） | B4 | 跨版本不可用 | MVP 接受依赖系统 bcc，迁移后消除 |
| IPC 协议设计不当成瓶颈 | M10 | 高频事件丢失 | 二进制 length-prefixed，避免 JSON |
| 符号解析对 stripped 二进制无效 | B1 | 栈不可读 | 提示加载 debuginfo，或退化为地址展示 |
| Web UI 端口冲突或暴露 | F1 | 安全/可用 | 默认绑 127.0.0.1，可配 0.0.0.0 |
| 契约设计与真实数据形态不符 | F0/B1 | 前台返工 | F0 契约预留扩展字段；B1 接真数据时校验并迭代 |
| 正则匹配开销（进程数多时） | B3 | 应用慢 | 限制刷新频率 30s，缓存匹配结果 |
| libbpf.so glibc 版本不兼容 | M11 | 打包后目标机无法加载 libbpf.so | 从 glibc 2.28 的发行版提取；或交叉编译 libbpf |
| ring buffer 事件丢失 | M10 | 高频事件时数据缺失 | 1MB ring buffer + 1/100 采样；丢失不影响趋势检测 |
| BPF 程序编译依赖头文件路径 | M10 | clang 找不到 `asm/types.h` | build_bpf.sh 自动检测 multiarch include 路径 |
| perf_event_open E2BIG（已解决） | M10 | perf buffer 创建失败 | 已改为 ring buffer，不调用 perf_event_open |

---

## 九、待办与开放问题

### 9.1 已确认决策（18 项）
见第二节"关键技术决策总览"。第 14 项为"容器指定方式：Web + 配置文件双触发"；第 15-18 项为前台先行相关决策（实现顺序/页面结构/前端技术/主题）。

### 9.2 实施前待确认
- [ ] 项目工作目录位置（建议 `C:\Users\lwh\leakdetect`）
- [ ] 是否先搭骨架再填充，还是从 F0 串行实施
- [ ] MVP 阶段是否需要单元测试框架（pytest）

### 9.3 后续可选增强（非阻塞）
- [ ] cgroup v2 支持（M12 已规划）
- [ ] on-CPU 火焰图
- [ ] webhook 告警（钉钉/飞书）
- [ ] 多 observer 集群聚合
- [ ] 容器名友好展示（Docker inspect / kubelet API）
- [ ] Go collector（进程隔离 + 零共享库依赖）— M9-M11 原始方案，当前用 Python + libbpf 替代；未来需要进程隔离或零依赖时可实施

---

## 十、附录

### 10.1 术语表

| 术语 | 含义 |
|---|---|
| eBPF | extended Berkeley Packet Filter，内核可编程虚拟机 |
| CO-RE | Compile Once - Run Everywhere，eBPF 可移植机制 |
| BTF | BPF Type Format，内核类型信息，CO-RE 依赖 |
| BCC | BPF Compiler Collection，Python eBPF 库 |
| cilium/ebpf | Go 语言 eBPF 库 |
| cgroup | control group，Linux 进程分组资源限制机制 |
| uprobe | 用户态函数探针 |
| tracepoint | 内核静态追踪点 |
| ring buffer | BPF 事件环形缓冲区（5.8+） |
| sidecar | 与主容器同 Pod 的辅助容器 |
| observer | 独立旁观容器（本方案未采用，改为 host 进程） |

### 10.2 参考资料

- libbpf CO-RE: https://libbpf.readthedocs.io/
- BCC Python API: https://github.com/iovisor/bcc
- cilium/ebpf: https://github.com/cilium/ebpf
- eBPF 架构: https://ebpf.io/
- Falco（同类工具参考）: https://falco.org/
- Tetragon（同类工具参考）: https://tetragon.io/

### 10.3 变更记录

| 版本 | 日期 | 变更 |
|---|---|---|
| v1.0 | 2026-07-07 | 初版：拓扑 B（observer 容器 + cgroup 过滤） |
| v1.1 | 2026-07-07 | 部署形态简化：host root 进程直接跑；去掉 observer 容器、Dockerfile、挂载要求；cgroup 过滤降级为可选功能；/host_proc 改回 /proc |
| v1.2 | 2026-07-07 | cgroup 过滤新增"配置文件预指定容器"触发方式；M6 范围扩展；新增 §5.3 配置文件预指定与行为规则表；已确认决策增至 14 项 |
| v1.3 | 2026-07-07 | 前端技术定为 Vue 3 (CDN) + Chart.js；实现顺序改为前台先行；里程碑重构为 F0-F4/B0-B4/M9-M13；项目结构 web/ 细化（vendor/components/）；新增决策 15-18 项；风险表里程碑号同步更新；新增"契约设计与真实数据不符"风险 |
| v1.4 | 2026-07-07 | 黑白名单功能纳入 F3/F4/B3（时长微调）；新增 §5.4 三层过滤架构（抓取层黑白名单 + 显示层容器/PID）；项目结构增 filter_manager.py + filter-config.js；决策第 12 项细化；风险表新增"正则匹配开销"；前台总工期 3 周、后端 2.5-3 周 |
| v1.5 | 2026-07-13 | BCC → libbpf 迁移：M9-M11 简化为 Python ctypes + libbpf.so（非 Go + IPC）；BPF 程序从 BCC 宏改为 libbpf SEC 风格（CO-RE .o）；perf buffer 改为 ring buffer（避免 perf_event_open E2BIG）；符号解析改用 pyelftools；打包方式改为 tar.gz（系统 Python 3 + libbpf.so + 纯 Python 包 + .o + start.sh）；决策 #2 #7 更新为三阶段（BCC → libbpf → Go 可选）；§4.1 替换项改为三阶段对比；§4.4 架构对比改为三阶段；§7.3 迁移阶段标注简化状态；§7.4 路线图更新；风险表新增 4 条（libbpf glibc / ring buffer 丢失 / 头文件路径 / E2BIG 已解决）；§9.3 新增 Go collector 可选增强；Go 方案保留为未来可选增强 |

---

## 十一、实施进展与问题修复记录（2026-07-25 增补）

> 2026-07-25 在 x86_64/ARM 节点实测验证期间发现的问题、已落地修复、容器监控设计细化与分期。
> fd 句柄监控的详细演进见 `D:\leakdetect-b2-fd-issue-summary.md`（v2.0）。

### 11.1 验证发现的问题与已落地修复

| # | 问题 | 根因 | 修复（文件:位置） | 验证 |
|---|---|---|---|---|
| 1 | REST 路由全走 mock（C1） | `web/app.py` 未调 `api.set_backend()`，`api.py` 的 `_backend` 恒 None → 8 路由 `if _backend is not None` 恒假 → 全走 mock | `web/app.py`：`from api import api, set_backend` + 成功分支 `set_backend(backend)` + 回退分支 `set_backend(None)`；`web/backend.py` `update_monitoring_config` 加 `isinstance` 类型硬化（防空串/None 致 `check()` TypeError） | `curl /api/containers` 返回诚实空 `[]`（原 4 假容器）；`/api/history`、`/api/config/monitoring` 走真后端 |
| 2 | host/port 硬编码（C2） | `app.py` 写死 `127.0.0.1:8080`，忽略 `config` 的 `server.host/port` | `config/default.yaml`：`host: "::"` + 注释；`web/app.py`：从 config 读 host/port + IPv6 URL 打印 `http://[%s]:%d` + try/except OSError 回退 `0.0.0.0`（`::` 绑不了时）+ docstring | 启动日志 `http://[::]:8080` + werkzeug `Running on all addresses (::)`，IPv6 双栈启用 |
| 3 | 符号 `[unknown]`（per-symbol 吞噬） | `symbolizer/symbols.py` `_get_symbols` 的 `except Exception:pass` 把 `.gnu.version` 段条目的 `KeyError('st_info')` 吞掉 → 整个 ELF 缓存空 → mem_leak 全帧 `[unknown]` | `_get_symbols`：except 收窄到单符号（per-symbol try/except 跳过坏条目）+ 外层 try/except/else 告警（读失败/0 符号不再静默） | mem_leak 栈 `_start` 从 `[unknown]` → `_start+0x25` |
| 4 | 符号 `[unknown]`（main 叶子帧丢失，符号解析方案 B） | `bpf_get_stack(BPF_F_USER_STACK)` 用 RBP 链回溯，在 malloc 入口跳过 `[RSP]` 里的 return-to-caller → main 整个不出现 | `bpf/mem.bpf.c` `trace_malloc_entry`：`bpf_probe_read_user` 读 `[RSP]` → 去重 → 后移插入 frame 1（保留 frame 0=malloc RIP） | mem_leak 栈 `malloc → main+0x4c → [unknown] → __libc_start_main+0x8b → _start+0x25`（main 现身） |
| 5 | `py_compile` Permission denied | `__pycache__` 被 `sudo python3` 留下 root 属主，非 root 用户写不进 | 环境侧（非代码）：`sudo chown -R $USER:$USER <repo>`；或直接 `sudo python3 web/app.py` | — |

残留（非代码可解）：
- 符号 `[unknown]` = stripped libc 内部函数（如 `__libc_start_call_main`），无符号可查；需装 `libc6-dbg`/`python3-dbg`（环境侧）。
- fd 句柄 close 侧窄缺口（close_range/进程退出/execve）+ mem 负数（未复现）——详见 `b2-fd-issue-summary.md` v2.0。

### 11.2 容器监控设计细化与分期

#### 背景：原 B3 cgroup 过滤设计的缺口
原 §5.2/§7.2 B3 假设"宿主 libc uprobe 能抓到容器进程"。实测（cscf-dfx-syn02，ARM）证伪：
- 容器进程用自己的 libc（不同 inode），不触发宿主 libc uprobe → mem 看不到容器。
- 证据：leakdetect uprobe 目标 = 宿主 `/lib64/libc.so.6`(inode 4177)；但容器 c-init/bash 用 `/usr/lib64/libc.so.6`(inode 263483/263485/263497) 等不同 inode。
- 宿主自身也有两个 libc（`/lib64` + `/usr/lib64`），单一 uprobe 连部分宿主进程都漏。

#### 目标形态
- 未选容器（宿主模式，默认）：只看宿主进程资源。
- 选了容器 X（容器模式）：只看 X 内进程全部资源（含 mem）。
- 后台全量记录、前台按需过滤：BPF/aggregator 全量采集存储；显示层按 target 过滤。切换不丢历史（历史按容器查延后到存储阶段）。

#### mem 全 libc uprobe 方案
- 给节点所有 libc inode（宿主 `/lib64` + `/usr/lib64` + 各容器 libc 经 `/proc/[pid]/root/` 访问）都挂 malloc/free uprobe，持续全量采集。
- 不随选择切换（启动 + 周期 60s 重枚举 attach/detach）；选择只影响显示过滤。
- 每 libc 用 pyelftools 重算 malloc 偏移。
- 容器 libc 发现：读 `/proc/[pid]/maps` 精确匹配 `libc.so.6`/`libc-2.*.so`（排除 libcjson/libcertsdk 假匹配）。
- 边角限制：静态链接容器进程、自研 allocator（jemalloc/tcmalloc）抓不到。

#### threads/fd/CPU：不加 BPF 过滤
- BPF 内核 hook 本就抓全量；aggregator 按 PID 存全量；显示层按 target PID 集过滤。
- 曾考虑 BPF `pid_filter_map` 减开销，因"记录全量"要求放弃（过滤=漏历史）。

#### 容器枚举（cgroup_enum）
- 遍历 `/proc/*/cgroup`，匹配 `/kubepods/`、`/docker/`（+ `/lxc/`、`/system.slice/docker` 兜底）；`cid = basename(cgroup_path)`。
- 同机/分机均适用（节点出现什么前缀就处理什么）。
- 取名：`docker ps --no-trunc --format '{{.ID}}\t{{.Names}}\t{{.Image}}'`（不可用→`crictl`→都不行→cid 短串）。
- 懒刷新 30s。
- （基于 cgroup v1 路径解析；v2 单行格式解析延后至 M12。）

#### 显示过滤定义
- 宿主模式：target=None → PID 集 = 不在任何容器 cgroup 的进程。
- 容器模式：target=cid → 该容器 PID 集。
- `aggregator.get_per_process_*` 改返回全量（去 top-5），backend 过滤后 top-5。

#### 分期
| 期 | 内容 | 状态 |
|---|---|---|
| Phase 1 | `cgroup_enum` + 下拉 + 显示过滤（threads/fd/CPU 实时，宿主/容器模式）；mem 仍只宿主 | ✅ 已验证（arm64/glibc 2.38/Python 3.11，50+ 容器 + 浏览器） |
| Phase 2 | mem 全 libc uprobe + symbolizer 走 `/proc/[pid]/root` | 待实施（Phase 1 后） |
| Phase 3（延后） | sample 填 container_id + `/api/history` 按容器查 + 降采样 + 保留期（与存储一起做） | 延后 |
| 黑白名单（原 B3 另一半） | 暂不做 | 延后 |

### 11.3 状态汇总（2026-08-15 更新）

**已落地并验证**：
- C1（REST 接线）✅ — VM + arm64 验证
- C2（host/port+IPv6+werkzeug 条件传参）✅ — VM + arm64 验证
- per-symbol 符号修复 ✅ — VM 验证（`_start+0x25`）
- mem [RSP] 符号解析方案 B ✅ — VM 验证（`main+0x4c`）
- fd_install kprobe（虚高主根因）✅ — 文档订正（`b2-fd-issue-summary.md` v2.0）
- mem 负数未复现 ✅
- Phase 1 容器选择 ✅ — arm64/glibc 2.38/Python 3.11 验证（50+ 容器 + 浏览器 + REST 真数据）
- 打包兼容性修复 ✅ — Python 3.9 兼容（wsproto 1.2.0/pyelftools 0.32）+ libelf1t64 回退 + libelf 不 bundle（防毒化）+ libbpf.so.0 回退（glibc 2.34）

**待实施**：
- Phase 2（mem 全 libc uprobe + symbolizer `/proc/[pid]/root`）
- 内存检测精度专项（5 根因 + 5 修复已分析，见 §11.7.1）
- 持久化专项（按进程/时间查历史 + 泄露点定位，见 §11.7.2）

**延后**：
- Phase 3 / 持久化（已立项，见 §11.7.2）
- 黑白名单（原 B3 另一半）
- fd close 侧 close_fd kprobe（长跑虚高复现再做）
- 方案 A libunwind（栈全栈回溯）——记入 `b2-fd-issue-summary.md` §8.5
- BPF_ATOMIC 5.10 兼容（设为环境需求，见 §11.5）

**验证环境**：

| 节点 | 架构 | Python | glibc | 内核 | 结果 |
|---|---|---|---|---|---|
| VM-0-10-ubuntu | x86_64 | 3.12 | 2.38+ | 6.x | C1/C2/符号/mem [RSP] 全验证 ✅ |
| dfx-syn01-csp-c-arm-0 | aarch64 | 3.11.6 | 2.38 | 6.x | Phase 1 全通过 ✅ |
| syn02-service-vdu-2 | aarch64 | 3.9.9 | 2.34 | 5.10 | Python 3.9 + libbpf.so.0 + libelf 修复 ✅；BPF 加载失败（5.10 不支持 BPF_ATOMIC）❌ |

### 11.4 打包兼容性修复（2026-08-15 增补）

| # | 问题 | 修复 | 文件 |
|---|---|---|---|
| 1 | Python 3.9 不兼容（wsproto 1.3.x 用 `bytes\|bytearray` 语法 ≥3.10） | `pip download --python-version "$TARGET_PY" --only-binary :all:` → pip 按 3.9 解析 → wsproto 1.2.0 + pyelftools 0.32 | `tools/package_arm.sh` L85 + `tools/package.sh` L61 |
| 2 | libelf1 在 noble 重命名为 libelf1t64（time64 迁移）→ apt-get download 失败 → libbpf 也没下到 | 拆分 apt-get（libbpf1 + libelf1 独立）+ `libelf1\|libelf1t64` 回退 + glob 匹配 | `tools/package_arm.sh` + `tools/package.sh` |
| 3 | noble libelf.so.1（glibc 2.38）毒化 glibc 2.34 节点的 libbpf.so.0 依赖 | 去掉 libelf bundle（不复制 libelf.so 到包 lib/）→ 系统提供 libelf.so.1（各节点 glibc 匹配） | `tools/package_arm.sh` |
| 4 | werkzeug 2.x 的 `run_simple` 不接受 `allow_unsafe_werkzeug` | `import werkzeug` → `_wz_major >= 3` 才传 `allow_unsafe_werkzeug=True` | `web/app.py` |
| 5 | glibc 2.34 节点 bundled libbpf.so.1（glibc 2.38）加载失败 | loader 尝试列表加 `libbpf.so.0`（系统 0.8.1, glibc 2.34 回退） | `core/loader.py` |

### 11.5 环境需求（最终确定）

| 需求 | 值 | 原因 |
|---|---|---|
| 权限 | root | eBPF 内核能力 |
| 内核 | ≥ 5.12 | BPF_ATOMIC 指令支持（`__sync_fetch_and_sub` 编译为 BPF_ATOMIC） |
| BTF | `/sys/kernel/btf/vmlinux` 存在 | CO-RE 依赖 |
| Python | 3.9 - 3.12 | pinned 依赖兼容（flask 2.2.5 + click 8.0.4 + werkzeug 2.3.8） |
| glibc | ≥ 2.34 | libbpf.so.0 回退（系统 0.8.1）或 ≥ 2.38（bundled .so.1） |
| 系统 libelf | `libelf.so.1` 存在 | libbpf 依赖（不再 bundle，由系统提供） |
| 系统 libz | `libz.so.1` 存在 | libbpf 依赖 |

### 11.6 已知限制

| # | 限制 | 原因 | 修复方向 |
|---|---|---|---|
| 1 | 内核 ≥ 5.12 | BPF 程序用 `__sync_fetch_and_sub`（BPF_ATOMIC），5.10 不支持 | 条件编译两套 .o（待需要时立项） |
| 2 | 容器 mem=0 | uprobe 只挂宿主 libc | Phase 2（全 libc uprobe） |
| 3 | 栈 `[unknown]`（部分） | symbolizer 缺 kallsyms + PIE 解析不全 | 方案 A（libunwind）或装 debuginfo |
| 4 | 内存值 `*100` 高估 | 1/100 采样 ×100 修正，少量大块分配放大 100 倍 | 内存检测精度专项（§11.7.1） |
| 5 | 自监控误报 | python3 自身 malloc 被监控 | 内存检测精度专项（排除自身 PID） |
| 6 | per-stack 粒度告警 | 每 (pid,stack) 独立状态机 → N 个告警 | 内存检测精度专项（按 PID 聚合） |
| 7 | chart 不按 target 过滤 | sampler 写全局 top-5 | 持久化专项（§11.7.2） |
| 8 | libelf 不自包含 | noble libelf 毒化 glibc 2.34 → 系统提供 | 从源码编 glibc 兼容的 libelf（复杂，暂不做） |
| 9 | dup2 tracepoint 缺失（arm64） | arm64 内核无 `sys_enter_dup2` | 已优雅跳过（`optional=True`），dup3 覆盖 |
| 10 | 无 retention purge | db.py 无 DELETE 逻辑 | 持久化专项 |

### 11.7 专项立项

#### 11.7.1 内存检测精度专项

**问题**：arm64/K8s 节点大量内存告警（疑似误报）；`/api/history` 显示 7.5GB 增长但环境长稳无问题 → `*100` 采样高估。

**5 个根因 + 5 个修复**（详见 `doc/后续关键节点记录/leakdetect-进展与后续-20260815.md` §九.1）：

| # | 根因 | 修复 |
|---|---|---|
| 1 | `*100` 高估（`aggregator.py` + `memory.py`） | 去掉 `*100`，显示原始采样值 |
| 2 | 自监控（`memory.py` 无自身 PID 排除） | `if pid == os.getpid(): continue` |
| 3 | per-stack 粒度（`memory.py` `key=(pid,sid)`） | 按 PID 聚合，每进程一个状态机 |
| 4 | 阈值对 `*100` 太低（1MB） | 去掉 `*100` 后调低（10KB 量级） |
| 5 | 启动期增长无法区分 | `observe_seconds` 30→120 |

#### 11.7.2 持久化专项

**目标**：用户能选一个进程 + 选一段时间 → 看资源趋势（是否泄露）+ 看告警 + 栈（泄露在哪）。

**6 个数据层改动 + REST API + 前端**（详见 `doc/后续关键节点记录/leakdetect-进展与后续-20260815.md` §九.2）：

| # | 改动 | 要点 |
|---|---|---|
| D1 | sampler 写全量 PID + 填 container_id | 不再 `[:5]`，从 cgroup_enum 取 pid→cid |
| D2 | db.py 加按 pid/容器/时间查询 | `query_process_history` / `query_container_history` / `query_alerts_by_pid` |
| D3 | 激活降采样 | `samples` → `samples_downsampled`（7d→10min, 30d→1h） |
| D4 | retention purge | 定时 DELETE 旧数据，retention 可配 |
| D5 | 索引优化 | 加 `idx_alerts_pid_ts` |
| D6 | alerts 填 container_id | 从 cgroup_enum 取 pid→cid |

### 11.8 BPF_ATOMIC 5.10 不兼容（环境需求）

**问题**：BPF 程序用 `__sync_fetch_and_sub`/`__sync_fetch_and_add`（编译为 BPF_ATOMIC 指令），内核 5.10 不支持（5.12 才加入）→ EulerOS 5.10 节点 BPF 加载失败。

**验证**：syn02-service-vdu-2（EulerOS 5.10, `5.10.0-136...eulerosv2r12`）→ `BPF_STX uses reserved fields` → Backend 回退 mock。

**决策**：不改 BPF 程序（保持原子 refcount，不影响已验证的 6.x 节点）。设为环境需求：**内核 ≥ 5.12**。

**如需支持 5.10**：条件编译两套 .o（原子/非原子），loader 按 `uname -r` 选 → 复杂度高，暂不做。

### 11.9 建议实施顺序

```
内存检测精度专项（修 *100 / 自监控 / per-stack）
    ↓ （值准确后才值得存历史）
持久化专项（存全量 + 按 pid/时间查）
    ↓ （容器 mem 有值才完整）
Phase 2（全 libc uprobe）
```

> 详见 `doc/后续关键节点记录/leakdetect-进展与后续-20260815.md` §十。
> 使用指导见 `doc/使用文档/leakdetect-使用指导-20260815.md`。
