# LeakDetect 使用指导

> 文档版本：v1.0
> 日期：2026-08-15
> 用途：指导用户在目标节点上部署、启动、访问和使用 LeakDetect 工具。

---

## 一、环境要求与限制

### 1.1 必须满足

| 需求 | 值 | 检查命令 | 说明 |
|---|---|---|---|
| 权限 | root | `id -u`（应为 0） | eBPF 需要内核能力 |
| 内核 | ≥ 5.12 | `uname -r` | BPF_ATOMIC 指令支持（BPF 程序用 `__sync_fetch_and_sub`） |
| BTF | 存在 | `ls /sys/kernel/btf/vmlinux` | CO-RE 依赖 |
| Python | 3.9 - 3.12 | `python3 --version` | 兼容范围（pinned 依赖） |
| glibc | ≥ 2.34 | `ldd --version` | libbpf 加载要求 |
| 系统 libelf | 存在 | `ls /usr/lib*/libelf.so.1` | libbpf 依赖（不再 bundle） |
| 系统 libz | 存在 | `ls /usr/lib*/libz.so.1` | libbpf 依赖 |

### 1.2 不支持的环境

| 环境 | 原因 | 表现 |
|---|---|---|
| **EulerOS 5.10**（内核 5.10） | 不支持 BPF_ATOMIC（5.12 才加入） | `BPF_STX uses reserved fields` → BPF 程序加载失败 → Backend 回退 mock |
| **glibc < 2.34** | libbpf.so.0（系统 0.8.1）也不兼容 | `libbpf not found` |
| **无系统 libelf** | libbpf 依赖 libelf.so.1，不再 bundle | `libbpf not found` |
| **Python < 3.9** | wsproto 1.2.0 最低 3.7，但 flask 2.2.5 最低 3.7，click 8.0.4 最低 3.6 — 实际 3.9 是安全下限 | `SyntaxError` / `ImportError` |
| **Python > 3.12** | 未测试 | 可能不兼容 |

### 1.3 已验证通过的环境

| 节点 | 架构 | Python | glibc | 内核 | 状态 |
|---|---|---|---|---|---|
| Ubuntu 24.04 (noble) | x86_64 | 3.12 | 2.38+ | 6.x | ✅ 全功能通过 |
| dfx-syn01-csp-c-arm-0 | aarch64 | 3.11.6 | 2.38 | 6.x | ✅ 全功能通过（含 Phase 1 容器选择） |

---

## 二、打包

### 2.1 构建机前置条件

构建机需要（x86_64 或 aarch64）：

```bash
clang --version                              # clang（编译 BPF .o）
ls /usr/include/bpf/bpf_helpers.h            # libbpf-dev 头文件
ls /usr/include/bpf/bpf_tracing.h
pip3 --version                               # pip（下载 Python 依赖）
```

缺什么装什么（Ubuntu/Debian）：
```bash
sudo apt install clang libbpf-dev python3-pip
```

### 2.2 打 arm64 包（在 x86 构建机上交叉打包）

**一次性配置** arm64 apt 源（用于下载 arm64 libbpf.so）：
```bash
CODE=$(lsb_release -cs)     # 如 noble(24.04) / jammy(22.04)
sudo sh -c "echo 'deb [arch=arm64] http://ports.ubuntu.com/ubuntu-ports $CODE main universe' > /etc/apt/sources.list.d/arm64.list"
sudo apt update
# 验证能下 arm64 包
cd /tmp && apt-get download libbpf1:arm64 2>&1; ls libbpf1_*arm64*
```

**打包**：
```bash
cd ~/workspace/leakdetect
bash tools/package_arm.sh 3.9
```

> 用 `3.9` 不是 `3.11`：脚本对 <3.10 用 pinned 依赖（flask<2.3 click<8.1 werkzeug<3.0），兼容 3.9-3.12。包名 `leakdetect-aarch64-py3.9` 只是标签，实际兼容 3.9-3.12。

**产出**：`dist/leakdetect-aarch64-py3.9.tar.gz`（约 2.2M）

### 2.3 打 x86 包（在 x86 构建机上原生打包）

```bash
cd ~/workspace/leakdetect
bash tools/package.sh 3.9
```

**产出**：`dist/leakdetect-x86_64-py3.9.tar.gz`

### 2.4 验证包完整性

```bash
PKG=dist/leakdetect-aarch64-py3.9    # 或 x86_64
ls $PKG/lib/                          # 应有 libbpf.so.1 + libbpf.so.1.3.0（无 libelf.so.1）
ls $PKG/py-packages/ | grep flask    # 应有 flask 目录
ls $PKG/bpf/compiled/                # 应有 mem.o threads.o fd.o
ls $PKG/start.sh                     # 应有 start.sh
ls $PKG/core/cgroup_enum.py          # 应有（Phase 1 容器选择）
du -sh dist/leakdetect-*.tar.gz      # 应 ~2.2M
```

---

## 三、部署

### 3.1 传包到目标节点

```bash
# 从构建机传到目标节点
scp dist/leakdetect-aarch64-py3.9.tar.gz <user>@<目标节点IP>:~/
```

### 3.2 解压

```bash
# 目标节点上
cd ~
tar xzf leakdetect-aarch64-py3.9.tar.gz
cd leakdetect-aarch64-py3.9
```

### 3.3 目录结构

```
leakdetect-aarch64-py3.9/
├── bpf/compiled/          # 预编译 BPF .o（mem/threads/fd）
├── lib/                   # libbpf.so.1 + libbpf.so.1.3.0
├── py-packages/           # Python 依赖（flask/socketio/pyelftools 等）
├── core/                  # 后端核心（loader/ingest/aggregator/cgroup_enum 等）
├── analyzer/              # 4 资源分析器
├── symbolizer/            # 符号解析
├── storage/               # SQLite 存储层
├── web/                   # Flask + SocketIO + Vue 前端
├── config/                # default.yaml
├── tests/leak_programs/   # 合成泄露程序源码
├── data/                  # 运行时数据（SQLite db + 告警日志）
├── start.sh               # 启动脚本
└── requirements.txt
```

---

## 四、启动

### 4.1 启动命令

```bash
sudo ./start.sh
```

start.sh 自动完成：
1. 检查 root 权限
2. 检查 BTF（`/sys/kernel/btf/vmlinux`）
3. 检查 Python 3
4. 设置 `LD_LIBRARY_PATH=lib` + `PYTHONPATH=py-packages`
5. 执行 `python3 web/app.py`

### 4.2 启动成功标志

```
LeakDetect starting...
  Dir: /home/...
  Python: Python 3.x.x
  BTF: OK
  libbpf: .../libbpf.so.1
[backend] Loading BPF programs...
[loader] mem loaded ... uprobe malloc attached ...
[loader] threads loaded ... tracepoint clone attached ...
[loader] fd loaded ... kprobe fd_install attached ...
[backend] All components started.
[app] LeakDetect starting at http://[::]:8080
 * Running on http://[::]:8080
```

### 4.3 启动失败排查

| 错误信息 | 原因 | 解决 |
|---|---|---|
| `ERROR: Need root` | 非 root 运行 | `sudo ./start.sh` |
| `ERROR: BTF not found` | 内核无 BTF | 内核需 5.10+ + `CONFIG_DEBUG_INFO_BTF` |
| `ERROR: python3 not found` | 无 Python 3 | 安装 python3 |
| `libbpf not found` | libbpf 加载失败 | 检查 `ls /usr/lib*/libbpf*`（需 .so.1 或 .so.0）+ `ls /usr/lib*/libelf.so.1` |
| `WARNING: Backend init failed, falling back to mock` | BPF 加载失败 | 看错误细节（见下） |
| `BPF_STX uses reserved fields` | 内核 < 5.12（不支持 BPF_ATOMIC） | 换内核 ≥ 5.12 的节点 |
| `GLIBC_2.38 not found` | bundled libbpf 需 glibc 2.38+ | 节点 glibc 不够新 → loader 应回退 .so.0（若系统有） |
| `invalid syntax (callframe.py)` | pyelftools 版本不对 | 用 `package_arm.sh 3.9`（pinned 依赖） |
| `TypeError: unsupported operand type(s) for \|` | wsproto 版本不对 | 用 `package_arm.sh 3.9`（pinned 依赖） |
| `TypeError: run_simple() ... allow_unsafe_werkzeug` | werkzeug 版本不匹配 | app.py 已有条件传参，检查包是否最新 |
| `py_compile: Permission denied` | __pycache__ 被 root 留下 | `sudo chown -R $USER:$USER <目录>` |

### 4.4 停止

```
Press CTRL+C to quit    # 在 start.sh 终端按 Ctrl+C
```

---

## 五、访问前台

### 5.1 方式 A：直接访问（节点端口可达时）

服务绑在 `[::]:8080`（所有接口）。如果目标节点的 8080 端口从你的机器可达（防火墙/安全组放行）：

**浏览器输入**：
```
http://<节点IP>:8080          # IPv4
http://[<节点IPv6>]:8080       # IPv6（地址用方括号包住）
```

**示例**（IPv6）：
```
http://[3d10:135:247:229::f7]:8080
```

### 5.2 方式 B：SSH 隧道（推荐）

从你的本地机器通过 SSH 连接节点，同时转发 8080 端口。

**方式 B1：标准 SSH 隧道（节点 8080 端口不可达时）**

```bash
ssh -L 8080:127.0.0.1:8080 <user>@<节点IP>
# 登录后这个窗口保持开着别关
```

浏览器打开：
```
http://127.0.0.1:8080
```

> 流量通过 SSH 隧道转发，不依赖节点防火墙放行 8080。

**方式 B2：SSH 隧道 + 直接访问节点 IP（节点 8080 端口可达时）**

```bash
ssh -L 8080:127.0.0.1:8080 <user>@<节点IP>
# 登录后这个窗口保持开着别关
```

浏览器打开：
```
http://<节点IP>:8080
```

> SSH 连接用于登录节点执行 `sudo ./start.sh`，浏览器直接访问节点 IP:8080。
> 适用于节点 8080 端口从本机可达（防火墙/安全组已放行）的场景。
> 如果 8080 不可达，用 B1（浏览器访问 `http://127.0.0.1:8080` 走隧道）。

### 5.3 方式 C：跳板机多跳（节点不可直达时）

如果需要先 SSH 到跳板机，再从跳板机 SSH 到目标节点：

#### C1：ProxyJump（跳板机允许 TCP 转发时）

```bash
ssh -L 8080:127.0.0.1:8080 -J <跳板user>@<跳板IP> <目标user>@<目标IP>
# 浏览器：http://127.0.0.1:8080
```

#### C2：两步隧道（跳板机禁用 TCP 转发时）

如果 C1 报 `administratively prohibited: open failed`（跳板机 `AllowTcpForwarding no`）：

**步骤 1**：SSH 到跳板机，从跳板机建隧道到目标节点：
```bash
# 本地 → 跳板机
ssh <跳板user>@<跳板IP>
# 在跳板机上：
ssh -L 8080:127.0.0.1:8080 <目标user>@<目标IP>
# 跳板机上现在 8080 → 目标节点 8080
```

**步骤 2**：如果跳板机也禁了转发，但目标节点 IPv6 可直达：
```bash
# 本地直接 SSH 到目标节点（IPv6）
ssh -L 8080:127.0.0.1:8080 <user>@<目标IPv6>
# 但目标节点也禁了 TCP 转发 → 隧道不通
```

**步骤 3**：如果所有 SSH 转发都被禁，只能直接访问：
```bash
# 在目标节点上开放 8080 端口
sudo iptables -I INPUT -p tcp --dport 8080 -j ACCEPT
# 或 firewalld：
sudo firewall-cmd --add-port=8080/tcp
# 然后浏览器直接访问 http://<节点IP>:8080
```

### 5.4 端口/防火墙检查

```bash
# 目标节点上检查 8080 是否开放
sudo iptables -L INPUT -n | grep 8080
# 或
sudo firewall-cmd --list-ports

# 如果没开，临时开
sudo iptables -I INPUT -p tcp --dport 8080 -j ACCEPT
sudo firewall-cmd --add-port=8080/tcp
```

### 5.5 云环境安全组

如果节点在云上（腾讯云/阿里云等），8080 端口还需在**云控制台安全组**中放行入站规则。SSH 隧道可绕过安全组（用 22 端口）。

---

## 六、前台使用

### 6.1 Dashboard 概览

打开后看到暗色主题界面：
- **顶部栏**：标题 + 容器下拉 + PID 输入 + 状态指示 + 配置按钮
- **告警区**（置顶）：当前告警 + 历史告警标签切换
- **4 个资源卡片**（2×2 网格）：
  - **CPU**（左上）：实时 CPU 占用率 + top-5 进程
  - **内存**（右上）：实时 outstanding 字节数 + top-5 进程
  - **线程**（左下）：实时线程数 + top-5 进程
  - **句柄**（右下）：实时 fd 数 + top-5 进程

### 6.2 容器选择

顶部下拉框：
- **"宿主机"**（默认）：显示宿主进程（排除容器进程）
- **各容器名**（如 `k8s_fmservice-software_... (099b40924b92)`）：选中后只显示该容器的进程

切换后 per_process 列表 + 资源卡片数值 + 告警都会按选定的 target 过滤。

> **注意**：容器模式下 **mem ≈ 0** 是 Phase 1 的已知限制（uprobe 只挂宿主 libc，容器 mem 未采集）。threads/fd/CPU 有值。

### 6.3 PID 过滤

在 PID 输入框输入进程 PID + 点"应用" → 在当前 target 范围内进一步按 PID 过滤。点"清除"恢复。

### 6.4 告警查看

- **当前告警**：告警区的"当前"标签，实时显示活跃告警
- **历史告警**：点"历史"标签，加载过去 24h 的告警
- **栈展开**：点击告警项 → 内联展开泄露调用栈（如 `malloc → main+0x4c → ...`）
- **再次点击**：收起

### 6.5 监控参数配置

点顶部"监控配置"按钮 → 进入监控参数配置页面：
- **内存**：告警增量阈值 / 观察期 / 确认泄露时长 / 恢复比例 / 恢复确认时长 / 清除时长 / 稳定消除时长
- **线程**：同结构
- **句柄**：同结构
- **CPU**：轮询间隔
- **采样率**：只读展示（需重启生效）

修改后点"保存并应用" → 运行时立即生效（setattr 分析器属性）。点"恢复默认值"重置。

### 6.6 进程配置

点顶部"进程配置"按钮 → 进入进程管理配置页面：
- 模式选择：全部监控 / 白名单
- 进程名正则
- PID 列表
- 导入/导出配置（JSON 文件）
- 预览匹配进程

> **注意**：后端 filter_manager 尚未实现（TODO 桩），当前保存不实际生效。

---

## 七、REST API 速查

### 7.1 容器列表

```bash
curl -s http://127.0.0.1:8080/api/containers
```

返回：`{"containers":[{"id":"...","id_short":"...","name":"...","image":"...","pid_count":N},...]}`

### 7.2 历史数据

```bash
curl -s 'http://127.0.0.1:8080/api/history?resource=mem&range=1d'
```

参数：
- `resource`：`mem` / `thread` / `fd` / `cpu`
- `range`：`1d` / `7d` / `30d`

返回：`{"range":"1d","series":[{"t":<unix时间戳>,"v":<值>},...]}`

### 7.3 监控参数

```bash
curl -s http://127.0.0.1:8080/api/config/monitoring
```

返回：`{"mem":{...},"thread":{...},"fd":{...},"cpu":{"cpu_interval":1},"sampling_rate":100}`

### 7.4 告警历史

```bash
curl -s http://127.0.0.1:8080/api/alerts?range=24h
```

返回：`{"alerts":[{...},...]}`（当前返回空，待持久化专项实现）

---

## 八、常见问题

### Q1：`py_compile` 报 `Permission denied`

```
[Errno 13] Permission denied: '.../__pycache__/...pyc...'
```

**原因**：之前 `sudo python3` 运行留下了 root 属主的 `__pycache__`。

**解决**：
```bash
sudo chown -R $USER:$USER ~/leakdetect-aarch64-py3.9
# 或直接用 sudo 跑（root 能写 pycache）
sudo ./start.sh
```

### Q2：`libbpf not found`

**原因**：libbpf 加载失败（可能 glibc 不兼容、libelf 缺失等）。

**排查**：
```bash
# 检查系统有没有 libbpf
ls /usr/lib*/libbpf*
# 检查 libelf
ls /usr/lib*/libelf.so.1
# 手动测加载
sudo env PYTHONPATH=py-packages:. python3 -c "import ctypes; ctypes.CDLL('libbpf.so.1')"
```

**常见根因**：
- glibc 太旧（< 2.34）→ bundled libbpf.so.1 需 2.38+，系统 .so.0 需 2.34+
- 系统 libelf.so.1 不存在
- LD_LIBRARY_PATH 毒化（已修复，但如果用旧包仍有此问题）

### Q3：Backend 回退 mock

```
[app] WARNING: Backend init failed, falling back to mock: ...
```

**原因**：BPF 加载失败（libbpf / .o / 内核 verifier）。

**排查**：看 `falling back to mock:` 后面的错误信息：
- `libbpf not found` → Q2
- `BPF_STX uses reserved fields` → 内核 < 5.12（不支持 BPF_ATOMIC）→ 换节点
- `Failed to load BPF object` → .o 加载失败，看 libbpf 错误日志

### Q4：`BPF_STX uses reserved fields`

**原因**：内核 5.10 不支持 BPF_ATOMIC 指令（5.12 才加入）。

**确认**：
```bash
uname -r    # 如果 5.10.x → 确认
```

**解决**：在内核 ≥ 5.12 的节点上运行。EulerOS 5.10 节点暂不支持。

### Q5：Python 3.9 兼容问题

**`invalid syntax (callframe.py)`** → pyelftools 版本不对（0.33 需 3.10+）
**`TypeError: unsupported operand type(s) for |`** → wsproto 版本不对（1.3.x 需 3.10+）

**解决**：用 `package_arm.sh 3.9` 打包（pinned 依赖 → pyelftools 0.32 + wsproto 1.2.0）。

### Q6：`TypeError: run_simple() ... allow_unsafe_werkzeug`

**原因**：werkzeug 2.x 的 `run_simple` 不接受 `allow_unsafe_werkzeug` 参数。

**解决**：app.py 已有条件传参（`_wz_major >= 3`）。如果仍报错 → 包是旧的，用最新源码重新打包。

### Q7：跳板机 SSH 转发被禁

```
channel 0: open failed: administratively prohibited: open failed
```

**原因**：跳板机 sshd 配置 `AllowTcpForwarding no`。

**解决**：
- 方案 1：在目标节点开放 8080 端口 → 浏览器直接访问 `http://<节点IP>:8080`
- 方案 2：找管理员开 `AllowTcpForwarding yes`
- 方案 3：用 `socat` 转发到其他可达端口

### Q8：dup2 tracepoint WARNING

```
libbpf: failed to determine tracepoint 'syscalls/sys_enter_dup2'
[loader] WARNING: tracepoint trace_dup2:syscalls/sys_enter_dup2 not available, skipping
```

**原因**：arm64 内核无 `sys_enter_dup2` tracepoint（dup2 在 arm64 上已废弃，用 dup3）。

**影响**：无（dup3 已覆盖，dup2 优雅跳过）。

### Q9：容器模式下只显示 `runc:[2:INIT]`

**原因**：BPF 是事件驱动的——只抓工具启动**之后**发生的 malloc/clone/fd_install。容器已有进程（启动前就存在）→ 没有新事件 → 不显示。

**影响**：正常行为。只有启动后有新活动的进程才显示。mem=0 是 Phase 1 限制（Phase 2 补全 libc uprobe）。

---

## 九、验证命令速查

```bash
# === 环境检查 ===
uname -r                           # ≥ 5.12
python3 --version                  # 3.9 - 3.12
ldd --version | head -1            # glibc ≥ 2.34
ls /sys/kernel/btf/vmlinux         # BTF 存在
ls /usr/lib*/libbpf*               # 系统 libbpf（.so.1 或 .so.0）
ls /usr/lib*/libelf.so.1           # 系统 libelf
ls /usr/lib*/libz.so.1             # 系统 libz

# === 启动 ===
sudo ./start.sh

# === REST 验证（另开终端） ===
curl -s http://127.0.0.1:8080/api/containers                    # 容器列表
curl -s 'http://127.0.0.1:8080/api/history?resource=mem&range=1d'  # 历史数据
curl -s http://127.0.0.1:8080/api/config/monitoring             # 监控参数

# === 浏览器访问 ===
# SSH 隧道
ssh -L 8080:127.0.0.1:8080 <user>@<节点IP>
# 浏览器 http://127.0.0.1:8080

# 或直接访问（端口可达时）
# 浏览器 http://<节点IP>:8080 或 http://[<节点IPv6>]:8080

# === 包验证 ===
ls dist/leakdetect-*/lib/                    # libbpf.so.1（无 libelf.so.1）
ls dist/leakdetect-*/py-packages/ | grep wsproto   # 1.2.0
ls dist/leakdetect-*/py-packages/ | grep elftools   # 0.32
grep "_wz_major" dist/leakdetect-*/web/app.py       # werkzeug 条件传参
ls dist/leakdetect-*/core/cgroup_enum.py            # Phase 1 容器选择

# === DB 检查 ===
# 如果有 sqlite3 CLI：
sqlite3 data/leakdetect.db "SELECT COUNT(*) FROM samples"
sqlite3 data/leakdetect.db "SELECT * FROM alerts ORDER BY timestamp DESC LIMIT 5"
# 如果没有 sqlite3 CLI：
python3 -c "import sqlite3; db=sqlite3.connect('data/leakdetect.db'); print(db.execute('SELECT COUNT(*) FROM samples').fetchone())"
```

---

## 十、栈解析与离线定位

### 10.1 栈显示分层说明

告警触发后，点击告警展开栈。栈按调用链从上到下展示（调用者在上方，被调用者在下方），最内层帧标"← 嫌疑点"（分配/创建发生处）。

栈帧的显示内容取决于目标环境是否有调试符号（debuginfo）：

**有 debuginfo（如 x86 VM 装了 libc6-dbg）**：

```
_start+0x25 (mem_leak.c:86)                              ← 函数名+源码行号
__libc_start_main_alias_2+0x8b (libc_start_call_main.h:128)
main+0x3a (mem_leak.c:22)
__GI___libc_malloc (arena.c:3294) ← 嫌疑点
```

每帧都有：函数名 + 偏移 + 源码文件:行号。开发者直接看到泄露发生在哪个源码的哪一行。

**无 debuginfo（如 ARM EulerOS 无网络）**：

```
_start+0x30                                              ← 用户程序符号(.symtab 自带)
__libc_start_main+0x98                                   ← 导出函数(.dynsym 自带)
libc.so.6+0x27784                                       ← 兜底(库名+偏移，无函数名)
main+0x4c                                                ← 用户程序符号
malloc ← 嫌疑点                                          ← 导出函数
```

导出函数（malloc, main, __libc_start_main）有名字；内部函数显示 `库名+偏移`（知道在哪个库的什么位置，但不知道函数名）。

**完全无信息**：`[unknown]`（地址不在任何文件映射里，极罕见，通常是帧指针断裂导致的垃圾地址）。

### 10.2 为什么有些帧没有函数名

系统库（如 libc）在发布时被 strip（移除了 `.symtab` 函数符号表），只保留 `.dynsym`（导出函数符号表）。导出函数（malloc, free, __libc_start_main 等）在 `.dynsym` 里，能解析。内部函数（`__libc_start_call_main`, `_int_malloc` 等）不在 `.dynsym` 里，无法解析。

补回内部函数名需要 debuginfo 包（含完整 `.symtab`）。debuginfo 与二进制版本严格绑定（build-id 匹配），不能跨版本/跨发行版使用。

### 10.3 有网络环境：安装 debuginfo

如果目标环境有网络，安装 debuginfo 后工具自动读取，无需额外配置：

```bash
# Ubuntu/Debian
sudo apt install libc6-dbg          # libc 内部函数名+行号
sudo apt install python3-dbg        # Python C 层函数名+行号

# RHEL/EulerOS（需要 debuginfo 仓库）
sudo yum install yum-utils
sudo debuginfo-install glibc        # libc 内部函数名+行号
```

安装后重启 leakdetect（清符号缓存），工具自动读取 debuginfo：
- 有 debuginfo 的帧：`__GI___libc_malloc (arena.c:3294)` ← 函数名+行号
- 无 debuginfo 的帧：`libc.so.6+0x偏移` ← 兜底

debuginfo 与二进制版本绑定（build-id 匹配），必须装对应版本的包。

### 10.4 无网络环境：离线解析（addr2line）

在无 debuginfo 的目标环境上，开发者可以把二进制文件拷到有 debuginfo 的机器上，用 `addr2line` 离线解析地址：

```bash
# 1. 从目标节点拷出 libc（或其他需要解析的二进制）
scp root@<目标节点>:/usr/lib64/libc.so.6 ~/libc-arm.so.6

# 2. 在有 debuginfo 的机器上（如 x86 开发机，装了对应版本的 debuginfo）
# 解析单个地址
addr2line -e libc-arm.so.6 -f 0x27784
# 输出示例：
# __libc_start_call_main
# /path/to/libc-start.c:74

# 3. 批量解析栈中所有地址
# 把栈里显示的偏移（如 libc.so.6+0x27784）提取出来，逐个 addr2line
for offset in 0x27784 0x27868 0x8f810; do
    echo -n "$offset: "
    addr2line -e libc-arm.so.6 -f $offset
done

# 4. 如果没有 addr2line，用 objdump 看反汇编（不需要 debuginfo）
objdump -d libc-arm.so.6 | grep -A5 "27784:"
# 输出该地址附近的汇编指令
```

**注意**：
- `addr2line` 需要对应版本的 debuginfo 才能解析出函数名和行号
- 没有 debuginfo 时，`addr2line` 只能输出 `?? ??:0`（和工具显示 [unknown] 一样）
- 不同发行版/版本的 debuginfo 不通用（build-id 必须匹配）
- 目标节点的 libc 版本可通过 `ldd --version` 查看

### 10.5 提升栈质量的建议

| 建议 | 效果 | 适用场景 |
|---|---|---|
| 目标环境装 debuginfo（如 `apt install libc6-dbg`） | 内部函数名+源码行号 | 有网络的目标环境 |
| 用户自有代码编译时加 `-g` | 用户程序的源码行号 | 用户可控制编译 |
| 用户自有代码编译时加 `-fno-omit-frame-pointer` | 栈完整不丢帧（BPF 帧指针回溯不断裂） | 用户可控制编译 |
| 工具打包自带 debuginfo（build-id 匹配时） | 内部函数名+行号，无需目标装包 | 无网络目标环境（需预先获取 .debug 文件，详见 0826 文档 P7） |

### 10.6 栈帧格式速查

| 显示格式 | 含义 | 信息量 |
|---|---|---|
| `func+0xoff (file:line)` | 函数名+偏移+源码文件行号 | ★★★ 最完整 |
| `func+0xoff` | 函数名+偏移（无行号） | ★★ 有函数名 |
| `func` | 函数名（偏移为0） | ★★ |
| `library.so+0xoff` | 库名+偏移（无函数名） | ★ 兜底（知道在哪个库） |
| `[unknown]` | 地址不在任何文件映射 | 无信息（极罕见） |
