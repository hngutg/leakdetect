# LeakDetect

基于 eBPF 的资源监控与泄露检测工具，对四种资源（内存、线程、句柄、CPU）实现实时监控与泄露检测，并通过 Web 前端实时告知用户当前资源使用情况及泄露告警。

## 监控资源

| 资源 | 实时监控 | 泄露检测 | 说明 |
|---|:---:|:---:|---|
| 内存 | ✅ | ✅ | malloc/free 配对追踪，定位到分配栈 |
| 线程 | ✅ | ✅ | clone/exit 配对，检测长期不退出的线程 |
| 句柄 | ✅ | ✅ | open/close 配对，按调用栈聚合未关闭 FD |
| CPU | ✅ | ❌ | 仅监控占用率，不做泄露检测 |

## 快速开始

> F1 里程碑完成后填写完整的启动步骤。

```bash
# 安装依赖
pip install -r requirements.txt

# 启动服务（F1 完成后可用）
python web/app.py

# 浏览器访问
# http://127.0.0.1:8080
```

## 项目结构

```
leakdetect/
├── bpf/                # BPF 程序（C 源 + 预编译 .o）
├── core/               # 后端核心（加载/采集/聚合/过滤/配置）
├── analyzer/           # 四资源泄露分析器
├── symbolizer/         # 内核+用户态符号解析
├── storage/            # SQLite 持久化
├── web/                # Flask + SocketIO + Vue 前端
├── logging/            # 告警本地日志
├── config/             # YAML 配置
├── tests/              # 测试（合成泄露程序）
├── packaging/          # 打包脚本
├── tools/              # 构建工具
└── data/               # 运行时数据（SQLite db）
```

## 技术栈

- **eBPF 框架**：libbpf + CO-RE（BPF 程序预编译为 .o）
- **MVP 加载层**：BCC（`BPF(obj_file=...)` CO-RE 路径）
- **迁移后加载层**：Go + cilium/ebpf（静态二进制，零依赖）
- **分析层**：Python
- **前端**：Flask + Flask-SocketIO + Vue 3 (CDN) + Chart.js
- **存储**：SQLite
- **目标 OS**：EulerOS（内核 5.10+，BTF 可用）
- **部署**：宿主机 root 进程直接运行

## 实施路线

| 阶段 | 内容 | 工期 |
|---|---|---|
| F0-F4 | 前端先行（契约 → 骨架+mock → 看板 → 告警+历史+配置 → 打磨） | ~3 周 |
| B0-B4 | 后端接上（技术验证 → 内存 → 其他资源 → 过滤 → 打包） | ~2.5-3 周 |
| M9-M13 | 迁移到 Go + cilium/ebpf | ~2-3 周 |

## 关联文档

- 总体方案：`D:\leakdetect-plan.md`（v1.4）
- 前端设计：`D:\leakdetect-frontend-design.md`（v1.0）

## 运行要求

- **权限**：root（eBPF 内核能力要求）
- **内核**：5.10+，BTF 可用（`/sys/kernel/btf/vmlinux` 存在）
- **MVP 阶段**：系统需装 bcc 包（`yum install bcc-python3`）
- **迁移后**：无额外依赖（Go 静态二进制 + PyInstaller Python）
