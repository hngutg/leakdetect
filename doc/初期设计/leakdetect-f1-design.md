# F1 里程碑设计文档 — 骨架 + Mock

> 文档版本：v1.0  
> 日期：2026-07-07  
> 状态：✅ 已完成  
> 关联文档：`D:\leakdetect-frontend-design.md`、`D:\leakdetect-plan.md`

---

## 一、F1 目标

端到端跑通 **"后端 mock 推数据 → WebSocket → Vue 接收 → 页面显示"** 链路，验证技术栈和契约可用。

**不含**：折线图渲染（F2）、告警弹窗/栈展示（F3）、容器下拉/PID 输入（F4）、真实 BPF 数据（B1+）。

---

## 二、交付物清单

### 2.1 后端文件（4 个 Python）

#### `web/app.py` — Flask 主服务

**职责**：Flask 应用入口，初始化 SocketIO，注册路由和 WebSocket 事件，启动后台推送。

**关键实现**：
- `Flask(__name__, static_folder=..., static_url_path="/static")`：静态文件服务
- `SocketIO(app, cors_allowed_origins="*", async_mode="eventlet")`：eventlet 支持 WebSocket
- `app.register_blueprint(api)`：注册 REST 路由蓝图
- `register_handlers(socketio)`：注册 WebSocket 事件
- `start_pusher(socketio, interval=1)`：启动后台推送任务
- `@app.route("/")`：返回 index.html
- `socketio.run(app, host="127.0.0.1", port=8080)`：启动服务

**启动方式**：
```bash
cd web
python3 app.py
```

#### `web/sockets.py` — WebSocket 推送

**职责**：后台定时推送 dashboard_update，处理客户端事件。

**关键实现**：
- `start_pusher(socketio, interval)`：
  - 使用 `socketio.start_background_task(push_loop)`（非裸线程）
  - 循环内用 `socketio.sleep(interval)`（非 time.sleep）
  - 每次调用 `producer.get_dashboard_update()` 获取数据
  - `socketio.emit("dashboard_update", data)` 推送
- `register_handlers(socketio)`：
  - `@socketio.on("connect")`：打印连接日志
  - `@socketio.on("disconnect")`：打印断开日志
  - `@socketio.on("select_container")`：接收容器切换（F4 用）

#### `web/api.py` — REST 路由

**职责**：提供历史查询、告警查询、容器列表、黑白名单配置接口。

**接口清单**：

| 路由 | 方法 | F1 实现 | 后续 |
|---|---|---|---|
| `/api/history` | GET | mock.get_history() | B1: 接 SQLite |
| `/api/alerts` | GET | 返回空列表 stub | F3: 接 SQLite |
| `/api/containers` | GET | 返回 mock 容器列表 | B3: 接 cgroup 枚举 |
| `/api/config/filter` | GET | 返回默认配置 stub | B3: 接 runtime.yaml |
| `/api/config/filter` | POST | 返回 received stub | B3: 写 BPF map |
| `/api/config/filter/preview` | GET | 返回假匹配 stub | B3: 解析 /proc |

#### `web/mock.py` — Mock 数据生产者

**职责**：生成符合 dashboard_update 契约的 mock 数据。

**MockProducer 类**：

| 方法 | 返回 | 说明 |
|---|---|---|
| `get_dashboard_update()` | dict | 实时快照（4 资源 + 告警 + 容器） |
| `get_history(resource, range)` | dict | 历史时序数据（F2 用） |

**资源趋势模拟**：

| 资源 | 基准值 | 趋势 | 泄露信号 |
|---|---|---|---|
| 内存 | 64 MB | +2MB/分钟 + 噪声 | 单调上升 → 30s 后告警 |
| 线程 | 20 | sin(±5) + 噪声 | 正常波动 |
| 句柄 | 80 | +0.5/分钟 + 噪声 | 单调上升 → 60s 后告警 |
| CPU | 15% | sin(±8) + 噪声 | 正常波动 |

**告警触发**：
- 30 秒后：内存泄露告警（PID 1234 nginx，4 层栈帧）
- 60 秒后：句柄泄露告警（PID 9012 app，3 层栈帧）

**伪造栈帧示例**：
```
内存泄露栈:
  main()           0x401000
    └─ start_worker()      0x4012a0
         └─ handle_request()   0x401580
              └─ malloc()      0x401800
```

### 2.2 前端文件（5 个）

#### `web/static/index.html` — 单页入口

**职责**：Vue 挂载点 + vendor 引入 + Vue 模板。

**结构**：
```
<head>
  <link style.css>
</head>
<body>
  <div id="app">
    <!-- Vue 内联模板 -->
    <div class="header">...</div>
    <div class="resource-grid">
      <div v-for="r in resourceOrder" class="resource-card">
        <div class="card-header">...</div>
        <div class="card-current">...</div>
        <div class="chart-placeholder">[折线图 - F2 实现]</div>
        <table class="process-table">...</table>
      </div>
    </div>
    <div class="alert-section">
      <div class="alert-list">...</div>
      <div class="stack-view">点击告警查看栈 → F3 实现</div>
    </div>
  </div>
  <script src="vendor/socket.io.min.js">
  <script src="vendor/vue.global.prod.js">
  <script src="vendor/chart.umd.min.js">
  <script src="js/api.js">
  <script src="js/app.js">
</body>
```

#### `web/static/js/api.js` — 数据接入层

**职责**：封装 Socket.IO 客户端 + REST 调用。

**LeakDetectAPI 对象**：

| 方法/属性 | 说明 |
|---|---|
| `init()` | 建立 Socket.IO 连接 |
| `onDashboardUpdate` | 回调：收到 dashboard_update |
| `onConnect` / `onDisconnect` | 回调：连接状态变化 |
| `selectContainer(cid)` | 发送容器切换（WebSocket emit） |
| `getHistory(resource, range)` | REST: GET /api/history |
| `getAlerts(range)` | REST: GET /api/alerts |
| `getContainers()` | REST: GET /api/containers |
| `getFilterConfig()` | REST: GET /api/config/filter |
| `saveFilterConfig(config)` | REST: POST /api/config/filter |
| `previewFilter(regex, pids)` | REST: GET /api/config/filter/preview |

#### `web/static/js/app.js` — Vue 主应用

**职责**：Vue 3 应用入口，响应式数据管理。

**响应式状态**：
```javascript
const connected = ref(false);         // WebSocket 连接状态
const resources = reactive({           // 4 资源数据
    mem:    { current: 0, status: "normal", perProcess: [] },
    thread: { current: 0, status: "normal", perProcess: [] },
    fd:     { current: 0, status: "normal", perProcess: [] },
    cpu:    { current: 0, status: "normal", perProcess: [] },
});
const alerts = ref([]);               // 告警列表
const containers = ref([]);           // 容器列表
const lastUpdate = ref("");           // 最后更新时间
```

**核心函数**：
- `handleDashboardUpdate(data)`：接收 WebSocket 数据 → 更新 resources/alerts/containers
- `formatValue(resource, v)`：bytes→MB, count→直接, percent→直接
- `statusText(status)`：normal→正常, leak_suspected→疑似泄露
- `resourceLabel(r)`：mem→内存, thread→线程, fd→句柄, cpu→CPU

**数据流**：
```
WebSocket 收到 dashboard_update
  → handleDashboardUpdate(data)
    → resources.mem.current = data.latest_points.mem.v
    → resources.mem.perProcess = data.per_process.mem
    → alerts.value = data.alerts
    → 告警存在则 resources[resource].status = "leak_suspected"
    → Vue 自动更新 DOM（响应式）
```

#### `web/static/css/style.css` — 暗色主题

**配色方案**：

| 元素 | 颜色 | 用途 |
|---|---|---|
| `body` 背景 | `#1a1a2e` | 全局暗色背景 |
| `.header` 背景 | `#16213e` | 顶部栏 |
| `.resource-card` 背景 | `#16213e` | 卡片背景 |
| `.resource-card` 边框 | `#0f3460` | 卡片边框 |
| `.leak_suspected` 边框 | `#f44336` | 泄露告警红色边框 |
| `.status-badge.normal` | `#4caf50` | 正常绿色 |
| `.status-badge.leak_suspected` | `#f44336` | 泄露红色 |
| `.card-current` | `#ffffff` | 当前值白色 |
| 进程表值 | `#4fc3f7` | 蓝色 |

**布局**：
- `.resource-grid`：`display: grid; grid-template-columns: 1fr 1fr; gap: 16px;`
- `.alert-section`：`display: grid; grid-template-columns: 1fr 1fr; gap: 16px;`

### 2.3 Vendor 库（3 个，本地存）

| 文件 | 大小 | 用途 | F1 是否使用 |
|---|---|---|---|
| `vue.global.prod.js` | 164 KB | Vue 3 响应式框架 | ✅ |
| `socket.io.min.js` | 50 KB | Socket.IO 客户端 | ✅ |
| `chart.umd.min.js` | 208 KB | Chart.js 图表库 | ❌ F2 才用，先就位 |

### 2.4 配置文件

#### `requirements.txt`
```
flask>=2.3
flask-socketio>=5.3
pyyaml>=6.0
eventlet  （WebSocket 支持，threading 模式不支持 WS）
```

---

## 三、数据流全链路

```
┌─────────────────────────────────────────────────────────┐
│ 服务器端                                                 │
│                                                         │
│  mock.py (MockProducer)                                 │
│    │                                                    │
│    │ get_dashboard_update()                             │
│    ▼                                                    │
│  sockets.py (start_pusher)                             │
│    │                                                    │
│    │ socketio.emit("dashboard_update", data)  每 1s    │
│    ▼                                                    │
│  Flask-SocketIO (eventlet)                              │
│    │                                                    │
│    │ WebSocket 推送                                     │
│    ▼                                                    │
└────────────────────┬────────────────────────────────────┘
                     │ 网络（WebSocket / SSH 隧道）
                     ▼
┌─────────────────────────────────────────────────────────┐
│ 浏览器端                                                 │
│                                                         │
│  api.js (LeakDetectAPI)                                 │
│    │                                                    │
│    │ socket.on("dashboard_update", cb)                  │
│    ▼                                                    │
│  app.js (Vue setup)                                     │
│    │                                                    │
│    │ handleDashboardUpdate(data)                        │
│    │  → resources.mem.current = data.latest_points.mem.v│
│    │  → alerts.value = data.alerts                      │
│    ▼                                                    │
│  Vue 响应式系统                                          │
│    │                                                    │
│    │ 数据变化 → 自动更新 DOM                             │
│    ▼                                                    │
│  index.html (Vue 模板)                                  │
│    │                                                    │
│    ▼                                                    │
│  页面渲染（数值刷新 + 告警显示 + 状态变色）              │
└─────────────────────────────────────────────────────────┘
```

---

## 四、页面布局

```
┌──────────────────────────────────────────────────────────┐
│  LeakDetect                                     ●运行中  │  ← 顶部栏
├──────────────────────────────────────────────────────────┤
│                                                          │
│  ┌──内存──────────────┐  ┌──线程──────────────┐         │
│  │ 当前: 128 MB       │  │ 当前: 42           │         │
│  │ ⚠ 疑似泄露         │  │ ✓ 正常             │         │
│  │                    │  │                    │         │
│  │ [折线图 - F2 实现] │  │ [折线图 - F2 实现] │         │
│  │                    │  │                    │         │
│  │ ── top 进程 ──     │  │ ── top 进程 ──     │         │
│  │ nginx(1234) 64MB   │  │ mysql(5678) 18     │         │
│  │ mysql(5678) 32MB   │  │ app(9012)   12     │         │
│  └────────────────────┘  └────────────────────┘         │
│                                                          │
│  ┌──句柄──────────────┐  ┌──CPU───────────────┐         │
│  │ 当前: 156          │  │ 当前: 18.5 %       │         │
│  │ ⚠ 疑似泄露         │  │ ✓ 正常             │         │
│  │                    │  │                    │         │
│  │ [折线图 - F2 实现] │  │ [折线图 - F2 实现] │         │
│  │                    │  │                    │         │
│  │ ── top 进程 ──     │  │ ── top 进程 ──     │         │
│  │ app(9012)   78 FD  │  │ nginx(1234) 23%    │         │
│  └────────────────────┘  └────────────────────┘         │
│                                                          │
├──────────────────────────────────────────────────────────┤
│  ┌─告警列表────────────┐  ┌─泄露栈展示（预留）─────┐    │
│  │ ⚠ 内存泄露          │  │ 点击告警查看栈         │    │
│  │   PID:1234 nginx    │  │ → F3 实现              │    │
│  │   outstanding +2MB  │  │                        │    │
│  │   14:32:01          │  │                        │    │
│  │                     │  │                        │    │
│  │ ⚠ 句柄泄露          │  │                        │    │
│  │   PID:9012 app      │  │                        │    │
│  │   +12 FD            │  │                        │    │
│  │   14:33:01          │  │                        │    │
│  └─────────────────────┘  └────────────────────────┘    │
└──────────────────────────────────────────────────────────┘
```

---

## 五、Mock 数据策略

### 5.1 资源趋势

| 资源 | 基准值 | 趋势公式 | 噪声 | 泄露信号 |
|---|---|---|---|---|
| 内存 | 64 MB | `base + elapsed * 2MB / 60` | ±0.5 MB | 单调上升 |
| 线程 | 20 | `base + 5 * sin(elapsed/30)` | ±1 | 波动（正常） |
| 句柄 | 80 | `base + elapsed * 0.5 / 60` | ±2 | 单调上升 |
| CPU | 15% | `base + 8 * sin(elapsed/10)` | ±2 | 波动（正常） |

### 5.2 告警触发时机

| 经过时间 | 生成告警 | 内容 |
|---|---|---|
| 30 秒 | 内存泄露 | PID 1234 nginx，outstanding +NMB in Ns |
| 60 秒 | 句柄泄露 | PID 9012 app，+N FD in Ns |

### 5.3 伪造栈帧

**内存泄露栈（4 层）**：
| 帧序 | 函数 | 地址 |
|---|---|---|
| 1 | main() | 0x401000 |
| 2 | start_worker() | 0x4012a0 |
| 3 | handle_request() | 0x401580 |
| 4 | malloc() ← 嫌疑点 | 0x401800 |

**句柄泄露栈（3 层）**：
| 帧序 | 函数 | 地址 |
|---|---|---|
| 1 | main() | 0x402000 |
| 2 | process_loop() | 0x4022a0 |
| 3 | open() ← 嫌疑点 | 0x402580 |

### 5.4 容器列表（固定）

| container_id | name | pid_count |
|---|---|---|
| a3f4b2c1... | nginx-server | 5 |
| b4e5c3d2... | mysql-db | 3 |
| c5f6d4e3... | app-worker | 4 |
| d6a7e5f4... | redis-cache | 2 |

---

## 六、技术选型记录

| 决策点 | 选择 | 备选 | 理由 |
|---|---|---|---|
| 前端框架 | Vue 3 CDN（global 构建） | React, 原生 JS | 响应式绑定 + 无构建链 + 契合免安装 |
| WebSocket 库 | Socket.IO | 原生 WebSocket | Flask-SocketIO 配套，自动重连 |
| 图表库 | Chart.js | ECharts | 轻量(208KB)，F2 才用 |
| CSS 方案 | 原生 CSS | Tailwind, Bootstrap | 不引入额外依赖 |
| 布局 | CSS Grid 2×2 | Flexbox | 资源卡片网格更简洁 |
| 主题 | 暗色 | 亮色 | 监控类工具常见，不刺眼 |
| async mode | eventlet | threading | threading 不支持 WebSocket 协议升级 |
| 组件定义方式 | JS 对象 + template 字符串 | .vue SFC | 避免 webpack 构建链 |
| Vendor 存放 | 本地文件 | CDN 引用 | 离线可用，契合免安装 |

---

## 七、已知限制（F1 范围外）

| 限制 | 何时补 | 对应里程碑 |
|---|---|---|
| 折线图为占位文字 | F2 | line-chart.js 组件 |
| 告警无弹窗，仅列表 | F3 | alert-popup.js 组件 |
| 栈展示区为占位文字 | F3 | stack-view.js 组件 |
| 无告警历史查询 | F3 | /api/alerts 接 SQLite |
| 无容器下拉框 | F4 | container-select.js 组件 |
| 无 PID 输入 | F4 | pid-input.js 组件 |
| 无过滤清除按钮 | F4 | filter-bar 补充 |
| 无黑白名单配置 | F3 | filter-config.js 组件 |
| 数据为 mock | B1+ | 替换 mock.py 为真实分析层 |
| 历史查询为 mock | F2/B1 | /api/history 接 SQLite |
| REST 接口为 stub | F2-F4/B3 | 逐步接真实数据 |

---

## 八、验证记录

| 验证项 | 结果 | 备注 |
|---|---|---|
| `pip3 install -r requirements.txt` | ✅ | Ubuntu 24.04，需 --break-system-packages |
| `python3 app.py` 启动 | ✅ | 监听 127.0.0.1:8080 |
| 浏览器页面加载 | ✅ | HTTP 200 |
| 静态资源加载 | ✅ | CSS/JS/vendor 全 200 |
| WebSocket 连接 | ✅ | 装eventlet 后正常（threading 模式报 500） |
| 4 资源数值每秒刷新 | ✅ | Vue 响应式自动更新 |
| 内存数值缓慢增长 | ✅ | mock 模拟泄露趋势 |
| 30s 后内存告警出现 | ✅ | 告警列表显示 |
| 60s 后句柄告警出现 | ✅ | 告警列表追加 |
| 告警卡片边框变红 | ✅ | leak_suspected class 生效 |
| 暗色主题渲染 | ✅ | 配色正确 |

---

## 九、后续里程碑衔接

F1 产出的契约和骨架，后续里程碑只需**填充组件**，不改架构：

| 里程碑 | 在 F1 基础上做什么 | 改动范围 |
|---|---|---|
| F2 | 替换"折线图占位"为真实 Chart.js 渲染 + 时间范围切换 | 新增 line-chart.js，改 resource-card.js |
| F3 | 替换"栈展示占位"为真实 stack-view 组件 + 黑白名单弹窗 | 新增 stack-view.js + filter-config.js |
| F4 | 顶部栏加 container-select + pid-input | 新增两个组件，改 index.html |
| B1 | 替换 mock.py 为真实 BPF + 分析层 | 替换 mock.py，其余不动 |
| B3 | REST stub 替换为真实实现 | 改 api.py，接 SQLite + BPF map |

**关键保证**：契约（§5）不变，前端切换数据源时零改动。
