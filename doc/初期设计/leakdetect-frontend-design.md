# 内存泄露检测工具 — 前端界面设计文档

> 文档版本：v1.0  
> 日期：2026-07-07  
> 状态：设计已收敛，待实施  
> 关联文档：`D:\leakdetect-plan.md`（总体方案 v1.4）

---

## 一、概述

### 1.1 文档范围

本文档定义前端界面的**功能列表、页面结构、组件设计、数据契约、与后端对接方式**，作为 F0-F4 里程碑的实施依据。

### 1.2 技术栈

| 项 | 选型 | 说明 |
|---|---|---|
| 框架 | Vue 3（CDN/global 构建，本地 vendor） | 响应式数据绑定，无构建链 |
| 图表 | Chart.js（UMD，本地 vendor） | 折线图、时间轴 |
| 后端 | Flask + Flask-SocketIO | WebSocket 实时推送 + REST 历史查询 |
| 样式 | 原生 CSS（暗色主题） | 不引入 UI 框架，保持轻量 |
| 构建 | **无构建链** | 浏览器直接加载 .js/.html，无需 node/webpack |

### 1.3 设计原则

- **契约驱动**：前端只依赖"展示契约"（DashboardUpdate），不感知后端实现（BCC/Go/...）
- **响应式优先**：数据变 → UI 自动变，不手动操作 DOM
- **解耦**：前端可用 mock 独立开发，后端就绪后替换 mock 即可
- **暗色主题**：监控类工具长时间观看不刺眼

---

## 二、功能列表

### 2.1 核心功能

| # | 功能 | 说明 | 所在里程碑 |
|---|---|---|---|
| 1 | 四资源实时看板 | 内存/线程/句柄/CPU 的当前值 + 状态标签 | F2 |
| 2 | 时间序列折线图 | 每资源一张折线图，支持 1天/7天/30天 切换 | F2 |
| 3 | top-N 进程表 | 每资源卡片底部展示 top 进程 | F2 |
| 4 | 容器下拉选择 | 切换监控的容器范围（默认"全部"） | F4 |
| 5 | PID 手动输入 | 输入 PID 聚焦特定进程（优先级高于容器） | F4 |
| 6 | 过滤清除 | 一键重置容器+PID 过滤 | F4 |
| 7 | 告警列表 | 实时展示当前泄露告警 | F3 |
| 8 | 泄露栈展示 | 点击告警 → 缩进树形展示调用栈（预留区域） | F3 |
| 9 | 告警历史 | 查询历史告警记录 | F3 |
| 10 | 黑白名单配置 | 弹窗配置抓取层过滤规则，含预览 | F3/F4 |

### 2.2 辅助功能

| # | 功能 | 说明 |
|---|---|---|
| 11 | 运行状态指示 | 顶部显示后端连接状态（●运行中/●断开） |
| 12 | 时间范围切换 | 每资源卡片独立切换 1天/7天/30天 |
| 13 | 实时数据追加 | WebSocket 推新点，图表右移 |

---

## 三、页面布局

### 3.1 整体布局（单页 + 面板切换）

```
┌──────────────────────────────────────────────────────────────────┐
│  LeakDetect   容器:[全部 ▼]  PID:[______] [应用] [清除]   ●运行中 │  ← 顶部过滤栏
│                                            [监控配置]            │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──内存──────────────────────┐  ┌──线程──────────────────────┐ │
│  │ 当前: 128 MB   ⚠ 疑似泄露  │  │ 当前: 42       ✓ 正常      │ │
│  │     [折线图]                │  │     [折线图]                │ │
│  │ 时间范围:[1天▼][7天][30天]  │  │ 时间范围:[1天▼]             │ │
│  │ ──top 进程──                │  │ ──top 进程──                │ │
│  │ nginx(1234)  64MB  +2MB/60s │  │ mysql(5678)  18 threads     │ │
│  └──────────────────────────────┘  └──────────────────────────────┘ │
│                                                                  │
│  ┌──句柄──────────────────────┐  ┌──CPU───────────────────────┐ │
│  │ 当前: 156       ⚠ 疑似泄露 │  │ top: nginx 23% mysql 18%    │ │
│  │     [折线图]                │  │     [折线图]                │ │
│  │ 时间范围:[1天▼]             │  │ 时间范围:[1天▼]             │ │
│  │ ──top 进程──                │  │ ──top 进程──                │ │
│  │ app(9012)    78 FD  +12/60s │  │ nginx(1234)  23%            │ │
│  └──────────────────────────────┘  └──────────────────────────────┘ │
├──────────────────────────────────────────────────────────────────┤
│  ┌─告警列表────────────────────┐  ┌─泄露栈展示（预留区域）──────┐ │
│  │ ⚠ 内存泄露  PID:1234 nginx  │  │  点击左侧告警 → 此处展示栈   │ │
│  │   outstanding +2.3MB/60s    │  │                              │ │
│  │   [查看栈]                   │  │  main()                      │ │
│  │ ⚠ 句柄泄露  PID:9012 app    │  │    └─ start_worker()         │ │
│  │   +12 FD/60s                │  │         └─ handle_request()  │ │
│  │   [查看栈]                   │  │              └─ malloc() ←   │ │
│  └─────────────────────────────┘  └──────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────┘
```

### 3.2 区域划分

| 区域 | 内容 | 组件 |
|---|---|---|
| 顶部过滤栏 | 容器下拉、PID 输入、清除、监控配置、状态指示 | `FilterBar` |
| 资源网格（2×2） | 四资源卡片，每卡含图表+top表 | `ResourceGrid` → `ResourceCard` ×4 |
| 告警区（底部） | 左：告警列表；右：栈展示（预留） | `AlertPanel` → `AlertList` + `StackView` |

---

## 四、组件结构（Vue 3）

### 4.1 组件树

```
App
├── FilterBar                         # 顶部过滤栏
│   ├── ContainerSelect               # 容器下拉框
│   ├── PidInput                      # PID 手动输入 + 应用按钮
│   ├── ClearButton                   # 清除过滤
│   ├── FilterConfigButton            # 打开监控配置弹窗
│   └── StatusIndicator               # 后端连接状态
│
├── ResourceGrid                      # 2×2 资源卡片网格
│   ├── ResourceCard (mem)            # 内存卡片
│   ├── ResourceCard (thread)         # 线程卡片
│   ├── ResourceCard (fd)             # 句柄卡片
│   └── ResourceCard (cpu)            # CPU 卡片
│       每个 ResourceCard 内含:
│       ├── CardHeader                # 当前值 + 状态标签(正常/疑似泄露)
│       ├── LineChart                 # Chart.js 折线图
│       ├── TimeRangeSelector         # 1天/7天/30天 切换
│       └── ProcessTable              # top-N 进程小表
│
├── AlertPanel                        # 底部告警区
│   ├── AlertList                     # 告警列表（左）
│   │   └── AlertItem                 # 单条告警
│   └── StackView                    # 泄露栈展示（右，预留）
│       └── StackFrame               # 单个栈帧
│
└── FilterConfigModal                 # 监控配置弹窗（模态）
    ├── ModeSelector                  # 全部/白名单/黑名单
    ├── NameRegexInput                # 进程名正则
    ├── PidListInput                  # PID 列表
    ├── PreviewList                   # 预览匹配进程
    └── SaveButton                    # 保存并应用
```

### 4.2 组件定义方式

Vue 3 CDN 模式下，组件用 JS 对象定义（非 .vue SFC），模板写在 `template` 字段：

```javascript
// 示例：ResourceCard 组件
const ResourceCard = {
  props: ['resource', 'data'],
  template: `
    <div class="resource-card" :class="{ 'leak-suspected': data.status === 'leak_suspected' }">
      <div class="card-header">
        <span class="current-value">{{ formatValue(data.current_value) }}</span>
        <span class="status-badge" :class="data.status">{{ statusText(data.status) }}</span>
      </div>
      <canvas ref="chartCanvas"></canvas>
      <div class="time-range">
        <button v-for="r in ranges" :key="r" @click="$emit('switch-range', r)"
                :class="{active: currentRange === r}">{{ r }}</button>
      </div>
      <table class="process-table">
        <tr v-for="p in data.per_process" :key="p.pid">
          <td>{{ p.name }}({{ p.pid }})</td>
          <td>{{ formatValue(p.value) }}</td>
          <td v-if="p.delta_60s">{{ formatDelta(p.delta_60s) }}</td>
        </tr>
      </table>
    </div>
  `,
  // ...
}
```

---

## 五、数据契约（与后端对接方式）

### 5.1 对接总览

```
┌─ 前端 ─────────────────────────────────────────────┐
│  Vue 应用                                           │
│    ├─ WebSocket 客户端 ─── 收 dashboard_update      │
│    ├─ REST 客户端 ──────── 调 /api/*                │
│    └─ Chart.js ─────────── 渲染折线图              │
└──────────────────────┬─────────────────────────────┘
                       │
        ┌──────────────┴──────────────┐
        │  契约（稳定接口）           │
        └──────────────┬──────────────┘
                       │
┌─ 后端 ───────────────┴─────────────────────────────┐
│  Flask + SocketIO                                  │
│    ├─ WebSocket 推送 ─── 每1s推 dashboard_update    │
│    ├─ REST 路由 ────────── /api/history 等         │
│    └─ (MVP: mock 生产者 / 迁移后: 真实分析层)      │
└────────────────────────────────────────────────────┘
```

前端**只依赖契约**，不感知后端是 mock 还是真实数据。后端就绪后替换 mock，前端零改动。

### 5.2 契约 1：WebSocket 推送（实时）

**连接**：`ws://<host>:8080/ws`

**服务端 → 客户端**：每 1s 推送 `dashboard_update`

```json
{
  "type": "dashboard_update",
  "timestamp": 1751827200,
  "filter": {"container_id": null, "pid": null},
  "latest_points": {
    "mem":    {"t": 1751827200, "v": 134217728},
    "thread": {"t": 1751827200, "v": 42},
    "fd":     {"t": 1751827200, "v": 156},
    "cpu":    {"t": 1751827200, "v": 18.5}
  },
  "per_process": {
    "mem":    [{"pid":1234,"name":"nginx","value":67108864,"delta_60s":2097152}],
    "thread": [{"pid":5678,"name":"mysql","value":18}],
    "fd":     [{"pid":9012,"name":"app","value":78}],
    "cpu":    [{"pid":1234,"name":"nginx","value":23.5}]
  },
  "alerts": [
    {
      "id": "a001",
      "resource": "mem",
      "pid": 1234,
      "process_name": "nginx",
      "severity": "leak",
      "detail": "outstanding +2.3MB in 60s",
      "timestamp": 1751827200,
      "stack": [
        {"func": "main", "addr": "0x401000"},
        {"func": "start_worker", "addr": "0x4012a0"},
        {"func": "handle_request", "addr": "0x401580"},
        {"func": "malloc", "addr": "0x401800"}
      ]
    }
  ],
  "containers": [
    {"id": "a3f4b2c1...", "name": "nginx-server", "pid_count": 5}
  ]
}
```

**客户端 → 服务端**：切换容器

```json
{"action": "select_container", "container_id": "a3f4b2c1..."}
```

### 5.3 契约 2：REST API（历史查询 + 配置）

| 接口 | 方法 | 用途 | 请求参数 | 返回 |
|---|---|---|---|---|
| `/api/history` | GET | 拉取历史时序数据 | `resource=mem&range=1d&container_id=...&pid=...` | `{range, interval, series:[{t,v}], per_process}` |
| `/api/alerts` | GET | 查询历史告警 | `range=24h` | `{alerts:[...]}` |
| `/api/containers` | GET | 容器列表 | 无 | `{containers:[{id,name,pid_count}]}` |
| `/api/config/filter` | GET | 读取黑白名单配置 | 无 | `{mode, name_regex, pid_list}` |
| `/api/config/filter` | POST | 保存并应用黑白名单 | `{mode, name_regex, pid_list}` | `{status, matched_pids}` |
| `/api/config/filter/preview` | GET | 预览匹配（不保存） | `name_regex=...&pid_list=...` | `{matched:[...], unmatched:[...]}` |

**`/api/history` 返回示例**
```json
{
  "range": "1d",
  "interval": "60s",
  "series": [
    {"t": 1751740800, "v": 12582912},
    {"t": 1751740860, "v": 12688000},
    "...",
    {"t": 1751827200, "v": 134217728}
  ],
  "per_process": [{"pid":1234,"name":"nginx","value":67108864}]
}
```

---

## 六、过滤逻辑

### 6.1 三层过滤架构

| 过滤维度 | 作用层 | 何时生效 | 持久性 | 配置位置 |
|---|---|---|---|---|
| 黑/白名单 | 抓取层（eBPF） | 事件采集前 | 持久化 | 监控配置弹窗 |
| 容器下拉 | 显示层 | 查看时 | 会话级 | 顶部过滤栏 |
| PID 输入 | 显示层 | 查看时 | 会话级 | 顶部过滤栏 |

### 6.2 容器下拉与 PID 的交互

| 容器下拉 | PID 输入 | 实际过滤范围 |
|---|---|---|
| 全部 | 空 | 所有进程（默认） |
| 容器A | 空 | 容器A 内所有进程 |
| 任意 | 1234 | 仅 PID 1234（**PID 优先**） |
| — | — | "清除"按钮重置为全部 |

**规则**：PID 非空时覆盖容器下拉（更具体的过滤生效）。

### 6.3 黑白名单配置弹窗

```
┌─ 监控配置 ──────────────────────────────────┐
│  过滤模式:  ( ) 全部监控（默认）            │
│             (•) 白名单（仅监控列出的）      │
│             ( ) 黑名单（监控除列出外的）    │
│  进程名正则: [nginx|mysql|redis          ] │
│  PID 列表:   [1234, 5678                  ] │
│  匹配逻辑: 进程名 OR PID 命中即视为匹配     │
│  ── 预览匹配进程 ──                         │
│  ✓ nginx (PID 1234)                         │
│  ✓ mysql (PID 5678)                         │
│  ✗ app (PID 9012)  不匹配                   │
│              [取消]    [保存并应用]         │
└─────────────────────────────────────────────┘
```

保存 → `POST /api/config/filter` → 后端更新 BPF map + 持久化。

---

## 七、折线图规格

### 7.1 各资源 Y 轴指标

| 资源 | Y 轴 | 单位 | 泄露信号 | 数据来源 |
|---|---|---|---|---|
| 内存 | outstanding allocated bytes（未释放分配量） | MB | 单调上升 | eBPF malloc/free 配对 |
| 线程 | thread count | 个 | 单调上升 | eBPF clone/exit |
| 句柄 | FD count（未关闭文件描述符数） | 个 | 单调上升 | eBPF open/close |
| CPU | CPU 占用率 | % | 仅监控 | /proc 轮询 |

> 内存选 outstanding 而非 RSS：本工具核心是泄露检测，outstanding 是直接的泄露信号；RSS 受碎片/mmap 干扰。

### 7.2 时间范围与采样

| 时间范围 | 采样间隔 | 数据点数 | 数据来源 | 切换方式 |
|---|---|---|---|---|
| 1天 | 1 分钟 | 1440 点 | SQLite + 实时追加 | 每卡片 `[1天][7天][30天]` 按钮 |
| 7天 | 10 分钟 | 1008 点 | SQLite（降采样） | 同上 |
| 30天 | 30 分钟 | 1440 点 | SQLite（降采样） | 同上 |

### 7.3 实时追加逻辑

- 图表 X 轴最右端始终是"当前时刻"
- WebSocket 每个采样间隔推一个新点 → 追加到图表数据 → 移除超出时间范围的旧点 → 无动画更新
- 切换时间范围 → 调 REST `/api/history` 拉历史数据 → 重绘图表

### 7.4 Chart.js 配置要点

```javascript
new Chart(ctx, {
  type: 'line',
  data: { datasets: [{ data: [], borderColor: '#4fc3f7', fill: true, pointRadius: 0, tension: 0.1 }] },
  options: {
    responsive: true,
    maintainAspectRatio: false,
    scales: {
      x: { type: 'time', time: { unit: 'minute' } },  // 1天=minute, 7天/30天=hour
      y: { beginAtZero: true }
    },
    animation: { duration: 0 },  // 实时追加关闭动画
    plugins: { legend: { display: false } }
  }
});
```

---

## 八、告警面板设计

### 8.1 告警列表（左侧）

每条告警展示：
```
⚠ [资源图标] 资源类型  PID:1234  进程名:nginx
  简述: outstanding +2.3MB/60s
  时间: 14:32:01
  [查看栈] 按钮
```

- 按严重度 + 时间排序（疑似泄露 > 观察 > 正常）
- 点击告警行或 [查看栈] → 右侧 StackView 加载该告警的栈
- 同一时刻只展示一个栈（点击新告警切换）

### 8.2 栈展示区（右侧，预留）

```
泄露栈 - PID 1234 (nginx)
─────────────────────────
main()                          0x401000
  └─ start_worker()             0x4012a0
       └─ handle_request()      0x401580
            └─ malloc()  ← 嫌疑点  0x401800
─────────────────────────
帧数: 4    首次出现: 14:30:00
```

- **缩进树形**展示（caller → callee）
- 高亮"嫌疑点"（最深的分配/创建帧）
- 显示帧地址 + 偏移（便于 debuginfo 对照）
- 若告警无栈（如 CPU），显示"该资源无栈信息"

---

## 九、文件结构

```
web/
├── app.py                         # Flask + SocketIO 主服务
├── sockets.py                     # WebSocket 推送 dashboard_update
├── api.py                         # REST 路由（history/alerts/containers/config）
├── mock.py                        # F1 阶段的 mock 数据生产者
├── static/
│   ├── vendor/
│   │   ├── vue.global.prod.js     # Vue 3 本地存（无需 CDN 联网）
│   │   └── chart.umd.min.js       # Chart.js 本地存
│   ├── css/
│   │   └── style.css              # 暗色主题
│   ├── js/
│   │   ├── app.js                 # Vue 主应用（createApp + setup + 路由）
│   │   ├── api.js                 # WebSocket + REST 封装
│   │   └── components/
│   │       ├── filter-bar.js      # 顶部过滤栏
│   │       ├── resource-card.js   # 资源卡片
│   │       ├── alert-popup.js     # 告警弹窗
│   │       ├── alert-list.js      # 告警列表
│   │       ├── stack-view.js      # 栈展示
│   │       ├── container-select.js # 容器下拉框
│   │       └── filter-config.js   # 监控配置弹窗
│   └── index.html                 # 单页入口
└── templates/
```

---

## 十、mock 数据策略（F1 阶段）

后端未就绪时，`mock.py` 模拟契约数据：

| mock 项 | 策略 |
|---|---|
| 4 资源时序点 | 内存/句柄每分钟缓慢增长（触发告警）；线程/CPU 波动（正常） |
| 告警事件 | 内存 outstanding 超 1MB/60s 阈值 → 生成告警（含伪造栈帧） |
| 容器列表 | 3-5 个假容器（nginx-server/mysql-db/app-worker/redis/...） |
| per_process | 每资源 3-5 个假进程 |
| 历史数据 | `/api/history` 返回生成的时序点（按 range 降采样） |

**mock 生成的内存趋势示意**：
```
   MB
   │            ╱  ← 单调上升（疑似泄露）
   │          ╱
   │        ╱
   │      ╱
   │    ╱
   │  ╱
   └───────────── 时间
```

---

## 十一、里程碑详细划分（F0-F4）

### 11.1 F0：契约定义（1-2 天）✅ 已完成

| 产出 | 说明 | 文档位置 |
|---|---|---|
| DashboardUpdate schema | WebSocket 推送格式 | §5.2 |
| REST API 规格 | 6 个接口定义 | §5.3 |
| 过滤逻辑定义 | 三层过滤架构 | §6 |
| 单位/颜色/状态定义 | 附录 | §13 |

### 11.2 F1：骨架 + mock（3-4 天）✅ 已完成

| 产出 | 文件 | 说明 |
|---|---|---|
| Flask + SocketIO 服务 | web/app.py, web/sockets.py | eventlet async mode，每 1s 推送 dashboard_update |
| mock 数据生产者 | web/mock.py | 4 资源时序 + 告警（含栈帧）+ 容器列表 |
| REST 路由 stub | web/api.py | history/alerts/containers/config 共 6 个接口 |
| Vue 3 主应用 | web/static/js/app.js | createApp + setup + 响应式数据 + WebSocket 接收 |
| 前端数据接入 | web/static/js/api.js | Socket.IO 客户端 + REST 封装 |
| 暗色主题样式 | web/static/css/style.css | CSS Grid 2×2 布局 + 状态色 + 告警样式 |
| 单页入口 | web/static/index.html | Vue 模板 + vendor 引入 |
| Vendor 库本地存 | web/static/vendor/ | vue.global.prod.js + chart.umd.min.js + socket.io.min.js |
| Python 依赖 | requirements.txt | flask + flask-socketio + pyyaml + eventlet |

**页面效果**：顶部状态栏 + 4 资源卡片（当前值+状态+进程表+折线图占位）+ 告警列表 + 栈展示占位

**验证标准**：浏览器打开 → 4 资源数值每秒刷新 → 30s 后内存告警出现 → 60s 后句柄告警出现 → 状态变红 ✅

**详细设计文档**：`D:\leakdetect-f1-design.md`

### 11.3 F2：四资源折线图（4-5 天）

| 产出 | 文件 | 说明 |
|---|---|---|
| Chart.js 折线图组件 | web/static/js/components/line-chart.js | 每个 ResourceCard 内嵌一个 Chart.js 实例 |
| 时间范围切换组件 | web/static/js/components/time-range-selector.js | 1天/7天/30天 按钮组，每卡片独立 |
| REST 历史对接 | web/static/js/api.js 补充 getHistory() | 切换时间范围 → 调 /api/history 拉数据 → 重绘 |
| 实时追加逻辑 | web/static/js/app.js 补充 | WebSocket 推新点 → 追加到图表 → 移除旧点 → 无动画更新 |
| ResourceCard 完善 | web/static/js/components/resource-card.js | 折线图嵌入 + top-N 排序 + delta 显示 |
| mock 历史数据 | web/mock.py 补充 get_history() | 按 range 生成降采样时序点 |

**验证标准**：4 张折线图正常渲染 → 切换 1天/7天/30天 图表重绘 → 实时新点追加右移 → 内存图呈单调上升趋势

### 11.4 F3：告警 + 历史 + 黑白名单（4-5 天）

| 产出 | 文件 | 说明 |
|---|---|---|
| 告警弹窗组件 | web/static/js/components/alert-popup.js | 点击告警 → 弹窗展示详情 |
| 栈展示组件 | web/static/js/components/stack-view.js | 缩进树形展示调用栈，高亮嫌疑帧（最深的分配/创建帧） |
| 告警历史查询 | web/api.py 补充 + web/static/js/app.js | REST /api/alerts 返回历史告警 + 列表展示 |
| 黑白名单配置弹窗 | web/static/js/components/filter-config.js | 模式选择（全部/白名单/黑名单）+ 进程名正则 + PID 列表 |
| 配置保存接口 | web/api.py 补充 POST /api/config/filter | 接收配置 + 返回 matched_pids |
| 配置预览接口 | web/api.py 补充 GET /api/config/filter/preview | 不保存，仅预览匹配结果 |
| 顶部栏按钮 | web/static/index.html 补充 | "监控配置"按钮 → 打开 filter-config 弹窗 |

**验证标准**：点击告警 → 栈树形展示（caller→callee 缩进）→ 嫌疑帧高亮 → 黑白名单弹窗可配置 → 预览显示匹配进程 → 保存生效

### 11.5 F4：容器选择 + PID 输入 + 打磨（3-4 天）

| 产出 | 文件 | 说明 |
|---|---|---|
| 容器下拉框组件 | web/static/js/components/container-select.js | 从 /api/containers 拉列表，默认"全部" |
| PID 输入组件 | web/static/js/components/pid-input.js | 手动输入 PID + 应用按钮 |
| 过滤清除按钮 | web/static/index.html 补充 | 一键重置容器 + PID |
| 过滤联动逻辑 | web/sockets.py + web/static/js/api.js | PID 优先覆盖容器；select_container 通过 WebSocket 发送 |
| 配置文件预指定 | web/api.py + core/config.py | 读 config/default.yaml 的 target_container_id |
| 样式优化 | web/static/css/style.css | 响应式布局 + 间距 + 过渡动画 + 滚动条 |

**验证标准**：容器下拉切换 → 数据范围变化 → PID 输入覆盖容器选择 → 清除按钮复位为全部 → 配置文件预指定容器启动即聚焦

### 11.6 总工期

| 里程碑 | 时长 | 状态 |
|---|---|---|
| F0 契约定义 | 1-2 天 | ✅ 已完成 |
| F1 骨架 + mock | 3-4 天 | ✅ 已完成 |
| F2 四资源折线图 | 4-5 天 | ⬜ 待实施 |
| F3 告警 + 历史 + 配置 | 4-5 天 | ⬜ 待实施 |
| F4 容器选择 + 打磨 | 3-4 天 | ⬜ 待实施 |
| **合计** | **约 3 周** | |

---

## 十二、与后端对接的演进路径

```
F0-F4 阶段（前端先行）:
  前端 ←── mock.py ──┐
                     │ 契约稳定
B0-B2 阶段（后端接上）:
  前端 ←── 真实分析层 ─┘  替换 mock，前端零改动
```

| 阶段 | 前端数据源 | 前端改动 |
|---|---|---|
| F1-F4 | `mock.py` | 无（开发期） |
| B1 完成 | 内存资源接真实数据 | 无（契约一致） |
| B2 完成 | 4 资源全真实数据 | 无 |
| B3 完成 | 容器/黑白名单生效 | 无 |

**关键保证**：只要 mock 与真实后端都遵守同一份契约（§5），前端切换数据源时零改动。

---

## 十三、附录

### 13.1 状态标签定义

| status 值 | 含义 | 颜色（暗色主题） |
|---|---|---|
| `normal` | 正常 | 绿色 `#4caf50` |
| `leak_suspected` | 疑似泄露 | 红色 `#f44336` |
| `observing` | 观察中 | 黄色 `#ff9800` |

### 13.2 资源图标

| 资源 | 图标 | 颜色 |
|---|---|---|
| 内存 | 💾 | `#4fc3f7`（蓝） |
| 线程 | 🧵 | `#81c784`（绿） |
| 句柄 | 📁 | `#ffb74d`（橙） |
| CPU | ⚡ | `#ce93d8`（紫） |

### 13.3 单位换算

| 资源 | 原始单位 | 显示单位 | 换算 |
|---|---|---|---|
| 内存 | bytes | MB | `v / 1024 / 1024` |
| 线程 | count | 个 | 直接显示 |
| 句柄 | count | 个 | 直接显示 |
| CPU | percent | % | 直接显示 |
