# F2 里程碑设计文档 — 四资源折线图

> 文档版本：v1.0  
> 日期：2026-07-08  
> 状态：⬜ 待实施  
> 关联文档：`D:\leakdetect-frontend-design.md` §11.3、`D:\leakdetect-f1-design.md`

---

## 一、F2 目标

将 F1 的"折线图占位"替换为 **真实 Chart.js 折线图**，实现：

1. 4 个资源各一张折线图，按时间展示使用趋势
2. 每张图可独立切换时间范围（1天/7天/30天）
3. 切换时间范围 → REST 拉取历史数据 → 重绘图表
4. WebSocket 实时推送新点 → 图表右移追加
5. top-N 进程表格式化完善

**不含**：告警弹窗/栈展示（F3）、容器下拉/PID输入（F4）、真实 BPF 数据（B1+）。

---

## 二、前置依赖

| 依赖 | 状态 | 说明 |
|---|---|---|
| F1 骨架 + mock | ✅ 已完成 | Flask + Vue + WebSocket 链路已通 |
| Chart.js vendor | ✅ 已就位 | F1 已下载 chart.umd.min.js（208KB） |
| mock.get_history() | ⚠️ 需修改 | F1 已有，但点数上限 200，需提升到 1440 |

---

## 三、新增 vendor 文件

Chart.js 4.x 的 time 轴需要额外的日期适配器。下载 **date-fns 适配器**（自包含 UMD，无需额外依赖）：

| 文件 | 下载地址 | 大小 | 用途 |
|---|---|---|---|
| `chartjs-adapter-date-fns.bundle.min.js` | `https://cdn.jsdelivr.net/npm/chartjs-adapter-date-fns/dist/chartjs-adapter-date-fns.bundle.min.js` | ~40 KB | Chart.js time 轴日期解析 |

下载到 `web/static/vendor/`，在 index.html 中 Chart.js 之后引入。

> 选 date-fns bundle 而非 dayjs/luxon：自包含（单文件无依赖），体积适中（40KB），UMD 自动注册。

---

## 四、组件设计

### 4.1 组件树变更

```
F1 结构:                          F2 结构:
App                               App
├── FilterBar (inline)            ├── FilterBar (inline)
├── ResourceGrid (inline)         ├── ResourceGrid (inline)
│   └── chart-placeholder文字     │   └── LineChart ← 新增组件
└── AlertPanel (inline)           └── AlertPanel (inline)
```

F2 **不提取 ResourceCard 组件**（减少 F1 改动），仅新增 `LineChart` 组件，在 index.html 模板内替换占位文字。

### 4.2 LineChart 组件

**文件**：`web/static/js/components/line-chart.js`

**职责**：封装 Chart.js 实例，接收时序数据，渲染折线图，包含时间范围切换按钮。

**Props**：

| Prop | 类型 | 说明 |
|---|---|---|
| `series` | Array `[{t, v}, ...]` | 时序数据点（t=Unix秒，v=原始值） |
| `resource` | String | `'mem'` / `'thread'` / `'fd'` / `'cpu'` |
| `range` | String | `'1d'` / `'7d'` / `'30d'` |

**Emits**：

| 事件 | 参数 | 说明 |
|---|---|---|
| `range-change` | String（新 range） | 用户点击时间范围按钮 |

**模板**：
```html
<div class="chart-container">
  <canvas ref="canvasEl"></canvas>
  <div class="time-range">
    <button v-for="r in ranges" :key="r"
            @click="$emit('range-change', r)"
            :class="{active: range === r}">{{ rangeLabel(r) }}</button>
  </div>
</div>
```

**内部数据**：
```javascript
data() {
  return {
    ranges: ['1d', '7d', '30d'],
    chart: null,  // Chart.js 实例
  }
}
```

**生命周期**：

| 钩子 | 操作 |
|---|---|
| `mounted()` | 调用 `initChart()` 创建 Chart.js 实例 |
| `watch.series` | 数据变化 → `updateChart()` 替换数据 + `chart.update('none')` |
| `watch.range` | 范围变化 → `adjustTimeUnit()` 调整 X 轴粒度 |
| `beforeUnmount()` | `chart.destroy()` 释放资源 |

**核心方法**：

```javascript
methods: {
  initChart() {
    const ctx = this.$refs.canvasEl.getContext('2d');
    this.chart = new Chart(ctx, {
      type: 'line',
      data: { datasets: [{ 
        data: this.transformData(this.series),
        borderColor: this.color(),
        backgroundColor: this.color() + '20',  // 透明填充
        fill: true,
        pointRadius: 0,
        tension: 0.1,
      }]},
      options: {
        responsive: true,
        maintainAspectRatio: false,
        animation: { duration: 0 },
        scales: {
          x: { 
            type: 'time', 
            time: { unit: this.timeUnit() },
            ticks: { maxTicksLimit: 8 }
          },
          y: { 
            beginAtZero: true,
            ticks: { callback: (v) => this.formatY(v) }
          }
        },
        plugins: { legend: { display: false } }
      }
    });
  },

  transformData(series) {
    // {t, v} → {x: Date, y: 转换后的值}
    return series.map(p => ({
      x: p.t * 1000,  // Unix秒 → 毫秒
      y: this.transformValue(p.v)
    }));
  },

  transformValue(v) {
    if (this.resource === 'mem') return v / 1024 / 1024;  // bytes → MB
    return v;  // thread/fd/cpu 直接
  },

  formatY(v) {
    if (this.resource === 'mem') return v.toFixed(0) + ' MB';
    if (this.resource === 'cpu') return v.toFixed(0) + '%';
    return v;
  },

  color() {
    return { mem: '#4fc3f7', thread: '#81c784', fd: '#ffb74d', cpu: '#ce93d8' }[this.resource];
  },

  timeUnit() {
    return { '1d': 'hour', '7d': 'day', '30d': 'day' }[this.range];
  },

  rangeLabel(r) {
    return { '1d': '1天', '7d': '7天', '30d': '30天' }[r];
  },

  updateChart() {
    if (!this.chart) return;
    this.chart.data.datasets[0].data = this.transformData(this.series);
    this.chart.update('none');
  },

  adjustTimeUnit() {
    if (!this.chart) return;
    this.chart.options.scales.x.time.unit = this.timeUnit();
    this.chart.update('none');
  }
}
```

### 4.3 在 app.js 中注册组件

```javascript
// app.js 顶部引入（实际通过 script 标签加载，全局可用）
const app = createApp({ setup() { ... } });
app.component('LineChart', LineChart);
app.mount('#app');
```

### 4.4 index.html 模板变更

**替换前（F1）**：
```html
<div class="chart-placeholder">[折线图 - F2 实现]</div>
```

**替换后（F2）**：
```html
<line-chart 
  :series="chartData[r].series" 
  :resource="r" 
  :range="chartData[r].range"
  @range-change="switchRange(r, $event)">
</line-chart>
```

---

## 五、数据管理

### 5.1 新增响应式状态（app.js）

```javascript
const chartData = reactive({
  mem:    { range: '1d', series: [], loading: false },
  thread: { range: '1d', series: [], loading: false },
  fd:     { range: '1d', series: [], loading: false },
  cpu:    { range: '1d', series: [], loading: false },
});
```

### 5.2 初始加载流程

```
页面挂载 (onMounted)
  │
  ├── 对 4 个资源并行调用 loadHistory(resource, '1d')
  │
  ▼
loadHistory(resource, range)
  │
  ├── chartData[resource].loading = true
  ├── 调 LeakDetectAPI.getHistory(resource, range)
  │     → GET /api/history?resource=mem&range=1d
  ├── chartData[resource].series = resp.series
  └── chartData[resource].loading = false
```

```javascript
async function loadHistory(resource, range) {
  chartData[resource].loading = true;
  try {
    const resp = await LeakDetectAPI.getHistory(resource, range);
    chartData[resource].series = resp.series;
  } catch (e) {
    console.error(`[history] load ${resource} failed:`, e);
  }
  chartData[resource].loading = false;
}
```

### 5.3 时间范围切换流程

```
用户点击"7天"按钮
  │
  ├── LineChart emit('range-change', '7d')
  ├── app.js switchRange(resource, '7d')
  │     ├── chartData[resource].range = '7d'
  │     └── loadHistory(resource, '7d')
  │           → REST 拉新数据 → 替换 series
  ▼
LineChart watch.series 触发 → updateChart() → 图表重绘
LineChart watch.range 触发 → adjustTimeUnit() → X 轴粒度变 day
```

```javascript
async function switchRange(resource, range) {
  chartData[resource].range = range;
  await loadHistory(resource, range);
}
```

### 5.4 实时追加流程

```
WebSocket 推送 dashboard_update（每 1s）
  │
  ├── handleDashboardUpdate(data)
  │     ├── F1 逻辑：更新 resources.current/perProcess/alerts（保留）
  │     └── 新增：对每个资源追加图表点
  │
  ▼
appendPoint(resource, point)
  ├── 将 {t, v} 追加到 chartData[resource].series 末尾
  ├── 移除超出时间范围的旧点
  └── Vue 响应式 → LineChart watch.series → updateChart()
```

```javascript
function appendPoint(resource, point) {
  const cd = chartData[resource];
  cd.series.push(point);
  // 移除超出时间范围的旧点
  const maxAge = { '1d': 86400, '7d': 604800, '30d': 2592000 }[cd.range];
  const cutoff = (Date.now() / 1000) - maxAge;
  cd.series = cd.series.filter(p => p.t >= cutoff);
}
```

**在 handleDashboardUpdate 中调用**：
```javascript
function handleDashboardUpdate(data) {
  // ... F1 既有逻辑 ...

  // F2 新增：追加图表点
  if (data.latest_points) {
    for (const r of resourceOrder) {
      appendPoint(r, data.latest_points[r]);
    }
  }
}
```

### 5.5 数据流全图

```
                      ┌─────────────────────────┐
                      │  初始加载 / 范围切换      │
                      │  loadHistory(r, range)   │
                      └────────────┬────────────┘
                                   │ REST GET /api/history
                                   ▼
                           chartData[r].series = [...]
                                   │
                                   ▼
                      ┌──── LineChart watch.series ────┐
                      │         updateChart()           │
                      └────────────────────────────────┘

                      ┌─────────────────────────┐
                      │  WebSocket 实时推送       │
                      │  handleDashboardUpdate   │
                      └────────────┬────────────┘
                                   │ appendPoint(r, point)
                                   ▼
                      chartData[r].series.push(point)
                                   │
                                   ▼
                      ┌──── LineChart watch.series ────┐
                      │         updateChart()           │
                      └────────────────────────────────┘
```

---

## 六、Chart.js 配置规格

### 6.1 通用配置

| 配置项 | 值 | 理由 |
|---|---|---|
| `type` | `'line'` | 折线图 |
| `animation.duration` | `0` | 实时更新无动画 |
| `pointRadius` | `0` | 点太多不显示圆点 |
| `tension` | `0.1` | 轻微平滑曲线 |
| `fill` | `true` | 区域填充 |
| `responsive` | `true` | 响应式 |
| `maintainAspectRatio` | `false` | 不锁宽高比，撑满容器 |
| `legend.display` | `false` | 不显示图例 |

### 6.2 各资源差异化配置

| 资源 | Y 轴值转换 | Y 轴标签格式 | 线条颜色 | 填充色 |
|---|---|---|---|---|
| mem | `v / 1024 / 1024`（bytes→MB） | `N MB` | `#4fc3f7` 蓝 | `#4fc3f720` |
| thread | 直接 | `N` | `#81c784` 绿 | `#81c78420` |
| fd | 直接 | `N` | `#ffb74d` 橙 | `#ffb74d20` |
| cpu | 直接 | `N%` | `#ce93d8` 紫 | `#ce93d820` |

### 6.3 X 轴 time 配置

| 时间范围 | `time.unit` | `maxTicksLimit` | 刻度格式 |
|---|---|---|---|
| 1天 | `'hour'` | 8 | `HH:00` |
| 7天 | `'day'` | 7 | `MM/DD` |
| 30天 | `'day'` | 10 | `MM/DD` |

### 6.4 CSS 样式补充（style.css）

```css
.chart-container {
  height: 120px;
  margin-bottom: 8px;
  position: relative;
}

.chart-container canvas {
  width: 100% !important;
  height: 100% !important;
}

.time-range {
  display: flex;
  gap: 4px;
  margin-bottom: 8px;
}

.time-range button {
  padding: 2px 10px;
  border: 1px solid #0f3460;
  background: transparent;
  color: #888;
  border-radius: 3px;
  cursor: pointer;
  font-size: 11px;
}

.time-range button.active {
  background: #0f3460;
  color: #4fc3f7;
  border-color: #4fc3f7;
}
```

---

## 七、mock.py 修改

### 7.1 提升历史数据点数

F1 的 `get_history()` 限制 `count = min(..., 200)`，F2 需更多点：

```python
# 修改前（F1）
count = min(duration // interval, 200)

# 修改后（F2）
count = min(duration // interval, 1440)
```

### 7.2 确保趋势正确

mock 历史数据应与实时趋势一致：
- 内存：从基准值缓慢增长到当前值（泄露趋势）
- 句柄：从基准值缓慢增长到当前值（泄露趋势）
- 线程/CPU：波动（正常）

当前 F1 的 `get_history()` 已有此逻辑，仅需提升点数。

---

## 八、修改文件清单

| 文件 | 操作 | 变更内容 |
|---|---|---|
| `web/static/vendor/chartjs-adapter-date-fns.bundle.min.js` | **新增** | 下载 date-fns 适配器（~40KB） |
| `web/static/js/components/line-chart.js` | **新增** | LineChart 组件（~100 行） |
| `web/static/index.html` | **修改** | 引入适配器 + line-chart.js；占位文字替换为 `<line-chart>` |
| `web/static/js/app.js` | **修改** | 新增 chartData 状态 + loadHistory + switchRange + appendPoint；注册 LineChart 组件 |
| `web/static/css/style.css` | **修改** | 新增 .chart-container + .time-range 样式 |
| `web/mock.py` | **修改** | get_history 点数上限 200→1440 |

**不变的文件**（F1 代码不动）：
- `web/app.py`、`web/sockets.py`、`web/api.py`
- `web/static/js/api.js`（已有 getHistory，无需改）
- `web/static/vendor/vue.global.prod.js`、`chart.umd.min.js`、`socket.io.min.js`

---

## 九、index.html 引入顺序

```html
<!-- Vendor（顺序重要） -->
<script src="/static/vendor/socket.io.min.js"></script>
<script src="/static/vendor/vue.global.prod.js"></script>
<script src="/static/vendor/chart.umd.min.js"></script>
<script src="/static/vendor/chartjs-adapter-date-fns.bundle.min.js"></script>  <!-- 新增 -->
<!-- 组件 -->
<script src="/static/js/components/line-chart.js"></script>  <!-- 新增 -->
<!-- 应用 -->
<script src="/static/js/api.js"></script>
<script src="/static/js/app.js"></script>
```

> date-fns 适配器必须在 Chart.js 之后加载，否则无法注册 time 轴。

---

## 十、验证标准

| # | 验证项 | 方法 | 预期 |
|---|---|---|---|
| 1 | 折线图渲染 | 打开页面 | 4 张折线图显示，非占位文字 |
| 2 | 初始数据加载 | 等 2 秒 | 图表有历史数据点（1天范围，数百点） |
| 3 | 内存图趋势 | 观察内存折线 | 呈缓慢上升趋势（模拟泄露） |
| 4 | 实时追加 | 等 10 秒 | 图表最右端有新点追加，左移 |
| 5 | 时间范围切换 | 点"7天" | 图表重绘，X 轴变 day 刻度，数据点变少 |
| 6 | 多范围切换 | 1天→7天→30天→1天 | 每次切换图表正确重绘 |
| 7 | 各图独立 | 内存选7天，CPU选1天 | 两图范围独立，互不影响 |
| 8 | Y 轴格式 | 看内存图 Y 轴 | 显示 "N MB" 而非原始 bytes |
| 9 | 颜色区分 | 看 4 张图 | 蓝/绿/橙/紫 四色 |
| 10 | 告警仍正常 | 等 30s | 告警列表仍出现（F1 功能不受影响） |

---

## 十一、已知限制（F2 范围外）

| 限制 | 何时补 | 里程碑 |
|---|---|---|
| 实时追加是每秒1点（非按采样间隔降采样） | B1+ | 真实后端按 1min 采样 |
| 历史数据是 mock 生成 | B1 | 接 SQLite 真实采样 |
| 无告警弹窗 | F3 | alert-popup 组件 |
| 无栈展示 | F3 | stack-view 组件 |
| 无容器/PID 过滤 | F4 | filter 组件 |
| 图表无缩放/导出 | 可选增强 | 后续 |

---

## 十二、实施步骤

| 步骤 | 操作 | 耗时 |
|---|---|---|
| 1 | 下载 date-fns 适配器到 vendor/ | 1 分钟 |
| 2 | 创建 line-chart.js 组件 | 30 分钟 |
| 3 | 修改 mock.py（点数上限） | 2 分钟 |
| 4 | 修改 app.js（chartData + loadHistory + switchRange + appendPoint + 注册组件） | 30 分钟 |
| 5 | 修改 index.html（引入 + 替换占位） | 10 分钟 |
| 6 | 修改 style.css（chart 容器 + 按钮样式） | 10 分钟 |
| 7 | 启动验证 + 调试 | 30-60 分钟 |

**预计总耗时：2-3 小时**
