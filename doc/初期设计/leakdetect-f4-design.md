# F4 里程碑设计文档 — 容器选择 + PID 输入 + 打磨

> 文档版本：v1.0  
> 日期：2026-07-08  
> 状态：⬜ 待实施  
> 关联文档：`D:\leakdetect-frontend-design.md` §11.5、`D:\leakdetect-f3-design.md`

---

## 一、F4 目标

实现前端最后一个功能模块：**显示层过滤控件**，并完成整体样式打磨。

1. **容器下拉框** — 从 WebSocket 数据获取容器列表，选择后后端按容器过滤数据
2. **PID 输入** — 手动输入 PID，前端按 PID 过滤 per_process 和告警
3. **过滤清除** — 一键重置容器 + PID
4. **过滤联动** — PID 优先级高于容器（PID 非空时覆盖容器选择）
5. **样式打磨** — 响应式布局、间距优化、过渡动画

**F4 完成后，前端阶段（F0-F4）全部结束。**

---

## 二、前置依赖

| 依赖 | 状态 | 说明 |
|---|---|---|
| F1-F3 | ✅ 全部完成 | 骨架+折线图+告警+黑白名单 |
| WebSocket containers 数据 | ✅ | mock 已在 dashboard_update 里推送 containers 列表 |
| WebSocket select_container 事件 | ⚠️ 需实现 | sockets.py 已注册 handler，需接 mock |
| mock 容器→PID 映射 | ⚠️ 需新增 | mock 需知道每个容器包含哪些进程 |

---

## 三、过滤架构

### 三层过滤回顾

| 过滤维度 | 作用层 | 实现状态 | F4 变更 |
|---|---|---|---|
| 黑/白名单 | 抓取层（mock 模拟） | ✅ F3 已实现 | 无变更 |
| **容器下拉** | **后端过滤（mock 模拟）** | ⬜ F4 实现 | mock 按 container 过滤数据 |
| **PID 输入** | **前端过滤（computed）** | ⬜ F4 实现 | 前端 computed 过滤 |

### 过滤优先级

```
用户设置容器 + PID：
  1. 容器选择 → WebSocket 发 select_container → mock 过滤数据
  2. PID 输入 → 前端 computed 在收到的数据上再按 PID 过滤
  3. 结果：只显示「选中容器内 + 指定 PID」的进程

PID 优先：PID 非空时，即使容器选了"全部"，也只看该 PID
```

### 数据流

```
容器选择:
  用户选容器 → WebSocket emit select_container
    → mock.set_selected_container(cid)
    → get_dashboard_update() 只返回该容器的进程
    → 前端收到已过滤的数据 → 直接展示

PID 输入:
  用户输入 PID → 前端 activePidFilter = 1234
    → computed filteredPerProcess 自动过滤
    → per_process 表只显示 PID 1234
    → 不涉及后端
```

---

## 四、组件设计

### 设计决策：内联 vs 独立组件

容器下拉和 PID 输入是简单 HTML 元素（select + input），**内联到 index.html 模板**中，不创建独立组件文件。理由：
- 减少文件数量和 script 标签
- 与 F1 的 FilterBar 内联方式一致
- 这两个控件逻辑简单，不值得单独封装

### 4.1 顶部栏布局变更

**F3 结构**：
```html
<div class="header">
  <h1>LeakDetect</h1>
  <div class="status">...</div>
</div>
```

**F4 结构**：
```html
<div class="header">
  <h1>LeakDetect</h1>
  <div class="filter-controls">
    <select v-model="selectedContainer" @change="onContainerChange" class="filter-select">
      <option :value="null">全部容器</option>
      <option v-for="c in containers" :key="c.id" :value="c.id">{{ c.name }}</option>
    </select>
    <input v-model="pidInput" placeholder="输入PID" @keyup.enter="applyPidFilter" class="filter-input">
    <button @click="applyPidFilter" class="filter-btn">应用</button>
    <button @click="clearFilters" class="filter-btn">清除</button>
  </div>
  <div class="status">
    <span :class="{...}">{{ ... }}</span>
    <button @click="openFilterConfig" class="btn-config">监控配置</button>
  </div>
</div>
```

### 4.2 页面布局效果

```
┌──────────────────────────────────────────────────────────────────┐
│ LeakDetect  容器:[全部▼]  PID:[____] [应用] [清除]  ●运行中 [配置]│
├──────────────────────────────────────────────────────────────────┤
│  ┌──内存──┐ ┌──线程──┐                                          │
│  │ 折线图 │ │ 折线图 │  ← 不受 PID 过滤影响（聚合值）             │
│  │ top进程│ │ top进程│  ← 受 PID 过滤影响                        │
│  └────────┘ └────────┘                                          │
│  ┌──句柄──┐ ┌──CPU───┐                                          │
│  │ ...    │ │ ...    │                                          │
│  └────────┘ └────────┘                                          │
├──────────────────────────────────────────────────────────────────┤
│  ┌─告警列表──┐  ┌─栈展示──┐                                     │
│  │ ...       │  │ ...     │  ← 告警受 PID 过滤影响               │
│  └───────────┘  └─────────┘                                     │
└──────────────────────────────────────────────────────────────────┘
```

> 折线图（聚合值）不受 PID 过滤影响；per_process 表和告警列表受 PID 过滤影响。

---

## 五、数据管理（app.js 变更）

### 5.1 新增响应式状态

```javascript
// 容器选择
const selectedContainer = ref(null);  // null = 全部

// PID 输入
const pidInput = ref("");             // 输入框文本
const activePidFilter = ref(null);    // 已应用的 PID（null = 无过滤）

// 原始数据（未过滤）
const rawPerProcess = reactive({
    mem: [], thread: [], fd: [], cpu: []
});
const rawAlerts = ref([]);
```

### 5.2 新增 computed（前端过滤）

```javascript
const { createApp, reactive, ref, computed, onMounted } = Vue;

// PID 过滤后的 per_process
const filteredPerProcess = computed(() => {
    var pid = activePidFilter.value;
    if (!pid) return rawPerProcess;
    var result = {};
    for (var i = 0; i < resourceOrder.length; i++) {
        var r = resourceOrder[i];
        result[r] = rawPerProcess[r].filter(function(p) { return p.pid === pid; });
    }
    return result;
});

// PID 过滤后的告警
const filteredAlerts = computed(() => {
    var pid = activePidFilter.value;
    if (!pid) return rawAlerts.value;
    return rawAlerts.value.filter(function(a) { return a.pid === pid; });
});
```

### 5.3 修改 handleDashboardUpdate

```javascript
function handleDashboardUpdate(data) {
    if (data.latest_points) {
        // ... 既有：更新 current + appendPoint（不变）
    }

    // F4: 存原始 per_process（不再直接赋给 resources）
    if (data.per_process) {
        rawPerProcess.mem = data.per_process.mem || [];
        rawPerProcess.thread = data.per_process.thread || [];
        rawPerProcess.fd = data.per_process.fd || [];
        rawPerProcess.cpu = data.per_process.cpu || [];
    }

    // F4: 存原始告警（不再直接赋给 alerts）
    rawAlerts.value = data.alerts || [];

    // 状态联动（基于 rawAlerts，不受 PID 过滤影响）
    for (const k of resourceOrder) {
        resources[k].status = "normal";
    }
    for (const a of rawAlerts.value) {
        if (resources[a.resource]) {
            resources[a.resource].status = "leak_suspected";
        }
    }

    containers.value = data.containers || [];
    lastUpdate.value = new Date().toLocaleTimeString();
}
```

> 注意：`resources[r].perProcess` 不再直接赋值，改为模板里用 `filteredPerProcess[r]`。`alerts` 改为 `filteredAlerts`。

### 5.4 新增过滤函数

```javascript
// 容器切换
function onContainerChange() {
    LeakDetectAPI.selectContainer(selectedContainer.value);
}

// PID 应用
function applyPidFilter() {
    var pid = parseInt(pidInput.value.trim());
    activePidFilter.value = isNaN(pid) ? null : pid;
}

// 清除所有过滤
function clearFilters() {
    selectedContainer.value = null;
    pidInput.value = "";
    activePidFilter.value = null;
    LeakDetectAPI.selectContainer(null);
}
```

### 5.5 return 补充

```javascript
return {
    // ... F1-F3 既有 ...
    selectedContainer, pidInput, activePidFilter,
    rawPerProcess, rawAlerts,
    filteredPerProcess, filteredAlerts,
    onContainerChange, applyPidFilter, clearFilters,
};
```

### 5.6 index.html 模板变更

per_process 表从 `resources[r].perProcess` 改为 `filteredPerProcess[r]`：
```html
<table class="process-table" v-if="filteredPerProcess[r].length">
    <tr v-for="p in filteredPerProcess[r]" :key="p.pid">
        ...
    </tr>
</table>
```

告警列表从 `alerts` 改为 `filteredAlerts`：
```html
<div v-if="filteredAlerts.length === 0" class="no-alerts">✓ 无告警</div>
<div v-for="a in filteredAlerts" :key="a.id" class="alert-item" ...>
    ...
</div>
```

当前告警计数也改：
```html
当前告警 ({{ filteredAlerts.length }})
```

---

## 六、后端变更

### 6.1 mock.py 变更

#### `__init__` 新增

```python
self.selected_container = None  # None = 全部
self.container_pids = {
    "a3f4b2c1d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0": [1234],      # nginx-server
    "b4e5c3d2e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1": [5678],      # mysql-db
    "c5f6d4e3f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2": [9012],      # app-worker
    "d6a7e5f4a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3": [3456],      # redis-cache
}
```

#### 新增 `set_selected_container()` 方法

```python
def set_selected_container(self, cid):
    self.selected_container = cid
```

#### `get_dashboard_update()` 内加容器过滤

在黑白名单过滤之后、return 之前加：

```python
# 容器过滤
if self.selected_container:
    allowed_pids = self.container_pids.get(self.selected_container, [])
    for resource in per_process:
        per_process[resource] = [
            p for p in per_process[resource]
            if p["pid"] in allowed_pids
        ]
    alerts = [
        a for a in alerts
        if a["pid"] in allowed_pids
    ]
```

#### 过滤执行顺序

```
1. 生成原始 per_process + alerts
2. 黑白名单过滤（_is_filtered）
3. 容器过滤（selected_container）  ← F4 新增
4. return
```

### 6.2 sockets.py 变更

`select_container` handler 接 mock：

```python
@socketio.on("select_container")
def on_select_container(data):
    cid = data.get("container_id") if data else None
    print("[ws] select_container: %s" % cid)
    producer.set_selected_container(cid)
```

> 需在 sockets.py 顶部 `from mock import producer`

---

## 七、CSS 样式新增 + 打磨（style.css）

### 7.1 过滤控件

```css
.filter-controls {
    display: flex;
    gap: 8px;
    align-items: center;
}

.filter-select {
    padding: 4px 8px;
    background: #0f3460;
    border: 1px solid #333;
    border-radius: 3px;
    color: #fff;
    font-size: 12px;
    cursor: pointer;
}

.filter-input {
    width: 80px;
    padding: 4px 8px;
    background: #0f3460;
    border: 1px solid #333;
    border-radius: 3px;
    color: #fff;
    font-size: 12px;
}

.filter-input:focus {
    border-color: #4fc3f7;
    outline: none;
}

.filter-btn {
    padding: 4px 12px;
    background: transparent;
    border: 1px solid #0f3460;
    color: #888;
    border-radius: 3px;
    cursor: pointer;
    font-size: 12px;
}

.filter-btn:hover {
    border-color: #4fc3f7;
    color: #4fc3f7;
}
```

### 7.2 header 布局调整

```css
.header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 12px 24px;
    background: #16213e;
    border-bottom: 1px solid #0f3460;
    flex-wrap: wrap;
    gap: 12px;
}
```

### 7.3 响应式

```css
@media (max-width: 768px) {
    .header {
        flex-direction: column;
        align-items: flex-start;
    }

    .filter-controls {
        width: 100%;
        flex-wrap: wrap;
    }

    .resource-grid {
        grid-template-columns: 1fr;
    }

    .alert-section {
        grid-template-columns: 1fr;
    }
}
```

### 7.4 打磨

```css
/* 卡片悬停 */
.resource-card {
    transition: border-color 0.2s, box-shadow 0.2s;
}
.resource-card:hover {
    border-color: #4fc3f7;
}

/* 告警项过渡 */
.alert-item {
    transition: background 0.2s, border-left-color 0.2s;
}

/* 滚动条 */
::-webkit-scrollbar {
    width: 6px;
}
::-webkit-scrollbar-track {
    background: #0f3460;
}
::-webkit-scrollbar-thumb {
    background: #333;
    border-radius: 3px;
}
::-webkit-scrollbar-thumb:hover {
    background: #555;
}

/* select 下拉箭头 */
.filter-select option {
    background: #16213e;
    color: #fff;
}
```

---

## 八、修改文件清单

| 文件 | 操作 | 变更内容 |
|---|---|---|
| `web/mock.py` | **修改** | 新增 selected_container/container_pids/set_selected_container()；get_dashboard_update() 加容器过滤 |
| `web/sockets.py` | **修改** | select_container handler 接 producer.set_selected_container()；顶部 import producer |
| `web/static/js/app.js` | **修改** | 新增 selectedContainer/pidInput/activePidFilter 状态 + rawPerProcess/rawAlerts + computed filteredPerProcess/filteredAlerts + onContainerChange/applyPidFilter/clearFilters；修改 handleDashboardUpdate 存原始数据 |
| `web/static/index.html` | **修改** | header 加过滤控件；per_process 用 filteredPerProcess；告警用 filteredAlerts |
| `web/static/css/style.css` | **修改** | 过滤控件样式 + header 布局 + 响应式 + 打磨 |

**不变的文件**：
- `web/app.py`、`web/api.py`（无需改）
- `web/static/js/api.js`（已有 selectContainer 方法）
- `web/static/js/components/*`（line-chart/stack-view/filter-config 不动）
- vendor 库（无新增）

> 不新增组件文件，过滤控件内联到 index.html（设计决策，见 §四）。

---

## 九、验证标准

| # | 验证项 | 方法 | 预期 |
|---|---|---|---|
| 1 | 容器下拉有数据 | 打开页面 | 下拉框显示 4 个容器 + "全部容器" |
| 2 | 选容器过滤 | 选"nginx-server" | per_process 只剩 nginx(1234) |
| 3 | 容器告警过滤 | 选"nginx-server" | 句柄告警(app)消失，只剩内存告警(nginx) |
| 4 | 切回全部 | 选"全部容器" | 所有进程恢复 |
| 5 | PID 输入 | 输入 5678 点应用 | per_process 只剩 mysql(5678) |
| 6 | PID 告警过滤 | PID 5678 | 只显示 mysql 的告警 |
| 7 | PID 优先 | 选容器 nginx + PID 5678 | 显示 PID 5678（mysql），nginx 被覆盖 |
| 8 | 清除按钮 | 点清除 | 容器复位全部 + PID 清空 + 数据恢复 |
| 9 | 回车应用 | PID 输入框按回车 | 等同点"应用" |
| 10 | 折线图不变 | 输入 PID | 折线图仍显示聚合值（不受 PID 影响） |
| 11 | 黑白名单仍生效 | 配置黑白名单 + 容器选择 | 两种过滤叠加生效 |
| 12 | 响应式 | 缩小浏览器窗口 | 布局自适应，卡片变单列 |
| 13 | 卡片悬停 | 鼠标悬停卡片 | 边框变蓝 |
| 14 | F1-F3 功能不受影响 | 检查折线图/告警/栈/配置 | 全部正常 |

---

## 十、已知限制（F4 范围外）

| 限制 | 何时补 | 里程碑 |
|---|---|---|
| 容器→PID 映射为 mock 固定 | B3 | 接 /proc/*/cgroup 真实枚举 |
| PID 过滤仅前端（不传后端） | 设计如此 | 显示层过滤 |
| 折线图不受 PID 过滤影响 | 可选增强 | 后续可加 per-PID 时序 |
| 配置文件预指定容器 | B3 | 启动时读 default.yaml 的 target_container_id |
| 容器列表实时刷新 | B3 | 当前只从 WebSocket 推送获取 |

---

## 十一、实施步骤

| 步骤 | 操作 | 耗时 |
|---|---|---|
| 1 | 修改 mock.py（container_pids + set_selected_container + 过滤逻辑） | 15 分钟 |
| 2 | 修改 sockets.py（select_container handler 接 producer） | 5 分钟 |
| 3 | 修改 app.js（新增状态 + computed + 过滤函数 + 改 handleDashboardUpdate） | 30 分钟 |
| 4 | 修改 index.html（header 过滤控件 + filteredPerProcess/filteredAlerts） | 20 分钟 |
| 5 | 修改 style.css（过滤控件 + header 布局 + 响应式 + 打磨） | 20 分钟 |
| 6 | 上传 + 启动 + 调试 | 30-60 分钟 |

**预计总耗时：2-3 小时**

---

## 十二、F4 完成后的状态

F4 是前端阶段最后一个里程碑。完成后：

| 里程碑 | 状态 | 交付物 |
|---|---|---|
| F0 契约定义 | ✅ | 数据契约文档 |
| F1 骨架+mock | ✅ | Flask+Vue+WebSocket 链路 |
| F2 折线图 | ✅ | 4 资源 Chart.js 图表 |
| F3 告警+历史+黑白名单 | ✅ | 栈展示+历史+配置弹窗 |
| F4 容器+PID+打磨 | ✅ | 过滤控件+响应式+打磨 |

**前端全部功能就绪，下一步进入后端 B0（eBPF 技术验证）。**
