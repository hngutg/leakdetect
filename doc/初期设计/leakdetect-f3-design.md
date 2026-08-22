# F3 里程碑设计文档 — 告警 + 历史 + 黑白名单

> 文档版本：v1.0  
> 日期：2026-07-08  
> 状态：⬜ 待实施  
> 关联文档：`D:\leakdetect-frontend-design.md` §11.4、`D:\leakdetect-f2-design.md`

---

## 一、F3 目标

在 F2 折线图基础上，实现三个功能模块：

1. **告警栈展示** — 点击告警 → 右侧缩进树形展示调用栈，高亮嫌疑帧
2. **告警历史查询** — 切换"当前/历史"标签，历史调 REST 拉取过去告警
3. **黑白名单配置** — 顶部栏"监控配置"按钮 → 弹窗配置过滤规则 + 预览 + 保存

**不含**：容器下拉/PID输入（F4）、真实 BPF 数据（B1+）。

---

## 二、前置依赖

| 依赖 | 状态 | 说明 |
|---|---|---|
| F1 骨架 + mock | ✅ | 告警列表已有，WebSocket 推送含 stack 数据 |
| F2 折线图 | ✅ | 图表已渲染，不影响 F3 |
| 告警数据含 stack 字段 | ✅ | mock 已生成 stack 数组 |
| REST /api/alerts stub | ⚠️ 需实现 | F1 返回空列表，F3 需返回 mock 历史告警 |
| REST /api/config/filter stub | ⚠️ 需实现 | F1 返回固定 stub，F3 需实现保存/预览 |

---

## 三、组件设计

### 3.1 组件树变更

```
F2 结构:                              F3 结构:
App                                   App
├── FilterBar (inline)                ├── FilterBar (inline)
│   └── (无监控配置按钮)              │   └── 监控配置按钮 ← 新增
├── ResourceGrid                      ├── ResourceGrid
│   └── LineChart                     │   └── LineChart
└── AlertPanel                        └── AlertPanel
    ├── AlertList (inline)                ├── AlertList (inline)
    │   └── (点击无效果)                  │   └── 点击告警 → 选中 ← 新增
    └── StackView (占位文字)              └── StackView ← 新组件
                                          (渲染选中告警的栈)
                                         └── FilterConfigModal ← 新组件（模态）
```

### 3.2 StackView 组件

**文件**：`web/static/js/components/stack-view.js`

**职责**：接收选中的告警对象，缩进树形展示其 stack 数组。

**Props**：

| Prop | 类型 | 说明 |
|---|---|---|
| `alert` | Object / null | 选中的告警对象（含 stack 数组）；null 时显示占位提示 |

**模板**：
```html
<div class="stack-view">
  <h3>泄露栈展示</h3>
  <div v-if="!alert" class="placeholder">点击左侧告警查看栈</div>
  <div v-else>
    <div class="stack-header">
      {{ alertLabel }} - PID {{ alert.pid }} ({{ alert.process_name }})
    </div>
    <div class="stack-tree">
      <div v-for="(frame, i) in alert.stack" :key="i"
           class="stack-frame"
           :class="{ suspect: i === alert.stack.length - 1 }"
           :style="{ marginLeft: (i * 20) + 'px' }">
        <span class="frame-func">{{ frame.func }}</span>
        <span class="frame-addr">{{ frame.addr }}</span>
        <span v-if="i === alert.stack.length - 1" class="suspect-tag">← 嫌疑点</span>
      </div>
    </div>
    <div class="stack-footer">
      帧数: {{ alert.stack.length }} | 首次出现: {{ formatTime(alert.timestamp) }}
    </div>
  </div>
</div>
```

**渲染效果**：
```
泄露栈展示
─────────────────────────
内存泄露 - PID 1234 (nginx)
─────────────────────────
main()                    0x401000
  └─ start_worker()       0x4012a0
       └─ handle_request() 0x401580
            └─ malloc() ←   0x401800  嫌疑点
─────────────────────────
帧数: 4 | 首次出现: 14:32:01
```

- `i * 20px` 缩进实现树形层级
- 最后一帧（`i === alert.stack.length - 1`）加 `suspect` class 高亮
- 函数名 + 地址并排显示

### 3.3 FilterConfigModal 组件

**文件**：`web/static/js/components/filter-config.js`

**职责**：模态弹窗，配置黑白名单过滤规则，支持预览和保存。

**Props**：

| Prop | 类型 | 说明 |
|---|---|---|
| `visible` | Boolean | 控制弹窗显隐 |

**Emits**：

| 事件 | 说明 |
|---|---|
| `close` | 关闭弹窗 |

**内部数据**：
```javascript
data() {
  return {
    mode: 'disabled',        // disabled | whitelist | blacklist
    nameRegex: '',           // 进程名正则字符串
    pidListText: '',         // PID 列表文本（逗号分隔）
    preview: null,           // 预览结果 {matched:[], unmatched:[]}
    previewLoading: false,
    saving: false,
  };
}
```

**模板**：
```html
<div v-if="visible" class="modal-overlay" @click.self="$emit('close')">
  <div class="modal-dialog">
    <h3>监控配置</h3>

    <!-- 模式选择 -->
    <div class="form-group">
      <label>过滤模式：</label>
      <label class="radio-label"><input type="radio" v-model="mode" value="disabled"> 全部监控</label>
      <label class="radio-label"><input type="radio" v-model="mode" value="whitelist"> 白名单</label>
      <label class="radio-label"><input type="radio" v-model="mode" value="blacklist"> 黑名单</label>
    </div>

    <!-- 进程名正则 -->
    <div class="form-group" v-if="mode !== 'disabled'">
      <label>进程名正则：</label>
      <input v-model="nameRegex" placeholder="nginx|mysql|redis" class="form-input">
      <small>多个用 | 分隔，支持正则</small>
    </div>

    <!-- PID 列表 -->
    <div class="form-group" v-if="mode !== 'disabled'">
      <label>PID 列表：</label>
      <input v-model="pidListText" placeholder="1234, 5678" class="form-input">
      <small>逗号分隔</small>
    </div>

    <!-- 匹配逻辑说明 -->
    <div class="form-hint" v-if="mode !== 'disabled'">
      匹配逻辑：进程名 OR PID 命中即视为匹配
    </div>

    <!-- 预览 -->
    <div class="form-group" v-if="mode !== 'disabled'">
      <button @click="doPreview" :disabled="previewLoading">
        {{ previewLoading ? '预览中...' : '预览匹配' }}
      </button>
    </div>
    <div v-if="preview" class="preview-results">
      <div v-for="p in preview.matched" :key="p.pid" class="preview-item matched">
        ✓ {{ p.name }} (PID {{ p.pid }})
      </div>
      <div v-for="p in preview.unmatched" :key="p.pid" class="preview-item unmatched">
        ✗ {{ p.name }} (PID {{ p.pid }})
      </div>
    </div>

    <!-- 按钮 -->
    <div class="modal-footer">
      <button @click="$emit('close')">取消</button>
      <button @click="doSave" :disabled="saving" class="btn-primary">
        {{ saving ? '保存中...' : '保存并应用' }}
      </button>
    </div>
  </div>
</div>
```

**方法**：
```javascript
methods: {
  async loadConfig() {
    const resp = await LeakDetectAPI.getFilterConfig();
    this.mode = resp.mode || 'disabled';
    this.nameRegex = resp.name_regex || '';
    this.pidListText = (resp.pid_list || []).join(', ');
  },

  async doPreview() {
    this.previewLoading = true;
    try {
      this.preview = await LeakDetectAPI.previewFilter(this.nameRegex, this.pidListText);
    } catch (e) {
      console.error('[filter] preview failed:', e);
    }
    this.previewLoading = false;
  },

  async doSave() {
    this.saving = true;
    try {
      await LeakDetectAPI.saveFilterConfig({
        mode: this.mode,
        name_regex: this.nameRegex,
        pid_list: this.pidListText.split(',').map(s => parseInt(s.trim())).filter(n => !isNaN(n)),
      });
      this.$emit('close');
    } catch (e) {
      console.error('[filter] save failed:', e);
    }
    this.saving = false;
  },
},

watch: {
  visible(val) {
    if (val) this.loadConfig();
    else { this.preview = null; }
  },
},
```

---

## 四、数据管理（app.js 变更）

### 4.1 新增响应式状态

```javascript
// 选中的告警（点击告警列表项时设置）
const selectedAlert = ref(null);

// 黑白名单弹窗显隐
const filterConfigVisible = ref(false);

// 告警面板标签：当前 / 历史
const alertTab = ref('current');  // 'current' | 'history'

// 历史告警列表
const historyAlerts = ref([]);

// 历史告警加载状态
const historyLoading = ref(false);
```

### 4.2 告警点击处理

```javascript
function selectAlert(alert) {
  selectedAlert.value = alert;
}
```

在 index.html 的告警列表项上加 `@click="selectAlert(a)"` 和 `:class="{selected: selectedAlert && selectedAlert.id === a.id}"`。

### 4.3 告警标签切换

```javascript
async function switchAlertTab(tab) {
  alertTab.value = tab;
  if (tab === 'history' && historyAlerts.value.length === 0) {
    historyLoading.value = true;
    try {
      const resp = await LeakDetectAPI.getAlerts('24h');
      historyAlerts.value = resp.alerts || [];
    } catch (e) {
      console.error('[alerts] load history failed:', e);
    }
    historyLoading.value = false;
  }
}
```

### 4.4 黑白名单弹窗控制

```javascript
function openFilterConfig() {
  filterConfigVisible.value = true;
}
function closeFilterConfig() {
  filterConfigVisible.value = false;
}
```

### 4.5 注册组件 + return 补充

```javascript
app.component('LineChart', LineChart);
app.component('StackView', StackView);
app.component('FilterConfigModal', FilterConfigModal);
```

setup() return 补充：
```javascript
return {
  // ... F1/F2 既有 ...
  selectedAlert, filterConfigVisible, alertTab, historyAlerts, historyLoading,
  selectAlert, switchAlertTab, openFilterConfig, closeFilterConfig,
};
```

---

## 五、页面布局变更

### 5.1 顶部栏新增"监控配置"按钮

```html
<div class="header">
  <h1>LeakDetect</h1>
  <div class="status">
    <span :class="{...}">{{ connected ? '● 运行中' : '● 断开' }}</span>
    <button @click="openFilterConfig" class="btn-config">监控配置</button>  <!-- 新增 -->
  </div>
</div>
```

### 5.2 告警区改为标签切换 + StackView 组件

```html
<div class="alert-section">
  <div class="alert-list">
    <!-- 标签切换 -->
    <div class="alert-tabs">
      <button @click="switchAlertTab('current')" :class="{active: alertTab==='current'}">
        当前告警 ({{ alerts.length }})
      </button>
      <button @click="switchAlertTab('history')" :class="{active: alertTab==='history'}">
        历史告警
      </button>
    </div>

    <!-- 当前告警 -->
    <template v-if="alertTab === 'current'">
      <div v-if="alerts.length === 0" class="no-alerts">✓ 无告警</div>
      <div v-for="a in alerts" :key="a.id" class="alert-item"
           :class="[a.severity, {selected: selectedAlert && selectedAlert.id === a.id}]"
           @click="selectAlert(a)">
        <!-- 告警内容同 F1 -->
      </div>
    </template>

    <!-- 历史告警 -->
    <template v-if="alertTab === 'history'">
      <div v-if="historyLoading" class="loading">加载中...</div>
      <div v-else-if="historyAlerts.length === 0" class="no-alerts">✓ 无历史告警</div>
      <div v-for="a in historyAlerts" :key="a.id" class="alert-item"
           :class="[a.severity, {selected: selectedAlert && selectedAlert.id === a.id}]"
           @click="selectAlert(a)">
        <!-- 告警内容同上 -->
      </div>
    </template>
  </div>

  <!-- StackView 组件（替换占位文字） -->
  <stack-view :alert="selectedAlert"></stack-view>
</div>
```

### 5.3 弹窗（页面末尾）

```html
<filter-config-modal :visible="filterConfigVisible" @close="closeFilterConfig">
</filter-config-modal>
```

---

## 六、API 变更

### 6.1 api.py 修改

```python
@api.route("/api/alerts")
def alerts():
    range_tag = request.args.get("range", "24h")
    return jsonify({"alerts": producer.get_alerts(range_tag)})

@api.route("/api/config/filter", methods=["GET"])
def get_filter():
    return jsonify(producer.get_filter_config())

@api.route("/api/config/filter", methods=["POST"])
def set_filter():
    data = request.get_json(silent=True) or {}
    result = producer.save_filter_config(data)
    return jsonify(result)

@api.route("/api/config/filter/preview")
def preview_filter():
    name_regex = request.args.get("name_regex", "")
    pid_list = request.args.get("pid_list", "")
    return jsonify(producer.preview_filter(name_regex, pid_list))
```

### 6.2 mock.py 新增方法

#### 假进程列表 + 配置状态（__init__ 补充）

```python
def __init__(self):
    # ... 既有 ...
    self.processes = [
        {"pid": 1234, "name": "nginx"},
        {"pid": 5678, "name": "mysql"},
        {"pid": 9012, "name": "app-worker"},
        {"pid": 3456, "name": "redis-server"},
        {"pid": 7890, "name": "sshd"},
        {"pid": 1111, "name": "systemd"},
        {"pid": 2222, "name": "kthreadd"},
    ]
    self.filter_config = {
        "mode": "disabled",
        "name_regex": "",
        "pid_list": [],
    }
```

#### get_alerts(range) — 历史告警

```python
def get_alerts(self, range_tag="24h"):
    """生成 mock 历史告警。"""
    now = int(time.time())
    history = []
    for i in range(5):
        t = now - random.randint(3600, 86400)
        resource = random.choice(["mem", "fd", "thread"])
        history.append({
            "id": "hist-%03d" % i,
            "resource": resource,
            "pid": random.choice([1234, 5678, 9012]),
            "process_name": random.choice(["nginx", "mysql", "app"]),
            "severity": "leak",
            "detail": "outstanding +%d%s in 60s" % (
                random.randint(1, 10),
                "MB" if resource == "mem" else " FD"
            ),
            "timestamp": t,
            "stack": [
                {"func": "main()", "addr": "0x%06x" % random.randint(0x400000, 0x410000)},
                {"func": "worker_loop()", "addr": "0x%06x" % random.randint(0x400000, 0x410000)},
                {"func": "malloc()" if resource == "mem" else "open()",
                 "addr": "0x%06x" % random.randint(0x400000, 0x410000)},
            ],
        })
    history.sort(key=lambda a: a["timestamp"], reverse=True)
    return history
```

#### get_filter_config() — 读取配置

```python
def get_filter_config(self):
    return dict(self.filter_config)
```

#### save_filter_config(config) — 保存配置

```python
def save_filter_config(self, config):
    self.filter_config = {
        "mode": config.get("mode", "disabled"),
        "name_regex": config.get("name_regex", ""),
        "pid_list": config.get("pid_list", []),
    }
    pid_str = ",".join(str(p) for p in self.filter_config["pid_list"])
    preview = self.preview_filter(self.filter_config["name_regex"], pid_str)
    return {
        "status": "applied",
        "matched_pids": [p["pid"] for p in preview["matched"]],
    }
```

#### preview_filter(name_regex, pid_list_str) — 预览匹配

```python
def preview_filter(self, name_regex, pid_list_str):
    import re
    matched = []
    unmatched = []
    pids = []
    if pid_list_str:
        for s in pid_list_str.split(","):
            s = s.strip()
            if s.isdigit():
                pids.append(int(s))
    for p in self.processes:
        name_match = False
        pid_match = False
        if name_regex:
            try:
                if re.search(name_regex, p["name"]):
                    name_match = True
            except re.error:
                pass
        if p["pid"] in pids:
            pid_match = True
        if name_match or pid_match:
            matched.append(p)
        else:
            unmatched.append(p)
    return {"matched": matched, "unmatched": unmatched}
```

---

## 七、CSS 样式新增（style.css）

### 7.1 栈展示

```css
.stack-header {
    color: #4fc3f7;
    margin-bottom: 12px;
    font-size: 14px;
    padding-bottom: 8px;
    border-bottom: 1px solid #0f3460;
}

.stack-tree {
    font-family: "Consolas", "Courier New", monospace;
    font-size: 13px;
}

.stack-frame {
    padding: 4px 0;
    display: flex;
    align-items: center;
    gap: 12px;
}

.stack-frame.suspect {
    color: #f44336;
    font-weight: bold;
}

.frame-func { min-width: 200px; }
.frame-addr { color: #888; font-size: 12px; }
.suspect-tag {
    color: #f44336;
    font-size: 11px;
    margin-left: 8px;
}

.stack-footer {
    margin-top: 12px;
    padding-top: 8px;
    border-top: 1px solid #0f3460;
    color: #888;
    font-size: 12px;
}

.alert-item.selected {
    border-left-color: #4fc3f7;
    background: #1a2e4a;
}
```

### 7.2 标签切换

```css
.alert-tabs {
    display: flex;
    gap: 4px;
    margin-bottom: 12px;
}

.alert-tabs button {
    padding: 4px 12px;
    border: 1px solid #0f3460;
    background: transparent;
    color: #888;
    border-radius: 3px;
    cursor: pointer;
    font-size: 12px;
}

.alert-tabs button.active {
    background: #0f3460;
    color: #4fc3f7;
}
```

### 7.3 模态弹窗

```css
.modal-overlay {
    position: fixed;
    top: 0; left: 0; right: 0; bottom: 0;
    background: rgba(0, 0, 0, 0.6);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 1000;
}

.modal-dialog {
    background: #16213e;
    border: 1px solid #0f3460;
    border-radius: 8px;
    padding: 24px;
    width: 500px;
    max-width: 90%;
}

.modal-dialog h3 {
    color: #4fc3f7;
    margin-bottom: 16px;
}

.form-group {
    margin-bottom: 16px;
}

.form-group label {
    display: block;
    margin-bottom: 4px;
    color: #ccc;
    font-size: 13px;
}

.form-group .radio-label {
    display: inline;
    margin-right: 16px;
}

.form-input {
    width: 100%;
    padding: 6px 10px;
    background: #0f3460;
    border: 1px solid #333;
    border-radius: 4px;
    color: #fff;
    font-size: 13px;
}

.form-hint {
    color: #888;
    font-size: 12px;
    margin-bottom: 12px;
}

.preview-results {
    max-height: 150px;
    overflow-y: auto;
    margin-bottom: 16px;
}

.preview-item {
    padding: 4px 8px;
    font-size: 12px;
}

.preview-item.matched { color: #4caf50; }
.preview-item.unmatched { color: #888; }

.modal-footer {
    display: flex;
    justify-content: flex-end;
    gap: 8px;
    margin-top: 16px;
}

.btn-primary {
    background: #0f3460;
    color: #4fc3f7;
    border-color: #4fc3f7;
}

.btn-config {
    padding: 4px 12px;
    background: #0f3460;
    border: 1px solid #4fc3f7;
    color: #4fc3f7;
    border-radius: 3px;
    cursor: pointer;
    font-size: 12px;
}

.loading { color: #888; padding: 8px 0; }
```

---

## 八、修改文件清单

| 文件 | 操作 | 变更内容 |
|---|---|---|
| `web/static/js/components/stack-view.js` | **新增** | StackView 组件（~50 行） |
| `web/static/js/components/filter-config.js` | **新增** | FilterConfigModal 组件（~100 行） |
| `web/static/js/app.js` | **修改** | 新增 selectedAlert/filterConfigVisible/alertTab 状态 + selectAlert/switchAlertTab/openFilterConfig 方法 + 注册 2 个组件 |
| `web/static/index.html` | **修改** | 顶部栏加"监控配置"按钮；告警区加标签切换 + 告警点击；占位文字替换为 `<stack-view>`；末尾加 `<filter-config-modal>` |
| `web/static/css/style.css` | **修改** | 新增栈展示/标签/弹窗/表单样式 |
| `web/api.py` | **修改** | /api/alerts 接 producer.get_alerts()；/api/config/filter GET/POST/preview 接 producer 方法 |
| `web/mock.py` | **修改** | 新增 processes 列表、filter_config 状态、get_alerts()、get_filter_config()、save_filter_config()、preview_filter() |

**不变的文件**：
- `web/app.py`、`web/sockets.py`（无需改）
- `web/static/js/api.js`（已有 getAlerts/getFilterConfig/saveFilterConfig/previewFilter）
- `web/static/js/components/line-chart.js`（F2 不动）
- vendor 库（无新增）

---

## 九、index.html 引入顺序

```html
<!-- Vendor -->
<script src="/static/vendor/socket.io.min.js"></script>
<script src="/static/vendor/vue.global.prod.js"></script>
<script src="/static/vendor/chart.umd.min.js"></script>
<script src="/static/vendor/chartjs-adapter-date-fns.bundle.min.js"></script>
<!-- 组件 -->
<script src="/static/js/components/line-chart.js"></script>
<script src="/static/js/components/stack-view.js"></script>          <!-- 新增 -->
<script src="/static/js/components/filter-config.js"></script>       <!-- 新增 -->
<!-- 应用 -->
<script src="/static/js/api.js"></script>
<script src="/static/js/app.js"></script>
```

---

## 十、验证标准

| # | 验证项 | 方法 | 预期 |
|---|---|---|---|
| 1 | 告警可点击 | 点击告警项 | 告警项高亮（蓝色左边框） |
| 2 | 栈展示渲染 | 点击告警后看右侧 | 缩进树形展示调用栈，4 层缩进 |
| 3 | 嫌疑帧高亮 | 看最后一帧 | 红色加粗 + "← 嫌疑点"标签 |
| 4 | 帧地址显示 | 看每帧右侧 | 显示 0x 开头地址 |
| 5 | 标签切换 | 点"历史告警" | 加载历史告警列表，显示 5 条 |
| 6 | 历史告警可点击 | 点击历史告警 | 栈展示区显示该告警的栈 |
| 7 | 监控配置按钮 | 点顶部"监控配置" | 弹出模态弹窗 |
| 8 | 模式切换 | 选"白名单" | 正则输入框和 PID 输入框出现 |
| 9 | 预览功能 | 输入 nginx，点"预览" | 显示 nginx PID 1234 ✓ 匹配 |
| 10 | 保存功能 | 点"保存并应用" | 弹窗关闭，Console 无报错 |
| 11 | F2 折线图不受影响 | 看图表 | 4 张图仍正常渲染和更新 |
| 12 | F1 告警仍出现 | 等 30s | 当前告警仍实时推送 |

---

## 十一、已知限制（F3 范围外）

| 限制 | 何时补 | 里程碑 |
|---|---|---|
| 告警保存仅 mock（不写 SQLite） | B1+ | 接真实存储 |
| 预览进程列表为 mock 固定 7 个 | B3 | 接 /proc 真实进程 |
| 黑白名单不实际过滤 BPF | B3 | 接 pid_filter_map |
| 无容器下拉/PID 输入 | F4 | container-select + pid-input |
| 历史告警无分页 | 可选增强 | 后续 |

---

## 十二、实施步骤

| 步骤 | 操作 | 耗时 |
|---|---|---|
| 1 | 创建 stack-view.js 组件 | 20 分钟 |
| 2 | 创建 filter-config.js 组件 | 40 分钟 |
| 3 | 修改 mock.py（新增 5 个方法 + processes 列表 + filter_config 状态） | 30 分钟 |
| 4 | 修改 api.py（4 个路由接 producer 方法） | 10 分钟 |
| 5 | 修改 app.js（新增状态 + 方法 + 注册组件） | 30 分钟 |
| 6 | 修改 index.html（顶部按钮 + 标签切换 + 告警点击 + stack-view + modal） | 30 分钟 |
| 7 | 修改 style.css（栈/标签/弹窗/表单样式） | 30 分钟 |
| 8 | 上传 + 启动 + 调试 | 30-60 分钟 |

**预计总耗时：3-4 小时**
