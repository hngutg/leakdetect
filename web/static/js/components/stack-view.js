// StackView 组件 - 泄露栈缩进树形展示
// 对应里程碑：F3
// 对应文档：leakdetect-f3-design.md §3.2

const StackView = {
  props: {
    alert: { type: Object, default: null },
  },
  template: `
    <div class="stack-view">
      <h3>泄露栈展示</h3>
      <div v-if="!alert" class="placeholder">点击左侧告警查看栈</div>
      <div v-else>
        <div class="stack-header">
          <span class="sev-badge" :class="'sev-' + alert.severity">{{ severityLabel(alert.severity) }}</span>
          {{ resourceLabel(alert.resource) }}泄露 - PID {{ alert.pid }} ({{ alert.process_name }})
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
  `,
  methods: {
    resourceLabel(r) {
      return { mem: '内存', thread: '线程', fd: '句柄', cpu: 'CPU' }[r] || r;
    },
    severityLabel(s) {
      return { suspected: '疑似', confirmed: '确认泄露', resolved: '已消除' }[s] || (s || '');
    },
    formatTime(ts) {
      if (!ts) return '-';
      var d = new Date(ts * 1000);
      var h = String(d.getHours()).padStart(2, '0');
      var m = String(d.getMinutes()).padStart(2, '0');
      var s = String(d.getSeconds()).padStart(2, '0');
      return h + ':' + m + ':' + s;
    },
  },
};
