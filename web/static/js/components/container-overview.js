// ContainerOverview 组件 - 容器概览条
// 横向滚动卡片，每张卡片 = 一个容器/宿主
// 含：名称、告警状态徽章、当前 mem 值、sparkline 趋势、进程数
// 点击卡片 → 下钻该容器；点已选中卡 → 回"全部"（toggle 逻辑在父组件）

const ContainerOverview = {
  props: {
    summary: { type: Array, default: () => [] },
    trendData: { type: Object, default: () => ({}) },
    selected: { default: "all" },
  },
  emits: ['select'],
  data() {
    return {
      resourceList: [
        { field: 'mem', label: 'mem' },
        { field: 'mmap', label: 'mmap' },
        { field: 'thread', label: '线程' },
        { field: 'fd', label: '句柄' },
        { field: 'cpu', label: 'CPU' },
      ],
    };
  },
  methods: {
    sevColor(sev) {
      return {
        confirmed: '#f44336',
        suspected: '#ff9800',
        normal: '#4fc3f7',
        resolved: '#888888',
      }[sev] || '#4fc3f7';
    },
    sevText(sev) {
      return {
        confirmed: '确认',
        suspected: '疑似',
        normal: '正常',
        resolved: '已消除',
      }[sev] || sev;
    },
    fmtMem(v) {
      if (!v) return '0';
      if (v >= 1048576) return (v / 1048576).toFixed(1) + ' MB';
      if (v >= 1024) return (v / 1024).toFixed(0) + ' KB';
      return v + ' B';
    },
    fmtValue(field, v) {
      if (field === 'mem' || field === 'mmap') return this.fmtMem(v);
      if (field === 'cpu') return (v || 0).toFixed(1) + '%';
      return v || 0;
    },
    trendKey(cid) {
      return String(cid);
    },
  },
  template: `
    <div class="container-overview-strip" v-if="summary && summary.length">
      <div v-for="c in summary" :key="String(c.id)"
           class="container-card"
           :class="[c.sev, {selected: selected === c.id}]"
           @click="$emit('select', c.id)">
        <div class="container-card-header">
          <span class="container-name" :title="c.name">{{ c.name }}</span>
          <span class="container-sev-badge" :style="{color: sevColor(c.sev)}">{{ sevText(c.sev) }}</span>
        </div>
        <div v-for="r in resourceList" :key="r.field" class="container-resource-block">
          <div class="container-resource-row">
            <span class="container-resource-label">{{ r.label }}</span>
            <span class="container-resource-value">{{ fmtValue(r.field, c[r.field]) }}</span>
          </div>
          <sparkline :points="trendData[trendKey(c.id)] || []" :field="r.field"
                     :color="sevColor(c.sev)" :height="24"></sparkline>
        </div>
        <div class="container-pid-count">{{ c.pid_count }} 进程</div>
        <span class="sparkline-caption">近 10 分钟趋势</span>
      </div>
    </div>
  `,
};
