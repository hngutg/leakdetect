// LineChart 组件 - Chart.js 折线图封装
// 对应里程碑：F2
// 对应文档：leakdetect-f2-design.md §4.2

const { toRaw } = Vue;

const LineChart = {
  props: {
    series: { type: Array, default: () => [] },
    resource: { type: String, required: true },
    range: { type: String, default: '1d' },
  },
  emits: ['range-change'],
  data() {
    return {
      ranges: ['1d', '7d', '30d'],
    };
  },
  template: `
    <div class="chart-container">
      <canvas ref="canvasEl"></canvas>
      <div class="time-range">
        <button v-for="r in ranges" :key="r"
                @click="$emit('range-change', r)"
                :class="{active: range === r}">{{ rangeLabel(r) }}</button>
      </div>
    </div>
  `,
  mounted() {
    this.chart = null;
    this.initChart();
  },
  watch: {
    series: {
      handler() { this.updateChart(); },
    },
  },
  beforeUnmount() {
    if (this.chart) {
      this.chart.destroy();
      this.chart = null;
    }
  },
  methods: {
    initChart() {
      var ctx = this.$refs.canvasEl.getContext('2d');
      this.chart = new Chart(ctx, {
        type: 'line',
        data: {
          datasets: [{
            data: this.transformData(this.series),
            borderColor: this.color(),
            backgroundColor: this.color() + '20',
            fill: true,
            pointRadius: 0,
            tension: 0.1,
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          animation: { duration: 0 },
          scales: {
            x: {
              type: 'time',
              time: { unit: this.timeUnit() },
              ticks: { maxTicksLimit: 8 },
              grid: { color: '#0f3460' },
            },
            y: {
              beginAtZero: true,
              ticks: { callback: (v) => this.formatY(v) },
              grid: { color: '#0f3460' },
            }
          },
          plugins: { legend: { display: false } }
        }
      });
    },

    transformData(series) {
      var raw = toRaw(series);
      if (!raw || !Array.isArray(raw)) return [];
      var self = this;
      return raw
        .filter(function(p) { return p && p.t !== undefined && p.t !== null; })
        .map(function(p) {
          return { x: p.t * 1000, y: self.transformValue(p.v) };
        });
    },

    transformValue(v) {
      if (v === undefined || v === null) return 0;
      if (this.resource === 'mem') return v / 1024 / 1024;
      return v;
    },

    formatY(v) {
      if (this.resource === 'mem') return v.toFixed(0) + ' MB';
      if (this.resource === 'cpu') return v.toFixed(0) + '%';
      return v;
    },

    color() {
      return {
        mem: '#4fc3f7',
        thread: '#81c784',
        fd: '#ffb74d',
        cpu: '#ce93d8'
      }[this.resource] || '#888';
    },

    timeUnit() {
      return { '1d': 'hour', '7d': 'day', '30d': 'day' }[this.range] || 'hour';
    },

    rangeLabel(r) {
      return { '1d': '1天', '7d': '7天', '30d': '30天' }[r] || r;
    },

    updateChart() {
      if (!this.chart) return;
      this.chart.data.datasets[0].data = this.transformData(this.series);
      if (this.chart.options && this.chart.options.scales && this.chart.options.scales.x) {
        if (!this.chart.options.scales.x.time) {
          this.chart.options.scales.x.time = {};
        }
        this.chart.options.scales.x.time.unit = this.timeUnit();
      }
      this.chart.update('none');
    },
  },
};
