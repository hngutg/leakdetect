// Sparkline 组件 - SVG 迷你折线图（轻量，无 Chart.js 开销）
// 用于容器概览卡片的内存趋势展示（近 10 分钟实时累积）

const Sparkline = {
  props: {
    points: { type: Array, default: () => [] },
    color: { type: String, default: '#4fc3f7' },
    field: { type: String, default: 'v' },
    showCaption: { type: Boolean, default: false },
    width: { type: Number, default: 120 },
    height: { type: Number, default: 32 },
  },
  computed: {
    renderPoints() {
      var p = Vue.toRaw(this.points);
      if (!Array.isArray(p) || p.length === 0) return [];
      return p;
    },
    _vals() {
      var f = this.field;
      return this.renderPoints.map(function(p) {
        return (typeof p === 'object' && p !== null) ? p[f] : p;
      });
    },
    pathD() {
      var pts = this.renderPoints;
      if (pts.length === 0) return '';
      var vals = this._vals;
      var min = 0;
      var max = Math.max.apply(null, vals);
      var n = pts.length;
      var w = this.width;
      var h = this.height;
      var d = '';
      for (var i = 0; i < n; i++) {
        var x = n === 1 ? w / 2 : (i / (n - 1)) * w;
        var y = (max === min) ? h / 2 : h - ((vals[i] - min) / (max - min)) * (h - 2) - 1;
        d += (i === 0 ? 'M' : 'L') + x.toFixed(1) + ' ' + y.toFixed(1);
      }
      return d;
    },
    areaD() {
      if (this.renderPoints.length < 2) return '';
      var d = this.pathD;
      d += 'L' + this.width.toFixed(1) + ' ' + this.height + ' L0 ' + this.height + ' Z';
      return d;
    },
  },
  template: `
    <div class="sparkline-wrap">
      <svg :width="width" :height="height" class="sparkline-svg" :viewBox="'0 0 ' + width + ' ' + height" preserveAspectRatio="none">
        <path v-if="areaD" :d="areaD" :fill="color + '20'" stroke="none" />
        <path :d="pathD" :stroke="color" stroke-width="1.2" fill="none" stroke-linejoin="round" stroke-linecap="round" />
      </svg>
      <span class="sparkline-caption" v-if="showCaption">近 10 分钟趋势</span>
    </div>
  `,
};
