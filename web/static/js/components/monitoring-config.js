// MonitoringConfigPage 组件 - 监控参数配置页面（表格布局）
// 所有运行时可调参数 + 采样率只读展示
// 精度专项（2026-08-21）：阈值语义 delta→斜率(单位/秒)；新增启动宽限期 grace_seconds

const MonitoringConfigPage = {
  emits: ['back'],
  data() {
    return {
      saving: false,
      samplingRate: 100,
      sections: [
        {
          title: '堆内存(malloc)', icon: '💾', resource: 'mem',
          params: [
            { key: 'outstanding_delta_bytes', label: '增长斜率阈值', value: 10240, unit: '字节/秒',
              desc: 'outstanding 净增长斜率（字节/秒）需超过此值且统计显著才可能告警。值越大越不易误报，但小速率泄露会漏检。默认 10KB/s（mem_leak 40KB/s 命中）。可调' },
            { key: 'grace_seconds', label: '启动宽限期', value: 120, unit: '秒',
              desc: '新进程前 N 秒只攒历史不判定，防启动爬坡误报。值越大越保守，但慢启动进程的检测延迟增加' },
            { key: 'confirm_seconds', label: '确认时长', value: 240, unit: '秒',
              desc: '疑似→确认：LEAK 持续此时长且仍 leaking 才升"确认泄露"。随机游走伪信号此时已老化→不升确认→自动消除。默认 240=2×趋势窗口' },
            { key: 'observe_seconds', label: '观察期时长', value: 30, unit: '秒',
              desc: 'outstanding 开始增长后，需持续此时长才从"正常"进入"观察中"。防止短暂分配导致误触发。值越大越保守' },
            { key: 'leak_seconds', label: '趋势检测窗口', value: 60, unit: '秒',
              desc: '趋势检测窗口时长。history 保留 2×此时长，OLS 斜率在此窗口上计算；斜率需 > 阈值且 slope/SE > 显著性才告警' },
            { key: 'clear_ratio', label: '恢复比例', value: 0.5, unit: '',
              desc: '泄露告警后，outstanding 需下降到峰值 × 此比例以下才认为"已恢复"。0.5=下降到峰值 50%，1.0=只要不增长就恢复，0.1=必须大幅下降' },
            { key: 'clear_seconds', label: '恢复确认时长', value: 30, unit: '秒',
              desc: 'outstanding 降到恢复比例以下后，需持续此时长才确认恢复。防止短暂释放误判为恢复' },
            { key: 'resolve_seconds', label: '清除时长', value: 60, unit: '秒',
              desc: '"已恢复"状态持续此时长后自动回到"正常"，告警从列表中消失' },
            { key: 'stabilize_seconds', label: '稳定消除时长', value: 300, unit: '秒',
              desc: '泄露告警后，如果 outstanding 不再增长（内存稳定不降），此时长后自动消除告警。覆盖"先升后稳"场景。值越大越保守' }
          ]
        },
        {
          title: '线程', icon: '🧵', resource: 'thread',
          params: [
            { key: 'delta_threshold', label: '增长斜率阈值', value: 0.1, unit: '个/秒',
              desc: '线程数净增长斜率（个/秒）需超过此值且统计显著才可能告警。默认 0.1（≈6个/分钟），需实测调' },
            { key: 'grace_seconds', label: '启动宽限期', value: 120, unit: '秒',
              desc: '新进程前 N 秒只攒历史不判定，防启动期创建线程误报' },
            { key: 'confirm_seconds', label: '确认时长', value: 240, unit: '秒',
              desc: '疑似→确认：LEAK 持续此时长且仍 leaking 才升"确认泄露"' },
            { key: 'observe_seconds', label: '观察期时长', value: 30, unit: '秒',
              desc: '线程数开始增长后的观察期。防止短暂创建线程导致误触发' },
            { key: 'leak_seconds', label: '趋势检测窗口', value: 120, unit: '秒',
              desc: '趋势检测窗口时长。线程比内存长（120s），因为线程泄露通常更慢' },
            { key: 'clear_ratio', label: '恢复比例', value: 0.5, unit: '',
              desc: '泄露告警后线程数需下降到峰值 × 此比例以下才认为"已恢复"' },
            { key: 'clear_seconds', label: '恢复确认时长', value: 30, unit: '秒',
              desc: '线程数降到恢复比例以下后需持续此时长才确认恢复' },
            { key: 'resolve_seconds', label: '清除时长', value: 60, unit: '秒',
              desc: '"已恢复"状态持续此时长后告警从列表中消失' },
            { key: 'stabilize_seconds', label: '稳定消除时长', value: 300, unit: '秒',
              desc: '泄露告警后线程数稳定不再增长，此时长后自动消除告警' }
          ]
        },
        {
          title: '句柄', icon: '📁', resource: 'fd',
          params: [
            { key: 'delta_threshold', label: '增长斜率阈值', value: 0.5, unit: '个/秒',
              desc: 'fd 数净增长斜率（个/秒）需超过此值且统计显著才可能告警。默认 0.5（≈30个/分钟），需实测调' },
            { key: 'grace_seconds', label: '启动宽限期', value: 120, unit: '秒',
              desc: '新进程前 N 秒只攒历史不判定，防启动期打开 fd 误报' },
            { key: 'confirm_seconds', label: '确认时长', value: 240, unit: '秒',
              desc: '疑似→确认：LEAK 持续此时长且仍 leaking 才升"确认泄露"' },
            { key: 'observe_seconds', label: '观察期时长', value: 30, unit: '秒',
              desc: 'fd 数开始增长后的观察期' },
            { key: 'leak_seconds', label: '趋势检测窗口', value: 120, unit: '秒',
              desc: '趋势检测窗口时长' },
            { key: 'clear_ratio', label: '恢复比例', value: 0.5, unit: '',
              desc: '泄露告警后 fd 数需下降到峰值 × 此比例以下才认为"已恢复"' },
            { key: 'clear_seconds', label: '恢复确认时长', value: 30, unit: '秒',
              desc: 'fd 数降到恢复比例以下后需持续此时长才确认恢复' },
            { key: 'resolve_seconds', label: '清除时长', value: 60, unit: '秒',
              desc: '"已恢复"状态持续此时长后告警从列表中消失' },
            { key: 'stabilize_seconds', label: '稳定消除时长', value: 300, unit: '秒',
              desc: '泄露告警后 fd 数稳定不再增长，此时长后自动消除告警' }
          ]
        },
        {
          title: 'CPU', icon: '⚡', resource: 'cpu',
          params: [
            { key: 'cpu_interval', label: '轮询间隔', value: 1, unit: '秒',
              desc: '每 N 秒读取一次 /proc/[pid]/stat 计算 CPU 占用率。值越小越实时但系统开销越大。默认 1 秒' }
          ]
        },
        {
          title: '映射内存(mmap)', icon: '🗂️', resource: 'mmap',
          params: [
            { key: 'outstanding_delta_bytes', label: '增长斜率阈值', value: 10240, unit: '字节/秒',
              desc: 'mmap outstanding 净增长斜率（字节/秒）需超过此值且统计显著才可能告警。全量追踪（无采样），值为精确值' },
            { key: 'grace_seconds', label: '启动宽限期', value: 120, unit: '秒',
              desc: '新进程前 N 秒只攒历史不判定，防启动期 mmap 误报' },
            { key: 'confirm_seconds', label: '确认时长', value: 240, unit: '秒',
              desc: '疑似→确认：LEAK 持续此时长且仍 leaking 才升"确认泄露"' },
            { key: 'observe_seconds', label: '观察期时长', value: 30, unit: '秒',
              desc: 'mmap outstanding 开始增长后的观察期' },
            { key: 'leak_seconds', label: '趋势检测窗口', value: 60, unit: '秒',
              desc: '趋势检测窗口时长。OLS 斜率在此窗口上计算' },
            { key: 'clear_ratio', label: '恢复比例', value: 0.5, unit: '',
              desc: '泄露告警后 mmap outstanding 需下降到峰值 × 此比例以下才认为"已恢复"' },
            { key: 'clear_seconds', label: '恢复确认时长', value: 30, unit: '秒',
              desc: 'mmap outstanding 降到恢复比例以下后需持续此时长才确认恢复' },
            { key: 'resolve_seconds', label: '清除时长', value: 60, unit: '秒',
              desc: '"已恢复"状态持续此时长后告警从列表中消失' },
            { key: 'stabilize_seconds', label: '稳定消除时长', value: 300, unit: '秒',
              desc: '泄露告警后 mmap outstanding 稳定不再增长，此时长后自动消除告警' }
          ]
        }
      ]
    };
  },
  template: `
    <div class="config-page">
      <div class="config-header">
        <button @click="$emit('back')" class="btn-back">← 返回</button>
        <h2>监控参数配置</h2>
      </div>
      <div class="config-body">
        <div v-for="section in sections" :key="section.resource" class="config-section">
          <h3 class="config-section-title">{{ section.icon }} {{ section.title }}</h3>
          <table class="config-table">
            <thead>
              <tr>
                <th class="col-name">参数</th>
                <th class="col-value">值</th>
                <th class="col-desc">说明</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="param in section.params" :key="param.key">
                <td class="col-name">{{ param.label }}</td>
                <td class="col-value">
                  <input type="number" v-model.number="param.value" class="param-input" step="any">
                  <span class="param-unit" v-if="param.unit">{{ param.unit }}</span>
                </td>
                <td class="col-desc">{{ param.desc }}</td>
              </tr>
            </tbody>
          </table>
        </div>

        <div class="config-section">
          <h3 class="config-section-title">⚙️ 采样（需重启生效）</h3>
          <table class="config-table">
            <thead>
              <tr>
                <th class="col-name">参数</th>
                <th class="col-value">值</th>
                <th class="col-desc">说明</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td class="col-name">内存采样率</td>
                <td class="col-value">
                  <span class="param-readonly">1 / {{ samplingRate }}</span>
                </td>
                <td class="col-desc">每 N 次 malloc 抓 1 次。值越大性能开销越小但估算精度越低。最终展示值 ×N 估算总量。修改后需重启服务生效（BPF 程序中硬编码）</td>
              </tr>
            </tbody>
          </table>
        </div>

        <div class="modal-footer">
          <button @click="resetDefaults">恢复默认值</button>
          <button @click="doSave" :disabled="saving" class="btn-primary">
            {{ saving ? '保存中...' : '保存并应用' }}
          </button>
        </div>
      </div>
    </div>
  `,
  mounted() {
    this.loadConfig();
  },
  methods: {
    async loadConfig() {
      try {
        var resp = await LeakDetectAPI.getMonitoringConfig();
        this.applyConfig(resp);
      } catch (e) {
        console.error('[monitoring] load config failed:', e);
      }
    },

    applyConfig(config) {
      for (var i = 0; i < this.sections.length; i++) {
        var section = this.sections[i];
        var cfg = config[section.resource];
        if (!cfg) continue;
        for (var j = 0; j < section.params.length; j++) {
          var param = section.params[j];
          if (cfg[param.key] !== undefined) {
            param.value = cfg[param.key];
          }
        }
      }
      if (config.sampling_rate) {
        this.samplingRate = config.sampling_rate;
      }
    },

    buildPayload() {
      var payload = {};
      for (var i = 0; i < this.sections.length; i++) {
        var section = this.sections[i];
        payload[section.resource] = {};
        for (var j = 0; j < section.params.length; j++) {
          var param = section.params[j];
          payload[section.resource][param.key] = param.value;
        }
      }
      return payload;
    },

    async doSave() {
      this.saving = true;
      try {
        await LeakDetectAPI.saveMonitoringConfig(this.buildPayload());
        this.$emit('back');
      } catch (e) {
        console.error('[monitoring] save failed:', e);
      }
      this.saving = false;
    },

    resetDefaults() {
      var defaults = {
        mem: {
          outstanding_delta_bytes: 10240,
          grace_seconds: 120,
          confirm_seconds: 240,
          observe_seconds: 30,
          leak_seconds: 60,
          clear_ratio: 0.5,
          clear_seconds: 30,
          resolve_seconds: 60,
          stabilize_seconds: 300
        },
        thread: {
          delta_threshold: 0.1,
          grace_seconds: 120,
          confirm_seconds: 240,
          observe_seconds: 30,
          leak_seconds: 120,
          clear_ratio: 0.5,
          clear_seconds: 30,
          resolve_seconds: 60,
          stabilize_seconds: 300
        },
        fd: {
          delta_threshold: 0.5,
          grace_seconds: 120,
          confirm_seconds: 240,
          observe_seconds: 30,
          leak_seconds: 120,
          clear_ratio: 0.5,
          clear_seconds: 30,
          resolve_seconds: 60,
          stabilize_seconds: 300
        },
        cpu: {
          cpu_interval: 1
        }
      };
      this.applyConfig(defaults);
    },
  },
};
