// FilterConfigModal 组件 - 黑白名单配置弹窗
// 对应里程碑：F3
// 对应文档：leakdetect-f3-design.md §3.3

const FilterConfigModal = {
  props: {
    visible: { type: Boolean, default: false },
  },
  emits: ['close'],
  data() {
    return {
      mode: 'disabled',
      nameRegex: '',
      pidListText: '',
      preview: null,
      previewLoading: false,
      saving: false,
    };
  },
  template: `
    <div v-if="visible" class="modal-overlay" @click.self="$emit('close')">
      <div class="modal-dialog">
        <h3>监控配置</h3>

        <div class="form-group">
          <label>过滤模式：</label>
          <label class="radio-label"><input type="radio" v-model="mode" value="disabled"> 全部监控</label>
          <label class="radio-label"><input type="radio" v-model="mode" value="whitelist"> 白名单</label>
          <label class="radio-label"><input type="radio" v-model="mode" value="blacklist"> 黑名单</label>
        </div>

        <div class="form-group" v-if="mode !== 'disabled'">
          <label>进程名正则：</label>
          <input v-model="nameRegex" placeholder="nginx|mysql|redis" class="form-input">
          <small>多个用 | 分隔，支持正则</small>
        </div>

        <div class="form-group" v-if="mode !== 'disabled'">
          <label>PID 列表：</label>
          <input v-model="pidListText" placeholder="1234, 5678" class="form-input">
          <small>逗号分隔</small>
        </div>

        <div class="form-hint" v-if="mode !== 'disabled'">
          匹配逻辑：进程名 OR PID 命中即视为匹配
        </div>

        <div class="form-group" v-if="mode !== 'disabled'">
          <button @click="doPreview" :disabled="previewLoading" class="btn-preview">
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

        <div class="modal-footer">
          <button @click="$emit('close')">取消</button>
          <button @click="doSave" :disabled="saving" class="btn-primary">
            {{ saving ? '保存中...' : '保存并应用' }}
          </button>
        </div>
      </div>
    </div>
  `,
  watch: {
    visible(val) {
      if (val) {
        this.loadConfig();
      } else {
        this.preview = null;
      }
    },
  },
  methods: {
    async loadConfig() {
      try {
        var resp = await LeakDetectAPI.getFilterConfig();
        this.mode = resp.mode || 'disabled';
        this.nameRegex = resp.name_regex || '';
        this.pidListText = (resp.pid_list || []).join(', ');
      } catch (e) {
        console.error('[filter] load config failed:', e);
      }
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
        var pids = [];
        var parts = this.pidListText.split(',');
        for (var i = 0; i < parts.length; i++) {
          var n = parseInt(parts[i].trim());
          if (!isNaN(n)) pids.push(n);
        }
        await LeakDetectAPI.saveFilterConfig({
          mode: this.mode,
          name_regex: this.nameRegex,
          pid_list: pids,
        });
        this.$emit('close');
      } catch (e) {
        console.error('[filter] save failed:', e);
      }
      this.saving = false;
    },
  },
};
