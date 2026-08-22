// ConfigPage 组件 - 进程管理配置页面（全屏页面，非模态弹窗）
// 支持白名单导入导出，不含黑名单

const ConfigPage = {
  emits: ['back'],
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
    <div class="config-page">
      <div class="config-header">
        <button @click="$emit('back')" class="btn-back">← 返回</button>
        <h2>进程管理配置</h2>
      </div>
      <div class="config-body">
        <div class="form-group">
          <label>过滤模式：</label>
          <label class="radio-label"><input type="radio" v-model="mode" value="disabled"> 全部监控</label>
          <label class="radio-label"><input type="radio" v-model="mode" value="whitelist"> 白名单</label>
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

        <div class="config-import-export">
          <input type="file" ref="fileInput" style="display:none" accept=".json" @change="doImport">
          <button @click="$refs.fileInput.click()" class="btn-import">导入配置</button>
          <button @click="doExport" class="btn-export">导出配置</button>
        </div>

        <div class="modal-footer">
          <button @click="$emit('back')">取消</button>
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
    parsePids() {
      var pids = [];
      var parts = this.pidListText.split(',');
      for (var i = 0; i < parts.length; i++) {
        var n = parseInt(parts[i].trim());
        if (!isNaN(n)) pids.push(n);
      }
      return pids;
    },

    async loadConfig() {
      try {
        var resp = await LeakDetectAPI.getFilterConfig();
        this.mode = resp.mode || 'disabled';
        if (this.mode === 'blacklist') this.mode = 'whitelist';
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
        await LeakDetectAPI.saveFilterConfig({
          mode: this.mode,
          name_regex: this.nameRegex,
          pid_list: this.parsePids(),
        });
        this.$emit('back');
      } catch (e) {
        console.error('[filter] save failed:', e);
      }
      this.saving = false;
    },

    doExport() {
      var config = {
        mode: this.mode,
        name_regex: this.nameRegex,
        pid_list: this.parsePids(),
      };
      var blob = new Blob([JSON.stringify(config, null, 2)], { type: 'application/json' });
      var url = URL.createObjectURL(blob);
      var a = document.createElement('a');
      a.href = url;
      a.download = 'leakdetect-whitelist.json';
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    },

    doImport(event) {
      var file = event.target.files[0];
      if (!file) return;
      var self = this;
      var reader = new FileReader();
      reader.onload = function(e) {
        try {
          var config = JSON.parse(e.target.result);
          self.mode = config.mode || 'disabled';
          if (self.mode === 'blacklist') self.mode = 'whitelist';
          self.nameRegex = config.name_regex || '';
          self.pidListText = (config.pid_list || []).join(', ');
          self.preview = null;
        } catch (err) {
          alert('导入失败：文件格式不正确');
        }
      };
      reader.readAsText(file);
      event.target.value = '';
    },
  },
};
