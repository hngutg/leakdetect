// Vue 主应用
// 对应里程碑：F1 + F2 + F3 + F4
// 对应文档：frontend-design.md、leakdetect-f2/f3/f4-design.md

const { createApp, reactive, ref, computed, watch, onMounted } = Vue;

const app = createApp({
    setup() {
        const connected = ref(false);
        const lastUpdate = ref("");
        const containers = ref([]);

        const resources = reactive({
            mem:    { current: 0, status: "normal" },
            thread: { current: 0, status: "normal" },
            fd:     { current: 0, status: "normal" },
            cpu:    { current: 0, status: "normal" },
        });

        const resourceOrder = ["mem", "thread", "fd", "cpu"];

        // F2: 图表数据
        const chartData = reactive({
            mem:    { range: "1d", series: [], loading: false },
            thread: { range: "1d", series: [], loading: false },
            fd:     { range: "1d", series: [], loading: false },
            cpu:    { range: "1d", series: [], loading: false },
        });

        // F3: 告警选中 + 标签切换 + 黑白名单弹窗
        const selectedAlert = ref(null);
        const alertTab = ref("current");
        const historyAlerts = ref([]);
        const historyLoading = ref(false);
        const filterConfigVisible = ref(false);

        // F4: 容器选择 + PID 输入
        const selectedContainer = ref(null);
        const pidInput = ref("");
        const activePidFilter = ref(null);

        // F4: 原始数据（未过滤）
        const rawPerProcess = reactive({
            mem: [], thread: [], fd: [], cpu: []
        });
        const rawAlerts = ref([]);

        // F4: computed 前端过滤
        const filteredPerProcess = computed(function() {
            var pid = activePidFilter.value;
            if (!pid) return rawPerProcess;
            var result = {};
            for (var i = 0; i < resourceOrder.length; i++) {
                var r = resourceOrder[i];
                result[r] = rawPerProcess[r].filter(function(p) { return p.pid === pid; });
            }
            return result;
        });

        const filteredAlerts = computed(function() {
            var pid = activePidFilter.value;
            if (!pid) return rawAlerts.value;
            return rawAlerts.value.filter(function(a) { return a.pid === pid; });
        });

        // F4: 状态联动 — 基于过滤后告警，PID/容器过滤后自动更新
        watch(filteredAlerts, function(newAlerts) {
            for (var j = 0; j < resourceOrder.length; j++) {
                resources[resourceOrder[j]].status = "normal";
            }
            for (var k = 0; k < newAlerts.length; k++) {
                var a = newAlerts[k];
                if (resources[a.resource]) {
                    resources[a.resource].status = "leak_suspected";
                }
            }
        });

        // F2: 加载历史数据
        async function loadHistory(resource, range) {
            chartData[resource].loading = true;
            try {
                var resp = await LeakDetectAPI.getHistory(resource, range);
                chartData[resource].series = resp.series || [];
            } catch (e) {
                console.error("[history] load " + resource + " failed:", e);
            }
            chartData[resource].loading = false;
        }

        async function switchRange(resource, range) {
            chartData[resource].range = range;
            await loadHistory(resource, range);
        }

        function appendPoint(resource, point) {
            if (!point) return;
            var cd = chartData[resource];
            var maxAge = { "1d": 86400, "7d": 604800, "30d": 2592000 }[cd.range] || 86400;
            var cutoff = (Date.now() / 1000) - maxAge;
            var newSeries = cd.series.filter(function(p) { return p.t >= cutoff; });
            newSeries.push(point);
            cd.series = newSeries;
        }

        function handleDashboardUpdate(data) {
            if (data.latest_points) {
                resources.mem.current = data.latest_points.mem.v;
                resources.thread.current = data.latest_points.thread.v;
                resources.fd.current = data.latest_points.fd.v;
                resources.cpu.current = data.latest_points.cpu.v;

                for (var i = 0; i < resourceOrder.length; i++) {
                    var r = resourceOrder[i];
                    if (data.latest_points[r]) {
                        appendPoint(r, data.latest_points[r]);
                    }
                }
            }

            // F4: 存原始 per_process
            if (data.per_process) {
                rawPerProcess.mem = data.per_process.mem || [];
                rawPerProcess.thread = data.per_process.thread || [];
                rawPerProcess.fd = data.per_process.fd || [];
                rawPerProcess.cpu = data.per_process.cpu || [];
            }

            // F4: 存原始告警
            rawAlerts.value = data.alerts || [];

            containers.value = data.containers || [];
            lastUpdate.value = new Date().toLocaleTimeString();
        }

        function formatValue(resource, v) {
            if (v === undefined || v === null) return "-";
            if (resource === "mem") {
                return (v / 1024 / 1024).toFixed(1) + " MB";
            }
            if (resource === "cpu") {
                return v.toFixed(1) + " %";
            }
            return String(v);
        }

        function statusText(status) {
            return { normal: "正常", leak_suspected: "疑似泄露", observing: "观察中" }[status] || status;
        }

        function resourceLabel(r) {
            return { mem: "内存", thread: "线程", fd: "句柄", cpu: "CPU" }[r] || r;
        }

        function formatTime(ts) {
            return new Date(ts * 1000).toLocaleTimeString();
        }

        // F3: 告警点击
        function selectAlert(alert) {
            selectedAlert.value = alert;
        }

        async function switchAlertTab(tab) {
            alertTab.value = tab;
            if (tab === "history" && historyAlerts.value.length === 0) {
                historyLoading.value = true;
                try {
                    var resp = await LeakDetectAPI.getAlerts("24h");
                    historyAlerts.value = resp.alerts || [];
                } catch (e) {
                    console.error("[alerts] load history failed:", e);
                }
                historyLoading.value = false;
            }
        }

        function openFilterConfig() {
            filterConfigVisible.value = true;
        }
        function closeFilterConfig() {
            filterConfigVisible.value = false;
        }

        // F4: 容器切换
        function onContainerChange() {
            LeakDetectAPI.selectContainer(selectedContainer.value);
        }

        // F4: PID 应用
        function applyPidFilter() {
            var pid = parseInt(pidInput.value.trim());
            activePidFilter.value = isNaN(pid) ? null : pid;
        }

        // F4: 清除所有过滤
        function clearFilters() {
            selectedContainer.value = null;
            pidInput.value = "";
            activePidFilter.value = null;
            LeakDetectAPI.selectContainer(null);
        }

        onMounted(function() {
            LeakDetectAPI.onDashboardUpdate = handleDashboardUpdate;
            LeakDetectAPI.onConnect = function() { connected.value = true; };
            LeakDetectAPI.onDisconnect = function() { connected.value = false; };
            LeakDetectAPI.init();

            for (var i = 0; i < resourceOrder.length; i++) {
                loadHistory(resourceOrder[i], "1d");
            }
        });

        return {
            connected, lastUpdate, containers, resources, resourceOrder,
            chartData, loadHistory, switchRange,
            selectedAlert, alertTab, historyAlerts, historyLoading, filterConfigVisible,
            selectAlert, switchAlertTab, openFilterConfig, closeFilterConfig,
            selectedContainer, pidInput, activePidFilter,
            rawPerProcess, rawAlerts,
            filteredPerProcess, filteredAlerts,
            onContainerChange, applyPidFilter, clearFilters,
            formatValue, statusText, resourceLabel, formatTime,
        };
    }
});

app.component('LineChart', LineChart);
app.component('StackView', StackView);
app.component('FilterConfigModal', FilterConfigModal);

app.mount("#app");
