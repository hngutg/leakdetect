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
            mmap:   { current: 0, status: "normal" },
            thread: { current: 0, status: "normal" },
            fd:     { current: 0, status: "normal" },
            cpu:    { current: 0, status: "normal" },
        });

        const resourceOrder = ["cpu", "mem", "mmap", "thread", "fd"];

        // F2: 图表数据
        const chartData = reactive({
            mem:    { range: "1d", series: [], loading: false },
            mmap:   { range: "1d", series: [], loading: false },
            thread: { range: "1d", series: [], loading: false },
            fd:     { range: "1d", series: [], loading: false },
            cpu:    { range: "1d", series: [], loading: false },
        });

        // F3: 告警选中 + 标签切换
        const selectedAlert = ref(null);
        const alertTab = ref("current");
        const historyAlerts = ref([]);
        const historyLoading = ref(false);

        // 页面切换：dashboard / config
        const currentView = ref("dashboard");

        // F4: 容器选择 + PID 输入
        const selectedContainer = ref("all");
        const pidInput = ref("");
        const activePidFilter = ref(null);

        // F4: 原始数据（未过滤）
        const rawPerProcess = reactive({
            mem: [], mmap: [], thread: [], fd: [], cpu: []
        });
        const rawAlerts = ref([]);

        // 容器概览：summary 来自契约，trends 前端实时累积（cap 600 = 10min@1s）
        const containerSummary = ref([]);
        const containerTrends = reactive({});

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

        // 疑似/确认分流（前台三 tab：当前告警=疑似、确认泄露=确认、历史告警）
        const suspectedAlerts = computed(function() {
            return filteredAlerts.value.filter(function(a) { return a.severity === "suspected"; });
        });
        const confirmedAlerts = computed(function() {
            return filteredAlerts.value.filter(function(a) { return a.severity === "confirmed"; });
        });

        // F4: 状态联动 — 基于过滤后告警，PID/容器过滤后自动更新
        watch(filteredAlerts, function(newAlerts) {
            for (var j = 0; j < resourceOrder.length; j++) {
                resources[resourceOrder[j]].status = "normal";
            }
            for (var k = 0; k < newAlerts.length; k++) {
                var a = newAlerts[k];
                if (resources[a.resource]) {
                    // confirmed 优先（红）；仅 suspected 则橙；resolved 不影响状态
                    if (a.severity === "confirmed") {
                        resources[a.resource].status = "leak_confirmed";
                    } else if (a.severity === "suspected" && resources[a.resource].status === "normal") {
                        resources[a.resource].status = "leak_suspected";
                    }
                }
            }
        });

        // F2: 加载历史数据
        async function loadHistory(resource, range) {
            var cid = selectedContainer.value;
            chartData[resource].loading = true;
            try {
                var resp = await LeakDetectAPI.getHistory(resource, range, cid);
                if (selectedContainer.value === cid) {
                    var dbSeries = resp.series || [];
                    // 合并：DB 长期历史（60s）+ containerTrends 近期波形（1s，10min）
                    if (cid !== "all") {
                        var trends = containerTrends[String(cid)] || [];
                        if (trends.length > 0) {
                            var trendSeries = trends.map(function(p) { return {t: p.t, v: p[resource]}; });
                            var trendStart = trendSeries[0].t;
                            var oldDb = dbSeries.filter(function(p) { return p.t < trendStart; });
                            chartData[resource].series = oldDb.concat(trendSeries);
                        } else {
                            chartData[resource].series = dbSeries;
                        }
                    } else {
                        chartData[resource].series = dbSeries;
                    }
                }
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
            // 容器一致性检查：只处理与当前选中容器匹配的推送（防止切换后旧容器推送残留）
            var pushCid = data.filter ? data.filter.container_id : undefined;
            if (pushCid === selectedContainer.value) {
                if (data.latest_points) {
                    resources.mem.current = data.latest_points.mem.v;
                    resources.mmap.current = data.latest_points.mmap.v;
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
                    rawPerProcess.mmap = data.per_process.mmap || [];
                    rawPerProcess.thread = data.per_process.thread || [];
                    rawPerProcess.fd = data.per_process.fd || [];
                    rawPerProcess.cpu = data.per_process.cpu || [];
                }

                // F4: 存原始告警
                rawAlerts.value = data.alerts || [];
            }

            // 以下始终更新（全局数据，不依赖 display_target）
            containers.value = data.containers || [];

            // 容器概览：更新 summary + 累积每容器 mem 趋势（cap 600 = 10min@1s）
            if (data.container_summary) {
                containerSummary.value = data.container_summary;
                var now = data.timestamp;
                var liveKeys = {};
                data.container_summary.forEach(function(c) {
                    var key = String(c.id);
                    liveKeys[key] = true;
                    var arr = containerTrends[key] || [];
                    var newArr = arr.slice();
                    newArr.push({ t: now, mem: c.mem, mmap: c.mmap, thread: c.thread, fd: c.fd, cpu: c.cpu });
                    if (newArr.length > 600) newArr.shift();
                    containerTrends[key] = newArr;
                });
                Object.keys(containerTrends).forEach(function(k) {
                    if (!liveKeys[k]) delete containerTrends[k];
                });
            }

            lastUpdate.value = new Date().toLocaleTimeString();
        }

        function formatValue(resource, v) {
            if (v === undefined || v === null) return "-";
            if (resource === "mem" || resource === "mmap") {
                return (v / 1024 / 1024).toFixed(1) + " MB";
            }
            if (resource === "cpu") {
                return v.toFixed(1) + " %";
            }
            return String(v);
        }

        function statusText(status) {
            return { normal: "正常", leak_suspected: "疑似泄露", leak_confirmed: "确认泄露", observing: "观察中" }[status] || status;
        }

        function resourceLabel(r) {
            return { mem: "堆内存(malloc)", mmap: "映射内存(mmap)", thread: "线程", fd: "句柄", cpu: "CPU" }[r] || r;
        }

        function formatTime(ts) {
            return new Date(ts * 1000).toLocaleTimeString();
        }

        // F3: 告警点击（toggle：再次点击同一告警收起）
        function selectAlert(alert) {
            if (selectedAlert.value && selectedAlert.value.id === alert.id) {
                selectedAlert.value = null;
            } else {
                selectedAlert.value = alert;
            }
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

        // 页面切换
        function showConfig() { currentView.value = "process_config"; }
        function showMonitoringConfig() { currentView.value = "monitoring_config"; }
        function showDashboard() { currentView.value = "dashboard"; }

        // F4: 容器切换
        function onContainerChange() {
            LeakDetectAPI.selectContainer(selectedContainer.value);
            clearChartData();
            if (selectedContainer.value !== "all") {
                loadContainerTrends(selectedContainer.value);
            }
        }

        // 概览条点击：toggle 下钻（点已选中卡 → 回"全部"）
        function onOverviewSelect(cid) {
            if (selectedContainer.value === cid) {
                selectedContainer.value = "all";
                LeakDetectAPI.selectContainer("all");
            } else {
                selectedContainer.value = cid;
                LeakDetectAPI.selectContainer(cid);
            }
            clearChartData();
            if (selectedContainer.value !== "all") {
                loadContainerTrends(selectedContainer.value);
            }
        }

        // F4: PID 应用
        function applyPidFilter() {
            var pid = parseInt(pidInput.value.trim());
            activePidFilter.value = isNaN(pid) ? null : pid;
        }

        // F4: 清除所有过滤
        function clearFilters() {
            selectedContainer.value = "all";
            pidInput.value = "";
            activePidFilter.value = null;
            LeakDetectAPI.selectContainer("all");
            clearChartData();
        }

        function clearChartData() {
            for (var i = 0; i < resourceOrder.length; i++) {
                chartData[resourceOrder[i]].series = [];
            }
        }

        function reloadAllHistory() {
            for (var i = 0; i < resourceOrder.length; i++) {
                var r = resourceOrder[i];
                loadHistory(r, chartData[r].range);
            }
        }

        function loadContainerTrends(cid) {
            var key = String(cid);
            var trends = containerTrends[key] || [];
            for (var i = 0; i < resourceOrder.length; i++) {
                var r = resourceOrder[i];
                chartData[r].series = trends.map(function(p) { return {t: p.t, v: p[r]}; });
            }
        }

        onMounted(function() {
            LeakDetectAPI.onDashboardUpdate = handleDashboardUpdate;
            LeakDetectAPI.onConnect = function() { connected.value = true; };
            LeakDetectAPI.onDisconnect = function() { connected.value = false; };
            LeakDetectAPI.init();
        });

        return {
            connected, lastUpdate, containers, resources, resourceOrder,
            chartData, loadHistory, switchRange,
            selectedAlert, alertTab, historyAlerts, historyLoading,
            selectAlert, switchAlertTab,
            currentView, showConfig, showMonitoringConfig, showDashboard,
            selectedContainer, pidInput, activePidFilter,
            rawPerProcess, rawAlerts,
            containerSummary, containerTrends, onOverviewSelect,
            filteredPerProcess, filteredAlerts, suspectedAlerts, confirmedAlerts,
            onContainerChange, applyPidFilter, clearFilters,
            formatValue, statusText, resourceLabel, formatTime,
        };
    }
});

app.component('LineChart', LineChart);
app.component('StackView', StackView);
app.component('Sparkline', Sparkline);
app.component('ContainerOverview', ContainerOverview);
app.component('ConfigPage', ConfigPage);
app.component('MonitoringConfigPage', MonitoringConfigPage);

app.mount("#app");
