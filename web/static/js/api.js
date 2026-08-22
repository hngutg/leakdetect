// WebSocket + REST 封装
// 对应里程碑：F1
// 对应契约：frontend-design.md §5 数据契约

const LeakDetectAPI = {
    socket: null,
    connected: false,
    onDashboardUpdate: null,
    onConnect: null,
    onDisconnect: null,

    init() {
        this.socket = io({ transports: ["websocket", "polling"] });

        this.socket.on("connect", () => {
            this.connected = true;
            console.log("[ws] connected");
            if (this.onConnect) this.onConnect();
        });

        this.socket.on("disconnect", () => {
            this.connected = false;
            console.log("[ws] disconnected");
            if (this.onDisconnect) this.onDisconnect();
        });

        this.socket.on("dashboard_update", (data) => {
            if (this.onDashboardUpdate) this.onDashboardUpdate(data);
        });
    },

    selectContainer(containerId) {
        this.socket.emit("select_container", { container_id: containerId });
    },

    async getHistory(resource, range) {
        const resp = await fetch("/api/history?resource=" + resource + "&range=" + range);
        return resp.json();
    },

    async getAlerts(range) {
        const resp = await fetch("/api/alerts?range=" + range);
        return resp.json();
    },

    async getContainers() {
        const resp = await fetch("/api/containers");
        return resp.json();
    },

    async getFilterConfig() {
        const resp = await fetch("/api/config/filter");
        return resp.json();
    },

    async saveFilterConfig(config) {
        const resp = await fetch("/api/config/filter", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(config)
        });
        return resp.json();
    },

    async previewFilter(nameRegex, pidList) {
        const resp = await fetch(
            "/api/config/filter/preview?name_regex=" +
            encodeURIComponent(nameRegex) + "&pid_list=" + pidList
        );
        return resp.json();
    },

    async getMonitoringConfig() {
        const resp = await fetch("/api/config/monitoring");
        return resp.json();
    },

    async saveMonitoringConfig(config) {
        const resp = await fetch("/api/config/monitoring", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(config)
        });
        return resp.json();
    }
};
