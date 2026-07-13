"""WebSocket 推送 dashboard_update。

对应里程碑：F1 + B1
对应文档：frontend-design.md §5.2、leakdetect-b1-design.md §8.2

B1 变更：推送数据源从 mock 切换到 backend（如果 backend 可用）
"""

backend = None  # app.py 初始化时赋值


def start_pusher(socketio, interval=1):
    """启动后台任务，每 interval 秒推送一次 dashboard_update。"""

    def push_loop():
        while True:
            socketio.sleep(interval)
            try:
                if backend is not None:
                    data = backend.get_dashboard_update()
                else:
                    from mock import producer
                    data = producer.get_dashboard_update()
                socketio.emit("dashboard_update", data)
            except Exception as e:
                print("[sockets] push error: %s" % e)

    socketio.start_background_task(push_loop)


def register_handlers(socketio):
    """注册 WebSocket 事件处理器。"""

    @socketio.on("connect")
    def on_connect():
        print("[ws] client connected")

    @socketio.on("disconnect")
    def on_disconnect():
        print("[ws] client disconnected")

    @socketio.on("select_container")
    def on_select_container(data):
        cid = data.get("container_id") if data else None
        print("[ws] select_container: %s" % cid)
        if backend is not None:
            pass  # B3: backend.loader.update_cgroup_filter(cid)
        else:
            from mock import producer
            producer.set_selected_container(cid)
