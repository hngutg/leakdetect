"""Flask + SocketIO 主服务。

对应里程碑：F1 + B1
对应文档：leakdetect-frontend-design.md §五、leakdetect-b1-design.md §八

启动方式：
    cd leakdetect
    python3 web/app.py
浏览器访问：
    http://127.0.0.1:8080
"""

import os
import sys

# 项目根目录 + web 目录加入 sys.path
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import Flask, send_from_directory
from flask_socketio import SocketIO

from api import api
from sockets import start_pusher, register_handlers
from core.config import load_config

# 加载配置
config = load_config()

# B1: 初始化后端（替代 mock）
try:
    from backend import Backend
    backend = Backend(config)
    backend.start()
    # 覆盖 sockets.py 中的全局 producer 引用
    import sockets as _sockets_mod
    _sockets_mod.backend = backend
except Exception as e:
    print("[app] WARNING: Backend init failed, falling back to mock: %s" % e)
    from mock import producer
    backend = None
    import sockets as _sockets_mod
    _sockets_mod.backend = None

STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")

app = Flask(__name__, static_folder=STATIC_DIR, static_url_path="/static")
app.config["SECRET_KEY"] = "leakdetect-dev"
app.register_blueprint(api)

socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")
register_handlers(socketio)


@socketio.on("connect")
def on_connect():
    print("[ws] client connected")


@socketio.on("disconnect")
def on_disconnect():
    print("[ws] client disconnected")


@app.route("/")
def index():
    return send_from_directory(STATIC_DIR, "index.html")


if __name__ == "__main__":
    start_pusher(socketio, interval=1)
    print("[app] LeakDetect starting at http://127.0.0.1:8080")
    print("[app] Press Ctrl+C to stop")
    socketio.run(app, host="127.0.0.1", port=8080,
                  debug=False, allow_unsafe_werkzeug=True)
