"""REST 路由（历史查询 + 配置）。

对应里程碑：F1 → B1
对应文档：frontend-design.md §5.3、leakdetect-b1-design.md §8.3

B1 变更：/api/history 从 mock 切换到 backend.db（如果 backend 可用）
"""

from flask import Blueprint, jsonify, request

api = Blueprint("api", __name__)

# backend 引用（app.py 初始化时设置）
_backend = None


def set_backend(b):
    global _backend
    _backend = b


@api.route("/api/history")
def history():
    resource = request.args.get("resource", "mem")
    range_tag = request.args.get("range", "1d")
    container_id = request.args.get("container_id")
    if _backend is not None:
        return jsonify(_backend.get_history(resource, range_tag, container_id))
    from mock import producer
    return jsonify(producer.get_history(resource, range_tag, container_id))


@api.route("/api/alerts")
def alerts():
    range_tag = request.args.get("range", "24h")
    if _backend is not None:
        return jsonify({"alerts": _backend.get_alerts(range_tag)})
    from mock import producer
    return jsonify({"alerts": producer.get_alerts(range_tag)})


@api.route("/api/containers")
def containers():
    if _backend is not None:
        return jsonify({"containers": _backend.cgroup_enum.enumerate()})
    from mock import producer
    return jsonify({"containers": producer.containers})


@api.route("/api/config/filter", methods=["GET"])
def get_filter():
    if _backend is not None:
        return jsonify({"mode": "disabled", "name_regex": "", "pid_list": []})
    from mock import producer
    return jsonify(producer.get_filter_config())


@api.route("/api/config/filter", methods=["POST"])
def set_filter():
    data = request.get_json(silent=True) or {}
    if _backend is not None:
        return jsonify({"status": "applied", "matched_pids": []})
    from mock import producer
    result = producer.save_filter_config(data)
    return jsonify(result)


@api.route("/api/config/filter/preview")
def preview_filter():
    name_regex = request.args.get("name_regex", "")
    pid_list = request.args.get("pid_list", "")
    if _backend is not None:
        return jsonify({"matched": [], "unmatched": []})
    from mock import producer
    return jsonify(producer.preview_filter(name_regex, pid_list))


@api.route("/api/config/monitoring", methods=["GET"])
def get_monitoring_config():
    if _backend is not None:
        return jsonify(_backend.get_monitoring_config())
    from mock import producer
    return jsonify(producer.get_monitoring_config())


@api.route("/api/config/monitoring", methods=["POST"])
def set_monitoring_config():
    data = request.get_json(silent=True) or {}
    if _backend is not None:
        _backend.update_monitoring_config(data)
        return jsonify({"status": "applied"})
    from mock import producer
    return jsonify(producer.save_monitoring_config(data))
