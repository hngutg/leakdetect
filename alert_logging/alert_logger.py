"""告警本地日志写入。

对应里程碑：B1
对应文档：leakdetect-b1-design.md §6.7
"""

import os
from datetime import datetime


class AlertLogger:
    """告警 + 恢复日志写入本地文件。"""

    def __init__(self, path):
        self.path = path
        dir_path = os.path.dirname(path)
        if dir_path and not os.path.exists(dir_path):
            os.makedirs(dir_path)

    def log(self, alert):
        """写入日志。"""
        with open(self.path, "a") as f:
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            if alert["severity"] == "leak":
                stack_str = " → ".join(
                    frame.get("func", "?") for frame in alert.get("stack", []))
                f.write("[%s] MEM LEAK PID=%d %s | %s | %s\n" % (
                    ts, alert["pid"], alert.get("process_name", ""),
                    alert["detail"], stack_str))
            elif alert["severity"] == "resolved":
                f.write("[%s] MEM RESOLVED PID=%d %s | %s\n" % (
                    ts, alert["pid"], alert.get("process_name", ""),
                    alert["detail"]))
