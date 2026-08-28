"""P4 验证脚本：/api/alerts 接 DB（query_alerts 往返测试）。

无需 root/eBPF，用内存 SQLite 测试 write_alert + query_alerts 往返。
验证：字段对齐、排序、INSERT OR REPLACE、时间过滤、stack 解析、空栈、未知 range。

运行：python3 tests/verify_p4.py
"""

import sys
import os
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from storage.db import Database

ALL_PASS = True


def check(name, actual, expected):
    global ALL_PASS
    ok = actual == expected
    if not ok:
        ALL_PASS = False
    print("  [%s] %s: actual=%s expected=%s" % (name, "PASS" if ok else "FAIL", actual, expected))


def check_true(name, cond):
    global ALL_PASS
    if not cond:
        ALL_PASS = False
    print("  [%s] %s" % (name, "PASS" if cond else "FAIL"))


db = Database(":memory:")
now = int(time.time())

print("=== P4 query_alerts 往返验证 ===")

# 写入 2 条告警
db.write_alert({
    "id": "mem-1234", "timestamp": now - 3600, "resource": "mem",
    "pid": 1234, "process_name": "nginx", "severity": "confirmed",
    "detail": "+5000000 in 300s",
    "stack": [{"func": "main+0x3a", "addr": "0x401000"},
              {"func": "malloc", "addr": "0x401800"}],
})
db.write_alert({
    "id": "fd-5678", "timestamp": now - 7200, "resource": "fd",
    "pid": 5678, "process_name": "mysql", "severity": "suspected",
    "detail": "+30 in 120s",
    "stack": [{"func": "open", "addr": "0x402000"}],
})

# 场景1: 查询返回 2 条
alerts = db.query_alerts("24h")
check("count", len(alerts), 2)

# 场景2: DESC 排序（最新在前）
check_true("sort_desc", alerts[0]["timestamp"] >= alerts[1]["timestamp"])

# 场景3: 字段格式
a = alerts[0]
check_true("has_id", "id" in a)
check_true("has_timestamp", "timestamp" in a)
check_true("has_resource", "resource" in a)
check_true("has_pid", "pid" in a)
check_true("has_process_name", "process_name" in a)
check_true("has_severity", "severity" in a)
check_true("has_detail", "detail" in a)
check_true("has_stack", "stack" in a)
check("pid_type", isinstance(a["pid"], int), True)
check("process_name_type", isinstance(a["process_name"], str), True)

# 场景4: stack 解析（JSON 字符串 → list of dict）
mem_alert = [a for a in alerts if a["id"] == "mem-1234"][0]
check("stack_type", isinstance(mem_alert["stack"], list), True)
check("stack_len", len(mem_alert["stack"]), 2)
check("stack_func", mem_alert["stack"][0]["func"], "main+0x3a")
check("stack_addr", mem_alert["stack"][0]["addr"], "0x401000")

fd_alert = [a for a in alerts if a["id"] == "fd-5678"][0]
check("fd_stack_len", len(fd_alert["stack"]), 1)
check("fd_stack_func", fd_alert["stack"][0]["func"], "open")

# 场景5: INSERT OR REPLACE（同 ID 写第二次 → 行数不变，状态更新为最新）
db.write_alert({
    "id": "mem-1234", "timestamp": now, "resource": "mem",
    "pid": 1234, "process_name": "nginx", "severity": "resolved",
    "detail": "resolved: 0 (peak 5000000)",
    "stack": [{"func": "main+0x3a", "addr": "0x401000"}],
})
alerts = db.query_alerts("24h")
check("replace_count", len(alerts), 2)
mem_alert = [a for a in alerts if a["id"] == "mem-1234"][0]
check("replace_severity", mem_alert["severity"], "resolved")
check("replace_timestamp", mem_alert["timestamp"], now)
check("replace_stack_len", len(mem_alert["stack"]), 1)

# 场景6: 时间范围过滤（25h 前的告警不在 24h 范围内）
db.write_alert({
    "id": "thread-9999", "timestamp": now - 90000,  # 25h ago
    "resource": "thread", "pid": 9999, "process_name": "old_proc",
    "severity": "confirmed", "detail": "old alert 25h ago",
    "stack": [{"func": "clone", "addr": "0x403000"}],
})
alerts = db.query_alerts("24h")
check("range_filter", len(alerts), 2)
check_true("old_excluded", all(a["id"] != "thread-9999" for a in alerts))

# 场景7: 空栈告警
db.write_alert({
    "id": "thread-8888", "timestamp": now, "resource": "thread",
    "pid": 8888, "process_name": "empty_stack", "severity": "suspected",
    "detail": "no stack info", "stack": [],
})
alerts = db.query_alerts("24h")
empty_alert = [a for a in alerts if a["id"] == "thread-8888"][0]
check("empty_stack", empty_alert["stack"], [])

# 场景8: 未知 range_tag 默认 24h
alerts_default = db.query_alerts("unknown_range")
check("unknown_range", len(alerts_default), len(db.query_alerts("24h")))

# 场景9: 空数据库
db2 = Database(":memory:")
check("empty_db", len(db2.query_alerts("24h")), 0)

print("")
if ALL_PASS:
    print("=== 全部 PASS ===")
else:
    print("=== 有 FAIL，请检查 ===")
    sys.exit(1)
