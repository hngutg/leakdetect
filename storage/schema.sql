-- LeakDetect SQLite Schema
-- 对应文档：前端文档 §7.2（历史采样）、§八（告警记录）

-- 资源采样表：每分钟快照一次各资源状态
CREATE TABLE IF NOT EXISTS samples (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   INTEGER NOT NULL,              -- Unix 时间戳（秒）
    resource    TEXT    NOT NULL,              -- 'mem' | 'thread' | 'fd' | 'cpu'
    pid         INTEGER,                       -- 进程 PID（聚合值为 NULL）
    process_name TEXT,
    container_id TEXT,                         -- 容器 ID（无容器为 NULL）
    value       REAL    NOT NULL,              -- 采样值（mem=bytes, thread=count, fd=count, cpu=percent）
    delta_60s   REAL                           -- 60 秒内变化量
);

CREATE INDEX IF NOT EXISTS idx_samples_resource_ts ON samples (resource, timestamp);
CREATE INDEX IF NOT EXISTS idx_samples_pid_ts      ON samples (pid, timestamp);
CREATE INDEX IF NOT EXISTS idx_samples_container   ON samples (container_id);

-- 降采样表：7天/30天视图从 samples 聚合
CREATE TABLE IF NOT EXISTS samples_downsampled (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   INTEGER NOT NULL,
    resource    TEXT    NOT NULL,
    pid         INTEGER,
    process_name TEXT,
    container_id TEXT,
    value       REAL    NOT NULL,
    range_tag   TEXT    NOT NULL               -- '7d' | '30d'
);

CREATE INDEX IF NOT EXISTS idx_downsampled_range ON samples_downsampled (range_tag, resource, timestamp);

-- 告警记录表
CREATE TABLE IF NOT EXISTS alerts (
    id           TEXT    PRIMARY KEY,          -- 告警 ID，如 'a001'
    timestamp    INTEGER NOT NULL,
    resource     TEXT    NOT NULL,             -- 'mem' | 'thread' | 'fd'
    pid          INTEGER NOT NULL,
    process_name TEXT,
    severity     TEXT    NOT NULL,             -- 'leak' | 'observing'
    detail       TEXT,
    stack_json   TEXT                           -- JSON 数组：[{func, addr}, ...]
);

CREATE INDEX IF NOT EXISTS idx_alerts_ts      ON alerts (timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_resource ON alerts (resource, timestamp);

-- 黑白名单配置持久化（运行时可被前台修改）
CREATE TABLE IF NOT EXISTS filter_config (
    key    TEXT PRIMARY KEY,
    value  TEXT
);
