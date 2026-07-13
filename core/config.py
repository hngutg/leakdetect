"""YAML 配置加载。

对应里程碑：F1（基础加载）/ B1（扩展阈值）
"""

import os
import yaml


def load_config(path=None):
    """加载 YAML 配置文件。"""
    if path is None:
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        path = os.path.join(root, "config", "default.yaml")
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)
