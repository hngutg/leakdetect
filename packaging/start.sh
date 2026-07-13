#!/bin/bash
# start.sh - LeakDetect 启动脚本（自包含打包版）
# 用法：./start.sh
# 前置：root 权限，BTF 可用，Python 3 已安装
set -e

DIR="$(cd "$(dirname "$0")" && pwd)"

# 1. 检查 root
if [ "$(id -u)" != "0" ]; then
    echo "ERROR: Need root (eBPF requires root)"
    exit 1
fi

# 2. 检查 BTF
if [ ! -f /sys/kernel/btf/vmlinux ]; then
    echo "ERROR: BTF not found (/sys/kernel/btf/vmlinux)"
    echo "Kernel 5.10+ with CONFIG_DEBUG_INFO_BTF required"
    exit 1
fi

# 3. 检查 Python 3
if ! command -v python3 >/dev/null 2>&1; then
    echo "ERROR: python3 not found"
    exit 1
fi

# 4. 设置环境变量
export LD_LIBRARY_PATH="$DIR/lib:$LD_LIBRARY_PATH"
export PYTHONPATH="$DIR/py-packages:$DIR:$PYTHONPATH"

echo "LeakDetect starting..."
echo "  Dir: $DIR"
echo "  Python: $(python3 --version)"
echo "  BTF: OK"
echo "  libbpf: $(ls $DIR/lib/libbpf* 2>/dev/null || echo 'not found')"
echo ""

cd "$DIR"
exec python3 web/app.py
