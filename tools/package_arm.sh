#!/bin/bash
# package_arm.sh - 在 x86_64 上打包 aarch64 自包含包
# 用法：./tools/package_arm.sh [python_version]
#   python_version: 目标机 Python 版本（默认：3.11）
# 前置：clang、pip、apt（用于下载 arm64 包）
#
# 前置条件（只需一次）：
#   sudo sh -c 'echo "deb [arch=arm64] http://ports.ubuntu.com/ubuntu-ports noble main" > /etc/apt/sources.list.d/arm64.list'
#   sudo apt update
set -e

DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$DIR"

TARGET_PY="${1:-3.11}"
PKG_NAME="leakdetect-aarch64-py${TARGET_PY}"
PKG_DIR="dist/$PKG_NAME"
ARM64_HEADERS="/tmp/arm64-headers"

echo "=== Packaging LeakDetect for aarch64 (Python $TARGET_PY) ==="

# ========== 1. 准备 aarch64 头文件 ==========
echo "[1/6] Preparing aarch64 headers..."

if [ ! -d "$ARM64_HEADERS/usr/include/aarch64-linux-gnu/asm" ]; then
    echo "  Downloading arm64 linux-libc-dev..."
    cd /tmp
    apt-get download linux-libc-dev:arm64 2>/dev/null || true
    mkdir -p "$ARM64_HEADERS"
    dpkg-deb -x linux-libc-dev_*_arm64.deb "$ARM64_HEADERS" 2>/dev/null || true
    cd "$DIR"
fi

if [ ! -d "$ARM64_HEADERS/usr/include/aarch64-linux-gnu/asm" ]; then
    echo "  ERROR: arm64 headers not found at $ARM64_HEADERS"
    echo "  Try: sudo sh -c 'echo \"deb [arch=arm64] http://ports.ubuntu.com/ubuntu-ports noble main\" > /etc/apt/sources.list.d/arm64.list' && sudo apt update"
    exit 1
fi

echo "  arm64 headers OK: $ARM64_HEADERS"

# ========== 2. 交叉编译 aarch64 .o ==========
echo "[2/6] Cross-compiling BPF .o for aarch64..."

mkdir -p bpf/compiled

CFLAGS="-target bpf -D__TARGET_ARCH_arm64 -g -O2"
INCLUDES="-I${ARM64_HEADERS}/usr/include/aarch64-linux-gnu -I${ARM64_HEADERS}/usr/include -I/usr/include -Ibpf"

clang $CFLAGS $INCLUDES -c bpf/mem.bpf.c -o bpf/compiled/mem.o
clang $CFLAGS $INCLUDES -c bpf/threads.bpf.c -o bpf/compiled/threads.o
clang $CFLAGS $INCLUDES -c bpf/fd.bpf.c -o bpf/compiled/fd.o

echo "  BPF .o compiled:"
ls -la bpf/compiled/*.o

# ========== 3. 组装包目录 ==========
echo "[3/6] Assembling package structure..."
rm -rf "$PKG_DIR"
mkdir -p "$PKG_DIR"/{bpf/compiled,lib,py-packages,config,tests/leak_programs,data}

# 拷贝 aarch64 .o
cp bpf/compiled/*.o "$PKG_DIR/bpf/compiled/"

# 拷贝项目源码
cp -r core analyzer symbolizer storage alert_logging web "$PKG_DIR/"
cp config/default.yaml "$PKG_DIR/config/"
cp -r tests/leak_programs/*.c "$PKG_DIR/tests/leak_programs/"
cp tests/verify_fd.py "$PKG_DIR/tests/"

# 交叉编译测试程序（直接编到包目录，不覆盖源码树 x86 二进制）
if command -v aarch64-linux-gnu-gcc >/dev/null 2>&1; then
    echo "  Cross-compiling test programs for aarch64..."
    aarch64-linux-gnu-gcc -O2 -fno-omit-frame-pointer tests/leak_programs/mem_leak.c -o "$PKG_DIR/tests/leak_programs/mem_leak"
    aarch64-linux-gnu-gcc -O2 -fno-omit-frame-pointer -pthread tests/leak_programs/thread_leak.c -o "$PKG_DIR/tests/leak_programs/thread_leak"
    aarch64-linux-gnu-gcc -O2 -fno-omit-frame-pointer tests/leak_programs/fd_leak.c -o "$PKG_DIR/tests/leak_programs/fd_leak"
    aarch64-linux-gnu-gcc -O2 -fno-omit-frame-pointer tests/leak_programs/steady_alloc.c -o "$PKG_DIR/tests/leak_programs/steady_alloc"
    aarch64-linux-gnu-gcc -O2 -fno-omit-frame-pointer tests/leak_programs/slow_start.c -o "$PKG_DIR/tests/leak_programs/slow_start"
    chmod +x "$PKG_DIR/tests/leak_programs/"{mem_leak,thread_leak,fd_leak,steady_alloc,slow_start}
else
    echo "  WARNING: aarch64-linux-gnu-gcc not found, test programs not compiled"
    echo "  Install: sudo apt install gcc-aarch64-linux-gnu"
fi

cp packaging/start.sh "$PKG_DIR/"
cp requirements.txt "$PKG_DIR/"

# ========== 4. 下载 Python 包 ==========
echo "[4/6] Downloading Python packages (target: Python $TARGET_PY)..."

TARGET_PY_MAJOR=$(echo "$TARGET_PY" | cut -d. -f1)
TARGET_PY_MINOR=$(echo "$TARGET_PY" | cut -d. -f2)
if [ "$TARGET_PY_MAJOR" -lt 3 ] || ([ "$TARGET_PY_MAJOR" -eq 3 ] && [ "$TARGET_PY_MINOR" -lt 10 ]); then
    echo "  Python $TARGET_PY < 3.10, using pinned versions"
    PIP_PACKS="flask<2.3 flask-socketio<5.3 click<8.1 werkzeug<3.0 markupsafe pyyaml pyelftools"
else
    echo "  Python $TARGET_PY >= 3.10, using latest versions"
    PIP_PACKS="flask flask-socketio pyyaml pyelftools"
fi

pip download --python-version "$TARGET_PY" --only-binary :all: -d "$PKG_DIR/py-packages/" $PIP_PACKS 2>/dev/null || true

# 解压 .whl
cd "$PKG_DIR/py-packages/"
for f in *.whl; do
    [ -f "$f" ] && unzip -oq "$f" && rm "$f"
done
cd "$DIR"

# ========== 5. 获取 aarch64 共享库 ==========
echo "[5/6] Fetching aarch64 shared libraries..."

cd /tmp
apt-get download libbpf1:arm64 2>/dev/null || true
rm -rf /tmp/arm64-libs
mkdir -p /tmp/arm64-libs
for deb in libbpf1_*_arm64.deb; do
    [ -f "$deb" ] && dpkg-deb -x "$deb" /tmp/arm64-libs/
done
cd "$DIR"

find /tmp/arm64-libs -name "libbpf.so*" -exec cp {} "$PKG_DIR/lib/" \; 2>/dev/null || true
rm -f /tmp/libbpf1_*_arm64.deb
rm -rf /tmp/arm64-libs

if [ -z "$(ls "$PKG_DIR/lib/"libbpf* 2>/dev/null)" ]; then
    echo "  WARNING: libbpf.so not found!"
    echo "  Try: sudo apt update && apt-get download libbpf1:arm64"
fi

# ========== 6. 打包 ==========
echo "[6/6] Creating tar.gz..."

# 去 BOM
sed -i '1s/^\xEF\xBB\xBF//' "$PKG_DIR/start.sh" 2>/dev/null || true
chmod +x "$PKG_DIR/start.sh"

cd dist
tar czf "${PKG_NAME}.tar.gz" "$PKG_NAME"
cd "$DIR"

echo ""
echo "=== Done ==="
echo "Package: dist/${PKG_NAME}.tar.gz"
echo "Size: $(du -sh "dist/${PKG_NAME}.tar.gz" | cut -f1)"
echo ""
echo "Deploy:"
echo "  scp dist/${PKG_NAME}.tar.gz target:~/"
echo "  ssh target"
echo "  tar xzf ${PKG_NAME}.tar.gz"
echo "  cd $PKG_NAME"
echo "  ./start.sh"
