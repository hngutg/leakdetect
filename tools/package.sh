#!/bin/bash
# package.sh - 打包 LeakDetect 为自包含 tar.gz
# 用法：./tools/package.sh [target_arch]
#   target_arch: x86_64 或 aarch64（默认：当前架构）
# 产出：dist/leakdetect-{arch}.tar.gz
#
# 前置：
#   - clang + libbpf-dev（编译 BPF .o）
#   - pip（下载 Python 包）
#   - 对于 aarch64 目标：需要能获取 aarch64 libbpf.so（见下方说明）
set -e

DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$DIR"

TARGET_ARCH="${1:-$(uname -m)}"
PKG_NAME="leakdetect-${TARGET_ARCH}"
PKG_DIR="dist/$PKG_NAME"

echo "=== Packaging LeakDetect for $TARGET_ARCH ==="

# 1. 预编译 BPF .o（使用当前机器的 clang）
echo "[1/5] Building BPF .o files..."
./tools/build_bpf.sh

# 2. 准备目录结构
echo "[2/5] Assembling package structure..."
rm -rf "$PKG_DIR"
mkdir -p "$PKG_DIR"/{bpf/compiled,lib,py-packages,config,tests/leak_programs,data}

# 拷贝项目源码
cp -r core analyzer symbolizer storage alert_logging web "$PKG_DIR/"
cp -r bpf/compiled/*.o "$PKG_DIR/bpf/compiled/"
cp config/default.yaml "$PKG_DIR/config/"
cp -r tests/leak_programs/*.c "$PKG_DIR/tests/leak_programs/"
cp packaging/start.sh "$PKG_DIR/"
cp requirements.txt "$PKG_DIR/"

# 3. 下载纯 Python 包
echo "[3/5] Downloading Python packages..."
pip download -d "$PKG_DIR/py-packages/" \
    flask flask-socketio pyyaml pyelftools \
    2>/dev/null || true

# 解压 .whl 文件（纯 Python 代码架构无关，C 扩展会回退到纯 Python）
cd "$PKG_DIR/py-packages/"
for f in *.whl; do
    [ -f "$f" ] && unzip -oq "$f" && rm "$f"
done
cd "$DIR"

# 4. 获取目标架构的共享库
echo "[4/5] Fetching $TARGET_ARCH shared libraries..."
if [ "$TARGET_ARCH" = "$(uname -m)" ]; then
    # 当前架构：从系统复制
    LIBBPF=$(find /usr/lib* -name "libbpf.so.1" 2>/dev/null | head -1)
    LIBELF=$(find /usr/lib* -name "libelf.so.1" 2>/dev/null | head -1)
    if [ -n "$LIBBPF" ]; then cp "$LIBBPF" "$PKG_DIR/lib/"; fi
    if [ -n "$LIBELF" ]; then cp "$LIBELF" "$PKG_DIR/lib/"; fi
else
    # 交叉架构：从 deb 包提取
    echo "  Downloading $TARGET_ARCH packages..."
    apt download "libbpf1:${TARGET_ARCH/amd64/x86_64}" "libelf1:${TARGET_ARCH/amd64/x86_64}" \
        -d /tmp/leakdetect-debs 2>/dev/null || true
    mkdir -p /tmp/leakdetect-extract
    for deb in /tmp/leakdetect-debs/*.deb; do
        [ -f "$deb" ] && dpkg-deb -x "$deb" /tmp/leakdetect-extract/
    done
    find /tmp/leakdetect-extract -name "libbpf.so*" -exec cp {} "$PKG_DIR/lib/" \; 2>/dev/null || true
    find /tmp/leakdetect-extract -name "libelf.so*" -exec cp {} "$PKG_DIR/lib/" \; 2>/dev/null || true
    rm -rf /tmp/leakdetect-debs /tmp/leakdetect-extract
fi

if [ -z "$(ls "$PKG_DIR/lib/"libbpf* 2>/dev/null)" ]; then
    echo "  WARNING: libbpf.so not found for $TARGET_ARCH"
    echo "  For aarch64: apt download libbpf1:arm64 libelf1:arm64"
fi

# 5. 打包
echo "[5/5] Creating tar.gz..."
# 去除 .sh 文件的 BOM
sed -i '1s/^\xEF\xBB\xBF//' "$PKG_DIR/start.sh" 2>/dev/null || true
chmod +x "$PKG_DIR/start.sh"

cd dist
tar czf "${PKG_NAME}.tar.gz" "$PKG_NAME"
cd "$DIR"

echo ""
echo "=== Done ==="
echo "Package: dist/${PKG_NAME}.tar.gz"
echo "Size: $(du -sh dist/${PKG_NAME}.tar.gz | cut -f1)"
echo ""
echo "Deploy:"
echo "  tar xzf dist/${PKG_NAME}.tar.gz"
echo "  cd $PKG_NAME"
echo "  ./start.sh"
