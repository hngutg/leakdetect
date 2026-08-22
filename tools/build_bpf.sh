#!/bin/bash
# build_bpf.sh - 预编译 BPF 程序为 CO-RE .o 文件
# 用法：./tools/build_bpf.sh
# 产出：bpf/compiled/{mem,threads,fd}.o
# 要求：clang（支持 -target bpf），libbpf-dev（提供 bpf/bpf_helpers.h 等头文件）
set -e

DIR="$(cd "$(dirname "$0")/.." && pwd)"
BPF_DIR="$DIR/bpf"
OUT_DIR="$DIR/bpf/compiled"

mkdir -p "$OUT_DIR"

# 架构检测
ARCH=$(uname -m)
case "$ARCH" in
    x86_64)  BPF_ARCH="x86" ;;
    aarch64) BPF_ARCH="arm64" ;;
    *) echo "Unsupported arch: $ARCH"; exit 1 ;;
esac

# multiarch include 路径检测
MULTIARCH=$(dpkg-architecture -qDEB_HOST_MULTIARCH 2>/dev/null || echo "$ARCH-linux-gnu")
INCLUDE_PATH="/usr/include/${MULTIARCH}"

if [ ! -d "$INCLUDE_PATH/asm" ]; then
    echo "WARNING: asm headers not found at $INCLUDE_PATH"
    echo "  Try: apt install linux-libc-dev (Debian/Ubuntu)"
    echo "  Or:  yum install kernel-headers (RHEL/EulerOS)"
fi

# __x86_64__ 让 bpf_tracing.h 选 64 位 PT_REGS 字段（clang -target bpf 不自动定义它，
# 否则落 32 位分支 eax/esp → 在 x86_64 pt_regs 上偏移错 → verifier 拒）。仅 x86_64 需要。
ARCH_FLAGS=""
[ "$BPF_ARCH" = "x86" ] && ARCH_FLAGS="-D__x86_64__"
CFLAGS="-target bpf -D__TARGET_ARCH_${BPF_ARCH} ${ARCH_FLAGS} -g -O2 -I${INCLUDE_PATH} -I${BPF_DIR}"

echo "Building BPF programs (arch=$ARCH, target=$BPF_ARCH)..."
clang $CFLAGS -c "$BPF_DIR/mem.bpf.c" -o "$OUT_DIR/mem.o"
clang $CFLAGS -c "$BPF_DIR/threads.bpf.c" -o "$OUT_DIR/threads.o"
clang $CFLAGS -c "$BPF_DIR/fd.bpf.c" -o "$OUT_DIR/fd.o"

echo "Done: mem.o threads.o fd.o"
ls -la "$OUT_DIR"/*.o
