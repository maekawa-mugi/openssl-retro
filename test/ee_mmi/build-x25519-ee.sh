#!/bin/sh
# Standalone PS2 ELF X25519 4-stream test, no OpenSSL link required.
# EE_X25519_SCALAR=1 compiles a pure C field-multiply baseline.
set -eu
cd "$(dirname "$0")/../.."
CC="${CC:-mips64r5900el-ps2-elf-gcc}"
CFLAGS="${CFLAGS:--O2 -march=r5900 -G0}"
LDFLAGS="${LDFLAGS:-}"
if [ "${EE_X25519_SCALAR:-0}" = 1 ]; then
    OUT="${OUT:-ee_x25519_scalar_test.elf}"
    CFLAGS="$CFLAGS -DEE_MMI_X25519_SCALAR_MULTIPLY"
    ASM_SOURCE=""
    echo "X25519 scalar field baseline (no MMI assembly)"
else
    OUT="${OUT:-ee_x25519_mmi_test.elf}"
    ASM_SOURCE="crypto/ec/x25519-ee-mmi.S"
    echo "X25519 four-stream EE PMULTUW/PMADDUW field backend"
fi
# Intentional word splitting for caller flags.
# shellcheck disable=SC2086
"$CC" $CFLAGS -std=c99 -Iinclude -I. \
  crypto/ec/x25519-ee-mmi.c $ASM_SOURCE \
  test/ee_mmi/x25519_test.c $LDFLAGS -o "$OUT"
printf 'Built X25519 ELF: %s\n' "$OUT"
