#!/bin/sh
# Build independent EE PS2 GHASH test, no OpenSSL libcrypto required.
# EE_GHASH_SCALAR=1 produces same-algorithm pure C baseline.
set -eu
cd "$(dirname "$0")/../.."
CC="${CC:-mips64r5900el-ps2-elf-gcc}"
CFLAGS="${CFLAGS:--O2 -march=r5900 -G0}"
LDFLAGS="${LDFLAGS:-}"
if [ "${EE_GHASH_SCALAR:-0}" = 1 ]; then
  OUT="${OUT:-ee_ghash_scalar_test.elf}"
  CFLAGS="$CFLAGS -DEE_MMI_GHASH_SCALAR_MULTIPLY"
  ASM_SRC=""
  printf 'GHASH pure C scalar comparison build\n'
else
  OUT="${OUT:-ee_ghash_mmi_test.elf}"
  ASM_SRC="crypto/modes/ghash-ee-mmi.S"
  printf 'GHASH R5900 PAND/PXOR/PSRLW/PSLLW SIMD build\n'
fi
# Intentional word splitting for caller CFLAGS/LDFLAGS.
# shellcheck disable=SC2086
"$CC" $CFLAGS -std=c99 -Iinclude -I. \
  crypto/modes/ghash-ee-mmi.c $ASM_SRC \
  test/ee_mmi/ghash_test.c $LDFLAGS -o "$OUT"
printf 'Built GHASH PS2 ELF: %s\n' "$OUT"
