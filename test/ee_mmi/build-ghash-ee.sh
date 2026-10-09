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
WINDOW_SRC=""
if [ "${EE_GHASH_WINDOW:-0}" != 0 ]; then
  if [ "${EE_GHASH_SCALAR:-0}" = 1 ]; then
    echo "EE_GHASH_WINDOW and EE_GHASH_SCALAR cannot be combined" >&2; exit 2
  fi
  case "${EE_GHASH_WINDOW}" in
    4|8) ;;
    *) echo "EE_GHASH_WINDOW must be 4 or 8" >&2; exit 2 ;;
  esac
  CFLAGS="$CFLAGS -DEE_MMI_GHASH_WINDOW_BITS=${EE_GHASH_WINDOW}"
  ASM_SRC=crypto/modes/ghash-ee-window-mmi.S
  WINDOW_SRC=crypto/modes/ghash-ee-window.c
  OUT="${OUT:-ee_ghash_window_${EE_GHASH_WINDOW}_test.elf}"
fi
# Intentional word splitting for caller CFLAGS/LDFLAGS.
# shellcheck disable=SC2086
"$CC" $CFLAGS -std=c99 -Iinclude -I. \
  crypto/modes/ghash-ee-mmi.c $WINDOW_SRC $ASM_SRC \
  test/ee_mmi/ghash_test.c $LDFLAGS -o "$OUT"
printf 'Built GHASH PS2 ELF: %s\n' "$OUT"
