#!/bin/sh
# Standalone PlayStation 2 Emotion Engine AES test.
# EE_AES_SCALAR=1 builds a portable MixColumns/AddRoundKey A/B variant.
set -eu
cd "$(dirname "$0")/../.."
CC="${CC:-mips64r5900el-ps2-elf-gcc}"
CFLAGS="${CFLAGS:--O2 -march=r5900 -G0}"
LDFLAGS="${LDFLAGS:-}"
if [ "${EE_AES_SCALAR:-0}" = 1 ]; then
    OUT="${OUT:-ee_aes_scalar_test.elf}"
    CFLAGS="$CFLAGS -DEE_MMI_AES_SCALAR_ROUND"
    ASM_SOURCE=""
    printf 'Building table-free AES with scalar MixColumns/ARK\n'
else
    OUT="${OUT:-ee_aes_mmi_test.elf}"
    ASM_SOURCE="crypto/aes/aes-ee-mmi.S"
    printf 'Building table-free AES with EE MMI MixColumns/ARK\n'
fi
# shellcheck disable=SC2086
"$CC" $CFLAGS -std=c99 -Wall -Wextra \
  -Iinclude -I. crypto/aes/aes-ee-mmi.c $ASM_SOURCE \
  test/ee_mmi/aes_test.c $LDFLAGS -o "$OUT"
printf 'Built EE AES test: %s\n' "$OUT"
