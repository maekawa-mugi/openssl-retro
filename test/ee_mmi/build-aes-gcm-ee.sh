#!/bin/sh
# Standalone PS2SDK native MMI AES-GCM test, separate scalar baseline.
set -eu
cd "$(dirname "$0")/../.."
CC="${CC:-mips64r5900el-ps2-elf-gcc}"
CFLAGS="${CFLAGS:--O2 -march=r5900 -G0}"
LDFLAGS="${LDFLAGS:-}"
if [ "${EE_GCM_SCALAR:-0}" = 1 ]; then
    OUT="${OUT:-ee_aes_gcm_scalar_test.elf}"
    EXTRA="-DEE_MMI_AES_SCALAR_ROUND -DEE_MMI_GHASH_SCALAR_MULTIPLY"
    ASM=""
else
    OUT="${OUT:-ee_aes_gcm_mmi_test.elf}"
    EXTRA=""
    ASM="crypto/aes/aes-ee-mmi.S crypto/modes/ghash-ee-mmi.S"
fi
# shellcheck disable=SC2086
"$CC" $CFLAGS -std=c99 -DEE_MMI_STANDALONE -Iinclude -I. \
  $EXTRA crypto/aes/aes-ee-mmi.c crypto/modes/aes-gcm-ee-mmi.c \
  $ASM test/ee_mmi/aes_gcm_test.c $LDFLAGS -o "$OUT"
printf 'Built %s\n' "$OUT"
