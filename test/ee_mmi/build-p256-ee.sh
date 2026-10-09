#!/bin/sh
# PS2 standalone P-256 ECDH verification against independent vectors.
# EE_P256_SCALAR=1 compiles a scalar CIOS Montgomery comparison.
set -eu
cd "$(dirname "$0")/../.."
CC="${CC:-mips64r5900el-ps2-elf-gcc}"
CFLAGS="${CFLAGS:--O2 -march=r5900 -G0}"
LDFLAGS="${LDFLAGS:-}"
if [ "${EE_P256_SCALAR:-0}" = 1 ]; then
    CFLAGS="$CFLAGS -DEE_MMI_BN_SCALAR_MUL"
    OUT="${OUT:-ee_p256_ecdh_scalar_test.elf}"
    ASM_SRC=""
    printf 'Building P-256 ECDH with scalar Montgomery multiplies\n'
else
    OUT="${OUT:-ee_p256_ecdh_mmi_test.elf}"
    ASM_SRC="crypto/bn/bn-ee-mmi.S"
    printf 'Building P-256 ECDH with EE PMULTUW Montgomery multiplies\n'
fi
# shellcheck disable=SC2086
"$CC" $CFLAGS -std=c99 -DEE_MMI_BN_STANDALONE \
  -Iinclude -I. crypto/bn/bn-ee-mmi.c \
  crypto/ec/p256-ee-mmi.c $ASM_SRC \
  test/ee_mmi/p256_ecdh_test.c $LDFLAGS -o "$OUT"
printf 'Built P-256 ECDH ELF: %s\n' "$OUT"
