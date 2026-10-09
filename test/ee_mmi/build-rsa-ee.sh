#!/bin/sh
# Standalone EE public RSA-65537 / SHA256 PKCS#1 v1.5 test.
# EE_RSA_SCALAR=1 substitutes scalar multiplications in the same CIOS.
set -eu
cd "$(dirname "$0")/../.."
CC="${CC:-mips64r5900el-ps2-elf-gcc}"
CFLAGS="${CFLAGS:--O2 -march=r5900 -G0}"
LDFLAGS="${LDFLAGS:-}"
if [ "${EE_RSA_SCALAR:-0}" = 1 ]; then
    OUT="${OUT:-ee_rsa_scalar_test.elf}"
    CFLAGS="$CFLAGS -DEE_MMI_BN_SCALAR_MUL"
    ASM_SOURCE=""
    printf 'Building public RSA with scalar 32x32 Montgomery multiplications\n'
else
    OUT="${OUT:-ee_rsa_pmultuw_test.elf}"
    ASM_SOURCE="crypto/bn/bn-ee-mmi.S"
    printf 'Building public RSA with EE PMULTUW Montgomery multiplications\n'
fi
# shellcheck disable=SC2086
"$CC" $CFLAGS -std=c99 -DEE_MMI_BN_STANDALONE \
  -Iinclude -I. \
  crypto/bn/bn-ee-mmi.c crypto/rsa/rsa-ee-mmi.c \
  $ASM_SOURCE test/ee_mmi/rsa_test.c $LDFLAGS -o "$OUT"
printf 'Built EE RSA test: %s\n' "$OUT"
