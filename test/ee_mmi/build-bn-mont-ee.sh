#!/bin/sh
# PS2SDK standalone Montgomery + 32bit PMULTUW tests, no libcrypto.
set -eu
cd "$(dirname "$0")/../.."
CC="${CC:-mips64r5900el-ps2-elf-gcc}"
CFLAGS="${CFLAGS:--O2 -march=r5900 -G0}"
LDFLAGS="${LDFLAGS:-}"
if [ "${EE_BN_SCALAR:-0}" = 1 ]; then
  OUT="${OUT:-ee_bn_mont_scalar_test.elf}"
  CFLAGS="$CFLAGS -DEE_MMI_BN_SCALAR_MUL"
  ASM_SOURCE=""
  printf 'Building Montgomery scalar multiply baseline\n'
else
  OUT="${OUT:-ee_bn_mont_pmultuw_test.elf}"
  ASM_SOURCE="crypto/bn/bn-ee-mmi.S"
  printf 'Building Montgomery R5900 PMULTUW two-product backend\n'
fi
# shellcheck disable=SC2086
"$CC" $CFLAGS -std=c99 -DEE_MMI_BN_STANDALONE \
  -Iinclude -I. crypto/bn/bn-ee-mmi.c \
  $ASM_SOURCE test/ee_mmi/bn_mont_test.c \
  $LDFLAGS -o "$OUT"
printf 'Built %s; run on PS2 hardware, pass --bench if supported\n' "$OUT"
