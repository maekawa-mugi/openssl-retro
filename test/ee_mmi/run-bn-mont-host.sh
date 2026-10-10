#!/bin/sh
# Host C test with an exact two-product emulator (not EE hardware).
set -eu
cd "$(dirname "$0")/../.."
CC="${CC:-cc}"
OUT="${OUT:-/tmp/ee-bn-mont-host}"
CFLAGS="${CFLAGS:--O2}"
EXTRA=""
EXTRA_SOURCE=""
if [ "${EE_BN_ROW:-0}" = 1 ]; then
  EXTRA="-DEE_MMI_BN_ROW_FUSED -DEE_MMI_BN_ROW_HOST_TEST"
fi
if [ "${EE_BN_REDC_SHIFT:-0}" = 1 ]; then
  EXTRA="-DEE_MMI_BN_ROW_FUSED -DEE_MMI_BN_ROW_HOST_TEST -DEE_MMI_BN_REDC_SHIFT"
fi
if [ "${EE_BN_PUBLIC_SQUARE:-0}" = 1 ]; then
  EXTRA="$EXTRA -DEE_MMI_BN_ROW_FUSED -DEE_MMI_BN_ROW_HOST_TEST -DEE_MMI_BN_PUBLIC_SQUARE"
  EXTRA_SOURCE="crypto/bn/bn-ee-square.c"
fi
# shellcheck disable=SC2086
"$CC" -std=c99 $CFLAGS -Wall -Wextra -Werror \
  -DEE_MMI_BN_STANDALONE -DEE_MMI_BN_HOST_TEST $EXTRA \
  -Iinclude -I. \
  crypto/bn/bn-ee-mmi.c $EXTRA_SOURCE test/ee_mmi/bn_mont_test.c \
  -o "$OUT"
"$OUT" "$@"
