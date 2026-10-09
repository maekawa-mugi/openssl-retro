#!/bin/sh
# Host-only P-256 Jacobian ECDH + R5900 BN PMULTUW C emulation.
set -eu
cd "$(dirname "$0")/../.."
CC="${CC:-cc}"
CFLAGS="${CFLAGS:--O2}"
OUT="${OUT:-/tmp/ee-p256-ecdh-host}"
# shellcheck disable=SC2086
"$CC" $CFLAGS -std=c99 -Wall -Wextra -Werror \
  -DEE_MMI_BN_STANDALONE -DEE_MMI_BN_HOST_TEST \
  -Iinclude -I. crypto/bn/bn-ee-mmi.c \
  crypto/ec/p256-ee-mmi.c test/ee_mmi/p256_ecdh_test.c \
  -o "$OUT"
"$OUT" "$@"
# Test the specialized 8-limb P-256 reduction using the same C-model
# whole-row multiplier as the production fused MMI assembler.
# shellcheck disable=SC2086
"$CC" $CFLAGS -std=c99 -Wall -Wextra -Werror \
  -DEE_MMI_BN_STANDALONE -DEE_MMI_BN_HOST_TEST -DEE_MMI_BN_ROW_FUSED \
  -Iinclude -I. crypto/bn/bn-ee-mmi.c \
  crypto/ec/p256-ee-mmi.c test/ee_mmi/p256_row_host.c \
  test/ee_mmi/p256_ecdh_test.c -o "$OUT-fused"
"$OUT-fused" "$@"
