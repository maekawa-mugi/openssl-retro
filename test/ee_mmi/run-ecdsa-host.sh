#!/bin/sh
# ECDSA P-256 SHA-256 verification: OpenSSL EC code + experimental EE BN core.
# Host builds emulate MMI 32x32 products in C; no R5900 instructions run.
set -eu
cd "$(dirname "$0")/../.."
CC="${CC:-cc}"
CFLAGS="${CFLAGS:--O2}"
LDFLAGS="${LDFLAGS:-}"
if [ "${EE_ECDSA_SCALAR:-0}" = 1 ]; then
  OUT="${OUT:-/tmp/ee-ecdsa-p256-scalar-host}"
  DEFINES="-DEE_MMI_ECDSA_SCALAR"
  BN_SOURCE=""
else
  OUT="${OUT:-/tmp/ee-ecdsa-p256-mont-host}"
  DEFINES="-DEE_MMI_BN_SCALAR_MUL"
  BN_SOURCE="crypto/bn/bn-ee-mmi.c"
fi
# Intentional splitting of caller-supplied compiler/linker flags.
# shellcheck disable=SC2086
"$CC" -std=c99 $CFLAGS -Wall -Wextra -Werror \
  $DEFINES -Iinclude -I. \
  crypto/ec/ee-ecdsa-p256.c $BN_SOURCE \
  test/ee_mmi/ecdsa_p256_test.c \
  $LDFLAGS -lcrypto -o "$OUT"
"$OUT" "$@"
