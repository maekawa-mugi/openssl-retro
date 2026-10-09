#!/bin/sh
# Host AES-GCM crosscheck: stand-in MMI kernels or entirely scalar.
# Neither option executes R5900 instructions.
set -eu
cd "$(dirname "$0")/../.."
CC="${CC:-cc}"
CFLAGS="${CFLAGS:--O2}"
OUT="${OUT:-/tmp/openssl-ee-aes-gcm-host}"
if [ "${EE_GCM_SCALAR:-0}" = 1 ]; then
    EXTRA="-DEE_MMI_AES_SCALAR_ROUND -DEE_MMI_GHASH_SCALAR_MULTIPLY"
else
    EXTRA="-DEE_MMI_HOST_TEST"
fi
# shellcheck disable=SC2086
"$CC" $CFLAGS -std=c99 -Wall -Wextra -Werror $EXTRA -Iinclude -I. \
  crypto/aes/aes-ee-mmi.c crypto/modes/aes-gcm-ee-mmi.c \
  test/ee_mmi/aes_gcm_test.c -o "$OUT"
"$OUT" "$@"
