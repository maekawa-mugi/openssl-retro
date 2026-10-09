#!/bin/sh
# Portable AES-128/192/256 MMI four-block host-emulator tests.
# Runs real C code, substitutes only the MMI MixColumns/ARK kernel.
set -eu
cd "$(dirname "$0")/../.."
CC="${CC:-cc}"
CFLAGS="${CFLAGS:--O2}"
OUT="${OUT:-/tmp/openssl-ee-mmi-aes-host}"
# shellcheck disable=SC2086
"$CC" $CFLAGS -std=c99 -Wall -Wextra -Werror \
  -DEE_MMI_HOST_TEST -Iinclude -I. \
  crypto/aes/aes-ee-mmi.c test/ee_mmi/aes_test.c \
  -o "$OUT"
"$OUT" "$@"
# Run the independent K2 constant-time GF(16) tower S-box through the
# complete NIST AES-128/192/256 and randomized four-lane regressions.
# shellcheck disable=SC2086
"$CC" $CFLAGS -std=c99 -Wall -Wextra -Werror \
  -DEE_MMI_HOST_TEST -DEE_MMI_AES_TOWER_SBOX -Iinclude -I. \
  crypto/aes/aes-ee-mmi.c test/ee_mmi/aes_test.c \
  -o "$OUT-tower"
"$OUT-tower" "$@"
