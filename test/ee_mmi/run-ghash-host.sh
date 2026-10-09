#!/bin/sh
# Host test of 4-way GHASH. MMI assembly replaced by scalar C emulator.
set -eu
cd "$(dirname "$0")/../.."
CC="${CC:-cc}"
OUT="${OUT:-/tmp/openssl-ee-mmi-ghash-host}"
CFLAGS="${CFLAGS:--O2}"
# shellcheck disable=SC2086
"$CC" -std=c99 $CFLAGS -Wall -Wextra -Werror \
  -DEE_MMI_HOST_TEST -Iinclude -I. \
  crypto/modes/ghash-ee-mmi.c test/ee_mmi/ghash_test.c \
  -o "$OUT"
"$OUT" "$@"
