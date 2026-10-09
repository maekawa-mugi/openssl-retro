#!/bin/sh
# Host-only Poly1305 tests, C emulator for MMI PADDW absorber.
set -eu
cd "$(dirname "$0")/../.."
CC="${CC:-cc}"
OUT="${OUT:-/tmp/openssl-ee-mmi-poly1305-host}"
CFLAGS="${CFLAGS:--O2}"
# shellcheck disable=SC2086
"$CC" -std=c99 $CFLAGS -Wall -Wextra -Werror \
  -DEE_MMI_HOST_TEST -Iinclude -I. \
  crypto/poly1305/poly1305-ee-mmi.c \
  test/ee_mmi/poly1305_test.c -o "$OUT"
"$OUT" "$@"
