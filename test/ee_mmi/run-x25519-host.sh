#!/bin/sh
# Host-only EE X25519 test: C replacement for MMI PMULTUW/PMADDUW.
set -eu
cd "$(dirname "$0")/../.."
CC="${CC:-cc}"
OUT="${OUT:-/tmp/openssl-ee-mmi-x25519-host}"
CFLAGS="${CFLAGS:--O2}"
# shellcheck disable=SC2086
"$CC" -std=c99 $CFLAGS -Wall -Wextra -Werror \
  -DEE_MMI_HOST_TEST -Iinclude -I. \
  crypto/ec/x25519-ee-mmi.c test/ee_mmi/x25519_test.c \
  -o "$OUT"
"$OUT" "$@"
