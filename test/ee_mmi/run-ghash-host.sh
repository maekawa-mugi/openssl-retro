#!/bin/sh
# Host test of 4-way GHASH. MMI assembly replaced by scalar C emulator.
set -eu
cd "$(dirname "$0")/../.."
CC="${CC:-cc}"
OUT="${OUT:-/tmp/openssl-ee-mmi-ghash-host}"
CFLAGS="${CFLAGS:--O2}"
EXTRA="-DEE_MMI_HOST_TEST"
WINDOW_SRC=""
case "${EE_GHASH_WINDOW:-0}" in
  0) ;;
  4|8)
    EXTRA="-DEE_MMI_GHASH_WINDOW_HOST -DEE_MMI_GHASH_WINDOW_BITS=${EE_GHASH_WINDOW}"
    WINDOW_SRC=crypto/modes/ghash-ee-window.c
    ;;
  *) echo "EE_GHASH_WINDOW must be 4 or 8" >&2; exit 2 ;;
esac
# shellcheck disable=SC2086
"$CC" -std=c99 $CFLAGS -Wall -Wextra -Werror \
  $EXTRA -Iinclude -I. \
  crypto/modes/ghash-ee-mmi.c $WINDOW_SRC test/ee_mmi/ghash_test.c \
  -o "$OUT"
"$OUT" "$@"
