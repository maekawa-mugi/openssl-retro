#!/bin/sh
# Portable EE SHA256 batch test. This uses a C emulator, NOT R5900 MMI.
set -eu
cd "$(dirname "$0")/../.."
CC="${CC:-cc}"
OUT="${OUT:-/tmp/openssl-ee-mmi-sha256-host}"
CFLAGS="${CFLAGS:--O2}"
# shellcheck disable=SC2086
"$CC" -std=c99 $CFLAGS -Wall -Wextra -Werror \
    -DEE_MMI_HOST_TEST -Iinclude -I. \
    crypto/sha/sha256-ee-mmi.c test/ee_mmi/sha256_test.c \
    -o "$OUT"
"$OUT" "$@"
