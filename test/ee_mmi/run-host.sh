#!/bin/sh
# Host functional smoke test, NOT execution of R5900 MMI instructions.
set -eu
cd "$(dirname "$0")/../.."
CC="${CC:-cc}"
OUT="${OUT:-/tmp/openssl-ee-mmi-chacha20-host}"
"$CC" -std=c99 -O2 -Wall -Wextra -Werror \
    -DEE_MMI_HOST_TEST -DINCLUDE_C_CHACHA20 \
    -Iinclude -I. \
    crypto/chacha/chacha-ee-mmi.c \
    test/ee_mmi/chacha20_test.c \
    -o "$OUT"
"$OUT" "$@"
