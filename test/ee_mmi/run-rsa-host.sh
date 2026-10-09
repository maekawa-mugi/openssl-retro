#!/bin/sh
# Portable RSA-65537+PKCS1 SHA256 host test using existing EE BN CIOS.
# Host C emulates the dual 32x32->64 PMULTUW primitive; no EE opcodes run.
set -eu
cd "$(dirname "$0")/../.."
CC="${CC:-cc}"
CFLAGS="${CFLAGS:--O2}"
OUT="${OUT:-/tmp/openssl-ee-mmi-rsa-host}"
# shellcheck disable=SC2086
"$CC" $CFLAGS -std=c99 -Wall -Wextra -Werror \
  -DEE_MMI_BN_STANDALONE -DEE_MMI_BN_HOST_TEST \
  -Iinclude -I. \
  crypto/bn/bn-ee-mmi.c crypto/rsa/rsa-ee-mmi.c \
  test/ee_mmi/rsa_test.c -o "$OUT"
"$OUT" "$@"
