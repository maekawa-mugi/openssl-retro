#!/bin/sh
# Standalone EE MMI SHA256 four-stream test, no libcrypto required.
set -eu
cd "$(dirname "$0")/../.."
CC="${CC:-mips64r5900el-ps2-elf-gcc}"
OUT="${OUT:-ee_mmi_sha256_test.elf}"
CFLAGS="${CFLAGS:--O2 -march=r5900 -G0}"
LDFLAGS="${LDFLAGS:-}"
# shellcheck disable=SC2086
"$CC" $CFLAGS -std=c99 -Iinclude -I. \
    crypto/sha/sha256-ee-mmi.c \
    crypto/sha/sha256-ee-mmi.S \
    test/ee_mmi/sha256_test.c \
    $LDFLAGS -o "$OUT"
printf 'Built EE SHA256 batch harness: %s\n' "$OUT"
printf 'Execute the ELF on PS2 hardware, optionally passing --bench.\n'
