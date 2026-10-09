#!/bin/sh
# Standalone PS2 EE MMI verification without first building libcrypto.a.
# Requires a PS2SDK EE compiler/assembler/linker and matching target libc.
set -eu
cd "$(dirname "$0")/../.."
CC="${CC:-mips64r5900el-ps2-elf-gcc}"
OUT="${OUT:-ee_mmi_chacha20_test.elf}"
CFLAGS="${CFLAGS:--O2 -march=r5900 -G0}"
LDFLAGS="${LDFLAGS:-}"
# Intentional unquoted flags: allows the caller to pass multiple flags.
# shellcheck disable=SC2086
"$CC" $CFLAGS -std=c99 -DEE_MMI_STANDALONE \
    -Iinclude -I. \
    crypto/chacha/chacha-ee-mmi.c \
    crypto/chacha/chacha-ee-mmi.S \
    test/ee_mmi/chacha20_test.c \
    $LDFLAGS -o "$OUT"
printf 'Built EE standalone differential harness: %s\n' "$OUT"
printf 'Transfer ELF to the PlayStation 2 and execute there.\n'
