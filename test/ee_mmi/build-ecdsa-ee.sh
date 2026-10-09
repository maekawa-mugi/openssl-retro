#!/bin/sh
# ECDSA P-256 public signature verification on the PS2 EE.
# Requires a previously built compatible static OpenSSL libcrypto.a.
# MMI path uses ee-ecdsa-p256.c and bn-ee-mmi.S from libcrypto.
# Scalar comparison overrides the ECDSA implementation at link time.
set -eu
cd "$(dirname "$0")/../.."
CC="${CC:-mips64r5900el-ps2-elf-gcc}"
CFLAGS="${CFLAGS:--O2 -march=r5900 -G0}"
LDFLAGS="${LDFLAGS:-}"
LIBCRYPTO="${LIBCRYPTO:-./libcrypto.a}"
if [ "${EE_ECDSA_SCALAR:-0}" = 1 ]; then
  OUT="${OUT:-ee_ecdsa_p256_scalar_test.elf}"
  SOURCE="crypto/ec/ee-ecdsa-p256.c"
  CFLAGS="$CFLAGS -DEE_MMI_ECDSA_SCALAR"
else
  OUT="${OUT:-ee_ecdsa_p256_mmi_test.elf}"
  SOURCE=""
fi
# shellcheck disable=SC2086
"$CC" $CFLAGS -std=c99 -Iinclude -I. \
  $SOURCE test/ee_mmi/ecdsa_p256_test.c \
  "$LIBCRYPTO" $LDFLAGS -o "$OUT"
printf 'Built PS2 ECDSA P-256 verification test: %s\n' "$OUT"
printf 'Transfer ELF to the EE, run vectors, then optionally --bench.\n'
