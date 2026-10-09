#!/bin/sh
# Compare three EE Poly1305 paths on the same console:
#   default                 PADDW + PMULTUW
#   EE_POLY_FUSED_MADD=1    PADDW + PMULTUW + PMADDUW fused sums
#   EE_POLY_MULT_SCALAR=1   PADDW + scalar multiply
#   EE_POLY_SCALAR=1        scalar add + scalar multiply
set -eu
cd "$(dirname "$0")/../.."
CC="${CC:-mips64r5900el-ps2-elf-gcc}"
CFLAGS="${CFLAGS:--O2 -march=r5900 -G0}"
LDFLAGS="${LDFLAGS:-}"
if [ "${EE_POLY_SCALAR:-0}" = 1 ]; then
    OUT="${OUT:-ee_poly1305_scalar_test.elf}"
    CFLAGS="$CFLAGS -DEE_MMI_POLY1305_SCALAR_ABSORB -DEE_MMI_POLY1305_SCALAR_MULTIPLY"
    ASM_SOURCES=""
    printf 'Building entirely scalar Poly1305 A/B baseline\n'
elif [ "${EE_POLY_MULT_SCALAR:-0}" = 1 ]; then
    OUT="${OUT:-ee_poly1305_paddw_test.elf}"
    CFLAGS="$CFLAGS -DEE_MMI_POLY1305_SCALAR_MULTIPLY"
    ASM_SOURCES="crypto/poly1305/poly1305-ee-mmi.S"
    printf 'Building PADDW absorption + scalar multiplication variant\n'
elif [ "${EE_POLY_FUSED_MADD:-0}" = 1 ]; then
    OUT="${OUT:-ee_poly1305_fused_madd_test.elf}"
    CFLAGS="$CFLAGS -DEE_MMI_POLY1305_FUSED_MADD"
    ASM_SOURCES="crypto/poly1305/poly1305-ee-mmi.S crypto/poly1305/poly1305-ee-pmadduw.S"
    printf 'Building PADDW absorption + fused PMULTUW/PMADDUW sums variant\n'
else
    OUT="${OUT:-ee_mmi_poly1305_test.elf}"
    ASM_SOURCES="crypto/poly1305/poly1305-ee-mmi.S crypto/poly1305/poly1305-ee-pmultuw.S"
    printf 'Building PADDW absorption + PMULTUW multiplication variant\n'
fi
# Intentional word splitting for caller-supplied compiler and linker flags.
# shellcheck disable=SC2086
"$CC" $CFLAGS -std=c99 -Iinclude -I. \
  crypto/poly1305/poly1305-ee-mmi.c \
  $ASM_SOURCES \
  test/ee_mmi/poly1305_test.c \
  $LDFLAGS -o "$OUT"
printf 'Built EE Poly1305 test: %s\n' "$OUT"
printf 'Run on PlayStation 2 hardware; pass --bench if supported.\n'
