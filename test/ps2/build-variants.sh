#!/usr/bin/env bash
# Build reference and scheduling candidates, all with the SAME B/F
# controls and the correctness-first A/B/F benchmark runner.
# Requires the SDK environment described in test/ps2/build.sh.
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
cd "$root"
prefix="${1:-build-ps2-schedules}"
# Reference and unrelated suites always select their default BN implementation.
export PS2_SCHED_BN=0
case "$prefix" in
    ""|"/") echo "Refusing empty/root output directory" >&2; exit 2 ;;
esac
PS2_AB=1 PS2_SCHED_CHACHA=0 PS2_SCHED_SHA=0 \
    PS2_SCHED_GHASH=0 PS2_SCHED_AES=0 \
    bash test/ps2/build.sh "$prefix/reference"
PS2_AB=1 PS2_SCHED_CHACHA=1 PS2_SCHED_SHA=0 \
    PS2_SCHED_GHASH=0 PS2_SCHED_AES=0 \
    bash test/ps2/build.sh "$prefix/chacha_interleave"
PS2_AB=1 PS2_SCHED_CHACHA=0 PS2_SCHED_SHA=1 \
    PS2_SCHED_GHASH=0 PS2_SCHED_AES=0 \
    bash test/ps2/build.sh "$prefix/sha_ch_first"
PS2_AB=1 PS2_SCHED_CHACHA=0 PS2_SCHED_SHA=2 \
    PS2_SCHED_GHASH=0 PS2_SCHED_AES=0 \
    bash test/ps2/build.sh "$prefix/sha_unroll2"
PS2_AB=1 PS2_SCHED_CHACHA=0 PS2_SCHED_SHA=0 \
    PS2_SCHED_GHASH=1 PS2_SCHED_AES=0 \
    bash test/ps2/build.sh "$prefix/ghash_mask_first"
PS2_AB=1 PS2_SCHED_CHACHA=0 PS2_SCHED_SHA=0 \
    PS2_SCHED_GHASH=2 PS2_SCHED_AES=0 \
    bash test/ps2/build.sh "$prefix/ghash_unroll4"
PS2_AB=1 PS2_SCHED_CHACHA=0 PS2_SCHED_SHA=0 \
    PS2_SCHED_GHASH=3 PS2_SCHED_AES=0 PS2_SCHED_BN=0 \
    bash test/ps2/build.sh "$prefix/ghash_window4"
PS2_AB=1 PS2_SCHED_CHACHA=0 PS2_SCHED_SHA=0 \
    PS2_SCHED_GHASH=4 PS2_SCHED_AES=0 PS2_SCHED_BN=0 \
    bash test/ps2/build.sh "$prefix/ghash_window8"
PS2_AB=1 PS2_SCHED_CHACHA=0 PS2_SCHED_SHA=0 \
    PS2_SCHED_GHASH=0 PS2_SCHED_AES=0 PS2_SCHED_BN=1 \
    bash test/ps2/build.sh "$prefix/bn_fused_row"
PS2_AB=1 PS2_SCHED_CHACHA=0 PS2_SCHED_SHA=0 \
    PS2_SCHED_GHASH=0 PS2_SCHED_AES=1 \
    bash test/ps2/build.sh "$prefix/aes_key_early"
PS2_AB=1 PS2_SCHED_CHACHA=1 PS2_SCHED_SHA=1 \
    PS2_SCHED_GHASH=1 PS2_SCHED_AES=1 \
    bash test/ps2/build.sh "$prefix/all_scheduled"
printf '\nVariant ELFs built in %s/*/openssl_mmi_test.elf\n' "$prefix"
printf 'Run each; A=selected MMI, B=identical scalar, F=fused Poly1305.\n'
printf 'Inspect all regression checks and compare B/A between ELFs.\n'
