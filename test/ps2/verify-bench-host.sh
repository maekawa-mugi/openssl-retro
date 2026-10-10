#!/usr/bin/env bash
# Native syntax checks for the PS2 A/B/F benchmark harness.
# Cross-compilation and actual MMI execution still require PS2SDK.
set -euo pipefail
cd "$(dirname "$0")/../.."
cc="${CC:-cc}"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
cat > "$tmp/debug.h" <<'EOF'
#ifndef PS2_BENCH_FAKE_DEBUG_H
#define PS2_BENCH_FAKE_DEBUG_H
#include <stdint.h>
void init_scr(void);
void scr_setXY(int, int);
void scr_setfontcolor(uint32_t);
void scr_setCursor(int);
void scr_printf(const char *, ...);
#endif
EOF
cat > "$tmp/kernel.h" <<'EOF'
#ifndef PS2_BENCH_FAKE_KERNEL_H
#define PS2_BENCH_FAKE_KERNEL_H
typedef unsigned long long u64;
void SleepThread(void);
#endif
EOF
cat > "$tmp/timer.h" <<'EOF'
#ifndef PS2_BENCH_FAKE_TIMER_H
#define PS2_BENCH_FAKE_TIMER_H
#include "kernel.h"
extern u64 GetTimerSystemTime(void);
#define kBUSCLK 147456000U
#endif
EOF
bash -n test/ps2/build.sh
bash -n test/ps2/build-variants.sh
bash -n test/ps2/build-experiments.sh
bash test/ps2/check-experiment-plan.sh all
bash test/ps2/check-experiment-plan.sh selected
"$cc" -std=c99 -Wall -Wextra -Werror -fsyntax-only \
    -Iinclude -I. test/ps2/bench.c
"$cc" -std=c99 -Wall -Wextra -Werror -fsyntax-only \
    -Iinclude -I. -DPS2_BENCH_POLY_ONLY test/ps2/bench.c
"$cc" -std=c99 -Wall -Wextra -Werror -fsyntax-only \
    -I"$tmp" test/ps2/main.c
"$cc" -std=c99 -Wall -Wextra -Werror -fsyntax-only \
    -I"$tmp" -DPS2_AB test/ps2/main.c
"$cc" -std=c99 -Wall -Wextra -Werror -fsyntax-only \
    -I"$tmp" -DPS2_AB -DPS2_EXPERIMENTS test/ps2/main.c
"$cc" -std=c99 -Wall -Wextra -Werror -fsyntax-only \
    -I"$tmp" -DPS2_AB -DPS2_EXPERIMENTS -DPS2_SELECTED test/ps2/main.c
python3 test/ps2/check-bench.py
python3 test/ps2/check-schedules.py
python3 test/ps2/check-experiments.py
python3 test/ps2/check-redc-shift.py
python3 test/ps2/check-poly-rsa.py
python3 test/ps2/check-public-square.py
python3 test/ps2/check-chacha-wrap.py
python3 test/ee_mmi/check-aes-tower.py
python3 test/ee_mmi/check-bn-row.py
python3 test/ee_mmi/check-ghash-windows.py
"$cc" -std=c99 -Wall -Wextra -Werror -fsyntax-only \
    -DEE_MMI_BN_STANDALONE -DEE_MMI_BN_ROW_FUSED \
    -Iinclude -I. crypto/bn/bn-ee-mmi.c
"$cc" -std=c99 -Wall -Wextra -Werror -fsyntax-only \
    -DEE_MMI_BN_STANDALONE -DEE_MMI_BN_ROW_FUSED -DEE_MMI_BN_REDC_SHIFT \
    -DEE_MMI_BN_ACTIVE_SCRATCH -Iinclude -I. crypto/bn/bn-ee-mmi.c
"$cc" -std=c99 -Wall -Wextra -Werror -fsyntax-only \
    -DEE_MMI_RSA_SWAP_POWERS -Iinclude -I. crypto/rsa/rsa-ee-mmi.c
"$cc" -std=c99 -Wall -Wextra -Werror -fsyntax-only \
    -DEE_MMI_BN_STANDALONE -DEE_MMI_BN_ROW_FUSED -DEE_MMI_BN_REDC_SHIFT \
    -DEE_MMI_BN_ROW_HOST_TEST -DEE_MMI_BN_HOST_TEST \
    -Iinclude -I. test/ee_mmi/bn_mont_test.c
"$cc" -std=c99 -Wall -Wextra -Werror -fsyntax-only \
    -DEE_MMI_BN_STANDALONE -DEE_MMI_BN_ROW_FUSED -DEE_MMI_BN_REDC_SHIFT \
    -Iinclude -I. crypto/bn/bn-ee-mmi.c
for width in 4 8; do
    "$cc" -std=c99 -Wall -Wextra -Werror -fsyntax-only \
        -DEE_MMI_GHASH_WINDOW_HOST \
        "-DEE_MMI_GHASH_WINDOW_BITS=$width" \
        -Iinclude -I. crypto/modes/ghash-ee-window.c
    "$cc" -std=c99 -Wall -Wextra -Werror -fsyntax-only \
        "-DEE_MMI_GHASH_WINDOW_BITS=$width" \
        -Iinclude -I. crypto/modes/ghash-ee-mmi.c
    "$cc" -std=c99 -Wall -Wextra -Werror -fsyntax-only \
        "-DEE_MMI_GHASH_WINDOW_BITS=$width" \
        -Iinclude -I. crypto/modes/aes-gcm-ee-mmi.c
done

"$cc" -std=c99 -Wall -Wextra -Werror -fsyntax-only \
    -DEE_MMI_POLY1305_FUSED_MADD -DEE_MMI_POLY1305_FUSED_REDUCE \
    -Iinclude -I. crypto/poly1305/poly1305-ee-mmi.c
"$cc" -std=c99 -Wall -Wextra -Werror -fsyntax-only \
    -DEE_MMI_RSA_SWAP_POWERS -DEE_MMI_BN_PUBLIC_SQUARE \
    -Iinclude -I. crypto/rsa/rsa-ee-mmi.c crypto/bn/bn-ee-square.c
"$cc" -std=c99 -Wall -Wextra -Werror -fsyntax-only \
    -DEE_MMI_BN_PUBLIC_SQUARE -DEE_MMI_BN_ROW_FUSED -DEE_MMI_BN_ROW_HOST_TEST \
    -DEE_MMI_BN_HOST_TEST -Iinclude -I. test/ee_mmi/bn_mont_test.c
"$cc" -std=c99 -Wall -Wextra -Werror -fsyntax-only \
    -Iinclude -I. crypto/chacha/chacha-ee-wrap.c
printf 'PASS: PS2 A/B/F benchmark host syntax and linkage-plan checks\n'
