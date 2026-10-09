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
"$cc" -std=c99 -Wall -Wextra -Werror -fsyntax-only \
    -Iinclude -I. test/ps2/bench.c
"$cc" -std=c99 -Wall -Wextra -Werror -fsyntax-only \
    -Iinclude -I. -DPS2_BENCH_POLY_ONLY test/ps2/bench.c
"$cc" -std=c99 -Wall -Wextra -Werror -fsyntax-only \
    -I"$tmp" test/ps2/main.c
"$cc" -std=c99 -Wall -Wextra -Werror -fsyntax-only \
    -I"$tmp" -DPS2_AB test/ps2/main.c
python3 test/ps2/check-bench.py
python3 test/ps2/check-schedules.py
python3 test/ee_mmi/check-bn-row.py
python3 test/ee_mmi/check-ghash-windows.py
"$cc" -std=c99 -Wall -Wextra -Werror -fsyntax-only \
    -DEE_MMI_BN_STANDALONE -DEE_MMI_BN_ROW_FUSED \
    -Iinclude -I. crypto/bn/bn-ee-mmi.c
for width in 4 8; do
    "$cc" -std=c99 -Wall -Wextra -Werror -fsyntax-only \
        -DEE_MMI_GHASH_WINDOW_HOST \
        "-DEE_MMI_GHASH_WINDOW_BITS=$width" \
        -Iinclude -I. crypto/modes/ghash-ee-window.c
done
printf 'PASS: PS2 A/B/F benchmark host syntax and linkage-plan checks\n'
