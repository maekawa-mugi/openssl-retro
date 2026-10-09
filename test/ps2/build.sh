#!/usr/bin/env bash
# Usage: PS2DEV=... PS2SDK=... bash test/ps2/build.sh [output-dir]
set -euo pipefail
source_dir=$(cd "$(dirname "$0")/../.." && pwd)
output_dir=${1:-"$source_dir/build-ps2-mmi"}
build_jobs=${BUILD_JOBS:-${JOBS:-$(nproc)}}
(( build_jobs >= 1 )) || { echo "BUILD_JOBS must be >= 1" >&2; exit 2; }
mkdir -p "$output_dir"
output_dir=$(cd "$output_dir" && pwd)
cd "$source_dir"
: "${PS2DEV:?Set PS2DEV to the installed PS2 toolchain root}"
: "${PS2SDK:?Set PS2SDK to the installed PS2 SDK root}"
cc=${CC:-"$PS2DEV/ee/bin/mips64r5900el-ps2-elf-gcc"}
crt_dir=${PS2EE_CRT_DIR:-"$PS2DEV/ee/mips64r5900el-ps2-elf/lib"}
if [[ ! -f "$crt_dir/crt0.o" && -f "$PS2SDK/../ee/mips64r5900el-ps2-elf/lib/crt0.o" ]]; then
    crt_dir="$PS2SDK/../ee/mips64r5900el-ps2-elf/lib"
fi
[[ -f "$crt_dir/crt0.o" && -f "$PS2SDK/ee/startup/linkfile" ]] || {
    echo 'Missing PS2SDK linkfile or EE crt0.o' >&2; exit 1;
}
flags=(-O2 -march=r5900 -G0 -D_EE -std=c99 -Wall -Wextra
       -DEE_MMI_STANDALONE -DINCLUDE_C_CHACHA20 -DEE_MMI_BN_STANDALONE
       -ffunction-sections -fdata-sections
       -Iinclude -I. "-I$PS2SDK/ee/include" "-I$PS2SDK/common/include")
# Each scheduled variant retains the original exported symbol and
# test suite. Only the A kernel changes; the scalar B and fused F
# comparison paths are kept bit-identical.
for setting in PS2_SCHED_CHACHA PS2_SCHED_AES PS2_SCHED_BN; do
    value=${!setting:-0}
    [[ "$value" == 0 || "$value" == 1 ]] || {
        echo "Invalid $setting=$value (expected 0 or 1)" >&2; exit 2;
    }
done
case "${PS2_SCHED_GHASH:-0}" in
    0|1|2|3|4) ;;
    *) echo "PS2_SCHED_GHASH must be 0..4" >&2; exit 2 ;;
esac
case "${PS2_SCHED_SHA:-0}" in
    0|1|2) ;;
    *) echo "PS2_SCHED_SHA must be 0, 1, or 2" >&2; exit 2 ;;
esac
chacha_asm=crypto/chacha/chacha-ee-mmi.S
sha_asm=crypto/sha/sha256-ee-mmi.S
ghash_asm=crypto/modes/ghash-ee-mmi.S
aes_asm=crypto/aes/aes-ee-mmi.S
if [[ ${PS2_SCHED_CHACHA:-0} == 1 ]]; then
    chacha_asm=crypto/chacha/chacha-ee-mmi-interleave.S
fi
if [[ ${PS2_SCHED_SHA:-0} == 1 ]]; then
    sha_asm=crypto/sha/sha256-ee-mmi-sched.S
fi
if [[ ${PS2_SCHED_SHA:-0} == 2 ]]; then
    sha_asm=crypto/sha/sha256-ee-mmi-unroll2.S
fi
if [[ ${PS2_SCHED_GHASH:-0} == 1 ]]; then
    ghash_asm=crypto/modes/ghash-ee-mmi-sched.S
fi
if [[ ${PS2_SCHED_GHASH:-0} == 2 ]]; then
    ghash_asm=crypto/modes/ghash-ee-mmi-unroll4.S
fi
ghash_extra=()
if [[ ${PS2_SCHED_GHASH:-0} == 3 || ${PS2_SCHED_GHASH:-0} == 4 ]]; then
    ghash_asm=crypto/modes/ghash-ee-window-mmi.S
    ghash_extra=(crypto/modes/ghash-ee-window.c)
    if [[ ${PS2_SCHED_GHASH:-0} == 3 ]]; then
        flags+=(-DEE_MMI_GHASH_WINDOW_BITS=4)
    else
        flags+=(-DEE_MMI_GHASH_WINDOW_BITS=8)
    fi
fi
if [[ ${PS2_SPR_BENCH:-0} == 1 ]]; then
    [[ ${PS2_AB:-0} == 1 && ( ${PS2_SCHED_GHASH:-0} == 3 || ${PS2_SCHED_GHASH:-0} == 4 ) ]] || {
        echo "PS2_SPR_BENCH=1 requires PS2_AB=1 and PS2_SCHED_GHASH=3 or 4" >&2; exit 2;
    }
    flags+=(-DPS2_SPR_BENCH)
elif [[ ${PS2_SPR_BENCH:-0} != 0 ]]; then
    echo "PS2_SPR_BENCH must be 0 or 1" >&2; exit 2
fi
bn_extra=()
if [[ ${PS2_SCHED_BN:-0} == 1 ]]; then
    flags+=(-DEE_MMI_BN_ROW_FUSED)
    bn_extra=(crypto/bn/bn-ee-row-mmi.S)
fi
if [[ ${PS2_SCHED_AES:-0} == 1 ]]; then
    aes_asm=crypto/aes/aes-ee-mmi-keyearly.S
fi
echo "EE A kernels: ChaCha=$chacha_asm SHA=$sha_asm GHASH=$ghash_asm AES=$aes_asm"
# Embed each A kernel's scheduling ID into the actual ELF, so serial
# logs and screenshots identify precisely which experiment was run.
flags+=("-DPS2_CONFIG_CHACHA=${PS2_SCHED_CHACHA:-0}"
        "-DPS2_CONFIG_SHA=${PS2_SCHED_SHA:-0}"
        "-DPS2_CONFIG_GHASH=${PS2_SCHED_GHASH:-0}"
        "-DPS2_CONFIG_AES=${PS2_SCHED_AES:-0}"
        "-DPS2_CONFIG_BN=${PS2_SCHED_BN:-0}")
objects=()
if [[ ${PS2_AB:-0} == 1 ]]; then
    flags+=(-DPS2_AB)
fi
compile_pids=()
compile() {
    local src=$1 obj="$output_dir/${object_tag:-}${1//\//_}.o"
    shift
    # Each object owns its output path. Namespace linking waits for
    # all of the asynchronous compilers before reading their objects.
    "$cc" "${flags[@]}" "$@" -c "$src" -o "$obj" &
    compile_pids+=("$!")
    objects+=("$obj")
    if (( ${#compile_pids[@]} >= build_jobs )); then
        wait "${compile_pids[0]}"
        compile_pids=("${compile_pids[@]:1}")
    fi
}
finish_compiles() {
    local pid
    for pid in "${compile_pids[@]}"; do wait "$pid"; done
    compile_pids=()
}
for suite in chacha20 sha256 poly1305 aes ghash bn_mont x25519 rsa p256_ecdh aes_gcm; do
    compile "test/ee_mmi/${suite}_test.c" "-Dmain=ps2_test_$suite"
done
if [[ ${PS2_AB:-0} == 1 ]]; then
    # The timing workload must not include differential/KAT checks.
    # Compile it separately, once into each implementation namespace.
    compile test/ps2/bench.c
    a_objects=("${objects[@]}")
    object_tag=b_
    objects=()
    # Keep both implementations in one ELF, with a separate symbol namespace.
    scalar_flags=(-UEE_MMI_BN_ROW_FUSED -UEE_MMI_GHASH_WINDOW_BITS
                  -DEE_MMI_POLY1305_SCALAR_ABSORB -DEE_MMI_POLY1305_SCALAR_MULTIPLY
                  -DEE_MMI_AES_SCALAR_ROUND -DEE_MMI_GHASH_SCALAR_MULTIPLY
                  -DEE_MMI_X25519_SCALAR_MULTIPLY -DEE_MMI_BN_SCALAR_MUL)
    for suite in chacha20 sha256 poly1305 aes ghash bn_mont x25519 rsa p256_ecdh aes_gcm; do
        extra=()
        if [[ $suite == chacha20 || $suite == sha256 ]]; then
            extra+=(-DEE_MMI_HOST_TEST -UEE_MMI_STANDALONE)
        fi
        compile "test/ee_mmi/${suite}_test.c" "${scalar_flags[@]}" "${extra[@]}" \
            "-Dmain=ps2_test_$suite"
    done
    for src in crypto/chacha/chacha-ee-mmi.c crypto/sha/sha256-ee-mmi.c \
        crypto/poly1305/poly1305-ee-mmi.c crypto/aes/aes-ee-mmi.c \
        crypto/modes/ghash-ee-mmi.c crypto/modes/aes-gcm-ee-mmi.c \
        crypto/bn/bn-ee-mmi.c crypto/bn/bn-ee-mmi.S \
        crypto/ec/x25519-ee-mmi.c crypto/rsa/rsa-ee-mmi.c crypto/ec/p256-ee-mmi.c; do
        compile "$src" "${scalar_flags[@]}"
    done
    compile test/ps2/bench.c "${scalar_flags[@]}"
    finish_compiles
    "${cc%gcc}ld" -r "${objects[@]}" -o "$output_dir/scalar.o"
    "${cc%gcc}nm" --defined-only --extern-only "$output_dir/scalar.o" |
        awk '{print $3 " b_" $3}' > "$output_dir/scalar-symbols.txt"
    "${cc%gcc}objcopy" --redefine-syms="$output_dir/scalar-symbols.txt" "$output_dir/scalar.o"
    # Third Poly1305 backend: fused PMULTUW/PMADDUW instead of the
    # separate-product default, with independent regression checks.
    object_tag=f_
    objects=()
    fused_flags=(-DEE_MMI_POLY1305_FUSED_MADD)
    compile test/ee_mmi/poly1305_test.c "${fused_flags[@]}" -Dmain=ps2_test_poly1305
    compile crypto/poly1305/poly1305-ee-mmi.c "${fused_flags[@]}"
    compile crypto/poly1305/poly1305-ee-mmi.S
    compile crypto/poly1305/poly1305-ee-pmadduw.S
    compile test/ps2/bench.c "${fused_flags[@]}" -DPS2_BENCH_POLY_ONLY
    finish_compiles
    "${cc%gcc}ld" -r "${objects[@]}" -o "$output_dir/fused.o"
    "${cc%gcc}nm" --defined-only --extern-only "$output_dir/fused.o" |
        awk '{print $3 " f_" $3}' > "$output_dir/fused-symbols.txt"
    "${cc%gcc}objcopy" --redefine-syms="$output_dir/fused-symbols.txt" "$output_dir/fused.o"

    objects=("${a_objects[@]}")
    objects+=("$output_dir/scalar.o" "$output_dir/fused.o")
    object_tag=
fi
for src in \
    crypto/chacha/chacha-ee-mmi.c "$chacha_asm" \
    crypto/sha/sha256-ee-mmi.c "$sha_asm" \
    crypto/poly1305/poly1305-ee-mmi.c crypto/poly1305/poly1305-ee-mmi.S \
    crypto/poly1305/poly1305-ee-pmultuw.S \
    crypto/aes/aes-ee-mmi.c "$aes_asm" \
    crypto/modes/ghash-ee-mmi.c crypto/modes/aes-gcm-ee-mmi.c "$ghash_asm" "${ghash_extra[@]}" \
    crypto/bn/bn-ee-mmi.c crypto/bn/bn-ee-mmi.S "${bn_extra[@]}" \
    crypto/ec/x25519-ee-mmi.c crypto/ec/x25519-ee-mmi.S \
    crypto/rsa/rsa-ee-mmi.c crypto/ec/p256-ee-mmi.c test/ps2/main.c; do
    compile "$src"
done
if [[ ${PS2_SPR_BENCH:-0} == 1 ]]; then
    compile test/ps2/spr-io.c
fi
finish_compiles
"$cc" -march=r5900 -G0 "-B$crt_dir/" \
    "-T$PS2SDK/ee/startup/linkfile" "-L$PS2SDK/ee/lib" \
    -Wl,-zmax-page-size=128,--gc-sections "-Wl,-Map,$output_dir/openssl_mmi.map" \
    "${objects[@]}" -Wl,--start-group -ldebug -lc -lcdvd -lcglue \
    -lpthread -lpthreadglue -lkernel -Wl,--end-group \
    -o "$output_dir/openssl_mmi.elf"
printf '\nELF: %s/openssl_mmi.elf (parallel jobs=%s)\n' "$output_dir" "$build_jobs"
