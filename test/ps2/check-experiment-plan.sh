#!/usr/bin/env bash
# Execute the namespace build plan with shell mocks: NO compiler/linker.
set -euo pipefail
cd "$(dirname "$0")/../.."
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
output_dir=$tmp
cc=plan_gcc
ps2_profile=${1:-all}
objects=(original-a.o original-b.o)
if [[ "$ps2_profile" != selected ]]; then objects+=(original-f.o); fi
object_tag=
outstanding=0
compile() {
    local src=$1
    shift
    [[ -f "$src" ]]
    printf '%s %s\n' "$src" "$*" >> "$tmp/${object_tag}plan.txt"
    objects+=("$tmp/${object_tag}${src//\//_}.o")
    outstanding=1
}
finish_compiles() { outstanding=0; }
plan_ld() {
    [[ $outstanding == 0 && $1 == -r ]]
    [[ ${#objects[@]} -ge 20 ]]
    for obj in "${objects[@]}"; do
        [[ "$obj" == "$tmp/${object_tag}"* ]]
    done
    [[ $(printf '%s\n' "${objects[@]}" | sort -u | wc -l) == ${#objects[@]} ]]
}
plan_nm() {
    printf '00000000 T ps2_bench_run\n'
    printf '00000000 T ossl_ee_bn_muladd_row_mmi\n'
}
plan_objcopy() {
    local mapping=${1#--redefine-syms=}
    [[ $(cat "$mapping") == "ps2_bench_run ${object_tag}ps2_bench_run
ossl_ee_bn_muladd_row_mmi ${object_tag}ossl_ee_bn_muladd_row_mmi" ]]
}
source test/ps2/build-experiments.sh
expected_objects=15
if [[ "$ps2_profile" == selected ]]; then
    expected_objects=9
    if [[ ${PS2_NEW_IDEAS:-1} == 1 ]]; then expected_objects=18; fi
fi
[[ ${#objects[@]} == "$expected_objects" && -z "$object_tag" ]]
[[ ${objects[0]} == original-a.o && ${objects[1]} == original-b.o ]]
if [[ "$ps2_profile" != selected ]]; then [[ ${objects[2]} == original-f.o ]]; fi
for tag in "${experiments[@]}"; do
    plan="$tmp/${tag}_plan.txt"
    [[ $(grep -c 'test/ps2/bench.c' "$plan") == 1 ]]
    [[ $(grep -c '^crypto/bn/bn-ee-row-.*mmi\.S ' "$plan") == 1 ]]
    [[ $(grep -c '^crypto/sha/sha256-ee-mmi[^ ]*\.S ' "$plan") == 1 ]]
    [[ $(grep -c '^crypto/modes/ghash-ee-mmi[^ ]*\.S ' "$plan") == 1 ]]
    [[ $(grep -c '^crypto/aes/aes-ee-mmi[^ ]*\.S ' "$plan") == 1 ]]
    [[ $(grep -c '^crypto/chacha/chacha-ee-mmi[^ ]*\.S ' "$plan") == 1 ]]
    [[ $(grep -Ec '^crypto/poly1305/poly1305-ee-(pmadduw|preload-mmi|reduce-mmi)\.S ' "$plan") == 1 ]]
    [[ $(grep -c -- '-UEE_MMI_GHASH_WINDOW_BITS' "$plan") == $(wc -l < "$plan") ]]
done
[[ $(grep -c 'test/ee_mmi/.*_test.c' "$tmp/r_plan.txt") == 3 ]]
grep -q 'bn-ee-row-reg-mmi.S' "$tmp/r_plan.txt"
if [[ "$ps2_profile" != selected ]]; then
grep -q -- '-DEE_MMI_POLY1305_SCALAR_ABSORB'  "$tmp/h_plan.txt"
grep -q 'sha256-ee-mmi-unroll4.S' "$tmp/s_plan.txt"
grep -q 'ghash-ee-mmi-unroll8.S' "$tmp/g_plan.txt"
grep -q 'aes-ee-mmi-keyearly.S' "$tmp/k_plan.txt"
grep -q -- '-DEE_MMI_AES_TOWER_SBOX' "$tmp/k_plan.txt"
fi
grep -q 'test/ee_mmi/aes_gcm_test.c' "$tmp/c_plan.txt"
grep -q 'ghash-ee-mmi-unroll8.S' "$tmp/c_plan.txt"
grep -q -- '-DEE_MMI_BN_REDC_SHIFT' "$tmp/d_plan.txt"
grep -q 'bn-ee-redc-shift-mmi.S' "$tmp/d_plan.txt"
[[ $(grep -c 'test/ee_mmi/.*_test.c' "$tmp/d_plan.txt") == 2 ]]
if [[ "$ps2_profile" != selected ]]; then
grep -q 'poly1305-ee-preload-mmi.S'  "$tmp/p_plan.txt"
fi
grep -q -- '-DEE_MMI_BN_ACTIVE_SCRATCH' "$tmp/q_plan.txt"
grep -q -- '-DEE_MMI_RSA_SWAP_POWERS' "$tmp/q_plan.txt"
grep -q -- '-DEE_MMI_POLY1305_FUSED_REDUCE' "$tmp/e_plan.txt"
grep -q 'poly1305-ee-reduce-mmi.S' "$tmp/e_plan.txt"
if [[ "$ps2_profile" != selected ]]; then
grep -q -- '-DEE_MMI_BN_PUBLIC_SQUARE' "$tmp/n_plan.txt"
grep -q 'bn-ee-square.c' "$tmp/n_plan.txt"
[[ $(grep -c 'test/ee_mmi/.*_test.c' "$tmp/n_plan.txt") == 2 ]]
fi
grep -q 'chacha-ee-wrap.c' "$tmp/w_plan.txt"
grep -q 'test/ee_mmi/chacha20_test.c' "$tmp/w_plan.txt"
[[ $(grep -c '^crypto/chacha/.*\.c ' "$tmp/w_plan.txt") == 1 ]]
if [[ "$ps2_profile" == selected && ${PS2_NEW_IDEAS:-1} == 1 ]]; then
    grep -q -- '-DEE_MMI_AES_SHIFTROWS_FIXED' "$tmp/j_plan.txt"
    grep -q -- '-DEE_MMI_GCM_FULL_BLOCK' "$tmp/l_plan.txt"
    grep -q 'ghash-ee-mmi-unroll8.S' "$tmp/l_plan.txt"
    grep -q -- '-DEE_MMI_P256_REDC_UNROLL' "$tmp/t_plan.txt"
    grep -q 'bn-ee-row-reg-mmi.S' "$tmp/t_plan.txt"
    [[ $(grep -c 'test/ee_mmi/.*_test.c' "$tmp/t_plan.txt") == 2 ]]
    grep -q -- '-DEE_MMI_AES_VECTOR_SBOX' "$tmp/u_plan.txt"
    grep -q 'aes-ee-subbytes-mmi.S' "$tmp/u_plan.txt"
    grep -q -- '-DEE_MMI_P256_MUL8' "$tmp/v_plan.txt"
    grep -q 'p256-ee-mul8-mmi.S' "$tmp/v_plan.txt"
    grep -q -- '-DEE_MMI_X25519_FUSED_REDUCE' "$tmp/x_plan.txt"
    grep -q 'x25519-ee-reduce-mmi.S' "$tmp/x_plan.txt"
    grep -q 'chacha-ee-wrap.c' "$tmp/y_plan.txt"
    grep -q 'chacha-ee-mmi-interleave.S' "$tmp/y_plan.txt"
    grep -q -- '-DEE_MMI_GCM_WORD_CORE' "$tmp/z_plan.txt"
    grep -q -- '-DEE_MMI_GCM_FULL_BLOCK' "$tmp/z_plan.txt"
    grep -q 'ghash-ee-mmi-unroll8.S' "$tmp/z_plan.txt"
    grep -q -- '-DEE_MMI_P256_SQUARE' "$tmp/o_plan.txt"
    grep -q 'p256-ee-square-mmi.S' "$tmp/o_plan.txt"
    for tag in u v x z o; do
        grep -q 'test/ee_mmi/six_ideas_test.c' "$tmp/${tag}_plan.txt"
    done
fi
printf 'PASS: experiment build plan, source selection, waits, symbol prefixes and original objects\n'
