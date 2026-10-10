#!/usr/bin/env bash
# Sourced by build.sh after the A/B/F compilers have finished.
# Each experiment owns its tests, crypto objects and benchmark state.
saved_objects=("${objects[@]}")
experiment_objects=()
experiments=(r h s g k c d p q e n w)
if [[ ${ps2_profile:-all} == selected ]]; then
    experiments=(r g c d q e w)
    if [[ ${PS2_NEW_IDEAS:-1} == 1 ]]; then experiments+=(j l t u v x y z o); fi
fi
for experiment in "${experiments[@]}"; do
    objects=()
    object_tag="${experiment}_"
    experiment_flags=(-UEE_MMI_GHASH_WINDOW_BITS -DEE_MMI_BN_ROW_FUSED
                      -DEE_MMI_POLY1305_FUSED_MADD -DEE_MMI_AES_TOWER_SBOX)
    experiment_chacha=crypto/chacha/chacha-ee-mmi.c
    experiment_chacha_asm=crypto/chacha/chacha-ee-mmi.S
    experiment_bn=crypto/bn/bn-ee-row-mmi.S
    experiment_sha=crypto/sha/sha256-ee-mmi.S
    experiment_ghash=crypto/modes/ghash-ee-mmi.S
    experiment_aes=crypto/aes/aes-ee-mmi.S
    experiment_poly=crypto/poly1305/poly1305-ee-pmadduw.S
    experiment_extra=()
    case "$experiment" in
        r) experiment_bn=crypto/bn/bn-ee-row-reg-mmi.S
           experiment_tests=(bn_mont rsa p256_ecdh) ;;
        h) experiment_flags+=(-DEE_MMI_POLY1305_SCALAR_ABSORB)
           experiment_tests=(poly1305) ;;
        s) experiment_sha=crypto/sha/sha256-ee-mmi-unroll4.S
           experiment_tests=(sha256) ;;
        g) experiment_ghash=crypto/modes/ghash-ee-mmi-unroll8.S
           experiment_tests=(ghash) ;;
        k) experiment_aes=crypto/aes/aes-ee-mmi-keyearly.S
           experiment_tests=(aes) ;;
        c) experiment_ghash=crypto/modes/ghash-ee-mmi-unroll8.S
           experiment_tests=(aes_gcm) ;;
        d) experiment_bn=crypto/bn/bn-ee-row-reg-mmi.S
           experiment_flags+=(-DEE_MMI_BN_REDC_SHIFT)
           experiment_extra=(crypto/bn/bn-ee-redc-shift-mmi.S)
           experiment_tests=(bn_mont rsa) ;;
        p) experiment_poly=crypto/poly1305/poly1305-ee-preload-mmi.S
           experiment_tests=(poly1305) ;;
        q) experiment_bn=crypto/bn/bn-ee-row-reg-mmi.S
           experiment_flags+=(-DEE_MMI_BN_REDC_SHIFT -DEE_MMI_BN_ACTIVE_SCRATCH
                             -DEE_MMI_RSA_SWAP_POWERS)
           experiment_extra=(crypto/bn/bn-ee-redc-shift-mmi.S)
           experiment_tests=(bn_mont rsa) ;;
        e) experiment_poly=crypto/poly1305/poly1305-ee-reduce-mmi.S
           experiment_flags+=(-DEE_MMI_POLY1305_FUSED_REDUCE)
           experiment_tests=(poly1305) ;;
        n) experiment_bn=crypto/bn/bn-ee-row-reg-mmi.S
           experiment_flags+=(-DEE_MMI_BN_REDC_SHIFT -DEE_MMI_BN_ACTIVE_SCRATCH
                             -DEE_MMI_RSA_SWAP_POWERS -DEE_MMI_BN_PUBLIC_SQUARE)
           experiment_extra=(crypto/bn/bn-ee-redc-shift-mmi.S crypto/bn/bn-ee-square.c)
           experiment_tests=(bn_mont rsa) ;;
        w) experiment_chacha=crypto/chacha/chacha-ee-wrap.c
           experiment_tests=(chacha20) ;;
        j) experiment_flags+=(-DEE_MMI_AES_SHIFTROWS_FIXED)
           experiment_tests=(aes) ;;
        l) experiment_flags+=(-DEE_MMI_GCM_FULL_BLOCK)
           experiment_ghash=crypto/modes/ghash-ee-mmi-unroll8.S
           experiment_tests=(aes_gcm) ;;
        t) experiment_bn=crypto/bn/bn-ee-row-reg-mmi.S
           experiment_flags+=(-DEE_MMI_P256_REDC_UNROLL)
           experiment_tests=(bn_mont p256_ecdh) ;;
        u) experiment_flags+=(-DEE_MMI_AES_SHIFTROWS_FIXED -DEE_MMI_AES_VECTOR_SBOX)
           experiment_extra=(crypto/aes/aes-ee-subbytes-mmi.S)
           experiment_tests=(aes six_ideas) ;;
        v) experiment_bn=crypto/bn/bn-ee-row-reg-mmi.S
           experiment_flags+=(-DEE_MMI_P256_REDC_UNROLL -DEE_MMI_P256_MUL8)
           experiment_extra=(crypto/ec/p256-ee-mul8-mmi.S)
           experiment_tests=(bn_mont p256_ecdh six_ideas) ;;
        x) experiment_flags+=(-DEE_MMI_X25519_FUSED_REDUCE)
           experiment_extra=(crypto/ec/x25519-ee-reduce-mmi.S)
           experiment_tests=(x25519 six_ideas) ;;
        y) experiment_chacha=crypto/chacha/chacha-ee-wrap.c
           experiment_chacha_asm=crypto/chacha/chacha-ee-mmi-interleave.S
           experiment_tests=(chacha20) ;;
        z) experiment_flags+=(-DEE_MMI_GCM_FULL_BLOCK -DEE_MMI_GCM_WORD_CORE)
           experiment_ghash=crypto/modes/ghash-ee-mmi-unroll8.S
           experiment_tests=(aes aes_gcm six_ideas) ;;
        o) experiment_bn=crypto/bn/bn-ee-row-reg-mmi.S
           experiment_flags+=(-DEE_MMI_P256_REDC_UNROLL -DEE_MMI_P256_SQUARE)
           experiment_extra=(crypto/ec/p256-ee-square-mmi.S)
           experiment_tests=(bn_mont p256_ecdh six_ideas) ;;
    esac
    echo "Extra rows namespace=$experiment tests=${experiment_tests[*]}"
    for suite in "${experiment_tests[@]}"; do
        compile "test/ee_mmi/${suite}_test.c" "${experiment_flags[@]}" \
            "-Dmain=ps2_test_$suite"
    done
    # Reuse identical workload inputs, calls, resets and digest code.
    for src in "$experiment_chacha" "$experiment_chacha_asm" \
        crypto/sha/sha256-ee-mmi.c "$experiment_sha" \
        crypto/poly1305/poly1305-ee-mmi.c crypto/poly1305/poly1305-ee-mmi.S \
        "$experiment_poly" \
        crypto/aes/aes-ee-mmi.c "$experiment_aes" \
        crypto/modes/ghash-ee-mmi.c "$experiment_ghash" \
        crypto/modes/aes-gcm-ee-mmi.c \
        crypto/bn/bn-ee-mmi.c crypto/bn/bn-ee-mmi.S "$experiment_bn" "${experiment_extra[@]}" \
        crypto/ec/x25519-ee-mmi.c crypto/ec/x25519-ee-mmi.S \
        crypto/rsa/rsa-ee-mmi.c crypto/ec/p256-ee-mmi.c test/ps2/bench.c; do
        compile "$src" "${experiment_flags[@]}"
    done
    finish_compiles
    combined="$output_dir/experiment-$experiment.o"
    symbols="$output_dir/experiment-$experiment-symbols.txt"
    "${cc%gcc}ld" -r "${objects[@]}" -o "$combined"
    "${cc%gcc}nm" --defined-only --extern-only "$combined" |
        awk -v prefix="${experiment}_" '{print $3 " " prefix $3}' > "$symbols"
    "${cc%gcc}objcopy" --redefine-syms="$symbols" "$combined"
    experiment_objects+=("$combined")
done
objects=("${saved_objects[@]}" "${experiment_objects[@]}")
object_tag=
