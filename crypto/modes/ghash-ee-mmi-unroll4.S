/*
 * Variant U4: unroll four independent GHASH bit steps per branch.
 * The EE MMI masks, XOR, and 128-bit right shifts are exactly those
 * of the scheduled G variant; 4 steps are evaluated sequentially.
 * Loop count drops from 32 to 8 per GHASH word (128 -> 32 branches).
 * Instruction cache pressure rises; real EE benchmarks required.
 */
/*
 * Copyright 2026 openssl-retro contributors. Licensed under Apache-2.0.
 *
 * EXPERIMENTAL R5900 Emotion Engine MMI four-stream GHASH multiply.
 * Variant G: schedule independent conditional-reduction mask and
 * X bit advancement before dependent four-word accumulator updates.
 *
 * void ossl_ee_ghash_mul4(uint32_t z[4][4],
 *                          const uint32_t x[4][4],
 *                          const uint32_t h[4][4]);
 *
 * Word-major layout: x[word][stream], H[word][stream], Z[word][stream].
 * Each 128-bit GPR packs four independent 32-bit streams. Words are
 * interpreted in GHASH big-endian order, unlike their EE memory bytes.
 *
 * SP 800-38D Algorithm 1:
 *   Z = 0, V = H
 *   for bit i = 0..127 (most significant first):
 *       if X_i: Z ^= V
 *       V = V>>1; if old V least bit: V ^= 0xe1 << 120
 *
 * PSRAW yields a per-stream all-ones mask from X's top bit.
 * PAND/PXOR applies conditional XOR without key-dependent branches.
 * PSLLW/PSRLW/POR shifts V over four packed 32-bit word vectors
 * with carries from more significant to less significant words.
 * All 128 rounds execute and have identical instruction counts.
 *
 * t0..t3: H/V words; t4..t7: Z words; t8: X current word;
 * t9: X bit mask; a3: scratch; v0: reduction mask; v1: R constant.
 * All caller-saved EE registers, leaf function, no stack or saved GPR.
 * a0=output, a1=X input, a2=H input initially; after loads a2
 * becomes the public fixed 32-bit round counter. HI/LO untouched.
 *
 * Requires all pointers 16-byte aligned and nonoverlapping.
 * Code assumes target static ELF relocation for .Lghash_reduction.
 * Must be assembled and verified on real PS2; no speedup claimed.
 */
/* Numeric GPRs 8..15 retain the original o32 temporary layout under
 * both o32 and modern PS2SDK n32 register naming. */
    .text
    .set noreorder
    .align 4

    .macro EE_GHASH_STEP
        /* Independent X-top and old V3-low masks are computed
         * before the four Z accumulations. This hides read-after-
         * write delays inside the four disjoint 32-bit word lanes. */
        psraw   $t9, $t8, 31
        psllw   $v0, $11, 31
        psraw   $v0, $v0, 31
        pand    $v0, $v0, $v1
        psllw   $t8, $t8, 1
        pand    $a3, $8, $t9
        pxor    $12, $12, $a3
        pand    $a3, $9, $t9
        pxor    $13, $13, $a3
        pand    $a3, $10, $t9
        pxor    $14, $14, $a3
        pand    $a3, $11, $t9
        pxor    $15, $15, $a3
        /* V is 128-bit big-endian: process low words FIRST to
         * preserve old cross-word bits for the right shift. */
        psrlw   $11, $11, 1
        psllw   $a3, $10, 31
        por     $11, $11, $a3

        psrlw   $10, $10, 1
        psllw   $a3, $9, 31
        por     $10, $10, $a3

        psrlw   $9, $9, 1
        psllw   $a3, $8, 31
        por     $9, $9, $a3

        psrlw   $8, $8, 1
        pxor    $8, $8, $v0

    .endm

    .macro EE_GHASH_WORD off
        lq      $t8, \off($a1)
        addiu   $a2, $zero, 8
.Lghash_loop\@:
        EE_GHASH_STEP
        EE_GHASH_STEP
        EE_GHASH_STEP
        EE_GHASH_STEP
        addiu   $a2, $a2, -1
        bnez    $a2, .Lghash_loop\@
        nop
    .endm

    .globl ossl_ee_ghash_mul4
    .ent ossl_ee_ghash_mul4
ossl_ee_ghash_mul4:
    lq      $8, 0($a2)
    lq      $9, 16($a2)
    lq      $10, 32($a2)
    lq      $11, 48($a2)

    pxor    $12, $zero, $zero
    pxor    $13, $zero, $zero
    pxor    $14, $zero, $zero
    pxor    $15, $zero, $zero

    lui     $v1, %hi(.Lghash_reduction)
    addiu   $v1, $v1, %lo(.Lghash_reduction)
    lq      $v1, 0($v1)

    EE_GHASH_WORD 0
    EE_GHASH_WORD 16
    EE_GHASH_WORD 32
    EE_GHASH_WORD 48

    sq      $12, 0($a0)
    sq      $13, 16($a0)
    sq      $14, 32($a0)
    sq      $15, 48($a0)
    jr      $ra
    nop

    .end ossl_ee_ghash_mul4
    .set reorder

    .section .rodata
    .align 4
.Lghash_reduction:
    .word 0xe1000000, 0xe1000000, 0xe1000000, 0xe1000000
