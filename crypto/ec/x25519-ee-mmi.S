/*
 * Copyright 2026 openssl-retro contributors. Licensed under Apache-2.0.
 *
 * Four independent X25519 field convolutions with EE PMULTUW/PMADDUW.
 * f and g are ten 26/25-bit limbs: weights 2^(ceil(25.5*i)).
 * For each term f_i*g_j at k=(i+j)%10, multiplying by 2
 * compensates for the extra bit when i and j are odd; multiplying
 * by 19 folds terms with i+j>=10 modulo 2^255-19.
 *
 * X25519 radix-25.5 MMI kernel: two unsigned 32x32->64 products
 * per instruction, 10 sums x 4 independent streams.
 *
 * g_scaled holds 4 aligned variants at offsets 0, 160, 320, 480:
 *   g, 2*g, 19*g, 38*g. Largest operand < 2^31.
 * All 64-bit output sums fit within 2^60 (10 products each).
 * 20 SQ instructions write only 320 bytes, no intermediate products.
 * All arguments are 16-byte aligned. Caller-saved t0..t4 and
 * EE HI/LO are modified. No stack frame is used.
 *
 * This is experimental, and its instruction syntax, HI/LO behavior,
 * ABI and performance require real R5900 cross-toolchain verification.
 */
/* Numeric GPRs 8..15 retain the original o32 temporary layout under
 * both o32 and modern PS2SDK n32 register naming. */
    .text
    .set noreorder
    .align 4

    .macro EE_X25519_ACC op, extract, aoff, boff
        lq       $8, \aoff($a1)
        lq       $9, \boff($a2)
        \extract $10, $zero, $8
        \extract $11, $zero, $9
        \op      $12, $10, $11
    .endm

    .globl ossl_ee_x25519_mul_sums4
    .ent ossl_ee_x25519_mul_sums4
ossl_ee_x25519_mul_sums4:

    EE_X25519_ACC pmultuw, pextlw, 0, 0  /* h0*g0 */
    EE_X25519_ACC pmadduw, pextlw, 16, 624  /* h1*38*g9 */
    EE_X25519_ACC pmadduw, pextlw, 32, 448  /* h2*19*g8 */
    EE_X25519_ACC pmadduw, pextlw, 48, 592  /* h3*38*g7 */
    EE_X25519_ACC pmadduw, pextlw, 64, 416  /* h4*19*g6 */
    EE_X25519_ACC pmadduw, pextlw, 80, 560  /* h5*38*g5 */
    EE_X25519_ACC pmadduw, pextlw, 96, 384  /* h6*19*g4 */
    EE_X25519_ACC pmadduw, pextlw, 112, 528  /* h7*38*g3 */
    EE_X25519_ACC pmadduw, pextlw, 128, 352  /* h8*19*g2 */
    EE_X25519_ACC pmadduw, pextlw, 144, 496  /* h9*38*g1 */
    sq      $12, 0($a0)
    EE_X25519_ACC pmultuw, pextuw, 0, 0  /* h0*g0 */
    EE_X25519_ACC pmadduw, pextuw, 16, 624  /* h1*38*g9 */
    EE_X25519_ACC pmadduw, pextuw, 32, 448  /* h2*19*g8 */
    EE_X25519_ACC pmadduw, pextuw, 48, 592  /* h3*38*g7 */
    EE_X25519_ACC pmadduw, pextuw, 64, 416  /* h4*19*g6 */
    EE_X25519_ACC pmadduw, pextuw, 80, 560  /* h5*38*g5 */
    EE_X25519_ACC pmadduw, pextuw, 96, 384  /* h6*19*g4 */
    EE_X25519_ACC pmadduw, pextuw, 112, 528  /* h7*38*g3 */
    EE_X25519_ACC pmadduw, pextuw, 128, 352  /* h8*19*g2 */
    EE_X25519_ACC pmadduw, pextuw, 144, 496  /* h9*38*g1 */
    sq      $12, 16($a0)
    EE_X25519_ACC pmultuw, pextlw, 0, 16  /* h0*g1 */
    EE_X25519_ACC pmadduw, pextlw, 16, 0  /* h1*g0 */
    EE_X25519_ACC pmadduw, pextlw, 32, 464  /* h2*19*g9 */
    EE_X25519_ACC pmadduw, pextlw, 48, 448  /* h3*19*g8 */
    EE_X25519_ACC pmadduw, pextlw, 64, 432  /* h4*19*g7 */
    EE_X25519_ACC pmadduw, pextlw, 80, 416  /* h5*19*g6 */
    EE_X25519_ACC pmadduw, pextlw, 96, 400  /* h6*19*g5 */
    EE_X25519_ACC pmadduw, pextlw, 112, 384  /* h7*19*g4 */
    EE_X25519_ACC pmadduw, pextlw, 128, 368  /* h8*19*g3 */
    EE_X25519_ACC pmadduw, pextlw, 144, 352  /* h9*19*g2 */
    sq      $12, 32($a0)
    EE_X25519_ACC pmultuw, pextuw, 0, 16  /* h0*g1 */
    EE_X25519_ACC pmadduw, pextuw, 16, 0  /* h1*g0 */
    EE_X25519_ACC pmadduw, pextuw, 32, 464  /* h2*19*g9 */
    EE_X25519_ACC pmadduw, pextuw, 48, 448  /* h3*19*g8 */
    EE_X25519_ACC pmadduw, pextuw, 64, 432  /* h4*19*g7 */
    EE_X25519_ACC pmadduw, pextuw, 80, 416  /* h5*19*g6 */
    EE_X25519_ACC pmadduw, pextuw, 96, 400  /* h6*19*g5 */
    EE_X25519_ACC pmadduw, pextuw, 112, 384  /* h7*19*g4 */
    EE_X25519_ACC pmadduw, pextuw, 128, 368  /* h8*19*g3 */
    EE_X25519_ACC pmadduw, pextuw, 144, 352  /* h9*19*g2 */
    sq      $12, 48($a0)
    EE_X25519_ACC pmultuw, pextlw, 0, 32  /* h0*g2 */
    EE_X25519_ACC pmadduw, pextlw, 16, 176  /* h1*2*g1 */
    EE_X25519_ACC pmadduw, pextlw, 32, 0  /* h2*g0 */
    EE_X25519_ACC pmadduw, pextlw, 48, 624  /* h3*38*g9 */
    EE_X25519_ACC pmadduw, pextlw, 64, 448  /* h4*19*g8 */
    EE_X25519_ACC pmadduw, pextlw, 80, 592  /* h5*38*g7 */
    EE_X25519_ACC pmadduw, pextlw, 96, 416  /* h6*19*g6 */
    EE_X25519_ACC pmadduw, pextlw, 112, 560  /* h7*38*g5 */
    EE_X25519_ACC pmadduw, pextlw, 128, 384  /* h8*19*g4 */
    EE_X25519_ACC pmadduw, pextlw, 144, 528  /* h9*38*g3 */
    sq      $12, 64($a0)
    EE_X25519_ACC pmultuw, pextuw, 0, 32  /* h0*g2 */
    EE_X25519_ACC pmadduw, pextuw, 16, 176  /* h1*2*g1 */
    EE_X25519_ACC pmadduw, pextuw, 32, 0  /* h2*g0 */
    EE_X25519_ACC pmadduw, pextuw, 48, 624  /* h3*38*g9 */
    EE_X25519_ACC pmadduw, pextuw, 64, 448  /* h4*19*g8 */
    EE_X25519_ACC pmadduw, pextuw, 80, 592  /* h5*38*g7 */
    EE_X25519_ACC pmadduw, pextuw, 96, 416  /* h6*19*g6 */
    EE_X25519_ACC pmadduw, pextuw, 112, 560  /* h7*38*g5 */
    EE_X25519_ACC pmadduw, pextuw, 128, 384  /* h8*19*g4 */
    EE_X25519_ACC pmadduw, pextuw, 144, 528  /* h9*38*g3 */
    sq      $12, 80($a0)
    EE_X25519_ACC pmultuw, pextlw, 0, 48  /* h0*g3 */
    EE_X25519_ACC pmadduw, pextlw, 16, 32  /* h1*g2 */
    EE_X25519_ACC pmadduw, pextlw, 32, 16  /* h2*g1 */
    EE_X25519_ACC pmadduw, pextlw, 48, 0  /* h3*g0 */
    EE_X25519_ACC pmadduw, pextlw, 64, 464  /* h4*19*g9 */
    EE_X25519_ACC pmadduw, pextlw, 80, 448  /* h5*19*g8 */
    EE_X25519_ACC pmadduw, pextlw, 96, 432  /* h6*19*g7 */
    EE_X25519_ACC pmadduw, pextlw, 112, 416  /* h7*19*g6 */
    EE_X25519_ACC pmadduw, pextlw, 128, 400  /* h8*19*g5 */
    EE_X25519_ACC pmadduw, pextlw, 144, 384  /* h9*19*g4 */
    sq      $12, 96($a0)
    EE_X25519_ACC pmultuw, pextuw, 0, 48  /* h0*g3 */
    EE_X25519_ACC pmadduw, pextuw, 16, 32  /* h1*g2 */
    EE_X25519_ACC pmadduw, pextuw, 32, 16  /* h2*g1 */
    EE_X25519_ACC pmadduw, pextuw, 48, 0  /* h3*g0 */
    EE_X25519_ACC pmadduw, pextuw, 64, 464  /* h4*19*g9 */
    EE_X25519_ACC pmadduw, pextuw, 80, 448  /* h5*19*g8 */
    EE_X25519_ACC pmadduw, pextuw, 96, 432  /* h6*19*g7 */
    EE_X25519_ACC pmadduw, pextuw, 112, 416  /* h7*19*g6 */
    EE_X25519_ACC pmadduw, pextuw, 128, 400  /* h8*19*g5 */
    EE_X25519_ACC pmadduw, pextuw, 144, 384  /* h9*19*g4 */
    sq      $12, 112($a0)
    EE_X25519_ACC pmultuw, pextlw, 0, 64  /* h0*g4 */
    EE_X25519_ACC pmadduw, pextlw, 16, 208  /* h1*2*g3 */
    EE_X25519_ACC pmadduw, pextlw, 32, 32  /* h2*g2 */
    EE_X25519_ACC pmadduw, pextlw, 48, 176  /* h3*2*g1 */
    EE_X25519_ACC pmadduw, pextlw, 64, 0  /* h4*g0 */
    EE_X25519_ACC pmadduw, pextlw, 80, 624  /* h5*38*g9 */
    EE_X25519_ACC pmadduw, pextlw, 96, 448  /* h6*19*g8 */
    EE_X25519_ACC pmadduw, pextlw, 112, 592  /* h7*38*g7 */
    EE_X25519_ACC pmadduw, pextlw, 128, 416  /* h8*19*g6 */
    EE_X25519_ACC pmadduw, pextlw, 144, 560  /* h9*38*g5 */
    sq      $12, 128($a0)
    EE_X25519_ACC pmultuw, pextuw, 0, 64  /* h0*g4 */
    EE_X25519_ACC pmadduw, pextuw, 16, 208  /* h1*2*g3 */
    EE_X25519_ACC pmadduw, pextuw, 32, 32  /* h2*g2 */
    EE_X25519_ACC pmadduw, pextuw, 48, 176  /* h3*2*g1 */
    EE_X25519_ACC pmadduw, pextuw, 64, 0  /* h4*g0 */
    EE_X25519_ACC pmadduw, pextuw, 80, 624  /* h5*38*g9 */
    EE_X25519_ACC pmadduw, pextuw, 96, 448  /* h6*19*g8 */
    EE_X25519_ACC pmadduw, pextuw, 112, 592  /* h7*38*g7 */
    EE_X25519_ACC pmadduw, pextuw, 128, 416  /* h8*19*g6 */
    EE_X25519_ACC pmadduw, pextuw, 144, 560  /* h9*38*g5 */
    sq      $12, 144($a0)
    EE_X25519_ACC pmultuw, pextlw, 0, 80  /* h0*g5 */
    EE_X25519_ACC pmadduw, pextlw, 16, 64  /* h1*g4 */
    EE_X25519_ACC pmadduw, pextlw, 32, 48  /* h2*g3 */
    EE_X25519_ACC pmadduw, pextlw, 48, 32  /* h3*g2 */
    EE_X25519_ACC pmadduw, pextlw, 64, 16  /* h4*g1 */
    EE_X25519_ACC pmadduw, pextlw, 80, 0  /* h5*g0 */
    EE_X25519_ACC pmadduw, pextlw, 96, 464  /* h6*19*g9 */
    EE_X25519_ACC pmadduw, pextlw, 112, 448  /* h7*19*g8 */
    EE_X25519_ACC pmadduw, pextlw, 128, 432  /* h8*19*g7 */
    EE_X25519_ACC pmadduw, pextlw, 144, 416  /* h9*19*g6 */
    sq      $12, 160($a0)
    EE_X25519_ACC pmultuw, pextuw, 0, 80  /* h0*g5 */
    EE_X25519_ACC pmadduw, pextuw, 16, 64  /* h1*g4 */
    EE_X25519_ACC pmadduw, pextuw, 32, 48  /* h2*g3 */
    EE_X25519_ACC pmadduw, pextuw, 48, 32  /* h3*g2 */
    EE_X25519_ACC pmadduw, pextuw, 64, 16  /* h4*g1 */
    EE_X25519_ACC pmadduw, pextuw, 80, 0  /* h5*g0 */
    EE_X25519_ACC pmadduw, pextuw, 96, 464  /* h6*19*g9 */
    EE_X25519_ACC pmadduw, pextuw, 112, 448  /* h7*19*g8 */
    EE_X25519_ACC pmadduw, pextuw, 128, 432  /* h8*19*g7 */
    EE_X25519_ACC pmadduw, pextuw, 144, 416  /* h9*19*g6 */
    sq      $12, 176($a0)
    EE_X25519_ACC pmultuw, pextlw, 0, 96  /* h0*g6 */
    EE_X25519_ACC pmadduw, pextlw, 16, 240  /* h1*2*g5 */
    EE_X25519_ACC pmadduw, pextlw, 32, 64  /* h2*g4 */
    EE_X25519_ACC pmadduw, pextlw, 48, 208  /* h3*2*g3 */
    EE_X25519_ACC pmadduw, pextlw, 64, 32  /* h4*g2 */
    EE_X25519_ACC pmadduw, pextlw, 80, 176  /* h5*2*g1 */
    EE_X25519_ACC pmadduw, pextlw, 96, 0  /* h6*g0 */
    EE_X25519_ACC pmadduw, pextlw, 112, 624  /* h7*38*g9 */
    EE_X25519_ACC pmadduw, pextlw, 128, 448  /* h8*19*g8 */
    EE_X25519_ACC pmadduw, pextlw, 144, 592  /* h9*38*g7 */
    sq      $12, 192($a0)
    EE_X25519_ACC pmultuw, pextuw, 0, 96  /* h0*g6 */
    EE_X25519_ACC pmadduw, pextuw, 16, 240  /* h1*2*g5 */
    EE_X25519_ACC pmadduw, pextuw, 32, 64  /* h2*g4 */
    EE_X25519_ACC pmadduw, pextuw, 48, 208  /* h3*2*g3 */
    EE_X25519_ACC pmadduw, pextuw, 64, 32  /* h4*g2 */
    EE_X25519_ACC pmadduw, pextuw, 80, 176  /* h5*2*g1 */
    EE_X25519_ACC pmadduw, pextuw, 96, 0  /* h6*g0 */
    EE_X25519_ACC pmadduw, pextuw, 112, 624  /* h7*38*g9 */
    EE_X25519_ACC pmadduw, pextuw, 128, 448  /* h8*19*g8 */
    EE_X25519_ACC pmadduw, pextuw, 144, 592  /* h9*38*g7 */
    sq      $12, 208($a0)
    EE_X25519_ACC pmultuw, pextlw, 0, 112  /* h0*g7 */
    EE_X25519_ACC pmadduw, pextlw, 16, 96  /* h1*g6 */
    EE_X25519_ACC pmadduw, pextlw, 32, 80  /* h2*g5 */
    EE_X25519_ACC pmadduw, pextlw, 48, 64  /* h3*g4 */
    EE_X25519_ACC pmadduw, pextlw, 64, 48  /* h4*g3 */
    EE_X25519_ACC pmadduw, pextlw, 80, 32  /* h5*g2 */
    EE_X25519_ACC pmadduw, pextlw, 96, 16  /* h6*g1 */
    EE_X25519_ACC pmadduw, pextlw, 112, 0  /* h7*g0 */
    EE_X25519_ACC pmadduw, pextlw, 128, 464  /* h8*19*g9 */
    EE_X25519_ACC pmadduw, pextlw, 144, 448  /* h9*19*g8 */
    sq      $12, 224($a0)
    EE_X25519_ACC pmultuw, pextuw, 0, 112  /* h0*g7 */
    EE_X25519_ACC pmadduw, pextuw, 16, 96  /* h1*g6 */
    EE_X25519_ACC pmadduw, pextuw, 32, 80  /* h2*g5 */
    EE_X25519_ACC pmadduw, pextuw, 48, 64  /* h3*g4 */
    EE_X25519_ACC pmadduw, pextuw, 64, 48  /* h4*g3 */
    EE_X25519_ACC pmadduw, pextuw, 80, 32  /* h5*g2 */
    EE_X25519_ACC pmadduw, pextuw, 96, 16  /* h6*g1 */
    EE_X25519_ACC pmadduw, pextuw, 112, 0  /* h7*g0 */
    EE_X25519_ACC pmadduw, pextuw, 128, 464  /* h8*19*g9 */
    EE_X25519_ACC pmadduw, pextuw, 144, 448  /* h9*19*g8 */
    sq      $12, 240($a0)
    EE_X25519_ACC pmultuw, pextlw, 0, 128  /* h0*g8 */
    EE_X25519_ACC pmadduw, pextlw, 16, 272  /* h1*2*g7 */
    EE_X25519_ACC pmadduw, pextlw, 32, 96  /* h2*g6 */
    EE_X25519_ACC pmadduw, pextlw, 48, 240  /* h3*2*g5 */
    EE_X25519_ACC pmadduw, pextlw, 64, 64  /* h4*g4 */
    EE_X25519_ACC pmadduw, pextlw, 80, 208  /* h5*2*g3 */
    EE_X25519_ACC pmadduw, pextlw, 96, 32  /* h6*g2 */
    EE_X25519_ACC pmadduw, pextlw, 112, 176  /* h7*2*g1 */
    EE_X25519_ACC pmadduw, pextlw, 128, 0  /* h8*g0 */
    EE_X25519_ACC pmadduw, pextlw, 144, 624  /* h9*38*g9 */
    sq      $12, 256($a0)
    EE_X25519_ACC pmultuw, pextuw, 0, 128  /* h0*g8 */
    EE_X25519_ACC pmadduw, pextuw, 16, 272  /* h1*2*g7 */
    EE_X25519_ACC pmadduw, pextuw, 32, 96  /* h2*g6 */
    EE_X25519_ACC pmadduw, pextuw, 48, 240  /* h3*2*g5 */
    EE_X25519_ACC pmadduw, pextuw, 64, 64  /* h4*g4 */
    EE_X25519_ACC pmadduw, pextuw, 80, 208  /* h5*2*g3 */
    EE_X25519_ACC pmadduw, pextuw, 96, 32  /* h6*g2 */
    EE_X25519_ACC pmadduw, pextuw, 112, 176  /* h7*2*g1 */
    EE_X25519_ACC pmadduw, pextuw, 128, 0  /* h8*g0 */
    EE_X25519_ACC pmadduw, pextuw, 144, 624  /* h9*38*g9 */
    sq      $12, 272($a0)
    EE_X25519_ACC pmultuw, pextlw, 0, 144  /* h0*g9 */
    EE_X25519_ACC pmadduw, pextlw, 16, 128  /* h1*g8 */
    EE_X25519_ACC pmadduw, pextlw, 32, 112  /* h2*g7 */
    EE_X25519_ACC pmadduw, pextlw, 48, 96  /* h3*g6 */
    EE_X25519_ACC pmadduw, pextlw, 64, 80  /* h4*g5 */
    EE_X25519_ACC pmadduw, pextlw, 80, 64  /* h5*g4 */
    EE_X25519_ACC pmadduw, pextlw, 96, 48  /* h6*g3 */
    EE_X25519_ACC pmadduw, pextlw, 112, 32  /* h7*g2 */
    EE_X25519_ACC pmadduw, pextlw, 128, 16  /* h8*g1 */
    EE_X25519_ACC pmadduw, pextlw, 144, 0  /* h9*g0 */
    sq      $12, 288($a0)
    EE_X25519_ACC pmultuw, pextuw, 0, 144  /* h0*g9 */
    EE_X25519_ACC pmadduw, pextuw, 16, 128  /* h1*g8 */
    EE_X25519_ACC pmadduw, pextuw, 32, 112  /* h2*g7 */
    EE_X25519_ACC pmadduw, pextuw, 48, 96  /* h3*g6 */
    EE_X25519_ACC pmadduw, pextuw, 64, 80  /* h4*g5 */
    EE_X25519_ACC pmadduw, pextuw, 80, 64  /* h5*g4 */
    EE_X25519_ACC pmadduw, pextuw, 96, 48  /* h6*g3 */
    EE_X25519_ACC pmadduw, pextuw, 112, 32  /* h7*g2 */
    EE_X25519_ACC pmadduw, pextuw, 128, 16  /* h8*g1 */
    EE_X25519_ACC pmadduw, pextuw, 144, 0  /* h9*g0 */
    sq      $12, 304($a0)
    jr      $ra
    nop
    .end ossl_ee_x25519_mul_sums4
    .set reorder
