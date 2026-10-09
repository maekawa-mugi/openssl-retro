/*
 * Copyright 2026 The openssl-retro contributors. All Rights Reserved.
 * Licensed under the Apache License 2.0; see LICENSE.txt.
 *
 * R5900 / Emotion Engine MMI ChaCha20: four blocks in parallel.
 * Variant C: instruction-level scheduling of four independent
 * quarter-rounds in each column and diagonal round.
 * Every step of 4 QRs is performed before the next dependent step,
 * increasing distance between packed ADD/XOR/rotation dependencies.
 * Uses the identical EE_ROTL and 128-bit saved-register ABI as A.
 *
 * void ossl_chacha20_ee_mmi_4way(uint32_t state[16][4]);
 * Input/output: 16-byte-aligned, word-major 16 x 4 array.
 *
 * A 128-bit GPR stores one 32-bit state word from each of four blocks.
 * GPRs v0,v1,a1-a3,t0-t9,s0 are the sixteen ChaCha words.
 * s1/s2 are rotation temporaries, s3 is the double-round counter.
 * a0 remains the state pointer; s0-s3 are preserved as 128-bit GPRs.
 */
/* Numeric GPRs 8..15 retain the original o32 temporary layout under
 * both o32 and modern PS2SDK n32 register naming. */
    .text
    .set noreorder
    .align 4

    .macro EE_ROTL reg, left, right
        psllw   $s1, \reg, \left
        psrlw   $s2, \reg, \right
        por     \reg, $s1, $s2
    .endm

    .macro EE_QR a, b, c, d
        paddw   \a, \a, \b
        pxor    \d, \d, \a
        EE_ROTL \d, 16, 16
        paddw   \c, \c, \d
        pxor    \b, \b, \c
        EE_ROTL \b, 12, 20
        paddw   \a, \a, \b
        pxor    \d, \d, \a
        EE_ROTL \d, 8, 24
        paddw   \c, \c, \d
        pxor    \b, \b, \c
        EE_ROTL \b, 7, 25
    .endm

    .globl ossl_chacha20_ee_mmi_4way
    .ent ossl_chacha20_ee_mmi_4way
ossl_chacha20_ee_mmi_4way:
    addiu   $sp, $sp, -64
    sq      $s0, 0($sp)
    sq      $s1, 16($sp)
    sq      $s2, 32($sp)
    sq      $s3, 48($sp)

    lq      $v0,   0($a0)   /* word  0 */
    lq      $v1,  16($a0)   /* word  1 */
    lq      $a1,  32($a0)   /* word  2 */
    lq      $a2,  48($a0)   /* word  3 */
    lq      $a3,  64($a0)   /* word  4 */
    lq      $8,  80($a0)   /* word  5 */
    lq      $9,  96($a0)   /* word  6 */
    lq      $10, 112($a0)   /* word  7 */
    lq      $11, 128($a0)   /* word  8 */
    lq      $12, 144($a0)   /* word  9 */
    lq      $13, 160($a0)   /* word 10 */
    lq      $14, 176($a0)   /* word 11 */
    lq      $15, 192($a0)   /* word 12 */
    lq      $t8, 208($a0)   /* word 13 */
    lq      $t9, 224($a0)   /* word 14 */
    lq      $s0, 240($a0)   /* word 15 */

    addiu   $s3, $zero, 10
.Lee_chacha_round:
    /* stage add1: 4 disjoint quarter-rounds */
    paddw   $v0, $v0, $a3    /* QR0 */
    paddw   $v1, $v1, $8    /* QR1 */
    paddw   $a1, $a1, $9    /* QR2 */
    paddw   $a2, $a2, $10    /* QR3 */
    /* stage xor1: 4 disjoint quarter-rounds */
    pxor    $15, $15, $v0    /* QR0 */
    pxor    $t8, $t8, $v1    /* QR1 */
    pxor    $t9, $t9, $a1    /* QR2 */
    pxor    $s0, $s0, $a2    /* QR3 */
    /* stage rot1: 4 disjoint quarter-rounds */
    EE_ROTL $15, 16, 16    /* QR0 */
    EE_ROTL $t8, 16, 16    /* QR1 */
    EE_ROTL $t9, 16, 16    /* QR2 */
    EE_ROTL $s0, 16, 16    /* QR3 */
    /* stage add2: 4 disjoint quarter-rounds */
    paddw   $11, $11, $15    /* QR0 */
    paddw   $12, $12, $t8    /* QR1 */
    paddw   $13, $13, $t9    /* QR2 */
    paddw   $14, $14, $s0    /* QR3 */
    /* stage xor2: 4 disjoint quarter-rounds */
    pxor    $a3, $a3, $11    /* QR0 */
    pxor    $8, $8, $12    /* QR1 */
    pxor    $9, $9, $13    /* QR2 */
    pxor    $10, $10, $14    /* QR3 */
    /* stage rot2: 4 disjoint quarter-rounds */
    EE_ROTL $a3, 12, 20    /* QR0 */
    EE_ROTL $8, 12, 20    /* QR1 */
    EE_ROTL $9, 12, 20    /* QR2 */
    EE_ROTL $10, 12, 20    /* QR3 */
    /* stage add3: 4 disjoint quarter-rounds */
    paddw   $v0, $v0, $a3    /* QR0 */
    paddw   $v1, $v1, $8    /* QR1 */
    paddw   $a1, $a1, $9    /* QR2 */
    paddw   $a2, $a2, $10    /* QR3 */
    /* stage xor3: 4 disjoint quarter-rounds */
    pxor    $15, $15, $v0    /* QR0 */
    pxor    $t8, $t8, $v1    /* QR1 */
    pxor    $t9, $t9, $a1    /* QR2 */
    pxor    $s0, $s0, $a2    /* QR3 */
    /* stage rot3: 4 disjoint quarter-rounds */
    EE_ROTL $15, 8, 24    /* QR0 */
    EE_ROTL $t8, 8, 24    /* QR1 */
    EE_ROTL $t9, 8, 24    /* QR2 */
    EE_ROTL $s0, 8, 24    /* QR3 */
    /* stage add4: 4 disjoint quarter-rounds */
    paddw   $11, $11, $15    /* QR0 */
    paddw   $12, $12, $t8    /* QR1 */
    paddw   $13, $13, $t9    /* QR2 */
    paddw   $14, $14, $s0    /* QR3 */
    /* stage xor4: 4 disjoint quarter-rounds */
    pxor    $a3, $a3, $11    /* QR0 */
    pxor    $8, $8, $12    /* QR1 */
    pxor    $9, $9, $13    /* QR2 */
    pxor    $10, $10, $14    /* QR3 */
    /* stage rot4: 4 disjoint quarter-rounds */
    EE_ROTL $a3, 7, 25    /* QR0 */
    EE_ROTL $8, 7, 25    /* QR1 */
    EE_ROTL $9, 7, 25    /* QR2 */
    EE_ROTL $10, 7, 25    /* QR3 */

    /* stage add1: 4 disjoint quarter-rounds */
    paddw   $v0, $v0, $8    /* QR0 */
    paddw   $v1, $v1, $9    /* QR1 */
    paddw   $a1, $a1, $10    /* QR2 */
    paddw   $a2, $a2, $a3    /* QR3 */
    /* stage xor1: 4 disjoint quarter-rounds */
    pxor    $s0, $s0, $v0    /* QR0 */
    pxor    $15, $15, $v1    /* QR1 */
    pxor    $t8, $t8, $a1    /* QR2 */
    pxor    $t9, $t9, $a2    /* QR3 */
    /* stage rot1: 4 disjoint quarter-rounds */
    EE_ROTL $s0, 16, 16    /* QR0 */
    EE_ROTL $15, 16, 16    /* QR1 */
    EE_ROTL $t8, 16, 16    /* QR2 */
    EE_ROTL $t9, 16, 16    /* QR3 */
    /* stage add2: 4 disjoint quarter-rounds */
    paddw   $13, $13, $s0    /* QR0 */
    paddw   $14, $14, $15    /* QR1 */
    paddw   $11, $11, $t8    /* QR2 */
    paddw   $12, $12, $t9    /* QR3 */
    /* stage xor2: 4 disjoint quarter-rounds */
    pxor    $8, $8, $13    /* QR0 */
    pxor    $9, $9, $14    /* QR1 */
    pxor    $10, $10, $11    /* QR2 */
    pxor    $a3, $a3, $12    /* QR3 */
    /* stage rot2: 4 disjoint quarter-rounds */
    EE_ROTL $8, 12, 20    /* QR0 */
    EE_ROTL $9, 12, 20    /* QR1 */
    EE_ROTL $10, 12, 20    /* QR2 */
    EE_ROTL $a3, 12, 20    /* QR3 */
    /* stage add3: 4 disjoint quarter-rounds */
    paddw   $v0, $v0, $8    /* QR0 */
    paddw   $v1, $v1, $9    /* QR1 */
    paddw   $a1, $a1, $10    /* QR2 */
    paddw   $a2, $a2, $a3    /* QR3 */
    /* stage xor3: 4 disjoint quarter-rounds */
    pxor    $s0, $s0, $v0    /* QR0 */
    pxor    $15, $15, $v1    /* QR1 */
    pxor    $t8, $t8, $a1    /* QR2 */
    pxor    $t9, $t9, $a2    /* QR3 */
    /* stage rot3: 4 disjoint quarter-rounds */
    EE_ROTL $s0, 8, 24    /* QR0 */
    EE_ROTL $15, 8, 24    /* QR1 */
    EE_ROTL $t8, 8, 24    /* QR2 */
    EE_ROTL $t9, 8, 24    /* QR3 */
    /* stage add4: 4 disjoint quarter-rounds */
    paddw   $13, $13, $s0    /* QR0 */
    paddw   $14, $14, $15    /* QR1 */
    paddw   $11, $11, $t8    /* QR2 */
    paddw   $12, $12, $t9    /* QR3 */
    /* stage xor4: 4 disjoint quarter-rounds */
    pxor    $8, $8, $13    /* QR0 */
    pxor    $9, $9, $14    /* QR1 */
    pxor    $10, $10, $11    /* QR2 */
    pxor    $a3, $a3, $12    /* QR3 */
    /* stage rot4: 4 disjoint quarter-rounds */
    EE_ROTL $8, 7, 25    /* QR0 */
    EE_ROTL $9, 7, 25    /* QR1 */
    EE_ROTL $10, 7, 25    /* QR2 */
    EE_ROTL $a3, 7, 25    /* QR3 */
    addiu   $s3, $s3, -1
    bnez    $s3, .Lee_chacha_round
    nop

    sq      $v0,   0($a0)
    sq      $v1,  16($a0)
    sq      $a1,  32($a0)
    sq      $a2,  48($a0)
    sq      $a3,  64($a0)
    sq      $8,  80($a0)
    sq      $9,  96($a0)
    sq      $10, 112($a0)
    sq      $11, 128($a0)
    sq      $12, 144($a0)
    sq      $13, 160($a0)
    sq      $14, 176($a0)
    sq      $15, 192($a0)
    sq      $t8, 208($a0)
    sq      $t9, 224($a0)
    sq      $s0, 240($a0)

    lq      $s0, 0($sp)
    lq      $s1, 16($sp)
    lq      $s2, 32($sp)
    lq      $s3, 48($sp)
    jr      $ra
    addiu   $sp, $sp, 64
    .end ossl_chacha20_ee_mmi_4way

    .set reorder
