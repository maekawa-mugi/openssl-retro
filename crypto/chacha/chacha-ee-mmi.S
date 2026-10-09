/*
 * Copyright 2026 The openssl-retro contributors. All Rights Reserved.
 * Licensed under the Apache License 2.0; see LICENSE.txt.
 *
 * R5900 / Emotion Engine MMI ChaCha20: four blocks in parallel.
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
    /* Column rounds: (0,4,8,12) (1,5,9,13) (2,6,10,14) (3,7,11,15) */
    EE_QR   $v0, $a3, $11, $15
    EE_QR   $v1, $8, $12, $t8
    EE_QR   $a1, $9, $13, $t9
    EE_QR   $a2, $10, $14, $s0

    /* Diagonal rounds: (0,5,10,15) (1,6,11,12)
     *                  (2,7,8,13)  (3,4,9,14) */
    EE_QR   $v0, $8, $13, $s0
    EE_QR   $v1, $9, $14, $15
    EE_QR   $a1, $10, $11, $t8
    EE_QR   $a2, $a3, $12, $t9

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
