/*
 * Copyright 2026 The openssl-retro contributors. All Rights Reserved.
 * Licensed under the Apache License 2.0; see LICENSE.txt.
 *
 * R5900 EE MMI SHA-256 compression for four independent hash streams.
 * Variant S4: hoist Ch(E,F,G) ahead of Sigma1 and unroll four rounds to overlap the
 * round's two independent dependency chains and W/K load latency.
 *
 * void ossl_ee_sha256_compress4(
 *     uint32_t state[8][4], const uint32_t schedule[64][4],
 *     const uint32_t constants[64][4]);
 *
 * All three pointers MUST be 16-byte aligned. Each 128-bit register
 * contains the same SHA-256 word position in four independent messages.
 * The C wrapper prepares the schedule and the four-lane K constants.
 *
 * Leaf function: a0=state, a1=W, a2=K, s0 and s1 preserved in full
 * 128-bit form. All shift operations are 32-bit word-lane logical shifts.
 */
/* Numeric GPRs 8..15 retain the original o32 temporary layout under
 * both o32 and modern PS2SDK n32 register naming. */
    .text
    .set noreorder
    .align 4

    .macro EE_ROTR32 dst, src, right, left, tmp
        psrlw   \dst, \src, \right
        psllw   \tmp, \src, \left
        por     \dst, \dst, \tmp
    .endm

    .macro EE_SHA_STEP
    lq      $t9, 0($a1)         /* W[t][0..3] */
    lq      $s0, 0($a2)         /* K[t] broadcast to 4 lanes */

    /* Ch(E,F,G) is independent of message W/K and Sigma1.
     * Calculate it first to separate the LQ load/use path and
     * leave Sigma1's $14 temporary free. */
    pxor    $15, $10, $11
    pand    $15, $15, $9
    pxor    $15, $15, $11

    /* Sigma1(E) = ROTR6(E) ^ ROTR11(E) ^ ROTR25(E) */
    EE_ROTR32 $13, $9, 6, 26, $t8
    EE_ROTR32 $14, $9, 11, 21, $t8
    pxor    $13, $13, $14
    EE_ROTR32 $14, $9, 25, 7, $t8
    pxor    $13, $13, $14

    /* T1 = H + Sigma1(E) + Ch + K + W */
    paddw   $13, $13, $12
    paddw   $13, $13, $15
    paddw   $13, $13, $s0
    paddw   $13, $13, $t9

    /* Sigma0(A) = ROTR2(A) ^ ROTR13(A) ^ ROTR22(A) */
    EE_ROTR32 $14, $v0, 2, 30, $t8
    EE_ROTR32 $15, $v0, 13, 19, $t8
    pxor    $14, $14, $15
    EE_ROTR32 $15, $v0, 22, 10, $t8
    pxor    $14, $14, $15

    /* Maj(A,B,C) = (A & B) ^ (C & (A ^ B)) */
    pxor    $15, $v0, $v1
    pand    $15, $15, $a3
    pand    $t8, $v0, $v1
    pxor    $15, $15, $t8

    paddw   $14, $14, $15     /* T2 */
    paddw   $15, $13, $14     /* next A */
    paddw   $t8, $8, $13     /* next E */

    /* H<-G, G<-F, F<-E, E<-D+T1, D<-C, C<-B, B<-A, A<-T1+T2 */
    por     $12, $11, $zero
    por     $11, $10, $zero
    por     $10, $9, $zero
    por     $9, $t8, $zero
    por     $8, $a3, $zero
    por     $a3, $v1, $zero
    por     $v1, $v0, $zero
    por     $v0, $15, $zero

    addiu   $a1, $a1, 16
    addiu   $a2, $a2, 16
    .endm

    .globl ossl_ee_sha256_compress4
    .ent ossl_ee_sha256_compress4
ossl_ee_sha256_compress4:
    addiu   $sp, $sp, -32
    sq      $s0, 0($sp)
    sq      $s1, 16($sp)

    /* A=v0 B=v1 C=a3 D=t0 E=t1 F=t2 G=t3 H=t4 */
    lq      $v0,   0($a0)
    lq      $v1,  16($a0)
    lq      $a3,  32($a0)
    lq      $8,  48($a0)
    lq      $9,  64($a0)
    lq      $10,  80($a0)
    lq      $11,  96($a0)
    lq      $12, 112($a0)

    /* Variant S4: four rounds per loop, same dependency-safe Ch-first
     * round macro repeated four times before testing loop counter.
     * Reduces branches from 64 to 16, no additional state registers. */
    addiu   $s1, $zero, 16
.Lee_sha256_round:
    EE_SHA_STEP
    EE_SHA_STEP
    EE_SHA_STEP
    EE_SHA_STEP
    addiu   $s1, $s1, -1
    bnez    $s1, .Lee_sha256_round
    nop

    /* SHA-256 compression feed-forward: state[i] += work[i]. */
    lq      $13, 0($a0)
    paddw   $v0, $v0, $13
    sq      $v0, 0($a0)
    lq      $13, 16($a0)
    paddw   $v1, $v1, $13
    sq      $v1, 16($a0)
    lq      $13, 32($a0)
    paddw   $a3, $a3, $13
    sq      $a3, 32($a0)
    lq      $13, 48($a0)
    paddw   $8, $8, $13
    sq      $8, 48($a0)
    lq      $13, 64($a0)
    paddw   $9, $9, $13
    sq      $9, 64($a0)
    lq      $13, 80($a0)
    paddw   $10, $10, $13
    sq      $10, 80($a0)
    lq      $13, 96($a0)
    paddw   $11, $11, $13
    sq      $11, 96($a0)
    lq      $13, 112($a0)
    paddw   $12, $12, $13
    sq      $12, 112($a0)

    lq      $s0, 0($sp)
    lq      $s1, 16($sp)
    jr      $ra
    addiu   $sp, $sp, 32
    .end ossl_ee_sha256_compress4

    .set reorder
