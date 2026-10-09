/*
 * Copyright 2026 openssl-retro contributors. Licensed under Apache-2.0.
 *
 * Experimental fused R5900/EE MMI Poly1305 four-stream accumulation.
 * void ossl_ee_poly1305_sums4(uint64_t sums[5][4],
 *     const uint32_t a[5][4], const uint32_t b[10][4]);
 *
 * Each PEXTLW/PEXTUW forms two 64-bit word-value operands from four
 * unsigned 26-bit input limbs, setting the high 32 bits to zero.
 *
 * For each of five output limbs and for each pair of message lanes:
 *   PMULTUW starts a fresh (HI,LO) accumulator.
 *   Four PMADDUW instructions accumulate the remaining exact products.
 *   The last GPR destination contains TWO complete 64-bit sums.
 *
 * Maximum magnitude: 5 * (2^27 - 1) * (5 * (2^26 - 1)) < 2^59.
 * Accordingly the 64-bit accumulators cannot overflow. No rounding.
 *
 * The 160-byte output contains five pairs of 128-bit registers,
 * each with two 64-bit sums: lanes (0,1) then lanes (2,3).
 * All three pointers must be 16-byte aligned, no saved GPRs used.
 * HI/LO are modified. This routine does not call into other code.
 *
 * PMULTUW/PMADDUW may stall on their accumulator dependency.
 * Throughput and potential EE pipeline hazards remain to be measured.
 */
/* Numeric GPRs 8..15 retain the original o32 temporary layout under
 * both o32 and modern PS2SDK n32 register naming. */
    .text
    .set noreorder
    .align 4

    .macro EE_POLY_ACC operation, extract, aoff, boff
        lq       $8, \aoff($a1)
        lq       $9, \boff($a2)
        \extract $10, $zero, $8
        \extract $11, $zero, $9
        \operation $12, $10, $11
    .endm

    .globl ossl_ee_poly1305_sums4
    .ent ossl_ee_poly1305_sums4
ossl_ee_poly1305_sums4:

    /* d0, lanes 0,1, HI/LO accumulates five exact 64-bit terms */
    EE_POLY_ACC pmultuw, pextlw, 0, 0  /* h0 * r0 */
    EE_POLY_ACC pmadduw, pextlw, 16, 144  /* h1 * 5*r4 */
    EE_POLY_ACC pmadduw, pextlw, 32, 128  /* h2 * 5*r3 */
    EE_POLY_ACC pmadduw, pextlw, 48, 112  /* h3 * 5*r2 */
    EE_POLY_ACC pmadduw, pextlw, 64, 96  /* h4 * 5*r1 */
    sq      $12, 0($a0)
    /* d0, lanes 2,3, HI/LO accumulates five exact 64-bit terms */
    EE_POLY_ACC pmultuw, pextuw, 0, 0  /* h0 * r0 */
    EE_POLY_ACC pmadduw, pextuw, 16, 144  /* h1 * 5*r4 */
    EE_POLY_ACC pmadduw, pextuw, 32, 128  /* h2 * 5*r3 */
    EE_POLY_ACC pmadduw, pextuw, 48, 112  /* h3 * 5*r2 */
    EE_POLY_ACC pmadduw, pextuw, 64, 96  /* h4 * 5*r1 */
    sq      $12, 16($a0)
    /* d1, lanes 0,1, HI/LO accumulates five exact 64-bit terms */
    EE_POLY_ACC pmultuw, pextlw, 0, 16  /* h0 * r1 */
    EE_POLY_ACC pmadduw, pextlw, 16, 0  /* h1 * r0 */
    EE_POLY_ACC pmadduw, pextlw, 32, 144  /* h2 * 5*r4 */
    EE_POLY_ACC pmadduw, pextlw, 48, 128  /* h3 * 5*r3 */
    EE_POLY_ACC pmadduw, pextlw, 64, 112  /* h4 * 5*r2 */
    sq      $12, 32($a0)
    /* d1, lanes 2,3, HI/LO accumulates five exact 64-bit terms */
    EE_POLY_ACC pmultuw, pextuw, 0, 16  /* h0 * r1 */
    EE_POLY_ACC pmadduw, pextuw, 16, 0  /* h1 * r0 */
    EE_POLY_ACC pmadduw, pextuw, 32, 144  /* h2 * 5*r4 */
    EE_POLY_ACC pmadduw, pextuw, 48, 128  /* h3 * 5*r3 */
    EE_POLY_ACC pmadduw, pextuw, 64, 112  /* h4 * 5*r2 */
    sq      $12, 48($a0)
    /* d2, lanes 0,1, HI/LO accumulates five exact 64-bit terms */
    EE_POLY_ACC pmultuw, pextlw, 0, 32  /* h0 * r2 */
    EE_POLY_ACC pmadduw, pextlw, 16, 16  /* h1 * r1 */
    EE_POLY_ACC pmadduw, pextlw, 32, 0  /* h2 * r0 */
    EE_POLY_ACC pmadduw, pextlw, 48, 144  /* h3 * 5*r4 */
    EE_POLY_ACC pmadduw, pextlw, 64, 128  /* h4 * 5*r3 */
    sq      $12, 64($a0)
    /* d2, lanes 2,3, HI/LO accumulates five exact 64-bit terms */
    EE_POLY_ACC pmultuw, pextuw, 0, 32  /* h0 * r2 */
    EE_POLY_ACC pmadduw, pextuw, 16, 16  /* h1 * r1 */
    EE_POLY_ACC pmadduw, pextuw, 32, 0  /* h2 * r0 */
    EE_POLY_ACC pmadduw, pextuw, 48, 144  /* h3 * 5*r4 */
    EE_POLY_ACC pmadduw, pextuw, 64, 128  /* h4 * 5*r3 */
    sq      $12, 80($a0)
    /* d3, lanes 0,1, HI/LO accumulates five exact 64-bit terms */
    EE_POLY_ACC pmultuw, pextlw, 0, 48  /* h0 * r3 */
    EE_POLY_ACC pmadduw, pextlw, 16, 32  /* h1 * r2 */
    EE_POLY_ACC pmadduw, pextlw, 32, 16  /* h2 * r1 */
    EE_POLY_ACC pmadduw, pextlw, 48, 0  /* h3 * r0 */
    EE_POLY_ACC pmadduw, pextlw, 64, 144  /* h4 * 5*r4 */
    sq      $12, 96($a0)
    /* d3, lanes 2,3, HI/LO accumulates five exact 64-bit terms */
    EE_POLY_ACC pmultuw, pextuw, 0, 48  /* h0 * r3 */
    EE_POLY_ACC pmadduw, pextuw, 16, 32  /* h1 * r2 */
    EE_POLY_ACC pmadduw, pextuw, 32, 16  /* h2 * r1 */
    EE_POLY_ACC pmadduw, pextuw, 48, 0  /* h3 * r0 */
    EE_POLY_ACC pmadduw, pextuw, 64, 144  /* h4 * 5*r4 */
    sq      $12, 112($a0)
    /* d4, lanes 0,1, HI/LO accumulates five exact 64-bit terms */
    EE_POLY_ACC pmultuw, pextlw, 0, 64  /* h0 * r4 */
    EE_POLY_ACC pmadduw, pextlw, 16, 48  /* h1 * r3 */
    EE_POLY_ACC pmadduw, pextlw, 32, 32  /* h2 * r2 */
    EE_POLY_ACC pmadduw, pextlw, 48, 16  /* h3 * r1 */
    EE_POLY_ACC pmadduw, pextlw, 64, 0  /* h4 * r0 */
    sq      $12, 128($a0)
    /* d4, lanes 2,3, HI/LO accumulates five exact 64-bit terms */
    EE_POLY_ACC pmultuw, pextuw, 0, 64  /* h0 * r4 */
    EE_POLY_ACC pmadduw, pextuw, 16, 48  /* h1 * r3 */
    EE_POLY_ACC pmadduw, pextuw, 32, 32  /* h2 * r2 */
    EE_POLY_ACC pmadduw, pextuw, 48, 16  /* h3 * r1 */
    EE_POLY_ACC pmadduw, pextuw, 64, 0  /* h4 * r0 */
    sq      $12, 144($a0)
    jr      $ra
    nop
    .end ossl_ee_poly1305_sums4
    .set reorder
