/*
 * Copyright 2026 openssl-retro contributors. Licensed under Apache-2.0.
 *
 * R5900/Emotion Engine PMULTUW Poly1305 four-stream products.
 *
 * void ossl_ee_poly1305_products4(
 *   uint64_t products[5][5][4],
 *   const uint32_t a[5][4],
 *   const uint32_t b[10][4]);
 *
 * This is an exact 4-way (four messages) 5x5 multiplication:
 * each PMULTUW performs TWO 32x32->64 unsigned products.
 * PEXTLW/PEXTUW split 4 lanes into pairs (0,1) and (2,3).
 *
 * PMULTUW inputs REQUIRE word-value upper bits in each 64-bit
 * half to be the sign-extension of the 32-bit operand. We ensure
 * these are ZERO using PEXTLW/PEXTUW with $zero as the first input.
 * This is valid because radix-2^26 h and scaled r (5*r) are < 2^31.
 * The EE reference manual explicitly says PMULTUW returns complete
 * 64-bit products in the destination GPR, not just LO/HI.
 *
 * Output for each k,i is 4 little-endian 64-bit values for lanes 0..3.
 * Inputs/outputs must be 16-byte aligned. NO saved GPRs are touched.
 * PMULTUW overwrites EE HI/LO, which is caller-clobbered.
 * All offsets are multiples of 16 so LQ/SQ never mask away low bits.
 *
 * This first-cut implementation materializes products in memory:
 * correctness and an exact A/B test come before scheduling tuning.
 */
/* Numeric GPRs 8..15 retain the original o32 temporary layout under
 * both o32 and modern PS2SDK n32 register naming. */
    .text
    .set noreorder
    .align 4

    .macro EE_POLY_MUL2 aoff, boff, out0, out1
        lq      $8, \aoff($a1)
        lq      $9, \boff($a2)
        pextlw  $10, $zero, $8  /* (lane0,zero,lane1,zero) */
        pextlw  $11, $zero, $9
        pmultuw $12, $10, $11   /* two unsigned 64-bit products */
        pextuw  $13, $zero, $8  /* (lane2,zero,lane3,zero) */
        pextuw  $14, $zero, $9
        sq      $12, \out0($a0)
        pmultuw $12, $13, $14
        sq      $12, \out1($a0)
    .endm

    .globl ossl_ee_poly1305_products4
    .ent ossl_ee_poly1305_products4
ossl_ee_poly1305_products4:

    EE_POLY_MUL2 0, 0, 0, 16    /* d0: h0 * r0 */
    EE_POLY_MUL2 16, 144, 32, 48    /* d0: h1 * 5*r4 */
    EE_POLY_MUL2 32, 128, 64, 80    /* d0: h2 * 5*r3 */
    EE_POLY_MUL2 48, 112, 96, 112    /* d0: h3 * 5*r2 */
    EE_POLY_MUL2 64, 96, 128, 144    /* d0: h4 * 5*r1 */
    EE_POLY_MUL2 0, 16, 160, 176    /* d1: h0 * r1 */
    EE_POLY_MUL2 16, 0, 192, 208    /* d1: h1 * r0 */
    EE_POLY_MUL2 32, 144, 224, 240    /* d1: h2 * 5*r4 */
    EE_POLY_MUL2 48, 128, 256, 272    /* d1: h3 * 5*r3 */
    EE_POLY_MUL2 64, 112, 288, 304    /* d1: h4 * 5*r2 */
    EE_POLY_MUL2 0, 32, 320, 336    /* d2: h0 * r2 */
    EE_POLY_MUL2 16, 16, 352, 368    /* d2: h1 * r1 */
    EE_POLY_MUL2 32, 0, 384, 400    /* d2: h2 * r0 */
    EE_POLY_MUL2 48, 144, 416, 432    /* d2: h3 * 5*r4 */
    EE_POLY_MUL2 64, 128, 448, 464    /* d2: h4 * 5*r3 */
    EE_POLY_MUL2 0, 48, 480, 496    /* d3: h0 * r3 */
    EE_POLY_MUL2 16, 32, 512, 528    /* d3: h1 * r2 */
    EE_POLY_MUL2 32, 16, 544, 560    /* d3: h2 * r1 */
    EE_POLY_MUL2 48, 0, 576, 592    /* d3: h3 * r0 */
    EE_POLY_MUL2 64, 144, 608, 624    /* d3: h4 * 5*r4 */
    EE_POLY_MUL2 0, 64, 640, 656    /* d4: h0 * r4 */
    EE_POLY_MUL2 16, 48, 672, 688    /* d4: h1 * r3 */
    EE_POLY_MUL2 32, 32, 704, 720    /* d4: h2 * r2 */
    EE_POLY_MUL2 48, 16, 736, 752    /* d4: h3 * r1 */
    EE_POLY_MUL2 64, 0, 768, 784    /* d4: h4 * r0 */
    jr      $ra
    nop
    .end ossl_ee_poly1305_products4
    .set reorder
