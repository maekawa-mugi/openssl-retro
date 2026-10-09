/*
 * Experimental R5900 EE MMI: two full-range unsigned 32x32->64 products.
 * Copyright 2026 openssl-retro contributors. Apache License 2.0.
 *
 * void ossl_ee_bn_mul2(uint64_t out[2], const uint32_t x[4],
 *                       const uint32_t y[4]);
 * All pointers 16-byte aligned, first two 32-bit slots of x/y used.
 *
 * Unlike Poly1305's <=26-bit digits, arbitrary BN_ULONG operands
 * include the sign bit. EE PMULTUW accepts *sign-extended word values*
 * even though the multiplication itself is unsigned. PSRAW followed
 * by PEXTLW synthesizes the required sign-extended 64-bit slots:
 * [x0, sign(x0), x1, sign(x1)].
 * Omitting PSRAW produces undefined results when bit31 is set.
 *
 * No saved GPRs or stack use. PMULTUW clobbers EE HI/LO (caller saved).
 */
/* Numeric GPRs 8..15 retain the original o32 temporary layout under
 * both o32 and modern PS2SDK n32 register naming. */
    .text
    .set noreorder
    .align 4
    .globl ossl_ee_bn_mul2
    .ent ossl_ee_bn_mul2
ossl_ee_bn_mul2:
    lq      $8, 0($a1)
    lq      $9, 0($a2)
    psraw   $10, $8, 31
    psraw   $11, $9, 31
    pextlw  $12, $10, $8
    pextlw  $13, $11, $9
    pmultuw $14, $12, $13
    sq      $14, 0($a0)
    jr      $ra
    nop
    .end ossl_ee_bn_mul2
    .set reorder
