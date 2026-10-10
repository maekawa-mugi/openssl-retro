/*
 * Poly1305 fused sums with h/r operands preloaded once per lane pair.
 * Copyright 2026 openssl-retro contributors. Apache License 2.0.
 * Same sums[5][4], h[5][4], scaled_r[10][4] ABI as the original kernel.
 * Save GPR16..19 in full 128-bit form on private aligned scratch.
 * Inputs <2^31; PEXTLW/PEXTUW make valid PMULTUW word values.
 * No secret-dependent branches or addresses. HI/LO are caller-clobbered.
 */
    .text
    .set noreorder
    .align 4
    .macro EE_POLY_LOAD dst, off, base, extract
        lq      $13, \off(\base)
        \extract \dst, $zero, $13
    .endm
    .globl ossl_ee_poly1305_sums4
    .ent ossl_ee_poly1305_sums4
ossl_ee_poly1305_sums4:
    daddiu  $sp, $sp, -80
    daddiu  $15, $sp, 15
    dsrl    $15, $15, 4
    dsll    $15, $15, 4
    sq      $16, 0($15)
    sq      $17, 16($15)
    sq      $18, 32($15)
    sq      $19, 48($15)
    /* Lane pair 0: all 14 operands reused across five sums. */
    EE_POLY_LOAD $v0, 0, $a1, pextlw
    EE_POLY_LOAD $v1, 16, $a1, pextlw
    EE_POLY_LOAD $a3, 32, $a1, pextlw
    EE_POLY_LOAD $t8, 48, $a1, pextlw
    EE_POLY_LOAD $t9, 64, $a1, pextlw
    EE_POLY_LOAD $8, 0, $a2, pextlw
    EE_POLY_LOAD $9, 16, $a2, pextlw
    EE_POLY_LOAD $10, 32, $a2, pextlw
    EE_POLY_LOAD $11, 48, $a2, pextlw
    EE_POLY_LOAD $12, 64, $a2, pextlw
    EE_POLY_LOAD $16, 96, $a2, pextlw
    EE_POLY_LOAD $17, 112, $a2, pextlw
    EE_POLY_LOAD $18, 128, $a2, pextlw
    EE_POLY_LOAD $19, 144, $a2, pextlw
    pmultuw $14, $v0, $8
    pmadduw $14, $v1, $19
    pmadduw $14, $a3, $18
    pmadduw $14, $t8, $17
    pmadduw $14, $t9, $16
    sq      $14, 0($a0)
    pmultuw $14, $v0, $9
    pmadduw $14, $v1, $8
    pmadduw $14, $a3, $19
    pmadduw $14, $t8, $18
    pmadduw $14, $t9, $17
    sq      $14, 32($a0)
    pmultuw $14, $v0, $10
    pmadduw $14, $v1, $9
    pmadduw $14, $a3, $8
    pmadduw $14, $t8, $19
    pmadduw $14, $t9, $18
    sq      $14, 64($a0)
    pmultuw $14, $v0, $11
    pmadduw $14, $v1, $10
    pmadduw $14, $a3, $9
    pmadduw $14, $t8, $8
    pmadduw $14, $t9, $19
    sq      $14, 96($a0)
    pmultuw $14, $v0, $12
    pmadduw $14, $v1, $11
    pmadduw $14, $a3, $10
    pmadduw $14, $t8, $9
    pmadduw $14, $t9, $8
    sq      $14, 128($a0)
    /* Lane pair 1: all 14 operands reused across five sums. */
    EE_POLY_LOAD $v0, 0, $a1, pextuw
    EE_POLY_LOAD $v1, 16, $a1, pextuw
    EE_POLY_LOAD $a3, 32, $a1, pextuw
    EE_POLY_LOAD $t8, 48, $a1, pextuw
    EE_POLY_LOAD $t9, 64, $a1, pextuw
    EE_POLY_LOAD $8, 0, $a2, pextuw
    EE_POLY_LOAD $9, 16, $a2, pextuw
    EE_POLY_LOAD $10, 32, $a2, pextuw
    EE_POLY_LOAD $11, 48, $a2, pextuw
    EE_POLY_LOAD $12, 64, $a2, pextuw
    EE_POLY_LOAD $16, 96, $a2, pextuw
    EE_POLY_LOAD $17, 112, $a2, pextuw
    EE_POLY_LOAD $18, 128, $a2, pextuw
    EE_POLY_LOAD $19, 144, $a2, pextuw
    pmultuw $14, $v0, $8
    pmadduw $14, $v1, $19
    pmadduw $14, $a3, $18
    pmadduw $14, $t8, $17
    pmadduw $14, $t9, $16
    sq      $14, 16($a0)
    pmultuw $14, $v0, $9
    pmadduw $14, $v1, $8
    pmadduw $14, $a3, $19
    pmadduw $14, $t8, $18
    pmadduw $14, $t9, $17
    sq      $14, 48($a0)
    pmultuw $14, $v0, $10
    pmadduw $14, $v1, $9
    pmadduw $14, $a3, $8
    pmadduw $14, $t8, $19
    pmadduw $14, $t9, $18
    sq      $14, 80($a0)
    pmultuw $14, $v0, $11
    pmadduw $14, $v1, $10
    pmadduw $14, $a3, $9
    pmadduw $14, $t8, $8
    pmadduw $14, $t9, $19
    sq      $14, 112($a0)
    pmultuw $14, $v0, $12
    pmadduw $14, $v1, $11
    pmadduw $14, $a3, $10
    pmadduw $14, $t8, $9
    pmadduw $14, $t9, $8
    sq      $14, 144($a0)
    lq      $16, 0($15)
    lq      $17, 16($15)
    lq      $18, 32($15)
    lq      $19, 48($15)
    sq      $zero, 0($15)
    sq      $zero, 16($15)
    sq      $zero, 32($15)
    sq      $zero, 48($15)
    pmultuw $zero, $zero, $zero
    pxor    $v0, $v0, $v0
    pxor    $v1, $v1, $v1
    pxor    $a3, $a3, $a3
    pxor    $t8, $t8, $t8
    pxor    $t9, $t9, $t9
    pxor    $8, $8, $8
    pxor    $9, $9, $9
    pxor    $10, $10, $10
    pxor    $11, $11, $11
    pxor    $12, $12, $12
    pxor    $13, $13, $13
    pxor    $14, $14, $14
    daddiu  $sp, $sp, 80
    jr      $ra
    nop
    .end ossl_ee_poly1305_sums4
    .set reorder
