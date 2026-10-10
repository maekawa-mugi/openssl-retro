/*
 * Poly1305 preload + fused radix-2^26 reduction, no sums buffer.
 * Copyright 2026 openssl-retro contributors. Apache License 2.0.
 * out[5][4], h[5][4], scaled_r[10][4]; out may alias h.
 * Save GPR16..22 in full 128-bit form on private aligned scratch.
 * h limbs <2^27, r limbs <2^26; 5r <2^31.
 * PEXTLW/PEXTUW make valid PMULTUW word values.
 * No secret-dependent branches or addresses. HI/LO are caller-clobbered.
 */
    .text
    .set noreorder
    .align 4
    .macro EE_POLY_LOAD dst, off, base, extract
        lq      $13, \off(\base)
        \extract \dst, $zero, $13
    .endm
    .globl ossl_ee_poly1305_mul_reduce4
    .ent ossl_ee_poly1305_mul_reduce4
ossl_ee_poly1305_mul_reduce4:
    daddiu  $sp, $sp, -128
    daddiu  $15, $sp, 15
    dsrl    $15, $15, 4
    dsll    $15, $15, 4
    sq      $16, 0($15)
    sq      $17, 16($15)
    sq      $18, 32($15)
    sq      $19, 48($15)
    sq      $20, 64($15)
    sq      $21, 80($15)
    sq      $22, 96($15)
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
    pcpyud  $21, $14, $14
    daddu   $13, $14, $zero
    dsll32  $22, $13, 6
    dsrl32  $22, $22, 6
    sw      $22, 0($a0)
    dsrl    $13, $13, 26
    dsll32  $22, $21, 6
    dsrl32  $22, $22, 6
    sw      $22, 4($a0)
    dsrl    $21, $21, 26
    pcpyld  $20, $21, $13
    pmultuw $14, $v0, $9
    pmadduw $14, $v1, $8
    pmadduw $14, $a3, $19
    pmadduw $14, $t8, $18
    pmadduw $14, $t9, $17
    pcpyud  $21, $14, $14
    pcpyud  $22, $20, $20
    daddu   $13, $14, $20
    daddu   $21, $21, $22
    dsll32  $22, $13, 6
    dsrl32  $22, $22, 6
    sw      $22, 16($a0)
    dsrl    $13, $13, 26
    dsll32  $22, $21, 6
    dsrl32  $22, $22, 6
    sw      $22, 20($a0)
    dsrl    $21, $21, 26
    pcpyld  $20, $21, $13
    pmultuw $14, $v0, $10
    pmadduw $14, $v1, $9
    pmadduw $14, $a3, $8
    pmadduw $14, $t8, $19
    pmadduw $14, $t9, $18
    pcpyud  $21, $14, $14
    pcpyud  $22, $20, $20
    daddu   $13, $14, $20
    daddu   $21, $21, $22
    dsll32  $22, $13, 6
    dsrl32  $22, $22, 6
    sw      $22, 32($a0)
    dsrl    $13, $13, 26
    dsll32  $22, $21, 6
    dsrl32  $22, $22, 6
    sw      $22, 36($a0)
    dsrl    $21, $21, 26
    pcpyld  $20, $21, $13
    pmultuw $14, $v0, $11
    pmadduw $14, $v1, $10
    pmadduw $14, $a3, $9
    pmadduw $14, $t8, $8
    pmadduw $14, $t9, $19
    pcpyud  $21, $14, $14
    pcpyud  $22, $20, $20
    daddu   $13, $14, $20
    daddu   $21, $21, $22
    dsll32  $22, $13, 6
    dsrl32  $22, $22, 6
    sw      $22, 48($a0)
    dsrl    $13, $13, 26
    dsll32  $22, $21, 6
    dsrl32  $22, $22, 6
    sw      $22, 52($a0)
    dsrl    $21, $21, 26
    pcpyld  $20, $21, $13
    pmultuw $14, $v0, $12
    pmadduw $14, $v1, $11
    pmadduw $14, $a3, $10
    pmadduw $14, $t8, $9
    pmadduw $14, $t9, $8
    pcpyud  $21, $14, $14
    pcpyud  $22, $20, $20
    daddu   $13, $14, $20
    daddu   $21, $21, $22
    dsll32  $22, $13, 6
    dsrl32  $22, $22, 6
    sw      $22, 64($a0)
    dsrl    $13, $13, 26
    dsll32  $22, $21, 6
    dsrl32  $22, $22, 6
    sw      $22, 68($a0)
    dsrl    $21, $21, 26
    pcpyld  $20, $21, $13
    dsll    $22, $13, 2
    daddu   $13, $13, $22
    lwu     $22, 0($a0)
    daddu   $13, $13, $22
    dsll32  $22, $13, 6
    dsrl32  $22, $22, 6
    sw      $22, 0($a0)
    dsrl    $13, $13, 26
    lwu     $22, 16($a0)
    daddu   $13, $13, $22
    sw      $13, 16($a0)
    dsll    $22, $21, 2
    daddu   $21, $21, $22
    lwu     $22, 4($a0)
    daddu   $21, $21, $22
    dsll32  $22, $21, 6
    dsrl32  $22, $22, 6
    sw      $22, 4($a0)
    dsrl    $21, $21, 26
    lwu     $22, 20($a0)
    daddu   $21, $21, $22
    sw      $21, 20($a0)
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
    pcpyud  $21, $14, $14
    daddu   $13, $14, $zero
    dsll32  $22, $13, 6
    dsrl32  $22, $22, 6
    sw      $22, 8($a0)
    dsrl    $13, $13, 26
    dsll32  $22, $21, 6
    dsrl32  $22, $22, 6
    sw      $22, 12($a0)
    dsrl    $21, $21, 26
    pcpyld  $20, $21, $13
    pmultuw $14, $v0, $9
    pmadduw $14, $v1, $8
    pmadduw $14, $a3, $19
    pmadduw $14, $t8, $18
    pmadduw $14, $t9, $17
    pcpyud  $21, $14, $14
    pcpyud  $22, $20, $20
    daddu   $13, $14, $20
    daddu   $21, $21, $22
    dsll32  $22, $13, 6
    dsrl32  $22, $22, 6
    sw      $22, 24($a0)
    dsrl    $13, $13, 26
    dsll32  $22, $21, 6
    dsrl32  $22, $22, 6
    sw      $22, 28($a0)
    dsrl    $21, $21, 26
    pcpyld  $20, $21, $13
    pmultuw $14, $v0, $10
    pmadduw $14, $v1, $9
    pmadduw $14, $a3, $8
    pmadduw $14, $t8, $19
    pmadduw $14, $t9, $18
    pcpyud  $21, $14, $14
    pcpyud  $22, $20, $20
    daddu   $13, $14, $20
    daddu   $21, $21, $22
    dsll32  $22, $13, 6
    dsrl32  $22, $22, 6
    sw      $22, 40($a0)
    dsrl    $13, $13, 26
    dsll32  $22, $21, 6
    dsrl32  $22, $22, 6
    sw      $22, 44($a0)
    dsrl    $21, $21, 26
    pcpyld  $20, $21, $13
    pmultuw $14, $v0, $11
    pmadduw $14, $v1, $10
    pmadduw $14, $a3, $9
    pmadduw $14, $t8, $8
    pmadduw $14, $t9, $19
    pcpyud  $21, $14, $14
    pcpyud  $22, $20, $20
    daddu   $13, $14, $20
    daddu   $21, $21, $22
    dsll32  $22, $13, 6
    dsrl32  $22, $22, 6
    sw      $22, 56($a0)
    dsrl    $13, $13, 26
    dsll32  $22, $21, 6
    dsrl32  $22, $22, 6
    sw      $22, 60($a0)
    dsrl    $21, $21, 26
    pcpyld  $20, $21, $13
    pmultuw $14, $v0, $12
    pmadduw $14, $v1, $11
    pmadduw $14, $a3, $10
    pmadduw $14, $t8, $9
    pmadduw $14, $t9, $8
    pcpyud  $21, $14, $14
    pcpyud  $22, $20, $20
    daddu   $13, $14, $20
    daddu   $21, $21, $22
    dsll32  $22, $13, 6
    dsrl32  $22, $22, 6
    sw      $22, 72($a0)
    dsrl    $13, $13, 26
    dsll32  $22, $21, 6
    dsrl32  $22, $22, 6
    sw      $22, 76($a0)
    dsrl    $21, $21, 26
    pcpyld  $20, $21, $13
    dsll    $22, $13, 2
    daddu   $13, $13, $22
    lwu     $22, 8($a0)
    daddu   $13, $13, $22
    dsll32  $22, $13, 6
    dsrl32  $22, $22, 6
    sw      $22, 8($a0)
    dsrl    $13, $13, 26
    lwu     $22, 24($a0)
    daddu   $13, $13, $22
    sw      $13, 24($a0)
    dsll    $22, $21, 2
    daddu   $21, $21, $22
    lwu     $22, 12($a0)
    daddu   $21, $21, $22
    dsll32  $22, $21, 6
    dsrl32  $22, $22, 6
    sw      $22, 12($a0)
    dsrl    $21, $21, 26
    lwu     $22, 28($a0)
    daddu   $21, $21, $22
    sw      $21, 28($a0)
    lq      $16, 0($15)
    lq      $17, 16($15)
    lq      $18, 32($15)
    lq      $19, 48($15)
    lq      $20, 64($15)
    lq      $21, 80($15)
    lq      $22, 96($15)
    sq      $zero, 0($15)
    sq      $zero, 16($15)
    sq      $zero, 32($15)
    sq      $zero, 48($15)
    sq      $zero, 64($15)
    sq      $zero, 80($15)
    sq      $zero, 96($15)
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
    daddiu  $sp, $sp, 128
    jr      $ra
    nop
    .end ossl_ee_poly1305_mul_reduce4
    .set reorder
