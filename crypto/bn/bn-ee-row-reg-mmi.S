/*
 * R5900 addmul row: register-only operand packing and product extraction.
 * Copyright 2026 openssl-retro contributors. Apache License 2.0.
 * Same ABI and unsigned arithmetic as bn-ee-row-mmi.S. No stack use.
 * LW sign-extends each 32-bit operand; PCPYLD combines its low 64-bit
 * halves into two valid PMULTUW word values. PCPYUD extracts product1.
 * Only caller-saved GPRs and HI/LO are modified. num is public.
 */
    .text
    .set noreorder
    .align 4
    .globl ossl_ee_bn_muladd_row_mmi
    .ent ossl_ee_bn_muladd_row_mmi
ossl_ee_bn_muladd_row_mmi:
    pcpyld  $12, $a2, $a2
    daddu   $8, $zero, $zero
.Lee_bn_reg_loop:
    beqz    $a3, .Lee_bn_reg_finish
    nop
    lw      $9, 0($a1)
    addiu   $10, $a3, -1
    beqz    $10, .Lee_bn_reg_odd
    nop
    lw      $10, 4($a1)
    b       .Lee_bn_reg_products
    nop
.Lee_bn_reg_odd:
    daddu   $10, $zero, $zero
.Lee_bn_reg_products:
    pcpyld  $11, $10, $9
    pmultuw $14, $11, $12
    /* Independent t load separates multiply from product consumers. */
    lwu     $10, 0($a0)
    pcpyud  $13, $14, $14
    daddu   $9, $14, $10
    daddu   $9, $9, $8
    sw      $9, 0($a0)
    dsrl32  $8, $9, 0
    addiu   $a3, $a3, -1
    beqz    $a3, .Lee_bn_reg_finish
    nop
    lwu     $10, 4($a0)
    daddu   $9, $13, $10
    daddu   $9, $9, $8
    sw      $9, 4($a0)
    dsrl32  $8, $9, 0
    addiu   $a3, $a3, -1
    addiu   $a0, $a0, 8
    b       .Lee_bn_reg_loop
    addiu   $a1, $a1, 8
.Lee_bn_reg_finish:
    sll     $v0, $8, 0
    /* Clear temporary packed operands/products without touching return. */
    pxor    $8, $8, $8
    pxor    $9, $9, $9
    pxor    $10, $10, $10
    pxor    $11, $11, $11
    pxor    $12, $12, $12
    pxor    $13, $13, $13
    pxor    $14, $14, $14
    jr      $ra
    nop
    .end ossl_ee_bn_muladd_row_mmi
    .set reorder
