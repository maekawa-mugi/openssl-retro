/*
 * Constant-time EE MMI 4-lane GHASH nibble-table select-and-XOR.
 * Copyright 2026 openssl-retro contributors. Apache License 2.0.
 *
 * void ossl_ee_ghash_window_xor4(uint32_t z[4][4],
 *                                 const uint32_t table[16][4][4],
 *                                 const uint32_t selector[4]);
 *
 * For each of 16 PUBLIC table indices: compare four 32-bit independent
 * selector lanes against broadcast index via PCEQW, mask four MMI
 * words of the table, and XOR them into z. ALL 16 entries are read,
 * always in ascending order. No data-dependent table address or
 * secret-controlled branch; H-derived table remains fixed-scan.
 * Each pointer must be 16-byte aligned. HI/LO untouched.
 *
 * Caller-saved EE registers only. $a3 is the public counter.
 */
    .text
    .set noreorder
    .align 4
    .globl ossl_ee_ghash_window_xor4
    .ent ossl_ee_ghash_window_xor4
ossl_ee_ghash_window_xor4:
    lq      $8, 0($a0)
    lq      $9, 16($a0)
    lq      $10, 32($a0)
    lq      $11, 48($a0)
    lq      $12, 0($a2)
    /* Four copies of 1 in a packed word vector. */
    lui     $13, %hi(.Lee_ghash_window_ones)
    addiu   $13, $13, %lo(.Lee_ghash_window_ones)
    lq      $13, 0($13)
    pxor    $14, $zero, $zero
    addiu   $a3, $zero, 16
.Lee_ghash_window_select:
    pceqw   $15, $12, $14
    lq      $t8, 0($a1)
    lq      $t9, 16($a1)
    pand    $t8, $t8, $15
    pand    $t9, $t9, $15
    pxor    $8, $8, $t8
    pxor    $9, $9, $t9
    lq      $t8, 32($a1)
    lq      $t9, 48($a1)
    pand    $t8, $t8, $15
    pand    $t9, $t9, $15
    pxor    $10, $10, $t8
    pxor    $11, $11, $t9
    paddw   $14, $14, $13
    addiu   $a1, $a1, 64
    addiu   $a3, $a3, -1
    bnez    $a3, .Lee_ghash_window_select
    nop
    sq      $8, 0($a0)
    sq      $9, 16($a0)
    sq      $10, 32($a0)
    sq      $11, 48($a0)
    jr      $ra
    nop
    .end ossl_ee_ghash_window_xor4
    .set reorder

    .section .rodata
    .align 4
.Lee_ghash_window_ones:
    .word 1,1,1,1
