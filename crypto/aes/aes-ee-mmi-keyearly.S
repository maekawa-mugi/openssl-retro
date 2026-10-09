/*
 * Copyright 2026 openssl-retro contributors. Licensed under Apache-2.0.
 *
 * R5900 MMI four-block AES MixColumns + AddRoundKey.
 * Variant K: prefetch round key into an unused caller-saved GPR
 * before the data-dependent MixColumns calculation. This overlaps
 * LS-pipe key load/use latency with arithmetic; the AES S-box C
 * implementation remains unchanged.
 * One packed 128-bit GPR holds four 32-bit AES columns, one from
 * each independent AES block. Each column is little-endian bytes:
 * [row0, row1, row2, row3] from least to most significant.
 *
 * MixColumns(col) = col ^ (col ^ ROTR8(col) ^ ROTR16(col) ^
 *                             ROTR24(col)) ^ xtime(col ^ ROTR8(col))
 * where xtime is GF(2^8) doubling on each of the four bytes.
 *
 * No key-indexed tables, data-dependent branches, or HI/LO usage.
 * All registers used are caller-saved. Stack is untouched.
 * R5900 assembly and ABI verification remain pending on PS2 hardware.
 */
/* Numeric GPRs 8..15 retain the original o32 temporary layout under
 * both o32 and modern PS2SDK n32 register naming. */
    .text
    .set noreorder
    .align 4
    .macro EE_AES_COL off
        /* Variant K: hide round-key LQ latency behind the full MixColumns
         * dependency chain. $a2 is caller-saved and unused by this API. */
        lq      $a2, \off($a1)
        lq      $8, \off($a0)
        psrlw   $9, $8, 8
        psllw   $10, $8, 24
        por     $9, $9, $10      /* rotr8 per 32-bit lane */
        psrlw   $10, $8, 16
        psllw   $11, $8, 16
        por     $10, $10, $11      /* rotr16 */
        psrlw   $11, $8, 24
        psllw   $12, $8, 8
        por     $11, $11, $12      /* rotr24 */
        pxor    $13, $8, $9
        pxor    $13, $13, $10
        pxor    $13, $13, $11     /* t = xor of 4 column bytes */

        pxor    $14, $8, $9     /* a[row] xor a[row+1] */
        psllw   $15, $14, 1
        pand    $15, $15, $t8     /* byte-local x<<1, & 0xfefefefe */
        psrlw   $14, $14, 7
        pand    $14, $14, $t9     /* high bit of each byte, at bit0 */

        /* Each 0x01 byte becomes 0x1b, no cross-byte carries. */
        psllw   $v0, $14, 1
        pxor    $v0, $v0, $14
        psllw   $v1, $14, 3
        pxor    $v0, $v0, $v1
        psllw   $v1, $14, 4
        pxor    $v0, $v0, $v1
        pxor    $15, $15, $v0    /* bytewise AES xtime */

        pxor    $13, $13, $8
        pxor    $13, $13, $15
        pxor    $13, $13, $a2
        sq      $13, \off($a0)
    .endm

    .globl ossl_ee_aes_mixcolumns_ark4
    .ent ossl_ee_aes_mixcolumns_ark4
ossl_ee_aes_mixcolumns_ark4:
    lui     $t8, %hi(.Laes_mmi_masks)
    addiu   $t8, $t8, %lo(.Laes_mmi_masks)
    lq      $t9, 16($t8)      /* replicated 0x01010101 */
    lq      $t8, 0($t8)       /* replicated 0xfefefefe */
    EE_AES_COL 0
    EE_AES_COL 16
    EE_AES_COL 32
    EE_AES_COL 48
    jr      $ra
    nop
    .end ossl_ee_aes_mixcolumns_ark4
    .set reorder

    .section .rodata
    .align 4
.Laes_mmi_masks:
    .word 0xfefefefe, 0xfefefefe, 0xfefefefe, 0xfefefefe
    .word 0x01010101, 0x01010101, 0x01010101, 0x01010101
