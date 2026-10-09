/*
 * R5900 EE MMI Montgomery CIOS addmul-row experiment.
 * Copyright 2026 openssl-retro contributors. Apache License 2.0.
 *
 * uint32_t ossl_ee_bn_muladd_row_mmi(
 *    uint32_t *t, const uint32_t *a, uint32_t multiplier, size_t num);
 *
 * t and a contain >=num 32-bit limbs, little-limb endian.
 * Updates t[j] with t[j]+a[j]*multiplier+carry, returns the final
 * 32-bit carry. This integrates all PMULTUW 2-product calls, carry
 * propagation, and stores into ONE assembler call per CIOS row.
 *
 * The C caller handles q=t[0]*n0, reduction row and word shift.
 * Both MMI operand pairs are sign-extended from their low 32 bits
 * before PMULTUW, as mandated by EE instruction operand encoding.
 * No input loads beyond num; num is publicly bounded and nonzero.
 * No callee-saved registers or HI/LO state is carried across calls.
 * 64-byte 16-byte-aligned local scratch is wiped by the C caller
 * on return? No: only PUBLIC BN row products are handled by this
 * experimental path, but callers MUST NOT use it for secret material
 * until stack-wiping and constant-time timing are audited.
 */
    .text
    .set noreorder
    .align 4
    .globl ossl_ee_bn_muladd_row_mmi
    .ent ossl_ee_bn_muladd_row_mmi
ossl_ee_bn_muladd_row_mmi:
    daddiu  $sp, $sp, -64
    /* [0..15] product, [16..31] broadcast multiplier,
     * [32..47] 2 packed operand words, [48..63] unused. */
    sw      $a2, 16($sp)
    sw      $a2, 20($sp)
    sw      $zero, 24($sp)
    sw      $zero, 28($sp)
    lq      $12, 16($sp)
    psraw   $13, $12, 31
    pextlw  $12, $13, $12
    daddu   $8, $zero, $zero   /* 64-bit carry, at most 32 bits */
.Lee_bn_row_loop:
    beqz    $a3, .Lee_bn_row_finish
    nop
    lw      $9, 0($a1)
    addiu   $10, $a3, -1
    beqz    $10, .Lee_bn_row_odd
    nop
    lw      $10, 4($a1)
    b       .Lee_bn_row_operands
    nop
.Lee_bn_row_odd:
    daddu   $10, $zero, $zero
.Lee_bn_row_operands:
    sw      $9, 32($sp)
    sw      $10, 36($sp)
    sw      $zero, 40($sp)
    sw      $zero, 44($sp)
    lq      $11, 32($sp)
    psraw   $13, $11, 31
    pextlw  $11, $13, $11
    pmultuw $14, $11, $12
    sq      $14, 0($sp)

    ld      $9, 0($sp)
    lwu     $10, 0($a0)
    daddu   $9, $9, $10
    daddu   $9, $9, $8
    sw      $9, 0($a0)
    dsrl32  $8, $9, 0

    addiu   $a3, $a3, -1
    beqz    $a3, .Lee_bn_row_finish
    nop
    ld      $9, 8($sp)
    lwu     $10, 4($a0)
    daddu   $9, $9, $10
    daddu   $9, $9, $8
    sw      $9, 4($a0)
    dsrl32  $8, $9, 0

    addiu   $a3, $a3, -1
    addiu   $a0, $a0, 8
    b       .Lee_bn_row_loop
    addiu   $a1, $a1, 8

.Lee_bn_row_finish:
    daddu   $v0, $8, $zero
    /* Wipe operands and products retained in stack slots, never
     * depend on compiler optimizations to remove this cleanup. */
    sq      $zero, 0($sp)
    sq      $zero, 16($sp)
    sq      $zero, 32($sp)
    daddiu  $sp, $sp, 64
    jr      $ra
    nop
    .end ossl_ee_bn_muladd_row_mmi
    .set reorder
