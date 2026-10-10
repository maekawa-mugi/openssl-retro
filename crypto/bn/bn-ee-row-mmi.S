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
    /* R5900 LQ/SQ require 16-byte addresses. O32 guarantees at
     * most 8-byte stack alignment at arbitrary call boundaries.
     * Reserve 64 bytes plus 15 bytes of slop, round a PRIVATE
     * scratch pointer up to 16, and restore the exact original SP.
     * A C caller's stack alignment must never determine correctness.
     *
     * $v1 (GPR3) is caller-clobbered and unused by the row body.
     * [0..15] product, [16..31] broadcast multiplier,
     * [32..47] 2 packed operand words, [48..63] unused padding. */
    daddiu  $sp, $sp, -80
    daddiu  $v1, $sp, 15
    dsrl    $v1, $v1, 4
    dsll    $v1, $v1, 4
    sw      $a2, 16($v1)
    sw      $a2, 20($v1)
    sw      $zero, 24($v1)
    sw      $zero, 28($v1)
    lq      $12, 16($v1)
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
    sw      $9, 32($v1)
    sw      $10, 36($v1)
    sw      $zero, 40($v1)
    sw      $zero, 44($v1)
    lq      $11, 32($v1)
    psraw   $13, $11, 31
    pextlw  $11, $13, $11
    pmultuw $14, $11, $12
    sq      $14, 0($v1)

    ld      $9, 0($v1)
    lwu     $10, 0($a0)
    daddu   $9, $9, $10
    daddu   $9, $9, $8
    sw      $9, 0($a0)
    dsrl32  $8, $9, 0

    addiu   $a3, $a3, -1
    beqz    $a3, .Lee_bn_row_finish
    nop
    ld      $9, 8($v1)
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
    /* C uint32_t returns must be sign-extended from bit31 in the
     * 64-bit GPR, even though the value is unsigned. DSRL32 above
     * keeps the internal carry zero-extended for exact additions;
     * DADDU here would violate the C ABI for carries >= 0x80000000.
     * A full-register comparison can then fail while printf("%08lx")
     * still prints identical low words. SLL canonicalizes the return. */
    sll     $v0, $8, 0
    /* Wipe operands and products retained in stack slots, never
     * depend on compiler optimizations to remove this cleanup. */
    sq      $zero, 0($v1)
    sq      $zero, 16($v1)
    sq      $zero, 32($v1)
    daddiu  $sp, $sp, 80
    jr      $ra
    nop
    .end ossl_ee_bn_muladd_row_mmi
    .set reorder
