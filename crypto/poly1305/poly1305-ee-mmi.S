/*
 * Copyright 2026 openssl-retro contributors. Licensed under Apache-2.0.
 *
 * EE/R5900 Poly1305 4-stream block absorption.
 * Each 128-bit vector contains one 32-bit limb from 4 independent MACs.
 * uint32_t h[5][4] and m[5][4] MUST be 16-byte aligned.
 *
 * This performs only the five 32-bit lane additions. It does NOT
 * normalize 26-bit limbs, multiply by r, or perform any FPU operation.
 * Those steps are in the C code; this helper is a correctness-first
 * foundation for future integer MMI multiplication.
 *
 * All registers used here (t0/t1) are caller-saved. Leaf function.
 */
/* Numeric GPRs 8..15 retain the original o32 temporary layout under
 * both o32 and modern PS2SDK n32 register naming. */
    .text
    .set noreorder
    .align 4
    .globl ossl_ee_poly1305_add4
    .ent ossl_ee_poly1305_add4
ossl_ee_poly1305_add4:
    lq      $8, 0($a0)
    lq      $9, 0($a1)
    paddw   $8, $8, $9
    sq      $8, 0($a0)
    lq      $8, 16($a0)
    lq      $9, 16($a1)
    paddw   $8, $8, $9
    sq      $8, 16($a0)
    lq      $8, 32($a0)
    lq      $9, 32($a1)
    paddw   $8, $8, $9
    sq      $8, 32($a0)
    lq      $8, 48($a0)
    lq      $9, 48($a1)
    paddw   $8, $8, $9
    sq      $8, 48($a0)
    lq      $8, 64($a0)
    lq      $9, 64($a1)
    paddw   $8, $8, $9
    sq      $8, 64($a0)
    jr      $ra
    nop
    .end ossl_ee_poly1305_add4
    .set reorder
