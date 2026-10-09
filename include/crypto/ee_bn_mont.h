/*
 * Experimental PS2 EE/R5900 word-based Montgomery multiplication.
 * Copyright 2026 openssl-retro contributors. Apache License 2.0.
 *
 * This header is intentionally usable without generated OpenSSL headers
 * so the R5900 MMI kernel can be validated before the full SDK port.
 */
#ifndef OSSL_EE_BN_MONT_H
#define OSSL_EE_BN_MONT_H

#include <stddef.h>
#include <stdint.h>

/* Fixed maximum to bound scratch space on the small EE stack.
 * 128 32-bit words covers 4096-bit RSA. Larger moduli return 0. */
#define OSSL_EE_BN_MONT_MAX_WORDS 128

/* Computes out = a*b*(2^(32*num))^-1 (mod mod), for reduced a,b and
 * odd mod, with n0 = -mod[0]^-1 mod 2^32. All little-limb-endian arrays
 * have exactly num uint32_t entries. out may alias a or b.
 * Never treat a 32-bit word with bit31 set as a signed multiplier.
 *
 * This is an experimental opt-in backend: 1=success, 0=invalid inputs.
 * Input magnitude bounds (a < mod, b < mod) are caller preconditions.
 * Valid inputs have fixed loop counts independent of operand values.
 */
int ossl_ee_bn_mont32(uint32_t *out, const uint32_t *a,
                       const uint32_t *b, const uint32_t *mod,
                       uint32_t n0, size_t num);

/* Experimental fused R5900 CIOS row. Never link the ASM backend
 * without its independent known-answer and boundary tests. Enabled
 * ONLY via EE_MMI_BN_ROW_FUSED and not part of default libcrypto.
 * It integrates every 2-product PMULTUW with carry propagation
 * across the entire addmul row, then returns the final carry.
 */
uint32_t ossl_ee_bn_muladd_row_mmi(uint32_t *t, const uint32_t *a,
                                    uint32_t multiplier, size_t num);

/* Performs two exact 32x32 unsigned multiplies in parallel. x and y
 * are 16-byte-aligned arrays of four words, only indices 0,1 matter.
 * out is 16-byte aligned; out[0] and out[1] contain full 64-bit
 * results, including when operand bit31 is set. */
void ossl_ee_bn_mul2(uint64_t out[2], const uint32_t x[4],
                      const uint32_t y[4]);

#endif /* OSSL_EE_BN_MONT_H */
