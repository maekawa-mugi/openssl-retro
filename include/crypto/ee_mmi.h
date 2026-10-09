/*
 * Copyright 2026 The openssl-retro contributors. All Rights Reserved.
 * Licensed under the Apache License 2.0; see LICENSE.txt.
 *
 * Experimental R5900/EE MMI batch primitives. Internal API only.
 * No public OpenSSL EVP or SHA256 dispatch is modified.
 */
#ifndef OSSL_CRYPTO_EE_MMI_H
#define OSSL_CRYPTO_EE_MMI_H
#pragma once

#include <stddef.h>
#include <stdint.h>

/*
 * SHA-256/SHA-224 over four independent messages of the SAME byte length.
 * Digest output is in network byte order, out[0]..out[3].
 *
 * Input byte buffers may be unaligned, may overlap each other, and
 * may be NULL only when len == 0. out may not overlap the input.
 * Returns 1 on success, 0 for invalid input or unrepresentable bit length.
 * No dynamic memory or heap allocation is used.
 *
 * This prototype is linked into libcrypto only for ps2-ee-mmi with asm.
 */
int ossl_ee_sha256_hash4(unsigned char out[4][32],
                         const unsigned char *const in[4], size_t len);

/* SHA-224 with the same 4-way MMI compressor, SHA-224 IV and 28-byte output. */
int ossl_ee_sha224_hash4(unsigned char out[4][28],
                         const unsigned char *const in[4], size_t len);

/* 4-lane SHA-256 compression core, 16-byte-aligned word-major arrays.
 * Exposed for tests only; callers should use ossl_ee_sha256_hash4.
 */
void ossl_ee_sha256_compress4(uint32_t state[8][4],
                              const uint32_t schedule[64][4],
                              const uint32_t constants[64][4]);

/*
 * Four independent Poly1305 authenticators, same message length but
 * independent 32-byte one-time keys. tags and keys are [4][16]/[4][32].
 * msg pointers may be NULL only if len == 0.
 * This is a standalone internal batch primitive, NOT an EVP MAC hook.
 * Returns 1 on success, 0 on invalid arguments.
 */
int ossl_ee_poly1305_auth4(unsigned char tags[4][16],
                            const unsigned char *const msgs[4], size_t len,
                            const unsigned char keys[4][32]);

/* EE MMI primitive: vector add of 5 x 4 packed 32-bit limbs.
 * All pointers must be 16-byte aligned. This deliberately does not
 * normalize 26-bit limbs. The caller's scalar multiply does that.
 */
void ossl_ee_poly1305_add4(uint32_t h[5][4],
                            const uint32_t m[5][4]);

/*
 * Multiply 4 streams in parallel with PMULTUW. The input arrays
 * contain 128-bit packed words, 16-byte aligned:
 *   a[5][lane]: absorbed h limbs, lane 0..3
 *   b[0..4][lane]: clamped r limbs
 *   b[5..9][lane]: five times each r limb
 *
 * products[k][i][lane] contains a[i][lane] *
 *   b[(k-i+5)%5 + (i>k ? 5 : 0)][lane].
 * Each value is an exact unsigned 64-bit integer.
 *
 * This interface is internal and deliberately exposes exact products
 * so scalar modular carry/reduction can be shared with the reference.
 */
void ossl_ee_poly1305_products4(uint64_t products[5][5][4],
                                 const uint32_t a[5][4],
                                 const uint32_t b[10][4]);

/*
 * Accumulated Poly1305 product sums for four lanes: 5 * 4 * 8 = 160
 * output bytes rather than 25 * 4 * 8 = 800 intermediate product bytes.
 * PMULTUW starts the first product; four PMADDUW operations accumulate
 * within EE HI/LO. Sums do not exceed 2^59, preserving exactness.
 * All arguments must be 16-byte aligned.
 */
void ossl_ee_poly1305_sums4(uint64_t sums[5][4],
                            const uint32_t a[5][4],
                            const uint32_t b[10][4]);

/*
 * Experimental 4-way X25519 scalar multiplication. Inputs are four
 * independent 32-byte private scalars and four independent encoded
 * Montgomery u coordinates. Scalars are clamped per RFC 7748.
 * All four messages always execute the same ladder operations.
 *
 * Not a replacement for the EVP_X25519 implementation. No implicit
 * all-zero shared-secret rejection: applications MUST check it when
 * establishing a shared secret. out must not alias the inputs.
 * Returns 1 for valid pointers or 0 if an argument is NULL.
 */
int ossl_ee_x25519_scalar_mult4(unsigned char out[4][32],
                                const unsigned char scalar[4][32],
                                const unsigned char point[4][32]);

/*
 * X25519 field-element multiply with 10 alternating 26/25-bit limbs
 * over p = 2^255-19. Each uint32_t contains one limb from one
 * independent lane, aligned and word-major [limb][stream].
 *
 * g_scaled[0..9]=g, [10..19]=2*g,
 * [20..29]=19*g, [30..39]=38*g.
 * Outputs exactly 10*4 uint64_t convolution sums (<2^60),
 * before scalar carry propagation. 16-byte alignment is required.
 */
void ossl_ee_x25519_mul_sums4(uint64_t sums[10][4],
                              const uint32_t f[10][4],
                              const uint32_t g_scaled[40][4]);

/*
 * Four independent GHASH state updates as used by AES-GCM.
 * Y is both the initial and final GHASH accumulator, with four
 * different authentication subkeys H and four independent byte strings.
 * Each input is exactly blocks*16 bytes. Callers implement GCM's
 * AAD/ciphertext final-block padding and the final length block.
 *
 * This does NOT replace OpenSSL's gcm128.c, EVP or TLS AES-GCM.
 * Returns 0 for invalid pointers or block-count overflow.
 * blocks == 0 accepts NULL input pointers but still requires Y and H.
 * Y must not alias H or input storage (except zero-block no-op).
 */
int ossl_ee_ghash_update4(unsigned char y[4][16],
                          const unsigned char h[4][16],
                          const unsigned char *const in[4],
                          size_t blocks);

/*
 * R5900 MMI four-way GF(2^128) multiply core.
 * x, h and z are word-major big-endian mathematical 32-bit
 * words [4][4], where inner index chooses independent stream.
 * Each array must be 16-byte aligned, no overlap.
 * Implements NIST SP 800-38D (128 fixed rounds).
 */
void ossl_ee_ghash_mul4(uint32_t z[4][4],
                        const uint32_t x[4][4],
                        const uint32_t h[4][4]);

/*
 * Experimental EE AES-128/192/256 encryption, four independent blocks
 * using ONE shared AES key. Optimized for CTR/GCM keystream generation.
 * Round keys are broadcast into 4 independent 32-bit MMI lanes.
 * This is internal-only, NOT OpenSSL AES_encrypt or EVP integration.
 */
typedef struct {
    uint32_t round_key[15][4][4] __attribute__((aligned(16)));
    unsigned int rounds;
} ossl_ee_aes4_key;

int ossl_ee_aes_set_encrypt_key(ossl_ee_aes4_key *ctx,
                                 const unsigned char *key,
                                 unsigned int bits);
/* Explicitly erase all key-dependent round-key material. */
void ossl_ee_aes_clear_key(ossl_ee_aes4_key *ctx);
int ossl_ee_aes_encrypt4(unsigned char out[4][16],
                         const unsigned char in[4][16],
                         const ossl_ee_aes4_key *ctx);

/*
 * AES-CTR using an explicit 96-bit prefix + big-endian 32-bit counter.
 * Arbitrary lengths, in-place supported. Returns 0 on pointer errors
 * or if the counter would wrap within this call. No GHASH or tag.
 * The caller must ensure counter/nonces are never reused under one key.
 */
int ossl_ee_aes_ctr32_xor(unsigned char *out, const unsigned char *in,
                          size_t len, const ossl_ee_aes4_key *ctx,
                          const unsigned char nonce[12], uint32_t counter);

/* Four AES MixColumns + AddRoundKey operations in parallel. Caller
 * has already applied SubBytes and ShiftRows (including first key).
 * state[col][lane] packs one AES column as little-endian bytes.
 * Pointers are 16-byte aligned, nonoverlapping (round key is const).
 */
void ossl_ee_aes_mixcolumns_ark4(uint32_t state[4][4],
                                 const uint32_t round_key[4][4]);

#endif
