/*
 * Copyright 2026 openssl-retro contributors. Licensed under Apache-2.0.
 * Experimental public-only RSA verification on PS2 EE / R5900.
 *
 * These APIs implement only exponent e=65537. They DO NOT implement
 * RSA private-key operations, OAEP, PSS, key generation, or TLS EVP
 * integration. In particular, this code must NEVER process private
 * exponents or private-key material.
 */
#ifndef OSSL_EE_RSA_VERIFY_H
#define OSSL_EE_RSA_VERIFY_H
#include <stddef.h>
#include <stdint.h>

#define OSSL_EE_RSA_LANES 4
#define OSSL_EE_RSA_MAX_BYTES 512

/*
 * Reusable public-key Montgomery precomputation. Four independent
 * moduli each get one object, reused for subsequent public operations.
 * This avoids recalculating R^2 mod n with 64*num modular doublings
 * on every call (2048 iterations per RSA-2048 public operation).
 * NOT suitable for private keys or secret exponents.
 */
typedef struct {
    uint32_t mod[OSSL_EE_RSA_MAX_BYTES / 4];
    uint32_t r2[OSSL_EE_RSA_MAX_BYTES / 4];
    uint32_t n0;
    size_t num;
} ossl_ee_rsa_public_key;

int ossl_ee_rsa_public_key_init(ossl_ee_rsa_public_key *key,
                                 const unsigned char *modulus,
                                 size_t mod_bytes);
void ossl_ee_rsa_public_key_clear(ossl_ee_rsa_public_key *key);

/* Exponentiate four inputs against independently prepared keys.
 * Context lifetime, ownership, and thread safety belong to caller:
 * initialization is not concurrent with calls; read-only concurrent
 * reuse after initialization is supported. Returns 0 on errors.
 * Exact in-place out[lane]==input[lane] is supported.
 */
int ossl_ee_rsa_public65537_prepared4(
    unsigned char *const out[OSSL_EE_RSA_LANES],
    const unsigned char *const input[OSSL_EE_RSA_LANES],
    const ossl_ee_rsa_public_key *const keys[OSSL_EE_RSA_LANES]);

/*
 * Four independent RSA public exponentiations:
 * out[lane] = input[lane]^65537 mod modulus[lane]
 *
 * Each input/modulus is mod_bytes bytes, unsigned big-endian.
 * Supported sizes: 128, 256, 384, 512 (1024..4096 bits).
 * Modulus must be odd with its topmost bit set, and input < modulus.
 * In-place out[lane]==input[lane] is supported. Other overlap is not.
 * Returns 1 on success, 0 on invalid arguments/input.
 *
 * This is four independent jobs, executed sequentially; the lower
 * Montgomery helper packs TWO 32x32->64 word multiplications in MMI.
 * Do not interpret "_4" as four simultaneous 2048-bit vector lanes.
 */
int ossl_ee_rsa_public65537_4(
    unsigned char *const out[OSSL_EE_RSA_LANES],
    const unsigned char *const input[OSSL_EE_RSA_LANES],
    const unsigned char *const modulus[OSSL_EE_RSA_LANES],
    size_t mod_bytes);

/*
 * Strict RSASSA-PKCS1-v1_5 / SHA-256 verification of four signatures.
 * The 32-byte SHA-256 message digests are supplied by the caller.
 * Returns 1 on valid arguments; valid[lane] is 0 or 1 for each
 * signature. Invalid signature representative >= modulus produces
 * valid[lane]=0 and does not invalidate other lanes.
 *
 * Rejects missing/short 0xff padding, noncanonical DigestInfo,
 * unexpected bytes, and malformed signatures.
 * This is TLS 1.2/certificate-style PKCS#1 v1.5, NOT RSA-PSS.
 */
int ossl_ee_rsa_pkcs1_sha256_verify4(
    unsigned char valid[OSSL_EE_RSA_LANES],
    const unsigned char *const signatures[OSSL_EE_RSA_LANES],
    const unsigned char *const modulus[OSSL_EE_RSA_LANES],
    const unsigned char digests[OSSL_EE_RSA_LANES][32],
    size_t mod_bytes);
#endif
