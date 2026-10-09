/*
 * Experimental P-256 ECDSA signature verifier for PS2 EE / R5900.
 * Copyright 2026 openssl-retro contributors. Apache-2.0.
 *
 * Explicit opt-in, NOT registered with EVP or the existing EC_METHOD.
 * Requires OpenSSL libcrypto and its EC/P-256 implementation.
 */
#ifndef OSSL_EE_ECDSA_P256_H
#define OSSL_EE_ECDSA_P256_H

#include <stdint.h>

/*
 * Verify a SHA-256 digest with an uncompressed SEC1 P-256 public key
 * (0x04 || X[32] || Y[32]) and a fixed-size IEEE P1363 signature
 * (r[32] || s[32], each big-endian). This is NOT an ASN.1 DER signature.
 * Inputs must not alias output (this routine has no output buffer).
 *
 * Returns:
 *    1 = valid signature
 *    0 = invalid signature, out-of-range r/s, malformed or off-curve key
 *   -1 = internal error (allocation, group or arithmetic failure)
 *
 * Uses the existing EC_POINT_mul for point operations and BN_mod_inverse
 * for inversion. Two order-modulus multiplications use the previously
 * added 8-limb EE MMI Montgomery backend unless compiled with
 * EE_MMI_ECDSA_SCALAR, in which case BN_mod_mul is used.
 *
 * Verification only. No private key, signing, nonce or RNG is involved.
 * No FIPS claim; hardware correctness/timing are unverified.
 */
int ossl_ee_ecdsa_p256_verify(const uint8_t public_key[65],
                              const uint8_t digest_sha256[32],
                              const uint8_t signature_rs[64]);
#endif
