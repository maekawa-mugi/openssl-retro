/*
 * Experimental P-256 ECDH / public point multiplication, EE R5900.
 * Copyright 2026 openssl-retro contributors. Apache License 2.0.
 */
#ifndef OSSL_EE_P256_ECDH_H
#define OSSL_EE_P256_ECDH_H

#include <stdint.h>

/*
 * SEC1 uncompressed P-256 points, 65 bytes (04 || x32 || y32).
 * Scalars must be canonical big-endian [1, order-1], 32 bytes.
 * The peer public point is checked for canonical coordinates and
 * curve membership before scalar multiplication.
 *
 * Returns 1 on success, 0 on invalid scalar/point or calculation error.
 * On failure, output is set to all zeros. Output must not overlap input.
 *
 * These are EXPERIMENTAL APIs: not installed in EVP, TLS or EC_METHOD.
 * Field multiplication uses the opt-in 32-bit EE MMI Montgomery kernel.
 * No hardware constant-time audit: DO NOT use real private TLS keys.
 */
int ossl_ee_p256_public_from_private(unsigned char public_key[65],
                                      const unsigned char scalar[32]);
int ossl_ee_p256_ecdh(unsigned char shared_x[32],
                       const unsigned char scalar[32],
                       const unsigned char peer_public[65]);
#endif
