/* Copyright 2026 openssl-retro contributors. Apache-2.0.
 * Benchmark and internal code only: no OpenSSL/EVP ABI changes.
 * A GHASH H is fixed across the blocks of a message. Prepare the
 * constant-address window table ONCE, then reuse it for every block.
 */
#ifndef EE_GHASH_WINDOW_INTERNAL_H
#define EE_GHASH_WINDOW_INTERNAL_H
#include <stdint.h>
#if defined(EE_MMI_GHASH_WINDOW_BITS)
typedef struct {
    uint32_t high[16][4][4];
#if EE_MMI_GHASH_WINDOW_BITS == 8
    uint32_t low[16][4][4];
#endif
} ossl_ee_ghash_window_ctx;
void ossl_ee_ghash_window_prepare(ossl_ee_ghash_window_ctx *ctx,
                                  const uint32_t h[4][4]);
void ossl_ee_ghash_window_mul(uint32_t out[4][4],
                              const uint32_t x[4][4],
                              const ossl_ee_ghash_window_ctx *ctx);
void ossl_ee_ghash_window_clear(ossl_ee_ghash_window_ctx *ctx);
#endif
#endif
