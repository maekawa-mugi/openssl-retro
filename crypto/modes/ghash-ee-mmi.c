/*
 * Copyright 2026 openssl-retro contributors. Licensed under Apache-2.0.
 *
 * Experimental four-independent-message GHASH for the PS2 R5900 MMI.
 * This is the GHASH block update only. It is NOT a full AES-GCM
 * implementation and is not attached to EVP or OpenSSL gcm128.c.
 * Each input is a whole number of 16-byte GHASH blocks; AES-GCM
 * users must supply proper AAD/ciphertext padding and the final
 * bit-length encoding. The caller owns independent Y/H per stream.
 */
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "crypto/ee_mmi.h"

static uint32_t load_be32(const unsigned char *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16)
         | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void store_be32(unsigned char *p, uint32_t x)
{
    p[0] = (unsigned char)(x >> 24);
    p[1] = (unsigned char)(x >> 16);
    p[2] = (unsigned char)(x >> 8);
    p[3] = (unsigned char)x;
}

static void wipe(void *p, size_t len)
{
    volatile unsigned char *v = (volatile unsigned char *)p;
    size_t i;
    for (i = 0; i < len; ++i)
        v[i] = 0;
}

#ifdef EE_MMI_GHASH_SCALAR_MULTIPLY
/* The same 128-bit long-multiplication algorithm with portable
 * uint32_t operations, for direct PS2 hardware A/B timing.
 * No table lookups or conditional branches depend on field values. */
static void ghash_mul_scalar(uint32_t z[4][4],
                             const uint32_t x[4][4],
                             const uint32_t h[4][4])
{
    unsigned int lane, i, w;
    for (lane = 0; lane < 4; ++lane) {
        uint32_t v[4], acc[4] = {0, 0, 0, 0};
        for (w = 0; w < 4; ++w)
            v[w] = h[w][lane];
        for (i = 0; i < 128; ++i) {
            uint32_t mask = 0U -
                ((x[i >> 5][lane] >> (31 - (i & 31))) & 1U);
            uint32_t reduction = 0U - (v[3] & 1U);
            for (w = 0; w < 4; ++w)
                acc[w] ^= v[w] & mask;
            v[3] = (v[3] >> 1) | (v[2] << 31);
            v[2] = (v[2] >> 1) | (v[1] << 31);
            v[1] = (v[1] >> 1) | (v[0] << 31);
            v[0] = (v[0] >> 1) ^ (0xe1000000U & reduction);
        }
        for (w = 0; w < 4; ++w)
            z[w][lane] = acc[w];
        wipe(v, sizeof(v));
        wipe(acc, sizeof(acc));
    }
}
#endif

int ossl_ee_ghash_update4(unsigned char y[4][16],
                          const unsigned char h[4][16],
                          const unsigned char *const in[4],
                          size_t blocks)
{
    uint32_t state[4][4] __attribute__((aligned(16)));
    uint32_t key[4][4] __attribute__((aligned(16)));
    uint32_t x[4][4] __attribute__((aligned(16)));
    uint32_t result[4][4] __attribute__((aligned(16)));
    unsigned int lane, w;
    size_t block;

    if (y == NULL || h == NULL)
        return 0;
    if (blocks > SIZE_MAX / 16U || (blocks != 0 && in == NULL))
        return 0;
    if (blocks != 0)
        for (lane = 0; lane < 4; ++lane)
            if (in[lane] == NULL)
                return 0;

    if (blocks == 0)
        return 1;

    for (w = 0; w < 4; ++w)
        for (lane = 0; lane < 4; ++lane) {
            key[w][lane] = load_be32(h[lane] + 4*w);
            state[w][lane] = load_be32(y[lane] + 4*w);
        }

    for (block = 0; block < blocks; ++block) {
        for (w = 0; w < 4; ++w)
            for (lane = 0; lane < 4; ++lane)
                x[w][lane] = state[w][lane]
                       ^ load_be32(in[lane] + block * 16U + 4*w);
#ifdef EE_MMI_GHASH_SCALAR_MULTIPLY
        ghash_mul_scalar(result, x, key);
#else
        ossl_ee_ghash_mul4(result, x, key);
#endif
        memcpy(state, result, sizeof(state));
    }
    for (w = 0; w < 4; ++w)
        for (lane = 0; lane < 4; ++lane)
            store_be32(y[lane] + 4*w, state[w][lane]);

    wipe(key, sizeof(key));
    wipe(x, sizeof(x));
    wipe(result, sizeof(result));
    wipe(state, sizeof(state));
    return 1;
}
