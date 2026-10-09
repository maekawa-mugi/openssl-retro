/*
 * Copyright 2026 The openssl-retro contributors. All Rights Reserved.
 * Licensed under the Apache License 2.0; see LICENSE.txt.
 *
 * Four independent same-length SHA-256 messages in parallel on EE MMI.
 * The message schedule is scalar and byte-order independent. The 64
 * compression rounds run in 128-bit EE GPRs (4 x 32-bit lanes).
 * This is a separate internal batch API, NOT a single-stream SHA-256
 * replacement and NOT an automatic OpenSSL EVP optimization.
 */
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "crypto/ee_mmi.h"

#if UINT_MAX != 0xffffffffU
# error "EE SHA256 requires a 32-bit unsigned int"
#endif

#define K4(n) { (n), (n), (n), (n) }
/* The word-major 4x repetition makes every LQ a per-lane broadcast. */
static const uint32_t ee_sha256_k4[64][4]
    __attribute__((aligned(16))) = {
    K4(0x428a2f98U), K4(0x71374491U), K4(0xb5c0fbcfU), K4(0xe9b5dba5U),
    K4(0x3956c25bU), K4(0x59f111f1U), K4(0x923f82a4U), K4(0xab1c5ed5U),
    K4(0xd807aa98U), K4(0x12835b01U), K4(0x243185beU), K4(0x550c7dc3U),
    K4(0x72be5d74U), K4(0x80deb1feU), K4(0x9bdc06a7U), K4(0xc19bf174U),
    K4(0xe49b69c1U), K4(0xefbe4786U), K4(0x0fc19dc6U), K4(0x240ca1ccU),
    K4(0x2de92c6fU), K4(0x4a7484aaU), K4(0x5cb0a9dcU), K4(0x76f988daU),
    K4(0x983e5152U), K4(0xa831c66dU), K4(0xb00327c8U), K4(0xbf597fc7U),
    K4(0xc6e00bf3U), K4(0xd5a79147U), K4(0x06ca6351U), K4(0x14292967U),
    K4(0x27b70a85U), K4(0x2e1b2138U),
    K4(0x4d2c6dfcU), K4(0x53380d13U), K4(0x650a7354U), K4(0x766a0abbU),
    K4(0x81c2c92eU), K4(0x92722c85U), K4(0xa2bfe8a1U), K4(0xa81a664bU),
    K4(0xc24b8b70U), K4(0xc76c51a3U), K4(0xd192e819U), K4(0xd6990624U),
    K4(0xf40e3585U), K4(0x106aa070U), K4(0x19a4c116U), K4(0x1e376c08U),
    K4(0x2748774cU), K4(0x34b0bcb5U), K4(0x391c0cb3U), K4(0x4ed8aa4aU),
    K4(0x5b9cca4fU), K4(0x682e6ff3U), K4(0x748f82eeU), K4(0x78a5636fU),
    K4(0x84c87814U), K4(0x8cc70208U), K4(0x90befffaU), K4(0xa4506cebU),
    K4(0xbef9a3f7U), K4(0xc67178f2U)
};
#undef K4

static const uint32_t ee_sha256_initial[8] = {
    0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
    0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U
};

static const uint32_t ee_sha224_initial[8] = {
    0xc1059ed8U, 0x367cd507U, 0x3070dd17U, 0xf70e5939U,
    0xffc00b31U, 0x68581511U, 0x64f98fa7U, 0xbefa4fa4U
};

static uint32_t rotr32(uint32_t x, unsigned int n)
{
    return (x >> n) | (x << (32 - n));
}

static uint32_t bigend32(const unsigned char *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16)
         | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

/* 16 input words per lane, then 48 schedule words per lane. */
static void sha256_prepare4(uint32_t schedule[64][4],
                            const unsigned char *const blocks[4])
{
    unsigned int t, lane;

    for (t = 0; t < 16; ++t)
        for (lane = 0; lane < 4; ++lane)
            schedule[t][lane] = bigend32(blocks[lane] + 4 * t);

    for (t = 16; t < 64; ++t)
        for (lane = 0; lane < 4; ++lane) {
            uint32_t x = schedule[t - 15][lane];
            uint32_t y = schedule[t - 2][lane];
            uint32_t sig0 = rotr32(x, 7) ^ rotr32(x, 18) ^ (x >> 3);
            uint32_t sig1 = rotr32(y, 17) ^ rotr32(y, 19) ^ (y >> 10);
            schedule[t][lane] = schedule[t - 16][lane] + sig0
                              + schedule[t - 7][lane] + sig1;
        }
}

static void sha256_process4(uint32_t state[8][4],
                            uint32_t schedule[64][4],
                            const unsigned char *const blocks[4])
{
    sha256_prepare4(schedule, blocks);
    ossl_ee_sha256_compress4(state, schedule, ee_sha256_k4);
}

static int ee_sha2_hash4(unsigned char *const out[4],
                         const unsigned char *const in[4], size_t len,
                         const uint32_t initial[8], size_t digest_words)
{
    uint32_t state[8][4] __attribute__((aligned(16)));
    uint32_t schedule[64][4] __attribute__((aligned(16)));
    unsigned char tail[4][128];
    const unsigned char *blocks[4];
    uint64_t length_bits;
    size_t offset = 0, remaining, tail_bytes, t, lane;

    if (out == NULL || in == NULL)
        return 0;
    for (lane = 0; lane < 4; ++lane)
        if (out[lane] == NULL || (len != 0 && in[lane] == NULL))
            return 0;
    /* SHA-2/32 uses a 64-bit length field. Do not silently wrap it. */
    if ((uint64_t)len > UINT64_MAX / 8)
        return 0;

    for (t = 0; t < 8; ++t)
        for (lane = 0; lane < 4; ++lane)
            state[t][lane] = initial[t];

    while (len - offset >= 64) {
        for (lane = 0; lane < 4; ++lane)
            blocks[lane] = in[lane] + offset;
        sha256_process4(state, schedule, blocks);
        offset += 64;
    }

    remaining = len - offset;
    tail_bytes = remaining <= 55 ? 64 : 128;
    memset(tail, 0, sizeof(tail));
    length_bits = (uint64_t)len * 8U;
    for (lane = 0; lane < 4; ++lane) {
        if (remaining != 0)
            memcpy(tail[lane], in[lane] + offset, remaining);
        tail[lane][remaining] = 0x80;
        for (t = 0; t < 8; ++t)
            tail[lane][tail_bytes - 8 + t] =
                (unsigned char)(length_bits >> (56 - 8 * t));
        blocks[lane] = tail[lane];
    }
    sha256_process4(state, schedule, blocks);
    if (tail_bytes == 128) {
        for (lane = 0; lane < 4; ++lane)
            blocks[lane] = tail[lane] + 64;
        sha256_process4(state, schedule, blocks);
    }

    for (lane = 0; lane < 4; ++lane)
        for (t = 0; t < digest_words; ++t) {
            uint32_t word = state[t][lane];
            out[lane][4 * t] = (unsigned char)(word >> 24);
            out[lane][4 * t + 1] = (unsigned char)(word >> 16);
            out[lane][4 * t + 2] = (unsigned char)(word >> 8);
            out[lane][4 * t + 3] = (unsigned char)word;
        }

    /* No secret-dependent branches or memory accesses in compression.
     * Length and number of blocks may be observable by design. */
    return 1;
}


/* Both SHA-224 and SHA-256 share the exact same MMI compression rounds.
 * SHA-224 differs only in its initial state and 7-word output length. */
int ossl_ee_sha256_hash4(unsigned char out[4][32],
                         const unsigned char *const in[4], size_t len)
{
    unsigned char *digests[4];
    size_t lane;
    if (out == NULL)
        return 0;
    for (lane = 0; lane < 4; ++lane)
        digests[lane] = out[lane];
    return ee_sha2_hash4(digests, in, len, ee_sha256_initial, 8);
}

int ossl_ee_sha224_hash4(unsigned char out[4][28],
                         const unsigned char *const in[4], size_t len)
{
    unsigned char *digests[4];
    size_t lane;
    if (out == NULL)
        return 0;
    for (lane = 0; lane < 4; ++lane)
        digests[lane] = out[lane];
    return ee_sha2_hash4(digests, in, len, ee_sha224_initial, 7);
}
