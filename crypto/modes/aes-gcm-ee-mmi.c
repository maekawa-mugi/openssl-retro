/*
 * Four-stream experimental R5900 AES-GCM with combined CTR/GHASH loop.
 * Copyright 2026 openssl-retro contributors. Apache License 2.0.
 *
 * This is a separate internal API, not EVP, TLS or FIPS.
 * Each of four independent streams uses a shared expanded AES key
 * with its own 96-bit IV, AAD, ciphertext and 128-bit tag.
 */
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "crypto/ee_aes_gcm.h"
#include "crypto/ee_ghash_window.h"
#if defined(EE_MMI_GHASH_WINDOW_BITS)
# define GCM_WIN_DECL , const ossl_ee_ghash_window_ctx *window
# define GCM_WIN_ARG , window
# define GCM_WIN_ROOT , &window
#else
# define GCM_WIN_DECL
# define GCM_WIN_ARG
# define GCM_WIN_ROOT
#endif

static void gcm_wipe(void *v, size_t n)
{
    volatile unsigned char *p = (volatile unsigned char *)v;
    while (n-- != 0)
        *p++ = 0;
}
static uint32_t be32(const unsigned char *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16)
         | ((uint32_t)p[2] << 8) | p[3];
}
static void put_be32(unsigned char *p, uint32_t x)
{
    p[0] = (unsigned char)(x >> 24);
    p[1] = (unsigned char)(x >> 16);
    p[2] = (unsigned char)(x >> 8);
    p[3] = (unsigned char)x;
}
static void put_be64(unsigned char *p, uint64_t x)
{
    put_be32(p, (uint32_t)(x >> 32));
    put_be32(p + 4, (uint32_t)x);
}

#if defined(EE_MMI_GHASH_WINDOW_BITS)
static void gcm_mul4(uint32_t z[4][4], const uint32_t x[4][4],
                     const uint32_t h[4][4] GCM_WIN_DECL)
{
    (void)h;
    ossl_ee_ghash_window_mul(z, x, window);
}
#elif defined(EE_MMI_GHASH_SCALAR_MULTIPLY)
/* Portable baseline for an identical streaming AES-GCM implementation.
 * The production MMI build instead calls the 4-way R5900 GHASH kernel. */
static void gcm_mul4(uint32_t z[4][4], const uint32_t x[4][4],
                     const uint32_t h[4][4])
{
    unsigned int lane, i, w;
    for (lane = 0; lane < 4; ++lane) {
        uint32_t v[4], acc[4] = {0,0,0,0};
        for (w = 0; w < 4; ++w)
            v[w] = h[w][lane];
        for (i = 0; i < 128; ++i) {
            uint32_t mask = 0U - ((x[i >> 5][lane]
                                       >> (31 - (i & 31))) & 1U);
            uint32_t red = 0U - (v[3] & 1U);
            for (w = 0; w < 4; ++w)
                acc[w] ^= v[w] & mask;
            v[3] = (v[3] >> 1) | (v[2] << 31);
            v[2] = (v[2] >> 1) | (v[1] << 31);
            v[1] = (v[1] >> 1) | (v[0] << 31);
            v[0] = (v[0] >> 1) ^ (0xe1000000U & red);
        }
        for (w = 0; w < 4; ++w)
            z[w][lane] = acc[w];
        gcm_wipe(v, sizeof(v));
        gcm_wipe(acc, sizeof(acc));
    }
}
#else
static void gcm_mul4(uint32_t z[4][4], const uint32_t x[4][4],
                     const uint32_t h[4][4])
{
    ossl_ee_ghash_mul4(z, x, h);
}
#endif

/* The state is kept word-major in 128-bit packed MMI registers.
 * Loading each 16-byte ciphertext directly into X avoids an extra
 * round trip through ossl_ee_ghash_update4 and its conversion buffers. */
static void gcm_auth_block(uint32_t state[4][4], const uint32_t h[4][4],
                           const unsigned char *const block[4] GCM_WIN_DECL)
{
    uint32_t x[4][4] __attribute__((aligned(16)));
    unsigned int lane, word;
    for (word = 0; word < 4; ++word)
        for (lane = 0; lane < 4; ++lane)
            x[word][lane] = state[word][lane]
                          ^ be32(block[lane] + 4 * word);
    gcm_mul4(state, x, h GCM_WIN_ARG);
    gcm_wipe(x, sizeof(x));
}

/* GHASH arbitrary equal byte-length buffers, zero padding only their
 * final short block. Data and AAD may be unaligned in user memory. */
static void gcm_auth_bytes(uint32_t state[4][4], const uint32_t h[4][4],
                           const unsigned char *const ptrs[4], size_t len
                           GCM_WIN_DECL)
{
    unsigned char last[4][16] __attribute__((aligned(16))) = {{0}};
    const unsigned char *chunk[4];
    size_t offset = 0;
    unsigned int lane;
    while (len - offset >= 16) {
        for (lane = 0; lane < 4; ++lane)
            chunk[lane] = ptrs[lane] + offset;
        gcm_auth_block(state, h, chunk GCM_WIN_ARG);
        offset += 16;
    }
    if (offset != len) {
        for (lane = 0; lane < 4; ++lane) {
            memcpy(last[lane], ptrs[lane] + offset, len - offset);
            chunk[lane] = last[lane];
        }
        gcm_auth_block(state, h, chunk GCM_WIN_ARG);
    }
    gcm_wipe(last, sizeof(last));
}

/* 32-bit GCM counter: J0 = IV||1, payload counters start at 2.
 * The validated number of counter blocks is at most 2^32-2. */
static int gcm_ctr4(const ossl_ee_aes_gcm4_key *ctx,
                    unsigned char *const out[4],
                    const unsigned char *const in[4], size_t len,
                    const unsigned char iv[4][12],
                    uint32_t state[4][4], int seal GCM_WIN_DECL)
{
    unsigned char count[4][16] __attribute__((aligned(16)));
    unsigned char stream[4][16] __attribute__((aligned(16)));
    unsigned char cipher[4][16] __attribute__((aligned(16)));
    const unsigned char *auth[4];
    uint32_t counter = 2;
    size_t offset = 0, n, j;
    unsigned int lane;
    while (offset < len) {
        n = len - offset < 16 ? len - offset : 16;
        for (lane = 0; lane < 4; ++lane) {
            memcpy(count[lane], iv[lane], 12);
            put_be32(count[lane] + 12, counter);
        }
        if (!ossl_ee_aes_encrypt4(stream, count, &ctx->aes)) {
            gcm_wipe(count, sizeof(count));
            gcm_wipe(stream, sizeof(stream));
            gcm_wipe(cipher, sizeof(cipher));
            return 0;
        }
        for (lane = 0; lane < 4; ++lane) {
            memset(cipher[lane], 0, 16);
            for (j = 0; j < n; ++j) {
                unsigned char value = in[lane][offset+j] ^ stream[lane][j];
                out[lane][offset+j] = value;
                cipher[lane][j] = value;
            }
            auth[lane] = cipher[lane];
        }
        if (seal)
            gcm_auth_block(state, ctx->h, auth GCM_WIN_ARG);
        offset += n;
        if (offset < len)
            ++counter;
    }
    gcm_wipe(count, sizeof(count));
    gcm_wipe(stream, sizeof(stream));
    gcm_wipe(cipher, sizeof(cipher));
    return 1;
}

static int gcm_args(const ossl_ee_aes_gcm4_key *ctx,
                    unsigned char *const out[4],
                    const unsigned char *const in[4], size_t len,
                    const unsigned char *const aad[4], size_t aad_len,
                    const unsigned char iv[4][12])
{
    unsigned int lane;
    uint64_t blocks = (uint64_t)(len / 16) + ((len % 16) != 0);
    if (ctx == NULL || out == NULL || in == NULL || iv == NULL
        || (ctx->aes.rounds != 10 && ctx->aes.rounds != 12
            && ctx->aes.rounds != 14)
        || blocks > (uint64_t)UINT32_MAX - 1U
        || (uint64_t)len > UINT64_MAX / 8
        || (uint64_t)aad_len > UINT64_MAX / 8)
        return 0;
    for (lane = 0; lane < 4; ++lane) {
        if ((len != 0 && (out[lane] == NULL || in[lane] == NULL))
            || (aad_len != 0 && (aad == NULL || aad[lane] == NULL)))
            return 0;
    }
    return 1;
}

/* Final GHASH length block, then mask with E(K,J0). Does not output
 * any sensitive AES intermediate buffers to public caller memory. */
static int gcm_tag(const ossl_ee_aes_gcm4_key *ctx,
                   uint32_t state[4][4], unsigned char tag[4][16],
                   const unsigned char iv[4][12], size_t aad_len,
                   size_t len GCM_WIN_DECL)
{
    unsigned char length_block[4][16] __attribute__((aligned(16))) = {{0}};
    unsigned char j0[4][16] __attribute__((aligned(16)));
    unsigned char mask[4][16] __attribute__((aligned(16)));
    const unsigned char *ptrs[4];
    unsigned int lane, word;
    for (lane = 0; lane < 4; ++lane) {
        put_be64(length_block[lane], (uint64_t)aad_len * 8);
        put_be64(length_block[lane] + 8, (uint64_t)len * 8);
        memcpy(j0[lane], iv[lane], 12);
        put_be32(j0[lane] + 12, 1);
        ptrs[lane] = length_block[lane];
    }
    gcm_auth_block(state, ctx->h, ptrs GCM_WIN_ARG);
    if (!ossl_ee_aes_encrypt4(mask, j0, &ctx->aes)) {
        gcm_wipe(length_block, sizeof(length_block));
        gcm_wipe(j0, sizeof(j0));
        gcm_wipe(mask, sizeof(mask));
        return 0;
    }
    for (lane = 0; lane < 4; ++lane)
        for (word = 0; word < 4; ++word) {
            uint32_t x = state[word][lane];
            tag[lane][4*word] = (unsigned char)((x >> 24) ^ mask[lane][4*word]);
            tag[lane][4*word+1] = (unsigned char)((x >> 16) ^ mask[lane][4*word+1]);
            tag[lane][4*word+2] = (unsigned char)((x >> 8) ^ mask[lane][4*word+2]);
            tag[lane][4*word+3] = (unsigned char)(x ^ mask[lane][4*word+3]);
        }
    gcm_wipe(length_block, sizeof(length_block));
    gcm_wipe(j0, sizeof(j0));
    gcm_wipe(mask, sizeof(mask));
    return 1;
}

int ossl_ee_aes_gcm4_init(ossl_ee_aes_gcm4_key *ctx,
                           const unsigned char *key, unsigned int bits)
{
    unsigned char zero[4][16] __attribute__((aligned(16))) = {{0}};
    unsigned char subkey[4][16] __attribute__((aligned(16)));
    unsigned int word, lane;
    if (ctx == NULL || key == NULL)
        return 0;
    if (!ossl_ee_aes_set_encrypt_key(&ctx->aes, key, bits)) {
        ossl_ee_aes_gcm4_clear(ctx);
        return 0;
    }
    if (!ossl_ee_aes_encrypt4(subkey, zero, &ctx->aes)) {
        ossl_ee_aes_gcm4_clear(ctx);
        gcm_wipe(subkey, sizeof(subkey));
        return 0;
    }
    for (word = 0; word < 4; ++word)
        for (lane = 0; lane < 4; ++lane)
            ctx->h[word][lane] = be32(subkey[lane] + 4*word);
    gcm_wipe(subkey, sizeof(subkey));
    return 1;
}
void ossl_ee_aes_gcm4_clear(ossl_ee_aes_gcm4_key *ctx)
{
    if (ctx != NULL)
        gcm_wipe(ctx, sizeof(*ctx));
}

int ossl_ee_aes_gcm4_seal(const ossl_ee_aes_gcm4_key *ctx,
                           unsigned char *const out[4],
                           unsigned char tags[4][16],
                           const unsigned char *const in[4], size_t len,
                           const unsigned char *const aad[4], size_t aad_len,
                           const unsigned char iv[4][12])
{
    uint32_t state[4][4] __attribute__((aligned(16))) = {{0}};
#if defined(EE_MMI_GHASH_WINDOW_BITS)
    ossl_ee_ghash_window_ctx window __attribute__((aligned(16)));
#endif
    int ok;
    if (!gcm_args(ctx, out, in, len, aad, aad_len, iv) || tags == NULL)
        return 0;
#if defined(EE_MMI_GHASH_WINDOW_BITS)
    ossl_ee_ghash_window_prepare(&window, ctx->h);
#endif
    if (aad_len != 0)
        gcm_auth_bytes(state, ctx->h, aad, aad_len GCM_WIN_ROOT);
    ok = gcm_ctr4(ctx, out, in, len, iv, state, 1 GCM_WIN_ROOT);
    if (ok)
        ok = gcm_tag(ctx, state, tags, iv, aad_len, len GCM_WIN_ROOT);
    gcm_wipe(state, sizeof(state));
#if defined(EE_MMI_GHASH_WINDOW_BITS)
    ossl_ee_ghash_window_clear(&window);
#endif
    return ok;
}
int ossl_ee_aes_gcm4_open(const ossl_ee_aes_gcm4_key *ctx,
                           unsigned char *const out[4],
                           const unsigned char tags[4][16],
                           const unsigned char *const in[4], size_t len,
                           const unsigned char *const aad[4], size_t aad_len,
                           const unsigned char iv[4][12])
{
    uint32_t state[4][4] __attribute__((aligned(16))) = {{0}};
#if defined(EE_MMI_GHASH_WINDOW_BITS)
    ossl_ee_ghash_window_ctx window __attribute__((aligned(16)));
#endif
    unsigned char expected[4][16] __attribute__((aligned(16)));
    unsigned int lane, j, diff = 0;
    int ok = 0;
    if (!gcm_args(ctx, out, in, len, aad, aad_len, iv) || tags == NULL)
        return 0;
#if defined(EE_MMI_GHASH_WINDOW_BITS)
    ossl_ee_ghash_window_prepare(&window, ctx->h);
#endif
    if (aad_len != 0)
        gcm_auth_bytes(state, ctx->h, aad, aad_len GCM_WIN_ROOT);
    if (len != 0)
        gcm_auth_bytes(state, ctx->h, in, len GCM_WIN_ROOT);
    if (!gcm_tag(ctx, state, expected, iv, aad_len, len GCM_WIN_ROOT))
        goto done;
    for (lane = 0; lane < 4; ++lane)
        for (j = 0; j < 16; ++j)
            diff |= (unsigned int)(expected[lane][j] ^ tags[lane][j]);
    if (diff != 0)
        goto done; /* no plaintext released on authentication failure */
    if (len == 0)
        ok = 1;
    else
        ok = gcm_ctr4(ctx, out, in, len, iv, state, 0 GCM_WIN_ROOT);
done:
    gcm_wipe(state, sizeof(state));
    gcm_wipe(expected, sizeof(expected));
#if defined(EE_MMI_GHASH_WINDOW_BITS)
    ossl_ee_ghash_window_clear(&window);
#endif
    return ok;
}
