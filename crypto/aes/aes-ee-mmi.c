/*
 * Copyright 2026 openssl-retro contributors. Licensed under Apache-2.0.
 *
 * EXPERIMENTAL AES-128/192/256, 4 independent blocks / one shared key.
 * Four AES columns are transposed across R5900 128-bit MMI registers.
 * The MMI backend accelerates MixColumns and AddRoundKey; SubBytes
 * and ShiftRows are deliberately portable and have constant-time,
 * table-free data flow. Do NOT treat this as a fast or audited AES.
 *
 * No OpenSSL AES_encrypt/EVP/AES-GCM dispatch is modified.
 * EE_MMI_AES_SCALAR_ROUND provides a directly comparable scalar
 * MixColumns/ARK backend on PS2. EE_MMI_HOST_TEST is for host emulation.
 */
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "crypto/ee_mmi.h"

#if UINT_MAX != 0xffffffffU
# error "EE AES MMI requires a 32-bit unsigned int"
#endif

static void aes_wipe(void *ptr, size_t n)
{
    volatile unsigned char *p = (volatile unsigned char *)ptr;
    while (n-- != 0)
        *p++ = 0;
}

static uint32_t load_le32(const unsigned char *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static void store_le32(unsigned char *p, uint32_t x)
{
    p[0] = (unsigned char)x;
    p[1] = (unsigned char)(x >> 8);
    p[2] = (unsigned char)(x >> 16);
    p[3] = (unsigned char)(x >> 24);
}

/* Four independent byte-wide GF(2^8) doublings in a uint32_t,
 * no cross-byte carries. The reduction polynomial is 0x11b. */
static uint32_t aes_xtime4(uint32_t a)
{
    uint32_t hi = (a >> 7) & 0x01010101U;
    return ((a << 1) & 0xfefefefeU)
         ^ hi ^ (hi << 1) ^ (hi << 3) ^ (hi << 4);
}

static uint32_t aes_gfmul4(uint32_t a, uint32_t b)
{
    uint32_t result = 0, bit, mask;
    unsigned int i;
    for (i = 0; i < 8; ++i) {
        bit = (b >> i) & 0x01010101U;
        mask = bit | (bit << 1);
        mask |= mask << 2;
        mask |= mask << 4; /* each byte is now 0xff or 0x00 */
        result ^= a & mask;
        a = aes_xtime4(a);
    }
    return result;
}

/*
 * GF(2^8) squaring is LINEAR over GF(2), unlike general multiplication.
 * Byte-polynomial residues for bits 0..7 are:
 * 01 04 10 40 1b 6c ab 9a (mod x^8+x^4+x^3+x+1).
 * Four byte lanes are operated on independently without any
 * indexed S-box/table loads or data-dependent branches.
 */
static uint32_t aes_gfsquare4(uint32_t x)
{
    uint32_t b;
    uint32_t r = (x & 0x01010101U)
               ^ ((x & 0x02020202U) << 1)
               ^ ((x & 0x04040404U) << 2)
               ^ ((x & 0x08080808U) << 3);
    b = (x >> 4) & 0x01010101U;
    r ^= b ^ (b << 1) ^ (b << 3) ^ (b << 4);
    b = (x >> 5) & 0x01010101U;
    r ^= (b << 2) ^ (b << 3) ^ (b << 5) ^ (b << 6);
    b = (x >> 6) & 0x01010101U;
    r ^= b ^ (b << 1) ^ (b << 3) ^ (b << 5) ^ (b << 7);
    b = (x >> 7) & 0x01010101U;
    r ^= (b << 1) ^ (b << 3) ^ (b << 4) ^ (b << 7);
    return r;
}

static uint32_t aes_rotbyte(uint32_t x, unsigned int bits,
                            uint32_t low_mask)
{
    return ((x << bits) & low_mask)
         | ((x >> (8 - bits)) & ~low_mask);
}

/* Compute 4 AES S-boxes at once with a fixed GF(256) exponentiation.
 * S(0)=0x63. No secret-dependent branch or indexed lookup table.
 * Constant-time design still needs verification on the EE toolchain. */
static uint32_t aes_sbox4(uint32_t x)
{
    uint32_t x2, x7, t, inverse, s;
    /*
     * Fixed addition chain:
     * x^2, x^3, x^6, x^7, x^14, x^15,
     * x^30, x^60, x^120, x^127, x^254.
     * Seven cheap GF squares and only FOUR general GF multiplies
     * instead of 13 general multiplies in the earlier exponentiation.
     */
    x2 = aes_gfsquare4(x);            /* 2 */
    t = aes_gfmul4(x2, x);           /* 3 */
    t = aes_gfsquare4(t);            /* 6 */
    x7 = aes_gfmul4(t, x);           /* 7 */
    t = aes_gfsquare4(x7);           /* 14 */
    t = aes_gfmul4(t, x);            /* 15 */
    t = aes_gfsquare4(t);            /* 30 */
    t = aes_gfsquare4(t);            /* 60 */
    t = aes_gfsquare4(t);            /* 120 */
    t = aes_gfmul4(t, x7);           /* 127 */
    inverse = aes_gfsquare4(t);      /* 254 */
    s = inverse
      ^ aes_rotbyte(inverse, 1, 0xfefefefeU)
      ^ aes_rotbyte(inverse, 2, 0xfcfcfcfcU)
      ^ aes_rotbyte(inverse, 3, 0xf8f8f8f8U)
      ^ aes_rotbyte(inverse, 4, 0xf0f0f0f0U)
      ^ 0x63636363U;
    aes_wipe(&x2, sizeof(x2));
    aes_wipe(&x7, sizeof(x7));
    aes_wipe(&t, sizeof(t));
    aes_wipe(&inverse, sizeof(inverse));
    return s;
}

static uint32_t aes_rot32_8(uint32_t x)
{
    return (x >> 8) | (x << 24);
}
static uint8_t aes_xtime8(uint8_t a)
{
    return (uint8_t)((a << 1) ^ ((0U - (unsigned int)(a >> 7)) & 0x1bU));
}

int ossl_ee_aes_set_encrypt_key(ossl_ee_aes4_key *ctx,
                                 const unsigned char *key,
                                 unsigned int bits)
{
    uint32_t w[60] = {0}, temp;
    unsigned int nk, rounds, total, i, round, col, lane;
    uint8_t rcon = 1;
    if (ctx == NULL || key == NULL)
        return 0;
    if (bits != 128 && bits != 192 && bits != 256)
        return 0;
    nk = bits / 32;
    rounds = nk + 6;
    total = 4 * (rounds + 1);
    for (i = 0; i < nk; ++i)
        w[i] = load_le32(key + 4*i);
    for (i = nk; i < total; ++i) {
        temp = w[i-1];
        if ((i % nk) == 0) {
            temp = aes_sbox4(aes_rot32_8(temp)) ^ rcon;
            rcon = aes_xtime8(rcon);
        } else if (nk > 6 && (i % nk) == 4) {
            temp = aes_sbox4(temp);
        }
        w[i] = w[i-nk] ^ temp;
    }
    for (round = 0; round <= rounds; ++round)
        for (col = 0; col < 4; ++col)
            for (lane = 0; lane < 4; ++lane)
                ctx->round_key[round][col][lane] = w[4*round+col];
    ctx->rounds = rounds;
    aes_wipe(w, sizeof(w));
    return 1;
}

void ossl_ee_aes_clear_key(ossl_ee_aes4_key *ctx)
{
    if (ctx != NULL)
        aes_wipe(ctx, sizeof(*ctx));
}

static void aes_shiftrows4(uint32_t state[4][4])
{
    unsigned int lane, col, row;
    for (lane = 0; lane < 4; ++lane) {
        uint32_t old[4], shifted[4];
        for (col = 0; col < 4; ++col)
            old[col] = state[col][lane];
        for (col = 0; col < 4; ++col) {
            uint32_t word = 0;
            for (row = 0; row < 4; ++row)
                word |= ((old[(col+row)&3] >> (8*row)) & 255U)
                         << (8*row);
            shifted[col] = word;
        }
        for (col = 0; col < 4; ++col)
            state[col][lane] = shifted[col];
    }
}

#ifdef EE_MMI_AES_SCALAR_ROUND
static uint32_t aes_mixword(uint32_t word)
{
    uint32_t r8 = aes_rot32_8(word);
    uint32_t r16 = (word >> 16) | (word << 16);
    uint32_t r24 = (word >> 24) | (word << 8);
    return r8 ^ r16 ^ r24 ^ aes_xtime4(word ^ r8);
    /* Equals word ^ (word ^ r8 ^ r16 ^ r24) ^ xtime(...). */
}
#endif

int ossl_ee_aes_encrypt4(unsigned char out[4][16],
                         const unsigned char in[4][16],
                         const ossl_ee_aes4_key *ctx)
{
    uint32_t state[4][4] __attribute__((aligned(16)));
    unsigned int round, col, lane;
    if (out == NULL || in == NULL || ctx == NULL
        || (ctx->rounds != 10 && ctx->rounds != 12
            && ctx->rounds != 14))
        return 0;

    /* Interleave 4 independent AES blocks, column-major by block. */
    for (col = 0; col < 4; ++col)
        for (lane = 0; lane < 4; ++lane)
            state[col][lane] = load_le32(in[lane] + 4*col)
                                   ^ ctx->round_key[0][col][lane];

    for (round = 1; round < ctx->rounds; ++round) {
        for (col = 0; col < 4; ++col)
            for (lane = 0; lane < 4; ++lane)
                state[col][lane] = aes_sbox4(state[col][lane]);
        aes_shiftrows4(state);
#ifdef EE_MMI_AES_SCALAR_ROUND
        for (col = 0; col < 4; ++col)
            for (lane = 0; lane < 4; ++lane)
                state[col][lane] = aes_mixword(state[col][lane])
                             ^ ctx->round_key[round][col][lane];
#else
        ossl_ee_aes_mixcolumns_ark4(state, ctx->round_key[round]);
#endif
    }

    /* Final round omits MixColumns. */
    for (col = 0; col < 4; ++col)
        for (lane = 0; lane < 4; ++lane)
            state[col][lane] = aes_sbox4(state[col][lane]);
    aes_shiftrows4(state);
    for (col = 0; col < 4; ++col)
        for (lane = 0; lane < 4; ++lane)
            store_le32(out[lane]+4*col, state[col][lane]
                              ^ ctx->round_key[ctx->rounds][col][lane]);

    aes_wipe(state, sizeof(state));
    return 1;
}

int ossl_ee_aes_ctr32_xor(unsigned char *out, const unsigned char *in,
                          size_t len, const ossl_ee_aes4_key *ctx,
                          const unsigned char nonce[12], uint32_t counter)
{
    unsigned char blocks[4][16], stream[4][16];
    size_t offset = 0, remaining, i, j, bcount;
    uint64_t needed;
    if (ctx == NULL || nonce == NULL || (len != 0
        && (out == NULL || in == NULL)))
        return 0;
    if (ctx->rounds != 10 && ctx->rounds != 12
        && ctx->rounds != 14)
        return 0;
    needed = (uint64_t)(len / 16) + ((len % 16) != 0);
    if (needed > (uint64_t)UINT32_MAX - counter + 1U)
        return 0;
    while (offset < len) {
        remaining = len - offset;
        bcount = remaining / 16 + ((remaining % 16) != 0);
        if (bcount > 4)
            bcount = 4;
        for (i = 0; i < 4; ++i) {
            uint32_t n = counter + (uint32_t)(i < bcount ? i : 0);
            memcpy(blocks[i], nonce, 12);
            blocks[i][12] = (unsigned char)(n >> 24);
            blocks[i][13] = (unsigned char)(n >> 16);
            blocks[i][14] = (unsigned char)(n >> 8);
            blocks[i][15] = (unsigned char)n;
        }
        if (!ossl_ee_aes_encrypt4(stream, blocks, ctx)) {
            aes_wipe(blocks, sizeof(blocks));
            aes_wipe(stream, sizeof(stream));
            return 0;
        }
        for (i = 0; i < bcount; ++i) {
            size_t count = len - offset < 16 ? len - offset : 16;
            for (j = 0; j < count; ++j)
                out[offset+j] = in[offset+j] ^ stream[i][j];
            offset += count;
        }
        counter += (uint32_t)bcount;
    }
    aes_wipe(blocks, sizeof(blocks));
    aes_wipe(stream, sizeof(stream));
    return 1;
}
