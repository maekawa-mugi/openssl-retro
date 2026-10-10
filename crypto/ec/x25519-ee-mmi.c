/*
 * Copyright 2026 openssl-retro contributors. Licensed under Apache-2.0.
 *
 * Experimental four-stream X25519 on R5900/EE MMI, NOT a replacement
 * for OpenSSL X25519 or its EVP provider implementation.
 *
 * The fused EE PMULTUW/PMADDUW primitive computes field products,
 * while this C wrapper handles constant-time Montgomery ladders,
 * 26/25-bit radix carries and the fixed inversion exponent.
 * For host tests, EE_MMI_HOST_TEST supplies a C product emulator.
 * EE_MMI_X25519_SCALAR_MULTIPLY uses a pure C 64-bit field multiply,
 * enabling an exact same-algorithm A/B test on the EE.
 *
 * Input/output encoding and scalar clamping follow RFC 7748.
 * No conditional branch depends on scalar bits or field values.
 */
#include <limits.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "crypto/ee_mmi.h"
#if defined(EE_MMI_X25519_FUSED_REDUCE) && defined(EE_MMI_X25519_SCALAR_MULTIPLY)
# error "Fused X25519 reduction requires the MMI multiplication backend"
#endif

#if UINT_MAX != 0xffffffffU
# error "X25519 EE MMI implementation requires a 32-bit unsigned int"
#endif

typedef struct __attribute__((aligned(16))) {
    uint32_t x[10][4];
} ee_fe4;

static unsigned int bits_at(unsigned int i)
{
    return (i & 1U) ? 25U : 26U;
}

static uint64_t mask_at(unsigned int i)
{
    return ((uint64_t)1 << bits_at(i)) - 1U;
}

/* Accepts loose 64-bit accumulators. Three unconditional reduction
 * passes cover convolution sums (<2^60), biased subtraction and
 * multiplication by 121665, with the top carry folded by 19. */
static void fe_reduce(ee_fe4 *out, uint64_t t[10][4])
{
    unsigned int lane, pass, i;
    for (lane = 0; lane < 4; ++lane) {
        uint64_t h[10];
        for (i = 0; i < 10; ++i)
            h[i] = t[i][lane];

        for (pass = 0; pass < 3; ++pass) {
            for (i = 0; i < 9; ++i) {
                unsigned int width = bits_at(i);
                h[i+1] += h[i] >> width;
                h[i] &= ((uint64_t)1 << width) - 1U;
            }
            h[0] += 19 * (h[9] >> 25);
            h[9] &= (((uint64_t)1 << 25) - 1U);
        }
        /* Full carry is normalized after two passes. The third pass
         * guarantees canonical limb bounds, not canonical field value.
         * All callers serialize with one conditional modulus subtraction. */
        for (i = 0; i < 10; ++i)
            out->x[i][lane] = (uint32_t)h[i];
    }
}

static void fe_zero(ee_fe4 *out)
{
    memset(out, 0, sizeof(*out));
}
static void fe_one(ee_fe4 *out)
{
    fe_zero(out);
    out->x[0][0] = 1;
    out->x[0][1] = 1;
    out->x[0][2] = 1;
    out->x[0][3] = 1;
}
static void fe_copy(ee_fe4 *out, const ee_fe4 *in)
{
    memcpy(out, in, sizeof(*out));
}
static void fe_add(ee_fe4 *out, const ee_fe4 *a, const ee_fe4 *b)
{
    uint64_t t[10][4];
    unsigned int i, lane;
    for (i = 0; i < 10; ++i)
        for (lane = 0; lane < 4; ++lane)
            t[i][lane] = (uint64_t)a->x[i][lane] + b->x[i][lane];
    fe_reduce(out, t);
}
static void fe_sub(ee_fe4 *out, const ee_fe4 *a, const ee_fe4 *b)
{
    uint64_t t[10][4];
    unsigned int i, lane;
    for (i = 0; i < 10; ++i) {
        uint64_t bias = i == 0 ? 2*((1UL << 26) - 19)
                                : 2 * mask_at(i);
        for (lane = 0; lane < 4; ++lane)
            t[i][lane] = bias + (uint64_t)a->x[i][lane] - b->x[i][lane];
    }
    fe_reduce(out, t);
}
static void fe_cswap(ee_fe4 *a, ee_fe4 *b, const uint32_t swap[4])
{
    unsigned int i, lane;
    for (i = 0; i < 10; ++i)
        for (lane = 0; lane < 4; ++lane) {
            uint32_t mask = 0U - swap[lane];
            uint32_t t = mask & (a->x[i][lane] ^ b->x[i][lane]);
            a->x[i][lane] ^= t;
            b->x[i][lane] ^= t;
        }
}
#ifdef EE_MMI_X25519_FUSED_REDUCE
extern void ossl_ee_x25519_mul_reduce4(uint32_t out[10][4],
                                       const uint32_t a[10][4],
                                       const uint32_t scaled[40][4]);
#endif
static void fe_mul(ee_fe4 *out, const ee_fe4 *a, const ee_fe4 *b)
{
#ifndef EE_MMI_X25519_FUSED_REDUCE
    uint64_t sums[10][4] __attribute__((aligned(16)));
#endif
    unsigned int i, lane;
#ifdef EE_MMI_X25519_SCALAR_MULTIPLY
    unsigned int j;
#endif

#ifdef EE_MMI_X25519_SCALAR_MULTIPLY
    memset(sums, 0, sizeof(sums));
    for (i = 0; i < 10; ++i)
        for (j = 0; j < 10; ++j) {
            unsigned int k = (i + j) % 10;
            unsigned int coef = (i + j >= 10 ? 19U : 1U)
                              * ((i & j & 1U) ? 2U : 1U);
            for (lane = 0; lane < 4; ++lane)
                sums[k][lane] += (uint64_t)a->x[i][lane]
                                               * b->x[j][lane] * coef;
        }
#else
    uint32_t scaled[40][4] __attribute__((aligned(16)));
    for (i = 0; i < 10; ++i)
        for (lane = 0; lane < 4; ++lane) {
            uint32_t v = b->x[i][lane];
            scaled[i][lane] = v;
            scaled[i+10][lane] = 2U * v;
            scaled[i+20][lane] = 19U * v;
            /* 38*g is used only when both limb indexes are odd.
             * Even limbs could exceed 2^31 when multiplied by 38;
             * keeping their unused entries zero avoids creating
             * non-word-values for the EE PMADDUW operand table. */
            scaled[i+30][lane] = (i & 1U) ? 38U * v : 0U;
        }
#ifdef EE_MMI_X25519_FUSED_REDUCE
    ossl_ee_x25519_mul_reduce4(out->x,a->x,scaled);
#else
    ossl_ee_x25519_mul_sums4(sums, a->x, scaled);
#endif
    /* Best-effort explicit wiping of key-dependent scratch values. */
    {
        volatile unsigned char *p = (volatile unsigned char *)scaled;
        size_t n;
        for (n = 0; n < sizeof(scaled); ++n) p[n] = 0;
    }
#endif
#ifndef EE_MMI_X25519_FUSED_REDUCE
    fe_reduce(out, sums);
    {
        volatile unsigned char *p = (volatile unsigned char *)sums;
        size_t n;
        for (n = 0; n < sizeof(sums); ++n) p[n] = 0;
    }
#endif
}
static void fe_square(ee_fe4 *out, const ee_fe4 *a)
{
    fe_mul(out, a, a);
}
static void fe_mul121665(ee_fe4 *out, const ee_fe4 *a)
{
    uint64_t t[10][4];
    unsigned int i, lane;
    for (i = 0; i < 10; ++i)
        for (lane = 0; lane < 4; ++lane)
            t[i][lane] = (uint64_t)a->x[i][lane] * 121665U;
    fe_reduce(out, t);
}

/* Decode the 255-bit u-coordinate as alternating 26/25-bit limbs.
 * RFC 7748 masks the most significant input bit. Values >=p are
 * allowed, and become equivalent to their residues modulo p. */
static void fe_frombytes(ee_fe4 *out, const unsigned char in[4][32])
{
    unsigned int i, lane, bit=0, j;
    for (i = 0; i < 10; ++i) {
        for (lane = 0; lane < 4; ++lane) {
            uint32_t v = 0;
            for (j = 0; j < bits_at(i); ++j) {
                unsigned int pos = bit + j;
                v |= (uint32_t)((in[lane][pos >> 3] >>
                                     (pos & 7)) & 1U) << j;
            }
            out->x[i][lane] = v;
        }
        bit += bits_at(i);
    }
}

/* Serialize normalized limbs and conditionally subtract p = 2^255-19.
 * Avoid signed arithmetic and branches on secret field values. */
static void fe_tobytes(unsigned char out[4][32], const ee_fe4 *input)
{
    unsigned int lane, i, j, bitpos;
    for (lane = 0; lane < 4; ++lane) {
        uint32_t h[10];
        uint64_t q, carry;
        uint32_t mask;
        for (i = 0; i < 10; ++i) h[i] = input->x[i][lane];
        q = ((uint64_t)h[0] + 19) >> 26;
        for (i = 1; i < 10; ++i)
            q = ((uint64_t)h[i] + q) >> bits_at(i);
        mask = 0U - (uint32_t)q;
        /* Convert h to canonical representative by h+19 and carrying
         * only when q=1, reducing 2^255 to zero. */
        carry = (uint64_t)h[0] + (19U & mask);
        h[0] = (uint32_t)(carry & mask_at(0));
        carry >>= 26;
        for (i = 1; i < 10; ++i) {
            carry += h[i];
            h[i] = (uint32_t)(carry & mask_at(i));
            carry >>= bits_at(i);
        }
        memset(out[lane], 0, 32);
        bitpos = 0;
        for (i = 0; i < 10; ++i)
            for (j = 0; j < bits_at(i); ++j, ++bitpos)
                out[lane][bitpos >> 3] |=
                    (unsigned char)(((h[i] >> j) & 1U)
                                      << (bitpos & 7));
    }
}

/* The fixed p-2 inversion addition chain used in OpenSSL's reference
 * curve25519 code: 254 squares and 11 (non-square) multiplies,
 * instead of 254 squares plus roughly 250 multiplies for binary
 * square-and-multiply. All loop counts are public constants.
 */
static void fe_invert(ee_fe4 *out, const ee_fe4 *z)
{
    ee_fe4 t0, t1, t2, t3;
    unsigned int i;
    fe_square(&t0, z);                  /* z^2 */
    fe_square(&t1, &t0);                /* z^4 */
    fe_square(&t1, &t1);                /* z^8 */
    fe_mul(&t1, &t1, z);                /* z^9 */
    fe_mul(&t0, &t0, &t1);              /* z^11 */
    fe_square(&t2, &t0);                /* z^22 */
    fe_mul(&t1, &t1, &t2);              /* z^(2^5-1) */

    fe_square(&t2, &t1);
    for (i = 1; i < 5; ++i) fe_square(&t2, &t2);
    fe_mul(&t1, &t1, &t2);              /* z^(2^10-1) */

    fe_square(&t2, &t1);
    for (i = 1; i < 10; ++i) fe_square(&t2, &t2);
    fe_mul(&t2, &t2, &t1);              /* z^(2^20-1) */

    fe_square(&t3, &t2);
    for (i = 1; i < 20; ++i) fe_square(&t3, &t3);
    fe_mul(&t2, &t3, &t2);              /* z^(2^40-1) */

    for (i = 0; i < 10; ++i) fe_square(&t2, &t2);
    fe_mul(&t1, &t2, &t1);              /* z^(2^50-1) */

    fe_square(&t2, &t1);
    for (i = 1; i < 50; ++i) fe_square(&t2, &t2);
    fe_mul(&t2, &t2, &t1);              /* z^(2^100-1) */

    fe_square(&t3, &t2);
    for (i = 1; i < 100; ++i) fe_square(&t3, &t3);
    fe_mul(&t2, &t3, &t2);              /* z^(2^200-1) */

    for (i = 0; i < 50; ++i) fe_square(&t2, &t2);
    fe_mul(&t1, &t2, &t1);              /* z^(2^250-1) */

    for (i = 0; i < 5; ++i) fe_square(&t1, &t1);
    fe_mul(out, &t1, &t0);             /* z^(2^255-21) */

    /* Clear inversion temporaries containing the secret ladder state. */
    {
        volatile unsigned char *p;
        size_t n;
#define EE_WIPE_INV(obj) do {                                  \
        p = (volatile unsigned char *)&(obj);                  \
        for (n = 0; n < sizeof(obj); ++n) p[n] = 0;            \
    } while (0)
        EE_WIPE_INV(t0); EE_WIPE_INV(t1); EE_WIPE_INV(t2);
        EE_WIPE_INV(t3);
#undef EE_WIPE_INV
    }
}

int ossl_ee_x25519_scalar_mult4(unsigned char out[4][32],
                                const unsigned char scalar[4][32],
                                const unsigned char point[4][32])
{
    ee_fe4 x1, x2, z2, x3, z3, a, aa, b, bb, e, c, d, da, cb, t0, t1;
    unsigned char ekey[4][32];
    uint32_t swap[4]={0,0,0,0}, bit[4];
    int pos;
    unsigned int lane;

    if (out == NULL || scalar == NULL || point == NULL)
        return 0;

    memcpy(ekey, scalar, sizeof(ekey));
    for (lane = 0; lane < 4; ++lane) {
        ekey[lane][0] &= 248U;
        ekey[lane][31] &= 127U;
        ekey[lane][31] |= 64U;
    }

    fe_frombytes(&x1, point);
    fe_one(&x2);
    fe_zero(&z2);
    fe_copy(&x3, &x1);
    fe_one(&z3);

    for (pos = 254; pos >= 0; --pos) {
        for (lane = 0; lane < 4; ++lane) {
            bit[lane] = ((uint32_t)ekey[lane][pos >> 3]
                         >> (pos & 7)) & 1U;
            swap[lane] ^= bit[lane];
        }
        fe_cswap(&x2, &x3, swap);
        fe_cswap(&z2, &z3, swap);
        for (lane = 0; lane < 4; ++lane)
            swap[lane] = bit[lane];

        /* RFC 7748 Montgomery ladder */
        fe_add(&a, &x2, &z2);
        fe_square(&aa, &a);
        fe_sub(&b, &x2, &z2);
        fe_square(&bb, &b);
        fe_sub(&e, &aa, &bb);
        fe_add(&c, &x3, &z3);
        fe_sub(&d, &x3, &z3);
        fe_mul(&da, &d, &a);
        fe_mul(&cb, &c, &b);
        fe_add(&t0, &da, &cb);
        fe_square(&x3, &t0);
        fe_sub(&t0, &da, &cb);
        fe_square(&t1, &t0);
        fe_mul(&z3, &x1, &t1);
        fe_mul(&x2, &aa, &bb);
        fe_mul121665(&t1, &e);
        fe_add(&t0, &aa, &t1);
        fe_mul(&z2, &e, &t0);
    }

    fe_cswap(&x2, &x3, swap);
    fe_cswap(&z2, &z3, swap);
    fe_invert(&t0, &z2);
    fe_mul(&t1, &x2, &t0);
    fe_tobytes(out, &t1);

    /* Wipe the secret ladder states (best effort, compiler-resistant). */
    {
        volatile unsigned char *p = (volatile unsigned char *)&x1;
        size_t n;
        /* The FE structs live at separate stack addresses, so each
         * must be cleared individually. */
#define EE_WIPE(obj) do {                                      \
        p=(volatile unsigned char *)&(obj);                    \
        for (n=0; n<sizeof(obj); ++n) p[n]=0;                   \
    } while (0)
        EE_WIPE(x1); EE_WIPE(x2); EE_WIPE(z2); EE_WIPE(x3);
        EE_WIPE(z3); EE_WIPE(a); EE_WIPE(aa); EE_WIPE(b);
        EE_WIPE(bb); EE_WIPE(e); EE_WIPE(c); EE_WIPE(d);
        EE_WIPE(da); EE_WIPE(cb); EE_WIPE(t0); EE_WIPE(t1);
        EE_WIPE(ekey); EE_WIPE(swap); EE_WIPE(bit);
#undef EE_WIPE
    }
    return 1;
}
