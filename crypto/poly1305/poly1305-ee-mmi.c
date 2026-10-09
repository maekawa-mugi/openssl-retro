/*
 * Copyright 2026 openssl-retro contributors. Licensed under Apache-2.0.
 *
 * EXPERIMENTAL Poly1305 authentication of four independent messages.
 * One-shot only: 4 equal-length messages, each with its own one-time key.
 *
 * R5900 MMI PADDW absorbs blocks in four parallel lanes. The default
 * exact radix-2^26 multiplication uses PEXTLW/PEXTUW + PMULTUW for
 * 2x32->64-bit packed integer products; carry/reduction remains scalar.
 * No floating point or secret-dependent data-indexing is used.
 *
 * This is not yet an EVP MAC/ChaCha20-Poly1305 acceleration.
 * Benchmark against the unmodified OpenSSL scalar path on EE hardware.
 */
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "crypto/ee_mmi.h"

#if UINT_MAX != 0xffffffffU
# error "EE Poly1305 requires 32-bit unsigned int"
#endif

#if defined(EE_MMI_POLY1305_FUSED_MADD) && \
    defined(EE_MMI_POLY1305_SCALAR_MULTIPLY)
# error "Select exactly one Poly1305 multiplication backend"
#endif

#define LIMB_MASK 0x3ffffffU

static uint32_t load32_le(const unsigned char *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void save32_le(unsigned char *p, uint32_t value)
{
    p[0] = (unsigned char)value;
    p[1] = (unsigned char)(value >> 8);
    p[2] = (unsigned char)(value >> 16);
    p[3] = (unsigned char)(value >> 24);
}

/* Each output limb is computed by exact 64-bit products. Feed all
 * code paths through the same scalar carry/reduction, making MMI-vs-C
 * differential testing sensitive to product/sign/packing errors. */
static void fold_reduce(uint32_t h[5][4], unsigned int lane,
                        uint64_t d0, uint64_t d1, uint64_t d2,
                        uint64_t d3, uint64_t d4)
{
    uint32_t a0, a1, a2, a3, a4, carry;
    carry = (uint32_t)(d0 >> 26); a0 = (uint32_t)d0 & LIMB_MASK;
    d1 += carry;
    carry = (uint32_t)(d1 >> 26); a1 = (uint32_t)d1 & LIMB_MASK;
    d2 += carry;
    carry = (uint32_t)(d2 >> 26); a2 = (uint32_t)d2 & LIMB_MASK;
    d3 += carry;
    carry = (uint32_t)(d3 >> 26); a3 = (uint32_t)d3 & LIMB_MASK;
    d4 += carry;
    carry = (uint32_t)(d4 >> 26); a4 = (uint32_t)d4 & LIMB_MASK;
    a0 += carry * 5;
    carry = a0 >> 26; a0 &= LIMB_MASK; a1 += carry;

    h[0][lane] = a0; h[1][lane] = a1; h[2][lane] = a2;
    h[3][lane] = a3; h[4][lane] = a4;
}

/* Fixed-size volatile wipe for temporary products of key-dependent state. */
static void poly_wipe(void *ptr, size_t len)
{
    volatile unsigned char *p = (volatile unsigned char *)ptr;
    size_t i;
    for (i = 0; i < len; ++i)
        p[i] = 0;
}

/* Called after PADDW block absorption, h is word-major, r is lane-major.
 * EE_MMI_POLY1305_SCALAR_MULTIPLY is an exact scalar A/B benchmark mode.
 * By default the EE build uses independent PEXTLW/PEXTUW+PMULTUW
 * terms; EE_MMI_POLY1305_FUSED_MADD enables the fused accumulator. */
static void multiply_reduce(uint32_t h[5][4],
#ifdef EE_MMI_POLY1305_SCALAR_MULTIPLY
                            const uint32_t r[4][5]
#else
                            const uint32_t scale_r[10][4]
#endif
                            )
{
    unsigned int lane;
#ifdef EE_MMI_POLY1305_SCALAR_MULTIPLY
    for (lane = 0; lane < 4; ++lane) {
        uint32_t a0 = h[0][lane], a1 = h[1][lane];
        uint32_t a2 = h[2][lane], a3 = h[3][lane], a4 = h[4][lane];
        uint32_t r0 = r[lane][0], r1 = r[lane][1], r2 = r[lane][2];
        uint32_t r3 = r[lane][3], r4 = r[lane][4];
        uint32_t s1 = r1 * 5, s2 = r2 * 5, s3 = r3 * 5, s4 = r4 * 5;
        uint64_t d0 = (uint64_t)a0*r0 + (uint64_t)a1*s4
                    + (uint64_t)a2*s3 + (uint64_t)a3*s2
                    + (uint64_t)a4*s1;
        uint64_t d1 = (uint64_t)a0*r1 + (uint64_t)a1*r0
                    + (uint64_t)a2*s4 + (uint64_t)a3*s3
                    + (uint64_t)a4*s2;
        uint64_t d2 = (uint64_t)a0*r2 + (uint64_t)a1*r1
                    + (uint64_t)a2*r0 + (uint64_t)a3*s4
                    + (uint64_t)a4*s3;
        uint64_t d3 = (uint64_t)a0*r3 + (uint64_t)a1*r2
                    + (uint64_t)a2*r1 + (uint64_t)a3*r0
                    + (uint64_t)a4*s4;
        uint64_t d4 = (uint64_t)a0*r4 + (uint64_t)a1*r3
                    + (uint64_t)a2*r2 + (uint64_t)a3*r1
                    + (uint64_t)a4*r0;
        fold_reduce(h, lane, d0, d1, d2, d3, d4);
    }
#else
    /* scale_r is constructed only once during Poly1305 key setup and
     * reused unchanged across all message blocks. */

    /* All packed operands are < 2^31, making their zero high word a
     * valid sign-extension for the R5900 word-value instructions. */
#ifdef EE_MMI_POLY1305_FUSED_MADD
    {
        /* Fused PMULTUW+PMADDUW exact 64-bit accumulation in HI/LO.
         * Only five output limbs per stream are materialized: 160 bytes. */
        uint64_t sums[5][4] __attribute__((aligned(16)));

        ossl_ee_poly1305_sums4(sums, h, scale_r);
        for (lane = 0; lane < 4; ++lane)
            fold_reduce(h, lane, sums[0][lane], sums[1][lane],
                        sums[2][lane], sums[3][lane], sums[4][lane]);
        poly_wipe(sums, sizeof(sums));
    }
#else
    {
        /* Baseline: individual PMULTUW terms in an 800-byte matrix.
         * This remains available as a hardware differential oracle. */
        uint64_t products[5][5][4] __attribute__((aligned(16)));
        unsigned int k, i;

        ossl_ee_poly1305_products4(products, h, scale_r);

        for (lane = 0; lane < 4; ++lane) {
            uint64_t d[5] = {0, 0, 0, 0, 0};
            for (k = 0; k < 5; ++k)
                for (i = 0; i < 5; ++i)
                    d[k] += products[k][i][lane];
            fold_reduce(h, lane, d[0], d[1], d[2], d[3], d[4]);
            poly_wipe(d, sizeof(d));
        }
        poly_wipe(products, sizeof(products));
    }
#endif
#endif
}

/* Canonical reduction and one-time-pad addition, based on radix 2^26.
 * g = h + 5 - 2^130; when nonnegative select g, else select h.
 * No conditional branch on the Poly1305 state. */
static void emit_tag(unsigned char tag[16], uint32_t h[5][4],
                     unsigned int lane, const unsigned char *pad)
{
    uint32_t a0=h[0][lane],a1=h[1][lane],a2=h[2][lane];
    uint32_t a3=h[3][lane],a4=h[4][lane],carry;
    uint32_t g0,g1,g2,g3,g4,mask;
    uint64_t f;

    carry = a1 >> 26; a1 &= LIMB_MASK; a2 += carry;
    carry = a2 >> 26; a2 &= LIMB_MASK; a3 += carry;
    carry = a3 >> 26; a3 &= LIMB_MASK; a4 += carry;
    carry = a4 >> 26; a4 &= LIMB_MASK; a0 += carry * 5;
    carry = a0 >> 26; a0 &= LIMB_MASK; a1 += carry;

    g0 = a0 + 5; carry = g0 >> 26; g0 &= LIMB_MASK;
    g1 = a1 + carry; carry = g1 >> 26; g1 &= LIMB_MASK;
    g2 = a2 + carry; carry = g2 >> 26; g2 &= LIMB_MASK;
    g3 = a3 + carry; carry = g3 >> 26; g3 &= LIMB_MASK;
    g4 = a4 + carry - (1U << 26);

    mask = (g4 >> 31) - 1U;
    a0 = (a0 & ~mask) | (g0 & mask);
    a1 = (a1 & ~mask) | (g1 & mask);
    a2 = (a2 & ~mask) | (g2 & mask);
    a3 = (a3 & ~mask) | (g3 & mask);
    a4 = (a4 & ~mask) | (g4 & mask);

    /* Compose 128 output bits, add the key's 128-bit s modulo 2^128. */
    f = (uint64_t)(a0 | (a1 << 26)) + load32_le(pad);
    save32_le(tag, (uint32_t)f);
    f = (uint64_t)((a1 >> 6) | (a2 << 20))
      + load32_le(pad + 4) + (f >> 32);
    save32_le(tag + 4, (uint32_t)f);
    f = (uint64_t)((a2 >> 12) | (a3 << 14))
      + load32_le(pad + 8) + (f >> 32);
    save32_le(tag + 8, (uint32_t)f);
    f = (uint64_t)((a3 >> 18) | (a4 << 8))
      + load32_le(pad + 12) + (f >> 32);
    save32_le(tag + 12, (uint32_t)f);
}

int ossl_ee_poly1305_auth4(unsigned char tags[4][16],
                            const unsigned char *const msgs[4], size_t len,
                            const unsigned char keys[4][32])
{
    uint32_t h[5][4] __attribute__((aligned(16))) = {{0}};
    uint32_t m[5][4] __attribute__((aligned(16)));
    uint32_t r[4][5];
#ifndef EE_MMI_POLY1305_SCALAR_MULTIPLY
    uint32_t scale_r[10][4] __attribute__((aligned(16)));
#endif
    unsigned char last[16];
    size_t offset=0, size, lane;
    unsigned int i;

    if (tags == NULL || msgs == NULL || keys == NULL)
        return 0;
    for (lane=0; lane<4; ++lane)
        if (len != 0 && msgs[lane] == NULL)
            return 0;

    for (lane=0; lane<4; ++lane) {
        const unsigned char *k = keys[lane];
        r[lane][0] = load32_le(k + 0) & 0x3ffffffU;
        r[lane][1] = (load32_le(k + 3) >> 2) & 0x3ffff03U;
        r[lane][2] = (load32_le(k + 6) >> 4) & 0x3ffc0ffU;
        r[lane][3] = (load32_le(k + 9) >> 6) & 0x3f03fffU;
        r[lane][4] = (load32_le(k + 12) >> 8) & 0x00fffffU;
    }

#ifndef EE_MMI_POLY1305_SCALAR_MULTIPLY
    /* Key-derived multiplication operands are invariant per message.
     * Keep them word-major and 16-byte aligned for EE LQ loads. */
    {
        unsigned int word;
        for (word = 0; word < 5; ++word)
            for (lane = 0; lane < 4; ++lane) {
                scale_r[word][lane] = r[lane][word];
                scale_r[word + 5][lane] = 5U * r[lane][word];
            }
    }
#endif

    while (offset < len) {
        size = len - offset < 16 ? len - offset : 16;
        for (lane=0; lane<4; ++lane) {
            const unsigned char *p = msgs[lane] + offset;
            if (size == 16) {
                m[0][lane] = load32_le(p + 0) & LIMB_MASK;
                m[1][lane] = (load32_le(p + 3) >> 2) & LIMB_MASK;
                m[2][lane] = (load32_le(p + 6) >> 4) & LIMB_MASK;
                m[3][lane] = (load32_le(p + 9) >> 6) & LIMB_MASK;
                m[4][lane] = (load32_le(p + 12) >> 8) | (1U << 24);
            } else {
                memset(last, 0, sizeof(last));
                memcpy(last, p, size);
                last[size] = 1;
                m[0][lane] = load32_le(last + 0) & LIMB_MASK;
                m[1][lane] = (load32_le(last + 3) >> 2) & LIMB_MASK;
                m[2][lane] = (load32_le(last + 6) >> 4) & LIMB_MASK;
                m[3][lane] = (load32_le(last + 9) >> 6) & LIMB_MASK;
                m[4][lane] = (load32_le(last + 12) >> 8);
            }
        }
#ifdef EE_MMI_POLY1305_SCALAR_ABSORB
        /* A/B performance baseline: same algorithm, no MMI PADDW. */
        {
            unsigned int word, stream;
            for (word = 0; word < 5; ++word)
                for (stream = 0; stream < 4; ++stream)
                    h[word][stream] += m[word][stream];
        }
#else
        ossl_ee_poly1305_add4(h, m);
#endif
#ifdef EE_MMI_POLY1305_SCALAR_MULTIPLY
        multiply_reduce(h, r);
#else
        multiply_reduce(h, scale_r);
#endif
        offset += size;
    }

    for (i=0; i<4; ++i)
        emit_tag(tags[i], h, i, keys[i] + 16);

    /* Wipe key-dependent and partially filled temporary buffers. */
    poly_wipe(h, sizeof(h));
    poly_wipe(r, sizeof(r));
#ifndef EE_MMI_POLY1305_SCALAR_MULTIPLY
    poly_wipe(scale_r, sizeof(scale_r));
#endif
    poly_wipe(m, sizeof(m));
    poly_wipe(last, sizeof(last));
    return 1;
}
