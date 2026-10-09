/*
 * Experimental PS2 EE Montgomery multiplication with 32-bit limbs.
 * Copyright 2026 openssl-retro contributors. Apache License 2.0.
 *
 * CIOS (coarsely integrated operand scanning) REDC, using the EE
 * PMULTUW two-product helper when EE_MMI_BN_SCALAR_MUL is not defined.
 *
 * Deliberately not enabled as OpenSSL's default bn_mul_mont. Compile
 * with -DOPENSSL_BN_ASM_MONT to opt into the bn_mont.c fast path after
 * the real EE ABI and tests are verified.
 */
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include "crypto/ee_bn_mont.h"

#if UINT_MAX != 0xffffffffU
# error "EE Montgomery primitive requires 32-bit unsigned int"
#endif

/* EE platform's OpenSSL BN_ULONG must also have 32 bits. */
#if defined(OPENSSL_BN_ASM_MONT) && !defined(EE_MMI_BN_STANDALONE)
# include "bn_local.h"
typedef char ossl_ee_bn_ulong_must_be_32_bits[(sizeof(BN_ULONG) == 4) ? 1 : -1];
#endif

static void ee_mont_wipe(void *ptr, size_t len)
{
    volatile unsigned char *p = (volatile unsigned char *)ptr;
    size_t i;
    for (i = 0; i < len; ++i)
        p[i] = 0;
}

static void ee_mont_multiply2(uint64_t product[2],
                             uint32_t x[4], uint32_t y[4])
{
#ifdef EE_MMI_BN_SCALAR_MUL
    product[0] = (uint64_t)x[0] * y[0];
    product[1] = (uint64_t)x[1] * y[1];
#else
    ossl_ee_bn_mul2(product, x, y);
#endif
}

int ossl_ee_bn_mont32(uint32_t *out, const uint32_t *a,
                       const uint32_t *b, const uint32_t *mod,
                       uint32_t n0, size_t num)
{
    uint32_t t[OSSL_EE_BN_MONT_MAX_WORDS + 2] = {0};
    uint32_t diff[OSSL_EE_BN_MONT_MAX_WORDS];
    uint32_t x[4] __attribute__((aligned(16))) = {0};
    uint32_t y[4] __attribute__((aligned(16))) = {0};
    uint64_t product[2] __attribute__((aligned(16))) = {0};
    uint32_t low_borrow, choose_t, mask;
    size_t i, j, k;

    if (out == NULL || a == NULL || b == NULL || mod == NULL
        || num == 0 || num > OSSL_EE_BN_MONT_MAX_WORDS
        || (mod[0] & 1U) == 0
        || (uint32_t)(mod[0] * n0) != UINT32_MAX)
        return 0;

    for (i = 0; i < num; ++i) {
        uint64_t carry = 0, z;
        uint32_t q;

        /* Add a * b[i] to the low num words of the accumulator. */
        y[0] = y[1] = b[i];
        for (j = 0; j < num; j += 2) {
            x[0] = a[j];
            x[1] = j + 1 < num ? a[j + 1] : 0;
            ee_mont_multiply2(product, x, y);
            for (k = 0; k < 2 && j + k < num; ++k) {
                z = (uint64_t)t[j + k] + product[k] + carry;
                t[j + k] = (uint32_t)z;
                carry = z >> 32;
            }
        }
        z = (uint64_t)t[num] + carry;
        t[num] = (uint32_t)z;
        t[num + 1] += (uint32_t)(z >> 32);

        /* q cancels the low limb, since mod[0]*n0 == -1 mod 2^32.
         * Add q*mod and divide by 2^32 in the same pass. */
        q = (uint32_t)(t[0] * n0);
        carry = 0;
        y[0] = y[1] = q;
        for (j = 0; j < num; j += 2) {
            x[0] = mod[j];
            x[1] = j + 1 < num ? mod[j + 1] : 0;
            ee_mont_multiply2(product, x, y);
            for (k = 0; k < 2 && j + k < num; ++k) {
                z = (uint64_t)t[j + k] + product[k] + carry;
                if (j + k != 0)
                    t[j + k - 1] = (uint32_t)z;
                carry = z >> 32;
            }
        }
        z = (uint64_t)t[num] + carry;
        t[num - 1] = (uint32_t)z;
        t[num] = t[num + 1] + (uint32_t)(z >> 32);
        t[num + 1] = 0;
    }

    /* One conditional subtraction. For canonical reduced inputs,
     * t is < 2*mod, and t[num] is at most 1. Subtract into a
     * separate buffer to support out aliasing a/b and constant-time
     * selection. No secret-dependent branches or memory addresses. */
    low_borrow = 0;
    for (i = 0; i < num; ++i) {
        uint64_t subtrahend = (uint64_t)mod[i] + low_borrow;
        uint64_t word = t[i];
        diff[i] = (uint32_t)(word - subtrahend);
        low_borrow = (uint32_t)(word < subtrahend);
    }
    choose_t = ((uint32_t)(t[num] == 0)) & low_borrow;
    mask = 0U - choose_t;
    for (i = 0; i < num; ++i)
        out[i] = (t[i] & mask) | (diff[i] & ~mask);

    ee_mont_wipe(t, sizeof(t));
    ee_mont_wipe(diff, sizeof(diff));
    ee_mont_wipe(x, sizeof(x));
    ee_mont_wipe(y, sizeof(y));
    ee_mont_wipe(product, sizeof(product));
    return 1;
}

/* OpenSSL opt-in (never supplied to the default no-asm build).
 * OPENSSL_BN_ASM_MONT must be explicitly defined at Configure time:
 * it enables bn_mont.c's existing fast-path dispatch and this symbol.
 * Unsupported bit widths and lengths cause bn_mont.c to use its
 * existing generic fallback after bn_mul_mont returns zero.
 */
#if defined(OPENSSL_BN_ASM_MONT) && !defined(EE_MMI_BN_STANDALONE)
int bn_mul_mont(BN_ULONG *rp, const BN_ULONG *ap, const BN_ULONG *bp,
                const BN_ULONG *np, const BN_ULONG *n0, int num)
{
    if (n0 == NULL || num <= 0)
        return 0;
    return ossl_ee_bn_mont32((uint32_t *)rp, (const uint32_t *)ap,
                              (const uint32_t *)bp, (const uint32_t *)np,
                              (uint32_t)n0[0], (size_t)num);
}
#endif
