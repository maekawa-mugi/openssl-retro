/*
 * Experimental PS2 EE BIGNUM Montgomery kernel differential test.
 * Copyright 2026 openssl-retro contributors. Apache License 2.0.
 *
 * Host builds emulate the exact two-product interface using C.
 * Hardware builds link crypto/bn/bn-ee-mmi.S and test PMULTUW.
 * The reference is independent schoolbook multiplication + REDC
 * over a 2n+2-word array; production uses integrated CIOS.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "crypto/ee_bn_mont.h"

#define MAXN OSSL_EE_BN_MONT_MAX_WORDS

static uint32_t rng_state = 0x5900bee5U;
static unsigned long case_count;

static uint32_t rand32(void)
{
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 17;
    rng_state ^= rng_state << 5;
    return rng_state;
}

#ifdef EE_MMI_BN_HOST_TEST
void ossl_ee_bn_mul2(uint64_t out[2], const uint32_t x[4],
                      const uint32_t y[4])
{
    out[0] = (uint64_t)x[0] * y[0];
    out[1] = (uint64_t)x[1] * y[1];
}
#endif

static uint32_t neg_inv32(uint32_t n)
{
    uint32_t inverse = 1U;
    unsigned int k;
    for (k = 0; k < 5; ++k)
        inverse *= 2U - n * inverse;
    return 0U - inverse;
}

static int ref_mont32(uint32_t *out, const uint32_t *a,
                      const uint32_t *b, const uint32_t *n,
                      uint32_t n0, size_t count)
{
    uint32_t t[2*MAXN+2] = {0}, diff[MAXN];
    uint32_t borrow = 0, mask, choose_t;
    size_t i,j;

    /* Independent schoolbook multiplication across 2n words. */
    for (i = 0; i < count; ++i) {
        uint64_t carry = 0, z;
        for (j = 0; j < count; ++j) {
            z = (uint64_t)a[j] * b[i] + t[i+j] + carry;
            t[i+j] = (uint32_t)z;
            carry = z >> 32;
        }
        for (j = i+count; j <= 2*count+1; ++j) {
            z = (uint64_t)t[j] + carry;
            t[j] = (uint32_t)z;
            carry = z >> 32;
        }
    }

    /* Plain REDC on the unshifted full product. */
    for (i = 0; i < count; ++i) {
        uint64_t carry = 0, z;
        uint32_t m = t[i] * n0;
        for (j = 0; j < count; ++j) {
            z = (uint64_t)m * n[j] + t[i+j] + carry;
            t[i+j] = (uint32_t)z;
            carry = z >> 32;
        }
        if (t[i] != 0)
            return 0;
        for (j = i+count; j <= 2*count+1; ++j) {
            z = (uint64_t)t[j] + carry;
            t[j] = (uint32_t)z;
            carry = z >> 32;
        }
    }

    /* REDC quotient < 2*n, so one branchless subtraction suffices.
     * For reference purposes carry propagation is intentionally
     * implemented differently from the integrated CIOS kernel. */
    for (i = 0; i < count; ++i) {
        uint64_t d = (uint64_t)n[i] + borrow;
        uint64_t a0 = t[count+i];
        diff[i] = (uint32_t)(a0 - d);
        borrow = (uint32_t)(a0 < d);
    }
    choose_t = ((t[2*count] | t[2*count+1]) == 0U) & borrow;
    mask = 0U - choose_t;
    for (i = 0; i < count; ++i)
        out[i] = (t[count+i] & mask) | (diff[i] & ~mask);
    return 1;
}

static int compare_case(const uint32_t *a, const uint32_t *b,
                        const uint32_t *n, size_t num,
                        const char *label, unsigned int repeat)
{
    uint32_t candidate[MAXN+4], expected[MAXN], scratch[MAXN];
    uint32_t n0 = neg_inv32(n[0]);
    size_t i;

    for (i = 0; i < MAXN+4; ++i)
        candidate[i] = 0x8a3e5c7dU;
    if (!ref_mont32(expected, a, b, n, n0, num)
        || !ossl_ee_bn_mont32(candidate+2, a, b, n, n0, num)) {
        fprintf(stderr, "FAIL: backend failure %s size=%lu iter=%u\n",
                label, (unsigned long)num, repeat);
        return 0;
    }
    if (candidate[0] != 0x8a3e5c7dU || candidate[1] != 0x8a3e5c7dU
        || candidate[num+2] != 0x8a3e5c7dU
        || candidate[num+3] != 0x8a3e5c7dU
        || memcmp(candidate+2, expected, num*sizeof(uint32_t)) != 0) {
        fprintf(stderr, "FAIL: difference/guard %s size=%lu iter=%u\n",
                label, (unsigned long)num, repeat);
        return 0;
    }
    /* out may alias a or b. */
    memcpy(scratch, a, num*sizeof(uint32_t));
    if (!ossl_ee_bn_mont32(scratch, scratch, b, n, n0, num)
        || memcmp(scratch, expected, num*sizeof(uint32_t)) != 0) {
        fprintf(stderr, "FAIL: alias-a %s size=%lu iter=%u\n",
                label, (unsigned long)num, repeat);
        return 0;
    }
    memcpy(scratch, b, num*sizeof(uint32_t));
    if (!ossl_ee_bn_mont32(scratch, a, scratch, n, n0, num)
        || memcmp(scratch, expected, num*sizeof(uint32_t)) != 0) {
        fprintf(stderr, "FAIL: alias-b %s size=%lu iter=%u\n",
                label, (unsigned long)num, repeat);
        return 0;
    }
    ++case_count;
    return 1;
}

static int exercise_two_products(void)
{
    uint32_t x[4] __attribute__((aligned(16))) = {0};
    uint32_t y[4] __attribute__((aligned(16))) = {0};
    struct {
        uint64_t before[2], product[2], after[2];
    } __attribute__((aligned(16))) guarded;
    size_t i;

    for (i = 0; i < 512; ++i) {
        x[0] = i == 0 ? 0xffffffffU : rand32();
        x[1] = i == 0 ? 0x80000000U : rand32();
        y[0] = i == 0 ? 0xffffffffU : rand32();
        y[1] = i == 0 ? 0xffffffffU : rand32();
        guarded.before[0] = guarded.before[1] = UINT64_C(0x5a5a5a5a5a5a5a5a);
        guarded.after[0] = guarded.after[1] = UINT64_C(0x5a5a5a5a5a5a5a5a);
        ossl_ee_bn_mul2(guarded.product, x, y);
        if (guarded.product[0] != (uint64_t)x[0]*y[0]
            || guarded.product[1] != (uint64_t)x[1]*y[1]
            || guarded.before[0] != UINT64_C(0x5a5a5a5a5a5a5a5a)
            || guarded.before[1] != UINT64_C(0x5a5a5a5a5a5a5a5a)
            || guarded.after[0] != UINT64_C(0x5a5a5a5a5a5a5a5a)
            || guarded.after[1] != UINT64_C(0x5a5a5a5a5a5a5a5a)) {
            fprintf(stderr, "FAIL: unsigned 32x32->64 pair %lu\n",
                    (unsigned long)i);
            return 0;
        }
    }
    return 1;
}

static int exercise_mont(void)
{
    static const size_t sizes[] = {1,2,3,4,5,7,8,16,32,64,128};
    uint32_t a[MAXN], b[MAXN], n[MAXN], bad[2] = {2U,1U}, out[2];
    size_t t, i;
    unsigned int trial, variant;

    if (ossl_ee_bn_mont32(NULL, a, b, n, 1, 1)
        || ossl_ee_bn_mont32(out, a, b, bad, 1, 2)
        || ossl_ee_bn_mont32(out, a, b, n, 1, 0)
        || ossl_ee_bn_mont32(out, a, b, n, 1, MAXN+1))
        return 0;

    for (t = 0; t < sizeof(sizes)/sizeof(sizes[0]); ++t) {
        size_t num = sizes[t];
        for (trial = 0; trial < 40; ++trial) {
            for (i = 0; i < num; ++i) {
                n[i] = rand32();
                a[i] = rand32();
                b[i] = rand32();
            }
            n[0] |= 1U;
            n[num-1] |= 0x80000000U;
            a[num-1] &= 0x7fffffffU;
            b[num-1] &= 0x7fffffffU;

            for (variant = 0; variant < 5; ++variant) {
                if (variant == 1) {
                    memset(a, 0, num*sizeof(uint32_t));
                    memset(b, 0, num*sizeof(uint32_t));
                } else if (variant == 2) {
                    memcpy(a, n, num*sizeof(uint32_t));
                    memcpy(b, n, num*sizeof(uint32_t));
                    a[0]--; b[0]--; /* n is odd: n-1 fits */
                } else if (variant == 3) {
                    memset(a, 0, num*sizeof(uint32_t));
                    memset(b, 0, num*sizeof(uint32_t));
                    a[0] = b[0] = 1;
                } else if (variant == 4) {
                    for (i = 0; i < num; ++i) {
                        a[i] = n[i];
                        b[i] = n[i];
                    }
                    a[0]--; b[0]--;
                }
                if (!compare_case(a, b, n, num, "random/edge", trial*5+variant))
                    return 0;
            }
        }
    }
    return 1;
}

static void benchmark(void)
{
    uint32_t a[64], b[64], n[64], out[64];
    size_t i;
    unsigned int t;
    uint32_t n0;
    clock_t start, end;
    for (i = 0; i < 64; ++i) {
        n[i] = 0xffffffffU;
        a[i] = 0x7fffffffU;
        b[i] = 0x3fffffffU;
    }
    n0 = neg_inv32(n[0]);
    start = clock();
    for (t = 0; t < 16; ++t)
        ossl_ee_bn_mont32(out, a, b, n, n0, 64);
    end = clock();
    if (start < 0 || end <= start)
        puts("Montgomery bench: clock unavailable");
    else
        printf("Montgomery 2048-bit x16: %.3f sec\n",
               (double)(end-start)/CLOCKS_PER_SEC);
}

int main(int argc, char **argv)
{
    if (!exercise_two_products() || !exercise_mont())
        return EXIT_FAILURE;
    printf("PASS: EE BN Montgomery %lu differential/alias/guard cases"
           ", 512 unsigned two-product checks\n", case_count);
#ifdef EE_MMI_BN_HOST_TEST
    puts("Host emulation only: EE MMI instructions not executed");
#else
    puts("R5900 PMULTUW linked: verify on actual PlayStation 2");
#endif
    if (argc > 1 && strcmp(argv[1], "--bench") == 0)
        benchmark();
    return EXIT_SUCCESS;
}
