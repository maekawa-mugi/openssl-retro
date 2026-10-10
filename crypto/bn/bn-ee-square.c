/*
 * Experimental Montgomery square for the prepared public RSA benchmark.
 * Copyright 2026 openssl-retro contributors. Apache License 2.0.
 * Symmetric Comba product followed by the register-only MMI REDC row.
 * No default OpenSSL dispatch. Canonical inputs are caller preconditions.
 */
#include <stddef.h>
#include <stdint.h>
#include "crypto/ee_bn_mont.h"

static void square_wipe(void *ptr, size_t bytes)
{
    volatile unsigned char *p = (volatile unsigned char *)ptr;
    while (bytes-- != 0)
        *p++ = 0;
}

int ossl_ee_bn_mont_sqr32(uint32_t *out, const uint32_t *a,
                          const uint32_t *mod, uint32_t n0, size_t num)
{
    uint32_t t[2 * OSSL_EE_BN_MONT_MAX_WORDS + 2];
    uint32_t diff[OSSL_EE_BN_MONT_MAX_WORDS];
    uint64_t low = 0;
    uint32_t high = 0, borrow = 0, mask;
    size_t k, i, j;

    if (out == NULL || a == NULL || mod == NULL || num == 0
        || num > OSSL_EE_BN_MONT_MAX_WORDS || (mod[0] & 1U) == 0
        || (uint32_t)(mod[0] * n0) != UINT32_MAX)
        return 0;

    /* Accumulator is 96 bits. Doubling each cross term via two additions
     * avoids overflowing a 64-bit product; at most num terms per column.
     * Diagonal/cross decisions depend only on public column indices. */
    for (k = 0; k < 2 * num - 1; ++k) {
        size_t first = k < num ? 0 : k + 1 - num;
        for (i = first; i <= k / 2; ++i) {
            uint64_t product, previous;
            j = k - i;
            product = (uint64_t)a[i] * a[j];
            previous = low;
            low += product;
            high += (uint32_t)(low < previous);
            if (i != j) {
                previous = low;
                low += product;
                high += (uint32_t)(low < previous);
            }
        }
        t[k] = (uint32_t)low;
        low = (low >> 32) | ((uint64_t)high << 32);
        high = 0;
    }
    t[2 * num - 1] = (uint32_t)low;
    t[2 * num] = (uint32_t)(low >> 32);
    t[2 * num + 1] = 0;

    for (i = 0; i < num; ++i) {
        uint32_t q = (uint32_t)(t[i] * n0);
        uint64_t carry = ossl_ee_bn_muladd_row_mmi(t + i, mod, q, num);
        /* Fixed public bounds also propagate a carry through all higher
         * words. The canceled low words are never read again. */
        for (j = i + num; j < 2 * num + 2; ++j) {
            uint64_t z = (uint64_t)t[j] + carry;
            t[j] = (uint32_t)z;
            carry = z >> 32;
        }
    }
    for (i = 0; i < num; ++i) {
        uint64_t word = t[num + i];
        uint64_t subtrahend = (uint64_t)mod[i] + borrow;
        diff[i] = (uint32_t)(word - subtrahend);
        borrow = (uint32_t)(word < subtrahend);
    }
    /* REDC(a^2) < 2*mod, hence one subtraction suffices. */
    mask = 0U - ((uint32_t)(t[2 * num] == 0) & borrow);
    for (i = 0; i < num; ++i)
        out[i] = (t[num + i] & mask) | (diff[i] & ~mask);
    square_wipe(t, (2 * num + 2) * sizeof(t[0]));
    square_wipe(diff, num * sizeof(diff[0]));
    return 1;
}
