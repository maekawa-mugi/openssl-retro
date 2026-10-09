/*
 * Experimental four-stream constant-address window GHASH over GF(2^128).
 * Copyright 2026 openssl-retro contributors. Apache License 2.0.
 *
 * Radix 16 (4-bit) and radix 256 (8-bit split into two 4-bit
 * masked lookups) use an identical fixed-scan R5900 MMI PCEQW/PAND/
 * PXOR kernel to combine the four independent stream results.
 * This is NOT a secret-indexed table lookup: EVERY 16-entry table
 * row is read, in order, regardless of ciphertext/key material.
 *
 * The 8-bit variant uses two 16-entry tables, not a 16KiB 256-entry
 * table, to keep EE stack footprint bounded.
 *
 * This alternative defines ossl_ee_ghash_mul4 and MUST replace,
 * not supplement, ghash-ee-mmi.S in the selected A build.
 */
#include <stddef.h>
#include <stdint.h>

#ifndef EE_MMI_GHASH_WINDOW_BITS
# error "Select EE_MMI_GHASH_WINDOW_BITS=4 or 8 for window GHASH"
#endif
#if EE_MMI_GHASH_WINDOW_BITS != 4 && EE_MMI_GHASH_WINDOW_BITS != 8
# error "Unsupported window width"
#endif

/* t[entry][word][lane], 16-byte aligned across packed EE words. */
typedef uint32_t ee_window_table[16][4][4];

static void ee_wipe_window(void *v, size_t n)
{
    volatile unsigned char *p = (volatile unsigned char *)v;
    while (n-- != 0)
        *p++ = 0;
}
static void ee_shift_right1(uint32_t v[4][4])
{
    unsigned int lane;
    for (lane = 0; lane < 4; ++lane) {
        uint32_t red = 0U - (v[3][lane] & 1U);
        v[3][lane] = (v[3][lane] >> 1) | (v[2][lane] << 31);
        v[2][lane] = (v[2][lane] >> 1) | (v[1][lane] << 31);
        v[1][lane] = (v[1][lane] >> 1) | (v[0][lane] << 31);
        v[0][lane] = (v[0][lane] >> 1) ^ (red & 0xe1000000U);
    }
}
static void ee_shift_n(uint32_t v[4][4], unsigned int bits)
{
    unsigned int i;
    for (i = 0; i < bits; ++i)
        ee_shift_right1(v);
}

#if defined(EE_MMI_GHASH_WINDOW_HOST)
static void ossl_ee_ghash_window_xor4(uint32_t z[4][4],
                                       const ee_window_table table,
                                       const uint32_t selector[4])
{
    unsigned int entry, lane, word;
    for (entry = 0; entry < 16; ++entry)
        for (lane = 0; lane < 4; ++lane) {
            uint32_t mask = 0U - (uint32_t)(selector[lane] == entry);
            for (word = 0; word < 4; ++word)
                z[word][lane] ^= table[entry][word][lane] & mask;
        }
}
#else
void ossl_ee_ghash_window_xor4(uint32_t z[4][4],
                               const ee_window_table table,
                               const uint32_t selector[4]);
#endif

static void ee_make_table(ee_window_table table,
                           const uint32_t basis[8][4][4],
                           unsigned int start)
{
    unsigned int idx, bit, lane, word;
    for (idx = 0; idx < 16; ++idx)
        for (word = 0; word < 4; ++word)
            for (lane = 0; lane < 4; ++lane) {
                uint32_t v = 0;
                for (bit = 0; bit < 4; ++bit) {
                    /* The index is PUBLIC; also expressed as
                     * a mask to keep table construction uniform. */
                    uint32_t mask =
                        0U - ((idx >> (3 - bit)) & 1U);
                    v ^= basis[start + bit][word][lane] & mask;
                }
                table[idx][word][lane] = v;
            }
}

void ossl_ee_ghash_mul4(uint32_t out[4][4],
                         const uint32_t x[4][4],
                         const uint32_t h[4][4])
{
    uint32_t basis[8][4][4] __attribute__((aligned(16))) = {{{0}}};
    ee_window_table high __attribute__((aligned(16)));
#if EE_MMI_GHASH_WINDOW_BITS == 8
    ee_window_table low __attribute__((aligned(16)));
#endif
    uint32_t state[4][4] __attribute__((aligned(16))) = {{0}};
    uint32_t selector[4] __attribute__((aligned(16)));
    unsigned int lane, word, step;
    int group;

    for (word = 0; word < 4; ++word)
        for (lane = 0; lane < 4; ++lane)
            basis[0][word][lane] = h[word][lane];
    for (step = 1; step < EE_MMI_GHASH_WINDOW_BITS; ++step) {
        for (word = 0; word < 4; ++word)
            for (lane = 0; lane < 4; ++lane)
                basis[step][word][lane] =
                    basis[step - 1][word][lane];
        ee_shift_right1(basis[step]);
    }
    ee_make_table(high, basis, 0);
#if EE_MMI_GHASH_WINDOW_BITS == 8
    ee_make_table(low, basis, 4);
    /* Reverse Horner order: least significant byte first, with
     * shift-right eight between the accumulated contributions. */
    for (group = 15; group >= 0; --group) {
        unsigned int xi = (unsigned int)group >> 2;
        unsigned int shift = (3U - ((unsigned int)group & 3U)) * 8U;
        ee_shift_n(state, 8);
        for (lane = 0; lane < 4; ++lane)
            selector[lane] = (x[xi][lane] >> (shift + 4U)) & 15U;
        ossl_ee_ghash_window_xor4(state, high, selector);
        for (lane = 0; lane < 4; ++lane)
            selector[lane] = (x[xi][lane] >> shift) & 15U;
        ossl_ee_ghash_window_xor4(state, low, selector);
    }
#else
    /* Same GHASH field multiplication in radix 16:
     * z <- T^4(z) XOR sum_{bit=0..3}(bit* T^bit(H)).
     * Nibble index depends on data, but all table accesses are
     * constant-address scans performed by the EE MMI assembly. */
    for (group = 31; group >= 0; --group) {
        unsigned int xi = (unsigned int)group >> 3;
        unsigned int shift = (7U - ((unsigned int)group & 7U)) * 4U;
        ee_shift_n(state, 4);
        for (lane = 0; lane < 4; ++lane)
            selector[lane] = (x[xi][lane] >> shift) & 15U;
        ossl_ee_ghash_window_xor4(state, high, selector);
    }
#endif
    for (word = 0; word < 4; ++word)
        for (lane = 0; lane < 4; ++lane)
            out[word][lane] = state[word][lane];
    ee_wipe_window(basis, sizeof(basis));
    ee_wipe_window(high, sizeof(high));
#if EE_MMI_GHASH_WINDOW_BITS == 8
    ee_wipe_window(low, sizeof(low));
#endif
    ee_wipe_window(state, sizeof(state));
    ee_wipe_window(selector, sizeof(selector));
}
