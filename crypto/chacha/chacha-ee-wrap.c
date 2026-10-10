/*
 * Experimental EE four-way ChaCha wrapper: reusable input state and
 * four-byte XOR. Copyright 2026 openssl-retro contributors. Apache-2.0.
 * The round kernel is unchanged. All external buffers may be unaligned;
 * memcpy avoids alignment and strict-aliasing violations, including in-place.
 */
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "crypto/chacha.h"

#if UINT_MAX != 0xffffffffU
# error "EE ChaCha requires 32-bit unsigned int"
#endif
#if defined(__MIPSEB__) || (defined(__BYTE_ORDER__) && \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__)
# error "This experimental word XOR requires little-endian EE"
#endif

extern void ossl_chacha20_ee_mmi_4way(uint32_t state[16][4]);

void ChaCha20_ctr32(unsigned char *out, const unsigned char *in, size_t len,
                    const unsigned int key[8], const unsigned int counter[4])
{
    static const uint32_t constants[4] = {
        0x61707865U, 0x3320646eU, 0x79622d32U, 0x6b206574U
    };
    uint32_t original[16][4] __attribute__((aligned(16)));
    uint32_t state[16][4] __attribute__((aligned(16)));
    unsigned int next[4];
    size_t word, lane;

    if (len == 0)
        return;
    /* Tail-only calls retain the scalar path without setting up vectors. */
    if (len < 256) {
        ChaCha20_ctr32_c(out, in, len, key, counter);
        return;
    }
    memcpy(next, counter, sizeof(next));
    /* Key, constants and nonce are expanded once per invocation. */
    for (word = 0; word < 16; ++word) {
        uint32_t value = word < 4 ? constants[word]
                         : word < 12 ? key[word - 4]
                         : next[word - 12];
        for (lane = 0; lane < 4; ++lane)
            original[word][lane] = value;
    }
    while (len >= 256) {
        for (lane = 0; lane < 4; ++lane)
            original[12][lane] = (uint32_t)next[0] + (uint32_t)lane;
        memcpy(state, original, sizeof(state));
        ossl_chacha20_ee_mmi_4way(state);
        for (lane = 0; lane < 4; ++lane) {
            for (word = 0; word < 16; ++word) {
                uint32_t input_word;
                size_t offset = 64 * lane + 4 * word;
                memcpy(&input_word, in + offset, sizeof(input_word));
                input_word ^= state[word][lane] + original[word][lane];
                memcpy(out + offset, &input_word, sizeof(input_word));
            }
        }
        next[0] = (uint32_t)next[0] + 4U; /* CTR32 never carries into nonce. */
        in += 256;
        out += 256;
        len -= 256;
    }
    if (len != 0)
        ChaCha20_ctr32_c(out, in, len, key, next);
}
