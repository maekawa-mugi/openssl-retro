/*
 * Copyright 2026 The openssl-retro contributors. All Rights Reserved.
 * Licensed under the Apache License 2.0; see LICENSE.txt.
 *
 * R5900 MMI four-block ChaCha20 path. MMI processes four independent
 * 32-bit state words per register, one word from each ChaCha20 block.
 * The assembly transform operates only on aligned internal state.
 * All external input/output can be byte-aligned and may be in-place.
 */
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "crypto/chacha.h"

#if UINT_MAX != 0xffffffffU
# error "EE ChaCha20 requires 32-bit unsigned int"
#endif

/*
 * state[word][lane] is a 16-byte MMI vector. The assembler runs exactly
 * 20 ChaCha rounds, without feed-forward, and modifies the state in place.
 */
extern void ossl_chacha20_ee_mmi_4way(uint32_t state[16][4]);

static const uint32_t chacha_constants[4] = {
    0x61707865U, 0x3320646eU, 0x79622d32U, 0x6b206574U
};

static void chacha20_ee_four(unsigned char *out, const unsigned char *in,
                            const unsigned int key[8],
                            const unsigned int counter[4])
{
    uint32_t state[16][4] __attribute__((aligned(16)));
    uint32_t original[16][4];
    size_t word, lane, byte;

    for (word = 0; word < 16; ++word) {
        for (lane = 0; lane < 4; ++lane) {
            uint32_t value;
            if (word < 4)
                value = chacha_constants[word];
            else if (word < 12)
                value = key[word - 4];
            else if (word == 12)
                value = (uint32_t)counter[0] + (uint32_t)lane;
            else
                value = counter[word - 12];
            state[word][lane] = original[word][lane] = value;
        }
    }

    ossl_chacha20_ee_mmi_4way(state);

    /* Bytewise XOR handles unaligned and in-place buffers without
     * native-endian assumptions or unaligned 128-bit external loads. */
    for (lane = 0; lane < 4; ++lane) {
        for (word = 0; word < 16; ++word) {
            uint32_t stream_word = state[word][lane] + original[word][lane];
            size_t offset = 64 * lane + 4 * word;
            for (byte = 0; byte < 4; ++byte)
                out[offset + byte] = in[offset + byte]
                                   ^ (unsigned char)(stream_word >> (8 * byte));
        }
    }
    /* No secret-dependent table lookup or branch. */
}

void ChaCha20_ctr32(unsigned char *out, const unsigned char *in, size_t len,
                    const unsigned int key[8], const unsigned int counter[4])
{
    unsigned int next_counter[4];
    size_t lane_blocks = 0;

    while (len >= 256) {
        next_counter[0] = (unsigned int)((uint32_t)counter[0]
                                        + (uint32_t)lane_blocks);
        next_counter[1] = counter[1];
        next_counter[2] = counter[2];
        next_counter[3] = counter[3];
        chacha20_ee_four(out, in, key, next_counter);
        out += 256;
        in += 256;
        len -= 256;
        lane_blocks += 4;
    }

    if (len != 0) {
        next_counter[0] = (unsigned int)((uint32_t)counter[0]
                                        + (uint32_t)lane_blocks);
        next_counter[1] = counter[1];
        next_counter[2] = counter[2];
        next_counter[3] = counter[3];
        ChaCha20_ctr32_c(out, in, len, key, next_counter);
    }
}
