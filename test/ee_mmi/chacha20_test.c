/*
 * Copyright 2026 The openssl-retro contributors. All Rights Reserved.
 * Licensed under the Apache License 2.0; see LICENSE.txt.
 *
 * Standalone differential test for the EE MMI ChaCha20 backend.
 *
 * PS2: link against EEMMI libcrypto.a (real MMI instructions execute).
 * Host: compile with EE_MMI_HOST_TEST and chacha-ee-mmi.c. The 4-way
 * assembly core is then replaced by a portable emulator. The host run
 * checks dispatcher/state layout/edge cases, NOT MMI instruction timing
 * or EE assembler/ABI correctness.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define MAX_TEST_LEN 4096
#define GUARD 32

void ChaCha20_ctr32(unsigned char *, const unsigned char *, size_t,
                    const unsigned int[8], const unsigned int[4]);

static uint32_t seed = 0xc001d00dU;

static uint32_t rng32(void)
{
    seed ^= seed << 13;
    seed ^= seed >> 17;
    seed ^= seed << 5;
    return seed;
}

static uint32_t rol(uint32_t value, unsigned int shift)
{
    return (value << shift) | (value >> (32 - shift));
}

static void scalar_rounds(uint32_t x[16])
{
    unsigned int round;
#define QR(a, b, c, d) do {       \
        x[a] += x[b];             \
        x[d] = rol(x[d] ^ x[a], 16); \
        x[c] += x[d];             \
        x[b] = rol(x[b] ^ x[c], 12); \
        x[a] += x[b];             \
        x[d] = rol(x[d] ^ x[a], 8);  \
        x[c] += x[d];             \
        x[b] = rol(x[b] ^ x[c], 7);  \
    } while (0)
    for (round = 0; round < 10; ++round) {
        QR(0, 4, 8, 12);
        QR(1, 5, 9, 13);
        QR(2, 6, 10, 14);
        QR(3, 7, 11, 15);
        QR(0, 5, 10, 15);
        QR(1, 6, 11, 12);
        QR(2, 7, 8, 13);
        QR(3, 4, 9, 14);
    }
#undef QR
}

static void reference_ctr32(unsigned char *out, const unsigned char *in,
                            size_t len, const unsigned int key[8],
                            const unsigned int counter[4])
{
    static const uint32_t constants[4] = {
        0x61707865U, 0x3320646eU, 0x79622d32U, 0x6b206574U
    };
    uint32_t input[16], x[16];
    size_t i, count;

    for (i = 0; i < 4; ++i)
        input[i] = constants[i];
    for (i = 0; i < 8; ++i)
        input[i + 4] = key[i];
    for (i = 0; i < 4; ++i)
        input[i + 12] = counter[i];

    while (len > 0) {
        count = len > 64 ? 64 : len;
        memcpy(x, input, sizeof(x));
        scalar_rounds(x);
        for (i = 0; i < count; ++i) {
            uint32_t word = x[i / 4] + input[i / 4];
            out[i] = in[i] ^ (unsigned char)(word >> (8 * (i % 4)));
        }
        in += count;
        out += count;
        len -= count;
        input[12]++; /* CTR32 deliberately does not carry into nonce. */
    }
}

#if defined(EE_MMI_STANDALONE) && defined(EE_MMI_HOST_TEST)
# error "Select exactly one EE MMI test build mode"
#endif

#ifdef EE_MMI_HOST_TEST
/* Host-only logical emulator of the 16 vector-register ChaCha core. */
void ossl_chacha20_ee_mmi_4way(uint32_t state[16][4])
{
    uint32_t lane_state[16];
    size_t lane, i;
    for (lane = 0; lane < 4; ++lane) {
        for (i = 0; i < 16; ++i)
            lane_state[i] = state[i][lane];
        scalar_rounds(lane_state);
        for (i = 0; i < 16; ++i)
            state[i][lane] = lane_state[i];
    }
}

#endif

/*
 * The standalone EE build intentionally avoids linking the entire OpenSSL
 * tree. Both standalone modes provide the tail symbol that the production
 * backend obtains from chacha_enc.c. Full libcrypto builds do not compile
 * this definition.
 */
#if defined(EE_MMI_HOST_TEST) || defined(EE_MMI_STANDALONE)
void ChaCha20_ctr32_c(unsigned char *out, const unsigned char *in,
                      size_t len, const unsigned int key[8],
                      const unsigned int counter[4])
{
    reference_ctr32(out, in, len, key, counter);
}
#endif

static int case_test(size_t len, size_t in_offset, size_t out_offset,
                     int inplace, uint32_t low_counter)
{
    unsigned char input[MAX_TEST_LEN + GUARD];
    unsigned char output[MAX_TEST_LEN + GUARD];
    unsigned char expected[MAX_TEST_LEN + GUARD];
    unsigned int key[8], counter[4], original_key[8], original_counter[4];
    unsigned char original_input[MAX_TEST_LEN + GUARD];
    size_t i;

    if (len > MAX_TEST_LEN || in_offset >= GUARD || out_offset >= GUARD)
        return 0;

    for (i = 0; i < 8; ++i)
        key[i] = rng32();
    counter[0] = low_counter;
    counter[1] = rng32();
    counter[2] = rng32();
    counter[3] = rng32();
    memcpy(original_key, key, sizeof(key));
    memcpy(original_counter, counter, sizeof(counter));

    memset(input, 0x3c, sizeof(input));
    memset(output, 0xa5, sizeof(output));
    memset(expected, 0xa5, sizeof(expected));
    for (i = 0; i < len; ++i)
        input[in_offset + i] = (unsigned char)rng32();
    memcpy(original_input, input, sizeof(input));

    reference_ctr32(expected + out_offset, input + in_offset,
                    len, key, counter);
    if (inplace) {
        memcpy(output + out_offset, input + in_offset, len);
        ChaCha20_ctr32(output + out_offset, output + out_offset,
                       len, key, counter);
    } else {
        ChaCha20_ctr32(output + out_offset, input + in_offset,
                       len, key, counter);
    }

    if (memcmp(input, original_input, sizeof(input)) != 0
            || memcmp(key, original_key, sizeof(key)) != 0
            || memcmp(counter, original_counter, sizeof(counter)) != 0) {
        fprintf(stderr, "FAIL: input or key/counter modified\n");
        return 0;
    }

    if (memcmp(output, expected, sizeof(output)) != 0) {
        fprintf(stderr,
                "FAIL: len=%lu in_off=%lu out_off=%lu inplace=%d ctr=%08lx\n",
                (unsigned long)len, (unsigned long)in_offset,
                (unsigned long)out_offset, inplace, (unsigned long)low_counter);
        return 0;
    }
    return 1;
}

static int rfc8439_test(void)
{
    static const unsigned char expected[64] = {
        0x10,0xf1,0xe7,0xe4,0xd1,0x3b,0x59,0x15,
        0x50,0x0f,0xdd,0x1f,0xa3,0x20,0x71,0xc4,
        0xc7,0xd1,0xf4,0xc7,0x33,0xc0,0x68,0x03,
        0x04,0x22,0xaa,0x9a,0xc3,0xd4,0x6c,0x4e,
        0xd2,0x82,0x64,0x46,0x07,0x9f,0xaa,0x09,
        0x14,0xc2,0xd7,0x05,0xd9,0x8b,0x02,0xa2,
        0xb5,0x12,0x9c,0xd1,0xde,0x16,0x4e,0xb9,
        0xcb,0xd0,0x83,0xe8,0xa2,0x50,0x3c,0x4e
    };
    unsigned int key[8] = {
        0x03020100U,0x07060504U,0x0b0a0908U,0x0f0e0d0cU,
        0x13121110U,0x17161514U,0x1b1a1918U,0x1f1e1d1cU
    };
    unsigned int counter[4] = {
        1U, 0x09000000U, 0x4a000000U, 0x00000000U
    };
    unsigned char zero[256] = {0}, output[256] = {0};
    ChaCha20_ctr32(output, zero, sizeof(output), key, counter);
    if (memcmp(output, expected, sizeof(expected)) != 0) {
        fprintf(stderr, "FAIL: RFC 8439 section 2.3.2 block vector\n");
        return 0;
    }
    return 1;
}


/* A split call at a 64-byte boundary must equal one contiguous call.
 * Splitting elsewhere is intentionally not equivalent to ChaCha20_ctr32:
 * each independent invocation begins at a fresh 64-byte block. */
static int split_call_test(void)
{
    static const size_t splits[] = {64, 256, 512, 1024};
    unsigned char input[1536], expected[1536], actual[1536];
    unsigned int key[8], counter[4], next[4];
    size_t i, j;
    for (i = 0; i < 8; ++i)
        key[i] = rng32();
    for (i = 0; i < 4; ++i)
        counter[i] = rng32();
    counter[0] = 0xfffffffeU;
    for (i = 0; i < sizeof(input); ++i)
        input[i] = (unsigned char)rng32();

    ChaCha20_ctr32(expected, input, sizeof(input), key, counter);
    for (j = 0; j < sizeof(splits)/sizeof(splits[0]); ++j) {
        size_t first = splits[j];
        memcpy(next, counter, sizeof(next));
        next[0] += (unsigned int)(first / 64);
        memset(actual, 0, sizeof(actual));
        ChaCha20_ctr32(actual, input, first, key, counter);
        ChaCha20_ctr32(actual + first, input + first,
                       sizeof(input) - first, key, next);
        if (memcmp(actual, expected, sizeof(actual)) != 0) {
            fprintf(stderr, "FAIL: split call boundary %lu\n",
                    (unsigned long)first);
            return 0;
        }
    }
    return 1;
}

static void benchmark(void)
{
    static const size_t sizes[] = {64, 256, 1024, 4096};
    unsigned char input[MAX_TEST_LEN], output[MAX_TEST_LEN];
    unsigned int key[8] = {0}, counter[4] = {0};
    unsigned int repeat, pass;
    size_t n;
    clock_t start, end;
    double elapsed[2], throughput;
    volatile unsigned char checksum = 0;

    memset(input, 0x5a, sizeof(input));
    for (n = 0; n < sizeof(sizes)/sizeof(sizes[0]); ++n) {
        unsigned int runs = sizes[n] < 1024 ? 512 : 256;
        for (pass = 0; pass < 2; ++pass) {
            start = clock();
            for (repeat = 0; repeat < runs; ++repeat) {
                if (pass == 0)
                    reference_ctr32(output, input, sizes[n], key, counter);
                else
                    ChaCha20_ctr32(output, input, sizes[n], key, counter);
                checksum ^= output[repeat % sizes[n]];
            }
            end = clock();
            if (start == (clock_t)-1 || end == (clock_t)-1 || end <= start) {
                printf("Benchmark timer unavailable (correctness remains valid)\n");
                return;
            }
            elapsed[pass] = (double)(end - start) / CLOCKS_PER_SEC;
        }
        throughput = (double)(sizes[n] * runs) / (1048576.0 * elapsed[1]);
        printf("%4lu bytes: scalar=%.4fs MMI=%.4fs "
               "MMI=%.2f MiB/s ratio=%.2fx\n",
               (unsigned long)sizes[n], elapsed[0], elapsed[1],
               throughput, elapsed[0] / elapsed[1]);
    }
    printf("Benchmark checksum=%u (timing includes call/dispatcher overhead)\n",
           (unsigned int)checksum);
}

int main(int argc, char **argv)
{
    static const size_t lengths[] = {
        0,1,31,63,64,65,127,128,191,192,255,256,257,319,
        511,512,513,768,769,1024,1536,4096
    };
    static const size_t offsets[] = {0,1,3,7,15};
    static const uint32_t counters[] = {
        0U, 0xfffffffcU, 0xffffffffU
    };
    size_t i, j, k;
    int inplace, count = 0;

    if (!rfc8439_test() || !split_call_test())
        return EXIT_FAILURE;

    for (i = 0; i < sizeof(lengths)/sizeof(lengths[0]); ++i)
        for (j = 0; j < sizeof(offsets)/sizeof(offsets[0]); ++j)
            for (k = 0; k < sizeof(counters)/sizeof(counters[0]); ++k)
                for (inplace = 0; inplace < 2; ++inplace) {
                    if (!case_test(lengths[i], offsets[j],
                                   offsets[(j + 2) % 5], inplace, counters[k]))
                        return EXIT_FAILURE;
                    ++count;
                }

    for (i = 0; i < 128; ++i) {
        size_t len = rng32() % (MAX_TEST_LEN + 1);
        if (!case_test(len, rng32() % 16, rng32() % 16,
                       (int)(rng32() & 1U), rng32()))
            return EXIT_FAILURE;
        ++count;
    }

    printf("PASS: RFC 8439 and %d ChaCha20 differential/guard cases\n", count);
#ifdef EE_MMI_HOST_TEST
    printf("HOST EMULATION ONLY: R5900 MMI assembly/ABI not exercised\n");
#elif defined(EE_MMI_STANDALONE)
    printf("EE MMI STANDALONE: directly linked C+R5900 MMI assembly\n");
#else
    printf("EE MMI libcrypto backend: independent scalar reference\n");
#endif
    if (argc > 1 && strcmp(argv[1], "--bench") == 0)
        benchmark();
    return EXIT_SUCCESS;
}
