/*
 * NIST SP 800-38D AES-GCM vectors and 4-lane streaming regression.
 * Apache License 2.0. Tests both packed MMI and scalar baselines.
 * Host MMI emulation below does not execute R5900 instructions.
 */
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "crypto/ee_aes_gcm.h"

#ifdef EE_MMI_HOST_TEST
#ifndef EE_MMI_AES_SCALAR_ROUND
static uint8_t xtime(uint8_t x)
{
    return (uint8_t)((x << 1) ^ ((x & 0x80U) ? 0x1bU : 0U));
}
void ossl_ee_aes_mixcolumns_ark4(uint32_t s[4][4],
                                  const uint32_t rk[4][4])
{
    unsigned int w, lane, i;
    for (w = 0; w < 4; ++w)
        for (lane = 0; lane < 4; ++lane) {
            uint8_t a[4], b[4], t;
            for (i = 0; i < 4; ++i)
                a[i] = (uint8_t)(s[w][lane] >> (i*8));
            t = (uint8_t)(a[0]^a[1]^a[2]^a[3]);
            for (i = 0; i < 4; ++i)
                b[i] = (uint8_t)(a[i]^t^xtime((uint8_t)(a[i]^a[(i+1)&3])));
            s[w][lane] = rk[w][lane];
            for (i = 0; i < 4; ++i)
                s[w][lane] ^= (uint32_t)b[i] << (i*8);
        }
}
#endif
#ifndef EE_MMI_GHASH_SCALAR_MULTIPLY
void ossl_ee_ghash_mul4(uint32_t z[4][4], const uint32_t x[4][4],
                        const uint32_t h[4][4])
{
    unsigned int lane, i, w;
    for (lane = 0; lane < 4; ++lane) {
        uint32_t v[4], acc[4] = {0,0,0,0};
        for (w = 0; w < 4; ++w)
            v[w] = h[w][lane];
        for (i = 0; i < 128; ++i) {
            uint32_t mask = 0U - ((x[i >> 5][lane]
                                       >> (31 - (i & 31))) & 1U);
            uint32_t red = 0U - (v[3] & 1U);
            for (w = 0; w < 4; ++w)
                acc[w] ^= v[w] & mask;
            v[3] = (v[3] >> 1) | (v[2] << 31);
            v[2] = (v[2] >> 1) | (v[1] << 31);
            v[1] = (v[1] >> 1) | (v[0] << 31);
            v[0] = (v[0] >> 1) ^ (0xe1000000U & red);
        }
        for (w = 0; w < 4; ++w)
            z[w][lane] = acc[w];
    }
}
#endif
#endif

static int unhex(char x)
{
    if (x >= '0' && x <= '9') return x-'0';
    if (x >= 'a' && x <= 'f') return x-'a'+10;
    if (x >= 'A' && x <= 'F') return x-'A'+10;
    return -1;
}
static size_t parse_hex(unsigned char *out, size_t capacity, const char *str)
{
    size_t n = 0;
    while (*str != '\0') {
        int hi = unhex(str[0]), lo = str[1] != '\0' ? unhex(str[1]) : -1;
        if (hi < 0 || lo < 0 || n >= capacity) return SIZE_MAX;
        out[n++] = (unsigned char)((hi<<4)|lo);
        str += 2;
    }
    return n;
}
static int check_hex(const unsigned char *got, size_t n, const char *hex)
{
    size_t i;
    for (i = 0; i < n; ++i)
        if ((int)got[i] != ((unhex(hex[2*i]) << 4) | unhex(hex[2*i+1])))
            return 0;
    return hex[2*n] == '\0';
}

#define MAX_BYTES 320
static ossl_ee_aes_gcm4_key ctx;
static unsigned char data[4][MAX_BYTES], ct[4][MAX_BYTES];
static unsigned char back[4][MAX_BYTES], aadbuf[4][MAX_BYTES];
static unsigned char ivs[4][12], tags[4][16];
static const unsigned char *inputs[4], *auth[4];
static unsigned char *outputs[4];
static uint32_t seed = 0x5900cafeU;
static uint32_t rnd(void)
{
    seed ^= seed << 13;
    seed ^= seed >> 17;
    seed ^= seed << 5;
    return seed;
}

static int nist_examples(void)
{
    static const char *key0 = "00000000000000000000000000000000";
    static const char *zeroiv = "000000000000000000000000";
    static const char *ct1 = "0388dace60b6a392f328c2b971b2fe78";
    static const char *tag0 = "58e2fccefa7e3061367f1d57a4e7455a";
    static const char *tag1 = "ab6e47d42cec13bdf53a67b21257bddf";
    static const char *keylong = "feffe9928665731c6d6a8f9467308308";
    static const char *ivlong = "cafebabefacedbaddecaf888";
    static const char *aadlong = "feedfacedeadbeeffeedfacedeadbeefabaddad2";
    static const char *ptlong =
        "d9313225f88406e5a55909c5aff5269a"
        "86a7a9531534f7da2e4c303d8a318a72"
        "1c3c0c95956809532fcf0e2449a6b525"
        "b16aedf5aa0de657ba637b391aafd255";
    static const char *ctlong =
        "42831ec2217774244b7221b784d0d49c"
        "e3aa212f2c02a4e035c17e2329aca12e"
        "21d514b25466931c7d8f6a5aac84aa05"
        "1ba30b396a0aac973d58e091";
    static const char *taglong = "5bc94fbc3221a5db94fae95ae7121a47";
    unsigned char k[16], iv[12];
    unsigned int lane;

    if (parse_hex(k, sizeof(k), key0) != 16
        || parse_hex(iv, sizeof(iv), zeroiv) != 12
        || !ossl_ee_aes_gcm4_init(&ctx, k, 128))
        return 0;
    for (lane = 0; lane < 4; ++lane) {
        memcpy(ivs[lane], iv, 12);
        inputs[lane] = data[lane];
        outputs[lane] = ct[lane];
        memset(data[lane], 0, MAX_BYTES);
    }
    if (!ossl_ee_aes_gcm4_seal(&ctx, outputs, tags, inputs, 0,
                               NULL, 0, ivs)
        || !check_hex(tags[0], 16, tag0))
        return 0;
    if (!ossl_ee_aes_gcm4_seal(&ctx, outputs, tags, inputs, 16,
                               NULL, 0, ivs)
        || !check_hex(ct[0], 16, ct1)
        || !check_hex(tags[0], 16, tag1))
        return 0;
    ossl_ee_aes_gcm4_clear(&ctx);

    if (parse_hex(k, sizeof(k), keylong) != 16
        || parse_hex(iv, sizeof(iv), ivlong) != 12
        || !ossl_ee_aes_gcm4_init(&ctx, k, 128))
        return 0;
    for (lane = 0; lane < 4; ++lane) {
        size_t a = parse_hex(aadbuf[lane], MAX_BYTES, aadlong);
        size_t p = parse_hex(data[lane], MAX_BYTES, ptlong);
        if (a != 20 || p != 64)
            return 0;
        memcpy(ivs[lane], iv, 12);
        auth[lane] = aadbuf[lane];
    }
    /* NIST 96-bit IV / 20-byte AAD / 60-byte message. */
    if (!ossl_ee_aes_gcm4_seal(&ctx, outputs, tags, inputs, 60,
                               auth, 20, ivs)
        || !check_hex(ct[0], 60, ctlong)
        || !check_hex(tags[0], 16, taglong))
        return 0;
    for (lane = 0; lane < 4; ++lane) {
        inputs[lane] = ct[lane];
        outputs[lane] = back[lane];
    }
    if (!ossl_ee_aes_gcm4_open(&ctx, outputs, tags, inputs, 60,
                               auth, 20, ivs)
        || memcmp(back[0], data[0], 60) != 0)
        return 0;
    ossl_ee_aes_gcm4_clear(&ctx);
    puts("PASS: NIST GCM empty, one block, 60-byte/AAD20");
    return 1;
}

/* Independent AES-192/256 vectors (same IV/AAD/pt generation
 * across four *distinct* nonces), generated using a separate
 * OpenSSL-compatible AEAD implementation, not this EE backend. */
static int multi_key_kat(void)
{
    static const char *tag192[4] = {
        "ff162e21cf01fe4a682c9b1742d0467c",
        "6a131ecb38ec64675685243acaa74586",
        "fd6c8cc1fd4cb9591e8c964c7246ef69",
        "bed76605dd1bc49f53ef619a27feb6b1"
    };
    static const char *tag256[4] = {
        "bfae5880f68e73188bf6ab424c5ddfb6",
        "01db965aff4bfd467a53b4e4f91e2a07",
        "1f4b84f87c03169c6639a65c07575032",
        "8f5b9187d26f8a4eafe5faf7dd743905"
    };
    static const char *cipher192 =
        "1a0b13b04fd391faacef52631f947406fe";
    static const char *cipher256 =
        "5b52c33b563c6c7a2c47911a5733abb7"
        "97c502c4e9e417d06b714e00f8cdf893"
        "53f354055402a7bf52cac676d475dc00"
        "a6f7ce802aee195bd5875c023404d58f";
    unsigned char key[32];
    unsigned int bits, lane;
    size_t i, n, a;
    for (i = 0; i < sizeof(key); ++i)
        key[i] = (unsigned char)i;
    for (bits = 192; bits <= 256; bits += 64) {
        n = bits == 192 ? 17 : 64;
        a = bits == 192 ? 7 : 20;
        if (!ossl_ee_aes_gcm4_init(&ctx, key, bits))
            return 0;
        for (lane = 0; lane < 4; ++lane) {
            for (i = 0; i < 12; ++i)
                ivs[lane][i] = (unsigned char)(7*i + 19*lane + 3);
            for (i = 0; i < n; ++i)
                data[lane][i] = (unsigned char)(5*i + 11*lane + 1);
            for (i = 0; i < a; ++i)
                aadbuf[lane][i] = (unsigned char)(9*i + 29*lane + 17);
            inputs[lane] = data[lane];
            outputs[lane] = ct[lane];
            auth[lane] = aadbuf[lane];
        }
        if (!ossl_ee_aes_gcm4_seal(&ctx, outputs, tags, inputs, n,
                                    auth, a, ivs)
            || !check_hex(ct[0], n, bits == 192 ? cipher192 : cipher256))
            return 0;
        for (lane = 0; lane < 4; ++lane)
            if (!check_hex(tags[lane], 16,
                           bits == 192 ? tag192[lane] : tag256[lane]))
                return 0;
        for (lane = 0; lane < 4; ++lane) {
            inputs[lane] = ct[lane];
            outputs[lane] = back[lane];
        }
        if (!ossl_ee_aes_gcm4_open(&ctx, outputs, tags, inputs, n,
                                    auth, a, ivs))
            return 0;
        for (lane = 0; lane < 4; ++lane)
            if (memcmp(back[lane], data[lane], n) != 0)
                return 0;
        ossl_ee_aes_gcm4_clear(&ctx);
    }
    puts("PASS: AES-192/256 independent four-nonce ciphertext/tag vectors");
    return 1;
}

static int random_regression(void)
{
#ifdef EE_MMI_STANDALONE
    /* Keep complete KATs on EE, but bound full randomized checks so
     * the PS2 console A/B correctness gate remains practical. */
    static const size_t lengths[] = {0,1,16,17,60};
    static const size_t aadlens[] = {0,1,20};
#else
    static const size_t lengths[] =
        {0,1,15,16,17,31,32,60,63,64,65,127,128,255,256};
    static const size_t aadlens[] = {0,1,15,16,17,20,32};
#endif
    unsigned char key[32], tagcopy[4][16], original[4][MAX_BYTES];
    unsigned int lane, bit;
    size_t i,j,n,m;
    for (bit = 128; bit <= 256; bit += 64) {
        for (i = 0; i < sizeof(key); ++i) key[i] = (unsigned char)rnd();
        if (!ossl_ee_aes_gcm4_init(&ctx, key, bit)) return 0;
        for (i = 0; i < sizeof(lengths)/sizeof(lengths[0]); ++i) {
            n = lengths[i];
            for (j = 0; j < sizeof(aadlens)/sizeof(aadlens[0]); ++j) {
                m = aadlens[j];
                for (lane = 0; lane < 4; ++lane) {
                    size_t k;
                    for (k = 0; k < MAX_BYTES; ++k) {
                        data[lane][k] = (unsigned char)rnd();
                        aadbuf[lane][k] = (unsigned char)rnd();
                    }
                    for (k = 0; k < 12; ++k)
                        ivs[lane][k] = (unsigned char)rnd();
                    inputs[lane] = data[lane];
                    outputs[lane] = ct[lane];
                    auth[lane] = aadbuf[lane];
                }
                if (!ossl_ee_aes_gcm4_seal(&ctx, outputs, tags,
                                            inputs, n, auth, m, ivs))
                    return 0;
                memcpy(tagcopy, tags, sizeof(tags));
                for (lane = 0; lane < 4; ++lane) {
                    inputs[lane] = ct[lane];
                    outputs[lane] = back[lane];
                    memset(back[lane], 0xa5, MAX_BYTES);
                }
                if (!ossl_ee_aes_gcm4_open(&ctx, outputs, tags, inputs,
                                            n, auth, m, ivs))
                    return 0;
                for (lane = 0; lane < 4; ++lane)
                    if (memcmp(back[lane], data[lane], n) != 0
                        || (n < MAX_BYTES && back[lane][n] != 0xa5))
                        return 0;

                /* One bad tag invalidates the entire four-lane batch.
                 * There must be NO plaintext released to any lane. */
                tags[1][7] ^= 1;
                memset(back, 0x5c, sizeof(back));
                if (ossl_ee_aes_gcm4_open(&ctx, outputs, tags, inputs,
                                           n, auth, m, ivs))
                    return 0;
                for (lane = 0; lane < 4; ++lane)
                    for (size_t k = 0; k < MAX_BYTES; ++k)
                        if (back[lane][k] != 0x5c) return 0;
                memcpy(tags, tagcopy, sizeof(tags));

                /* A different IV or ciphertext must also fail tag
                 * verification without releasing any plaintext. */
                if (j == 0) {
                    ivs[2][3] ^= 1;
                    if (ossl_ee_aes_gcm4_open(&ctx, outputs, tags,
                                               inputs, n, auth, m, ivs))
                        return 0;
                    ivs[2][3] ^= 1;
                    if (n != 0) {
                        ct[3][0] ^= 1;
                        if (ossl_ee_aes_gcm4_open(&ctx, outputs, tags,
                                                   inputs, n, auth, m, ivs))
                            return 0;
                        ct[3][0] ^= 1;
                    }
                }

                /* Authentication includes all AAD (also partial). */
                if (m != 0) {
                    aadbuf[2][m-1] ^= 1;
                    if (ossl_ee_aes_gcm4_open(&ctx, outputs, tags, inputs,
                                               n, auth, m, ivs))
                        return 0;
                    aadbuf[2][m-1] ^= 1;
                }

                /* In-place decryption only after full verification. */
                for (lane = 0; lane < 4; ++lane) {
                    memcpy(original[lane], ct[lane], n);
                    outputs[lane] = ct[lane];
                    inputs[lane] = ct[lane];
                }
                if (!ossl_ee_aes_gcm4_open(&ctx, outputs, tags, inputs,
                                            n, auth, m, ivs))
                    return 0;
                for (lane = 0; lane < 4; ++lane)
                    if (memcmp(ct[lane], data[lane], n) != 0)
                        return 0;
                /* In-place encryption for the same plaintext. */
                if (!ossl_ee_aes_gcm4_seal(&ctx, outputs, tags,
                                            inputs, n, auth, m, ivs))
                    return 0;
                for (lane = 0; lane < 4; ++lane)
                    if (memcmp(ct[lane], original[lane], n) != 0
                        || memcmp(tags[lane], tagcopy[lane], 16) != 0)
                        return 0;
            }
        }
        ossl_ee_aes_gcm4_clear(&ctx);
    }
    printf("PASS: %lu length/AAD/key-size cases, 4 independent IV lanes, "
           "tamper rejection and in-place roundtrips\n",
           (unsigned long)(3U * (sizeof(lengths)/sizeof(lengths[0]))
                             * (sizeof(aadlens)/sizeof(aadlens[0]))));
    return 1;
}

static int invalid_args(void)
{
    unsigned char k[16] = {0};
    const unsigned char *in4[4] = {NULL,NULL,NULL,NULL};
    unsigned char *out4[4] = {NULL,NULL,NULL,NULL};
    unsigned int lane;
    if (ossl_ee_aes_gcm4_init(&ctx, k, 160))
        return 0;
    if (!ossl_ee_aes_gcm4_init(&ctx, k, 128))
        return 0;
    memset(ivs, 0, sizeof(ivs));
    if (!ossl_ee_aes_gcm4_seal(&ctx, out4, tags, in4, 0, NULL, 0, ivs)
        || !ossl_ee_aes_gcm4_open(&ctx, out4, tags, in4, 0,
                                   NULL, 0, ivs))
        return 0;
    if (ossl_ee_aes_gcm4_seal(&ctx, out4, tags, in4, 16, NULL, 0, ivs)
        || ossl_ee_aes_gcm4_seal(&ctx, out4, tags, in4, 0, NULL, 1, ivs))
        return 0;
    for (lane = 0; lane < 4; ++lane) {
        out4[lane] = ct[lane];
        in4[lane] = data[lane];
    }
    /* On 64-bit hosts the GCM 2^32-2 block limit is representable.
     * On 32-bit PS2 size_t cannot express that many bytes. */
#if SIZE_MAX > UINT32_MAX
    if (ossl_ee_aes_gcm4_seal(&ctx, out4, tags, in4,
                               (size_t)UINT64_C(0xffffffff0),
                               NULL, 0, ivs))
        return 0;
#endif
    ossl_ee_aes_gcm4_clear(&ctx);
    return 1;
}
int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    if (!nist_examples() || !multi_key_kat() ||
        !random_regression() || !invalid_args()) {
        puts("FAIL: EE AES-GCM regression");
        return EXIT_FAILURE;
    }
#if defined(EE_MMI_HOST_TEST)
    puts("PASS: host C emulates MMI AES/GHASH kernels (no R5900 executed)");
#elif defined(EE_MMI_AES_SCALAR_ROUND)
    puts("PASS: portable AES-GCM scalar comparison build");
#else
    puts("PASS: R5900 four-stream fused AES-GCM regression");
#endif
    return EXIT_SUCCESS;
}
