/*
 * Copyright 2026 openssl-retro contributors. Licensed under Apache-2.0.
 * Standalone EE MMI Poly1305 tests. The golden vectors below were
 * generated independently using arbitrary precision integer arithmetic:
 *   h = ((h + message_block + (1 << (8*n))) * r) % (2^130-5)
 *   tag = (h + s) % 2^128
 * Each message has its own RFC-clamped r and one-time 128-bit pad s.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "crypto/ee_mmi.h"

#define MAX_DATA 1024
#define GUARD 16

static const size_t lengths[] = { 0, 1, 15, 16, 17, 31, 32, 33, 55, 56, 63, 64, 65, 127, 128, 129, 255, 256, 257, 511, 1024 };
static const char *golden[21][4] = {
    { "03a25c7eb475eaed1cd8ba666b2d3599", "d76d4b3da868e6d3230deea4753c81f9", "fe27dccbc3974b91833aa27fee083074", "519300bd0beb4f9ead80413a3b2d170b" },
    { "e51fc97c5813b80bd77eadd46715ee69", "1689f4c06e169cf7ce1629ed0d40d9c5", "bc80527274411df415b8851209495b00", "ba39a458b30b4655e4b8008a46be2749" },
    { "fbfb2002897993974039124e93b509b4", "efb88527cfe8ab1ae0f83b1d9ee85b06", "5e1bce82d9f877415d862e429df9809d", "818eb3a54140a68d9673f0d7a87631f2" },
    { "7b70ef0a5003e614bfd9d1384b62ddbf", "f811443e3724322eb26824467db77f27", "2b45498f1c8dc57f9d1795c2453bcd78", "249aa33b098468d5b0305274fa0a127c" },
    { "7e3ddaebd2aaa74100035f7fd1d2bc9c", "a63c2884f221b08555569f4b15eb6413", "92fe3cdd70883f7ceeeaa55702c0557b", "c3c3b093fc3b40aee5138b85d0a864ac" },
    { "b6e76691f5d9e429bb8941d19d135263", "923ce4ef4f2fa4e96c5be97d8028d0ae", "80ecf548bfdf8b9510229b7e6f76d11e", "632fdd9a2e79453f7cca5514da7ac3f0" },
    { "1a6fd0c511631fa06f8b45657388fa73", "186987b3d7169ef74cc91179bbb613b6", "03857398983e32fe63442c56cd13ffe4", "1a2364b497cac48b573c4e63288b2ff2" },
    { "a2f53114338663e372c87fc060c9113e", "4bccfe5a5abbf14091f88732fa7cd43a", "47cfc6fb934dd86f492381d87fd0af74", "3f4c01fffba4c442d24567c35d3b99c3" },
    { "73ccd91d3e20de639d4213a247e22d35", "d11ba0bd7254ce6a1049e90d895e8bcc", "631942a5ed3feb779fc7dabbdd43bd4a", "6cc5392a30306736049c2758c15bc21d" },
    { "eff2288b6b4e5ccdb89943ae4c1be247", "f95e3b246bc4bd571ea7baece3b1e0a5", "ddce5beb665f9a311f7f6cc740a4075b", "fe6e0f3209dba95b47b7031fda67d435" },
    { "42694dce9dd92a95a59c96ba4a57f0e0", "587dddbbbfe533cc5e050301b35ded84", "1f5b12b8ca17423bbbf4da6a49a74dfe", "da1c546b01efa0f9f97d06c3afe0c0b6" },
    { "41d0850d0eb64c495140030ce5b389ab", "5079cc214f0cebf3a07af2e8c38a3ac2", "9e30f4800c03eed2923e5fef0889b3bf", "8cfdced2fbacd26e83204ecff6b38c3c" },
    { "102cc2d06b9e8f3748116d86cef20934", "c07cab393c0e256dbe09726fcb46de41", "2c7268952215e63f57a3ab8315f45352", "5dad9032ca37003188a72869ea099c25" },
    { "74d1ea964279a73e6b75cc89d7f0b6c3", "7b3e320b0b73c48ce3b21c204576806e", "9c9ac130411ff679bb5d3d69cd6f1e3d", "f8807386a5805894e22b2e9a312e2224" },
    { "9bd55e14fbfe218e69335d7d729822ce", "32ae86a7b8abda73414d8f35252d3535", "9766297ca3a97c79c5571143e5ba526a", "1b632a28e384272a0e33cdbc7ac7dc8c" },
    { "2da81c1d38aeed4928a21ecbc817b0fe", "dd6132915d0739aa32b0fc5b94856e3c", "7e00cdd37facc75baa6d727f4d5054d7", "cee811aabff0f1dc8cbe2a6b8efc9d33" },
    { "ecd48f9b2bd9acfeba09203ef302121a", "f7982dc13686836127c5714fd117c8a5", "497361e0c008faabea56fefda54c4a8b", "d462097657e71d81bbd04c3c6ee30d1b" },
    { "cfc517b05bd87dcc0a6b3f4df4c5780d", "fa77283cbe4ef7e978b7501c1a534bc4", "d5f58933c788ab1aaf391610c3edbe3a", "a794e0b8226e1afb6a40275fadb1acd6" },
    { "0a5b04f36ae6f2c2574cdd11a96f783b", "1ca78ee2fdd0a11a1c090c15afa25a76", "b1775f9b7c447d08a94e3ef0be672de0", "358d7d883ea81b4ed6d3f8181671c6b5" },
    { "eea3c7a43541ddb58eaf8c58fe492a5c", "2fc5d9f92e7927593fdc6e062de96cae", "148362213f08f7ece55ab2fc93d2b314", "60e72af7b709cee53f860ddaeee8baf6" },
    { "abd68ebdfd99d5644e88ca0935b9f8a2", "c8f72ec594390aeb0550266e4c801e5d", "504482d700f24e8ae75f4f2a998d0e99", "4c270f42d6afb07b642c70dfc6fabf60" },
};

static uint32_t randstate;
static uint32_t rand32(void)
{
    randstate ^= randstate << 13;
    randstate ^= randstate >> 17;
    randstate ^= randstate << 5;
    return randstate;
}

#ifdef EE_MMI_HOST_TEST
/* Host emulation for the R5900 PADDW absorber. Not EE instructions. */
void ossl_ee_poly1305_add4(uint32_t h[5][4], const uint32_t m[5][4])
{
    unsigned int i, lane;
    for (i = 0; i < 5; ++i)
        for (lane = 0; lane < 4; ++lane)
            h[i][lane] += m[i][lane];
}

/*
 * C emulation of the packed PMULTUW product interface. This is not an
 * MMI instruction emulator and does not validate EE instruction timing.
 */
void ossl_ee_poly1305_products4(uint64_t products[5][5][4],
                                 const uint32_t a[5][4],
                                 const uint32_t b[10][4])
{
    unsigned int k, i, lane;
    for (k = 0; k < 5; ++k)
        for (i = 0; i < 5; ++i) {
            unsigned int j = (k + 5 - i) % 5 + (i > k ? 5 : 0);
            for (lane = 0; lane < 4; ++lane)
                products[k][i][lane] = (uint64_t)a[i][lane] * b[j][lane];
        }
}


/* Exact C model of PMULTUW once followed by four PMADDUW operations.
 * The target assembly accumulates within the EE HI/LO register bank;
 * this host reference deliberately uses independent uint64_t sums. */
void ossl_ee_poly1305_sums4(uint64_t sums[5][4],
                            const uint32_t a[5][4],
                            const uint32_t b[10][4])
{
    unsigned int k, i, lane;
    for (k = 0; k < 5; ++k) {
        for (lane = 0; lane < 4; ++lane)
            sums[k][lane] = 0;
        for (i = 0; i < 5; ++i) {
            unsigned int j = (k + 5 - i) % 5 + (i > k ? 5 : 0);
            for (lane = 0; lane < 4; ++lane)
                sums[k][lane] += (uint64_t)a[i][lane] * b[j][lane];
        }
    }
}
#endif

static unsigned int unhex(unsigned char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    return 99;
}
static int equals_hex(const unsigned char *tag, const char *str)
{
    unsigned int i;
    for (i = 0; i < 16; ++i)
        if (tag[i] != (unsigned char)(unhex((unsigned char)str[2*i])*16
                                  + unhex((unsigned char)str[2*i+1])))
            return 0;
    return 1;
}


#if !defined(EE_MMI_POLY1305_SCALAR_MULTIPLY) && !defined(EE_MMI_POLY1305_FUSED_MADD)
/*
 * Tests the real multiplication interface directly (without Poly1305
 * reduction), including 64-bit high halves, lane ordering and overrun
 * sentinels. The host runner executes the C interface emulator instead.
 */
static int products_check(void)
{
    struct {
        uint32_t before[4];
        uint64_t product[5][5][4];
        uint32_t after[4];
    } __attribute__((aligned(16))) buffer;
    uint32_t a[5][4] __attribute__((aligned(16)));
    uint32_t b[10][4] __attribute__((aligned(16)));
    uint32_t old_a[5][4], old_b[10][4];
    unsigned int iteration, k, i, lane, j;
    randstate = 0x79ca1305U;
    for (iteration = 0; iteration < 256; ++iteration) {
        for (i = 0; i < 5; ++i)
            for (lane = 0; lane < 4; ++lane) {
                /* Fixed seeds plus extreme 26-bit Poly1305 limbs. */
                a[i][lane] = iteration == 0 ? 0U :
                             iteration == 1 ? 0x07ffffffU :
                             rand32() & 0x07ffffffU;
                b[i][lane] = iteration == 0 ? 0U :
                             iteration == 1 ? 0x03ffffffU :
                             rand32() & 0x03ffffffU;
                b[i + 5][lane] = b[i][lane] * 5U;
            }
        memcpy(old_a, a, sizeof(a));
        memcpy(old_b, b, sizeof(b));
        memset(&buffer, 0xa5, sizeof(buffer));
        ossl_ee_poly1305_products4(buffer.product, a, b);

        for (k = 0; k < 5; ++k)
            for (i = 0; i < 5; ++i) {
                j = (k + 5 - i) % 5 + (i > k ? 5 : 0);
                for (lane = 0; lane < 4; ++lane) {
                    uint64_t expected = (uint64_t)a[i][lane] * b[j][lane];
                    if (buffer.product[k][i][lane] != expected) {
                        fprintf(stderr,
                                "FAIL: PMULTUW product[%u][%u][%u] test=%u\n",
                                k, i, lane, iteration);
                        return 0;
                    }
                }
            }
        for (i = 0; i < 4; ++i)
            if (buffer.before[i] != 0xa5a5a5a5U
                || buffer.after[i] != 0xa5a5a5a5U) {
                puts("FAIL: PMULTUW output sentinel");
                return 0;
            }
        if (memcmp(a, old_a, sizeof(a)) != 0
            || memcmp(b, old_b, sizeof(b)) != 0) {
            puts("FAIL: PMULTUW modified input operands");
            return 0;
        }
    }
    puts("PASS: PMULTUW 256 x (25 x 4) direct 64-bit product checks");
    return 1;
}
#endif

#if defined(EE_MMI_POLY1305_FUSED_MADD) && !defined(EE_MMI_POLY1305_FUSED_REDUCE)
/* This directly exercises the PMADDUW interface on target hardware,
 * separately from tag generation. 256 cases * five sums * four lanes.
 * It covers zero, maximal limbs, distinct lanes and 64-bit carry. */
static int sums_check(void)
{
    struct {
        uint32_t before[4];
        uint64_t sums[5][4];
        uint32_t after[4];
    } __attribute__((aligned(16))) buffer;
    uint32_t a[5][4] __attribute__((aligned(16)));
    uint32_t b[10][4] __attribute__((aligned(16)));
    uint32_t original_a[5][4], original_b[10][4];
    unsigned int iteration, i, k, lane;

    randstate = 0x1357abdfU;
    for (iteration = 0; iteration < 256; ++iteration) {
        for (i = 0; i < 5; ++i)
            for (lane = 0; lane < 4; ++lane) {
                a[i][lane] = iteration == 0 ? 0U
                           : iteration == 1 ? 0x07ffffffU
                           : rand32() & 0x07ffffffU;
                b[i][lane] = iteration == 0 ? 0U
                           : iteration == 1 ? 0x03ffffffU
                           : rand32() & 0x03ffffffU;
                b[i + 5][lane] = 5U * b[i][lane];
            }
        memcpy(original_a, a, sizeof(a));
        memcpy(original_b, b, sizeof(b));
        memset(&buffer, 0xa5, sizeof(buffer));

        ossl_ee_poly1305_sums4(buffer.sums, a, b);

        for (k = 0; k < 5; ++k)
            for (lane = 0; lane < 4; ++lane) {
                uint64_t expected = 0;
                for (i = 0; i < 5; ++i) {
                    unsigned int j = (k + 5 - i) % 5
                                   + (i > k ? 5 : 0);
                    expected += (uint64_t)a[i][lane] * b[j][lane];
                }
                if (buffer.sums[k][lane] != expected) {
                    fprintf(stderr,
                            "FAIL: PMADDUW sum[%u][%u] iteration=%u\n",
                            k, lane, iteration);
                    return 0;
                }
            }
        for (i = 0; i < 4; ++i)
            if (buffer.before[i] != 0xa5a5a5a5U
                || buffer.after[i] != 0xa5a5a5a5U) {
                puts("FAIL: PMADDUW sum sentinel corrupted");
                return 0;
            }
        if (memcmp(original_a, a, sizeof(a)) != 0
            || memcmp(original_b, b, sizeof(b)) != 0) {
            puts("FAIL: PMADDUW modified input");
            return 0;
        }
    }
    puts("PASS: PMADDUW 256 x (5 x 4) exact 64-bit accumulated sums");
    return 1;
}
#elif defined(EE_MMI_POLY1305_FUSED_REDUCE)
/* Test the actual reduced-output helper, not the older sums4 interface.
 * Separate output and exact in-place operation both retain guards. */
static int sums_check(void)
{
    struct {
        uint32_t before[4], h[5][4], after[4];
    } __attribute__((aligned(16))) buffer;
    uint32_t a[5][4] __attribute__((aligned(16)));
    uint32_t b[10][4] __attribute__((aligned(16)));
    uint32_t original_a[5][4], original_b[10][4], expected[5][4];
    unsigned int iteration, i, k, lane, alias;
    randstate = 0x1357abdfU;
    for (iteration = 0; iteration < 256; ++iteration) {
        for (i = 0; i < 5; ++i)
            for (lane = 0; lane < 4; ++lane) {
                a[i][lane] = iteration == 0 ? 0U : iteration == 1
                            ? 0x7ffffffU : rand32() & 0x7ffffffU;
                b[i][lane] = iteration == 0 ? 0U : iteration == 1
                            ? 0x3ffffffU : rand32() & 0x3ffffffU;
                b[i+5][lane] = 5U * b[i][lane];
            }
        memcpy(original_a, a, sizeof(a));
        memcpy(original_b, b, sizeof(b));
        for (lane = 0; lane < 4; ++lane) {
            uint64_t carry = 0;
            for (k = 0; k < 5; ++k) {
                uint64_t sum = carry;
                for (i = 0; i < 5; ++i) {
                    unsigned int j = (k + 5 - i) % 5 + (i > k ? 5 : 0);
                    sum += (uint64_t)a[i][lane] * b[j][lane];
                }
                expected[k][lane] = (uint32_t)sum & 0x3ffffffU;
                carry = sum >> 26;
            }
            carry = expected[0][lane] + carry * 5;
            expected[0][lane] = (uint32_t)carry & 0x3ffffffU;
            expected[1][lane] += (uint32_t)(carry >> 26);
        }
        for (alias = 0; alias < 2; ++alias) {
            for (i = 0; i < 4; ++i)
                buffer.before[i] = buffer.after[i] = 0xa5a5a5a5U;
            memcpy(buffer.h, a, sizeof(a));
            ossl_ee_poly1305_mul_reduce4(buffer.h, alias ? buffer.h : a, b);
            if (memcmp(buffer.h, expected, sizeof(expected)) != 0
                || memcmp(a, original_a, sizeof(a)) != 0
                || memcmp(b, original_b, sizeof(b)) != 0) {
                printf("FAIL: fused reduction iteration=%u alias=%u\n",iteration,alias);
                return 0;
            }
            for (i = 0; i < 4; ++i)
                if (buffer.before[i] != 0xa5a5a5a5U
                    || buffer.after[i] != 0xa5a5a5a5U) {
                    puts("FAIL: fused reduction sentinel corrupted");
                    return 0;
                }
        }
    }
    puts("PASS: fused reduction 512 direct carry/alias/guard cases");
    return 1;
}
#endif

static int rfc7539(void)
{
    static const char msg[] = "Cryptographic Forum Research Group";
    static const char keyhex[] =
        "85d6be7857556d337f4452fe42d506a8"
        "0103808afb0db2fd4abff6af4149f51b";
    unsigned char key[4][32];
    unsigned char out[4][16];
    const unsigned char *input[4];
    size_t lane, i;

    for (lane = 0; lane < 4; ++lane) {
        input[lane] = (const unsigned char *)msg;
        for (i = 0; i < 32; ++i)
            key[lane][i] = (unsigned char)(16*unhex(keyhex[2*i])
                                           + unhex(keyhex[2*i+1]));
    }
    if (!ossl_ee_poly1305_auth4(out, input, strlen(msg), key)) {
        puts("FAIL: RFC 7539 Poly1305 call");
        return 0;
    }
    for (lane = 0; lane < 4; ++lane)
        if (!equals_hex(out[lane], "a8061dc1305136c6c22b8baf0c0127a9")) {
            fprintf(stderr, "FAIL: RFC 7539 Poly1305 lane %lu\n",
                    (unsigned long)lane);
            return 0;
        }
    return 1;
}

static int golden_case(size_t index)
{
    unsigned char key[4][32], original_key[4][32];
    unsigned char data[4][MAX_DATA + GUARD];
    unsigned char original_data[4][MAX_DATA + GUARD];
    const unsigned char *input[4];
    struct {
        unsigned char before[16];
        unsigned char tags[4][16];
        unsigned char after[16];
    } result;
    size_t len = lengths[index], lane, i;

    randstate = 0x61707865U ^ ((uint32_t)len * 0x9e3779b9U);
    memset(data, 0xa7, sizeof(data));
    memset(&result, 0x5c, sizeof(result));
    for (lane = 0; lane < 4; ++lane) {
        size_t offset = (lane * 3 + 1) & 15;
        for (i = 0; i < 32; ++i)
            key[lane][i] = (unsigned char)rand32();
        for (i = 0; i < len; ++i)
            data[lane][offset + i] = (unsigned char)rand32();
        input[lane] = data[lane] + offset;
    }
    memcpy(original_data, data, sizeof(data));
    memcpy(original_key, key, sizeof(key));
    if (!ossl_ee_poly1305_auth4(result.tags, input, len, key)) {
        fprintf(stderr, "FAIL: Poly1305 rejected length %lu\n",
                (unsigned long)len);
        return 0;
    }
    for (lane = 0; lane < 4; ++lane)
        if (!equals_hex(result.tags[lane], golden[index][lane])) {
            fprintf(stderr, "FAIL: Poly1305 len=%lu lane=%lu\n",
                    (unsigned long)len, (unsigned long)lane);
            return 0;
        }
    for (i = 0; i < 16; ++i)
        if (result.before[i] != 0x5c || result.after[i] != 0x5c) {
            fprintf(stderr, "FAIL: Poly1305 output guard\n");
            return 0;
        }
    if (memcmp(original_data, data, sizeof(data)) != 0 ||
        memcmp(original_key, key, sizeof(key)) != 0) {
        fprintf(stderr, "FAIL: Poly1305 modified input or key\n");
        return 0;
    }
    return 1;
}

static int invalid_arguments(void)
{
    unsigned char tags[4][16];
    unsigned char keys[4][32] = {{0}};
    const unsigned char *input[4] = {NULL, NULL, NULL, NULL};
    if (!ossl_ee_poly1305_auth4(tags, input, 0, keys))
        return 0;
    if (ossl_ee_poly1305_auth4(tags, input, 1, keys))
        return 0;
    if (ossl_ee_poly1305_auth4(NULL, input, 0, keys))
        return 0;
    if (ossl_ee_poly1305_auth4(tags, NULL, 0, keys))
        return 0;
    if (ossl_ee_poly1305_auth4(tags, input, 0, NULL))
        return 0;
    return 1;
}

static void bench(void)
{
    unsigned char tags[4][16], keys[4][32] = {{0}};
    unsigned char buf[4][4096] = {{0}};
    const unsigned char *input[4];
    unsigned int i;
    clock_t start, end;
    for (i = 0; i < 4; ++i)
        input[i] = buf[i];
    start = clock();
    for (i = 0; i < 128; ++i)
        ossl_ee_poly1305_auth4(tags, input, 4096, keys);
    end = clock();
    if (start == (clock_t)-1 || end == (clock_t)-1 || end <= start)
        puts("Poly1305 benchmark: clock() unavailable");
    else
        printf("Poly1305 4x4096 x128: %.3f s, %.2f MiB/s total\n",
               (double)(end-start)/CLOCKS_PER_SEC,
               (double)(4*4096*128) * CLOCKS_PER_SEC
                  / ((double)(end-start) * 1048576.0));
}

int main(int argc, char **argv)
{
    size_t index;
    if (!rfc7539() || !invalid_arguments())
        return EXIT_FAILURE;
#ifdef EE_MMI_POLY1305_FUSED_MADD
    if (!sums_check())
        return EXIT_FAILURE;
#elif !defined(EE_MMI_POLY1305_SCALAR_MULTIPLY)
    if (!products_check())
        return EXIT_FAILURE;
#endif
    for (index = 0; index < sizeof(lengths)/sizeof(lengths[0]); ++index)
        if (!golden_case(index))
            return EXIT_FAILURE;
    printf("PASS: Poly1305 RFC 7539 and %lu x4 BigInt reference cases\n",
           (unsigned long)(sizeof(lengths)/sizeof(lengths[0])));
#ifdef EE_MMI_HOST_TEST
    puts("Host test only: MMI instructions and EE ABI are NOT exercised");
#elif defined(EE_MMI_POLY1305_SCALAR_MULTIPLY)
    puts("EE SCALAR MULTIPLICATION: PMULTUW disabled for A/B baseline");
#elif defined(EE_MMI_POLY1305_FUSED_REDUCE)
    puts("EE FUSED REDUCTION: R5900 mul_reduce4 path linked");
#elif defined(EE_MMI_POLY1305_FUSED_MADD)
    puts("EE FUSED PMADDUW: R5900 exact 64-bit accumulation path linked");
#else
    puts("EE PMULTUW: R5900 2x32->64-bit instruction path linked");
#endif
    if (argc > 1 && strcmp(argv[1], "--bench") == 0)
        bench();
    return EXIT_SUCCESS;
}
