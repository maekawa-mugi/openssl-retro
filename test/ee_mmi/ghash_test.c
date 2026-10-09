/*
 * Copyright 2026 openssl-retro contributors. Licensed under Apache-2.0.
 *
 * Independent four-stream GHASH correctness tests. Each golden tag is
 * computed using an arbitrary-precision integer reference operating
 * on the NIST SP 800-38D GF(2^128) bit-serial algorithm.
 *
 * The EE_MMI_HOST_TEST function below is a C replacement for the
 * R5900 core; it is NOT evidence that EE MMI assembly executes.
 */
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "crypto/ee_mmi.h"

#define MAX_BLOCKS 16
#define DATA_OFFSET 16

static const size_t lengths[8] = {0, 1, 2, 3, 4, 7, 8, 16};
static const char *golden[8][4] = {
    { "03a25c7eb475eaed1cd8ba666b2d3599", "d76d4b3da868e6d3230deea4753c81f9", "fe27dccbc3974b91833aa27fee083074", "519300bd0beb4f9ead80413a3b2d170b" },
    { "1dc16f33b594013489439022c6e46642", "f1325685327432ed70ad29f2ef9947d2", "c62fbe147c634d18576715da45ec7aa6", "04f27083c81dd5a5ffbcf16bd8867543" },
    { "6031f9c0f691446e173b00c3823ebf79", "3b6ae8dcd9ff9545aee9a01d61801cd9", "f7601f982fed727da41e25c882053c0c", "d2a016c1b8edf841349e88aeb22e151b" },
    { "334bf809016790a43061f0eb96f1d021", "59ce859170694152b934d4a7ee4ea9d8", "d09a1157bc06634dd934126ab4f1a826", "c6899e0049f6e2cc3d11c75c376c7a33" },
    { "0d69b6101256dc28e028ae7ba7f725a3", "952cdb91b387164cd76bea065d6797ca", "284d26c6b59ad5841b3ced66be5387ec", "2c6c18efbb125983dcd28bca18e30f72" },
    { "03278fdf849be4d92fbb000d8e16c5de", "b928ecadc9189cee151e38982f979061", "b0dd6583b2fa0059982cba3857c3eec2", "ed9bccf69aed9826d469924459e5bb9a" },
    { "20b98768778638839cf264524d00893b", "48610ac070977027244624cbaa15074c", "b78477801e4ef3c69683aa7c332672f4", "12a65440f0f1295d8feca82a5d33227c" },
    { "e654fb10f21a3c35873659640acf066c", "eaebd68d00757bc8d38c1cedfeed78ba", "38415159c11a3617f5a17c59608fd05f", "a21c884fc63a0f1c23923fed2c6e4ddc" },
};

static uint32_t random_state;
static uint32_t random32(void)
{
    random_state ^= random_state << 13;
    random_state ^= random_state >> 17;
    random_state ^= random_state << 5;
    return random_state;
}
#if defined(EE_MMI_HOST_TEST) || !defined(EE_MMI_GHASH_SCALAR_MULTIPLY)
static void reference_mul(uint32_t z[4], const uint32_t x[4],
                          const uint32_t h[4])
{
    uint32_t v[4], acc[4] = {0,0,0,0};
    unsigned int bit, w;
    memcpy(v, h, sizeof(v));
    for (bit = 0; bit < 128; ++bit) {
        uint32_t mask = 0U - ((x[bit/32] >> (31-bit%32)) & 1U);
        uint32_t red = 0U - (v[3] & 1U);
        for (w = 0; w < 4; ++w) acc[w] ^= v[w] & mask;
        v[3] = (v[3] >> 1) | (v[2] << 31);
        v[2] = (v[2] >> 1) | (v[1] << 31);
        v[1] = (v[1] >> 1) | (v[0] << 31);
        v[0] = (v[0] >> 1) ^ (0xe1000000U & red);
    }
    memcpy(z, acc, sizeof(acc));
}

#endif

#ifdef EE_MMI_HOST_TEST
void ossl_ee_ghash_mul4(uint32_t z[4][4], const uint32_t x[4][4],
                        const uint32_t h[4][4])
{
    unsigned int lane, w;
    for (lane = 0; lane < 4; ++lane) {
        uint32_t xx[4], hh[4], zz[4];
        for (w = 0; w < 4; ++w) {
            xx[w] = x[w][lane];
            hh[w] = h[w][lane];
        }
        reference_mul(zz, xx, hh);
        for (w = 0; w < 4; ++w) z[w][lane] = zz[w];
    }
}
#endif

static unsigned int unhex(unsigned char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return 99;
}
static void decode(unsigned char *out, const char *hex)
{
    unsigned int i;
    for (i = 0; i < 16; ++i)
        out[i] = (unsigned char)(16*unhex(hex[2*i])
                                    + unhex(hex[2*i+1]));
}
static int match(const unsigned char *tag, const char *hex)
{
    unsigned int i;
    for (i = 0; i < 16; ++i)
        if (tag[i] != (unsigned char)(16*unhex(hex[2*i])
                                      + unhex(hex[2*i+1])))
            return 0;
    return 1;
}

static int nist_gcm_example(void)
{
    /* NIST GCM case: 128-bit zero AES key, one 16-byte ciphertext
     * block, zero AAD. H=E(K,0). C and final length block determine
     * GHASH before E(K,J0) is XORed into the authentication tag. */
    static const char hstr[] = "66e94bd4ef8a2c3b884cfa59ca342b2e";
    static const char cipher[] = "0388dace60b6a392f328c2b971b2fe78";
    static const char lenblk[] = "00000000000000000000000000000080";
    static const char expected[] = "f38cbb1ad69223dcc3457ae5b6b0f885";
    unsigned char y[4][16] = {{0}};
    unsigned char h[4][16], input[4][32];
    const unsigned char *ptrs[4];
    unsigned int lane;
    for (lane = 0; lane < 4; ++lane) {
        decode(h[lane], hstr);
        decode(input[lane], cipher);
        decode(input[lane] + 16, lenblk);
        ptrs[lane] = input[lane];
    }
    if (!ossl_ee_ghash_update4(y, h, ptrs, 2)) {
        puts("FAIL: NIST GHASH rejected valid input");
        return 0;
    }
    for (lane = 0; lane < 4; ++lane)
        if (!match(y[lane], expected)) {
            fprintf(stderr, "FAIL: NIST GHASH lane %u\n", lane);
            return 0;
        }
    return 1;
}

static int golden_case(size_t index)
{
    struct {
        unsigned char before[16];
        unsigned char y[4][16];
        unsigned char after[16];
    } output, split;
    unsigned char h[4][16], h_before[4][16];
    unsigned char data[4][MAX_BLOCKS*16 + DATA_OFFSET];
    unsigned char data_before[4][MAX_BLOCKS*16 + DATA_OFFSET];
    const unsigned char *input[4], *second[4];
    size_t blocks = lengths[index], first = blocks/2;
    unsigned int lane, i;
    random_state = 0x61707865U ^ ((uint32_t)blocks * 0x9e3779b9U);
    memset(&output, 0x5c, sizeof(output));
    memset(&split, 0x5c, sizeof(split));
    memset(data, 0xa7, sizeof(data));
    for (lane = 0; lane < 4; ++lane) {
        unsigned int offset = (lane*3+1) & 15;
        for (i = 0; i < 16; ++i)
            h[lane][i] = (unsigned char)random32();
        for (i = 0; i < 16; ++i)
            output.y[lane][i] = (unsigned char)random32();
        for (i = 0; i < blocks*16; ++i)
            data[lane][offset+i] = (unsigned char)random32();
        input[lane] = data[lane] + offset;
        second[lane] = input[lane] + first*16;
    }
    memcpy(split.y, output.y, sizeof(output.y));
    memcpy(h_before, h, sizeof(h));
    memcpy(data_before, data, sizeof(data));

    if (!ossl_ee_ghash_update4(output.y, h, input, blocks)) {
        printf("FAIL: GHASH rejected %lu blocks\n", (unsigned long)blocks);
        return 0;
    }
    if (!ossl_ee_ghash_update4(split.y, h, input, first)
        || !ossl_ee_ghash_update4(split.y, h, second,
                                  blocks-first)) {
        puts("FAIL: GHASH split update failed");
        return 0;
    }
    for (lane = 0; lane < 4; ++lane) {
        if (!match(output.y[lane], golden[index][lane])) {
            fprintf(stderr, "FAIL: BigInt GHASH length=%lu lane=%u\n",
                    (unsigned long)blocks, lane);
            return 0;
        }
        if (memcmp(split.y[lane], output.y[lane], 16) != 0) {
            puts("FAIL: GHASH split update differs");
            return 0;
        }
    }
    for (i = 0; i < 16; ++i)
        if (output.before[i] != 0x5c || output.after[i] != 0x5c
            || split.before[i] != 0x5c || split.after[i] != 0x5c) {
            puts("FAIL: GHASH output guard");
            return 0;
        }
    if (memcmp(h, h_before, sizeof(h)) != 0
        || memcmp(data, data_before, sizeof(data)) != 0) {
        puts("FAIL: GHASH modified H or input");
        return 0;
    }
    return 1;
}

static int invalid_arguments(void)
{
    unsigned char y[4][16]={{0}}, h[4][16]={{0}};
    const unsigned char *in[4]={NULL,NULL,NULL,NULL};
    unsigned char previous[4][16];
    memcpy(previous, y, sizeof(y));
    if (ossl_ee_ghash_update4(NULL,h,in,0)
        || ossl_ee_ghash_update4(y,NULL,in,0)
        || ossl_ee_ghash_update4(y,h,NULL,1)
        || ossl_ee_ghash_update4(y,h,in,1)
        || ossl_ee_ghash_update4(y,h,in,((size_t)-1)/16+1))
        return 0;
    if (!ossl_ee_ghash_update4(y,h,NULL,0)
        || memcmp(y,previous,sizeof(y)) != 0)
        return 0;
    return 1;
}

#ifndef EE_MMI_GHASH_SCALAR_MULTIPLY
static int multiplier_test(void)
{
    struct {
        uint32_t pre[4];
        uint32_t z[4][4];
        uint32_t post[4];
    } __attribute__((aligned(16))) buf;
    uint32_t x[4][4] __attribute__((aligned(16)));
    uint32_t h[4][4] __attribute__((aligned(16)));
    uint32_t old_x[4][4], old_h[4][4];
    unsigned int i, lane, w, iteration;
    random_state=0x3e7c9849U;
    for (iteration = 0; iteration < 256; ++iteration) {
        for (w=0; w<4; ++w)
            for (lane=0; lane<4; ++lane) {
                x[w][lane]=iteration==0?0U:
                           iteration==1?0xffffffffU:random32();
                h[w][lane]=iteration==0?0U:
                           iteration==1?0xffffffffU:random32();
            }
        memcpy(old_x,x,sizeof(x)); memcpy(old_h,h,sizeof(h));
        memset(&buf,0xa5,sizeof(buf));
        ossl_ee_ghash_mul4(buf.z,x,h);
        for (lane=0; lane<4; ++lane) {
            uint32_t xx[4],hh[4],zz[4];
            for (w=0;w<4;++w) {
                xx[w]=x[w][lane]; hh[w]=h[w][lane];
            }
            reference_mul(zz,xx,hh);
            for (w=0;w<4;++w)
                if (buf.z[w][lane] != zz[w]) {
                    fprintf(stderr,
                       "FAIL: MMI GHASH mult case=%u lane=%u word=%u\n",
                       iteration,lane,w);
                    return 0;
                }
        }
        for (i=0;i<4;++i)
            if (buf.pre[i]!=0xa5a5a5a5U
                || buf.post[i]!=0xa5a5a5a5U) {
                puts("FAIL: GHASH MMI output sentinel");
                return 0;
            }
        if (memcmp(old_x,x,sizeof(x))!=0
            || memcmp(old_h,h,sizeof(h))!=0) {
            puts("FAIL: GHASH MMI modified multiplication input");
            return 0;
        }
    }
    puts("PASS: 256 x four-stream MMI GHASH products vs independent C");
    return 1;
}
#endif

static void bench(void)
{
    unsigned char y[4][16]={{0}}, h[4][16]={{0}};
    unsigned char data[4][16*128]={{0}};
    const unsigned char *ptrs[4];
    clock_t begin,end;
    unsigned int i,lane;
    for (lane=0;lane<4;++lane) {
        h[lane][lane]=1;
        ptrs[lane]=data[lane];
    }
    begin=clock();
    for (i=0;i<8;++i)
        ossl_ee_ghash_update4(y,h,ptrs,128);
    end=clock();
    if (begin!=(clock_t)-1 && end>begin)
        printf("GHASH 4x128 blocks x8: %.3f s, %.2f MiB/s total\n",
               (double)(end-begin)/CLOCKS_PER_SEC,
               (double)(4*128*16*8)*CLOCKS_PER_SEC
                    / ((double)(end-begin)*1048576.0));
    else
        puts("GHASH benchmark: clock() unavailable");
}

int main(int argc,char **argv)
{
    size_t i;
    if (!nist_gcm_example() || !invalid_arguments())
        return EXIT_FAILURE;
    for (i=0;i<sizeof(lengths)/sizeof(lengths[0]);++i)
        if (!golden_case(i))
            return EXIT_FAILURE;
#ifndef EE_MMI_GHASH_SCALAR_MULTIPLY
    if (!multiplier_test())
        return EXIT_FAILURE;
#endif
    puts("PASS: GHASH NIST GCM and 32 independent BigInt golden states");
#ifdef EE_MMI_HOST_TEST
    puts("HOST TEST ONLY: R5900 MMI instructions and ABI NOT exercised");
#elif defined(EE_MMI_GHASH_SCALAR_MULTIPLY)
    puts("EE SCALAR GHASH multiplication comparison enabled");
#else
    puts("EE MMI GHASH four-stream multiplication linked");
#endif
    if (argc>1 && strcmp(argv[1],"--bench")==0)
        bench();
    return EXIT_SUCCESS;
}
