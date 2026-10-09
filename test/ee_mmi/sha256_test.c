/*
 * Copyright 2026 The openssl-retro contributors. All Rights Reserved.
 * Licensed under the Apache License 2.0; see LICENSE.txt.
 *
 * Standalone four-message EE MMI SHA-256 test.
 * EE_MMI_HOST_TEST substitutes the MMI compressor with a portable one.
 * Without that define, link the REAL R5900 assembly compressor.
 */
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "crypto/ee_mmi.h"

#define MAX_DATA 4096
#define OFFSET_SPACE 16

static unsigned char samples[4][MAX_DATA + OFFSET_SPACE];
static unsigned char original[4][MAX_DATA + OFFSET_SPACE];
static uint32_t random_state = 0x13243546U;

static const uint32_t k_ref[64] = {
    0x428a2f98U,0x71374491U,0xb5c0fbcfU,0xe9b5dba5U,
    0x3956c25bU,0x59f111f1U,0x923f82a4U,0xab1c5ed5U,
    0xd807aa98U,0x12835b01U,0x243185beU,0x550c7dc3U,
    0x72be5d74U,0x80deb1feU,0x9bdc06a7U,0xc19bf174U,
    0xe49b69c1U,0xefbe4786U,0x0fc19dc6U,0x240ca1ccU,
    0x2de92c6fU,0x4a7484aaU,0x5cb0a9dcU,0x76f988daU,
    0x983e5152U,0xa831c66dU,0xb00327c8U,0xbf597fc7U,
    0xc6e00bf3U,0xd5a79147U,0x06ca6351U,0x14292967U,
    0x27b70a85U,0x2e1b2138U,0x4d2c6dfcU,0x53380d13U,
    0x650a7354U,0x766a0abbU,0x81c2c92eU,0x92722c85U,
    0xa2bfe8a1U,0xa81a664bU,0xc24b8b70U,0xc76c51a3U,
    0xd192e819U,0xd6990624U,0xf40e3585U,0x106aa070U,
    0x19a4c116U,0x1e376c08U,0x2748774cU,0x34b0bcb5U,
    0x391c0cb3U,0x4ed8aa4aU,0x5b9cca4fU,0x682e6ff3U,
    0x748f82eeU,0x78a5636fU,0x84c87814U,0x8cc70208U,
    0x90befffaU,0xa4506cebU,0xbef9a3f7U,0xc67178f2U
};

static uint32_t next_random(void)
{
    random_state ^= random_state << 13;
    random_state ^= random_state >> 17;
    random_state ^= random_state << 5;
    return random_state;
}

static uint32_t rightrotate(uint32_t x, unsigned int n)
{
    return (x >> n) | (x << (32 - n));
}

static uint32_t load_be32(const unsigned char *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16)
         | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void scalar_compress(uint32_t h[8], const unsigned char data[64])
{
    uint32_t w[64];
    uint32_t a,b,c,d,e,f,g,hh,t1,t2;
    unsigned int i;

    for (i = 0; i < 16; ++i)
        w[i] = load_be32(data + i*4);
    for (i = 16; i < 64; ++i) {
        uint32_t x = w[i - 15], y = w[i - 2];
        w[i] = w[i - 16] + (rightrotate(x, 7) ^ rightrotate(x, 18) ^ (x >> 3))
             + w[i - 7] + (rightrotate(y, 17) ^ rightrotate(y, 19) ^ (y >> 10));
    }
    a=h[0]; b=h[1]; c=h[2]; d=h[3];
    e=h[4]; f=h[5]; g=h[6]; hh=h[7];
    for (i = 0; i < 64; ++i) {
        t1 = hh + (rightrotate(e, 6) ^ rightrotate(e, 11) ^ rightrotate(e, 25))
           + ((e & f) ^ (~e & g)) + k_ref[i] + w[i];
        t2 = (rightrotate(a, 2) ^ rightrotate(a, 13) ^ rightrotate(a, 22))
           + ((a & b) ^ (a & c) ^ (b & c));
        hh=g; g=f; f=e; e=d+t1;
        d=c; c=b; b=a; a=t1+t2;
    }
    h[0]+=a; h[1]+=b; h[2]+=c; h[3]+=d;
    h[4]+=e; h[5]+=f; h[6]+=g; h[7]+=hh;
}

static const uint32_t iv_sha256[8] = {
    0x6a09e667U,0xbb67ae85U,0x3c6ef372U,0xa54ff53aU,
    0x510e527fU,0x9b05688cU,0x1f83d9abU,0x5be0cd19U
};
static const uint32_t iv_sha224[8] = {
    0xc1059ed8U,0x367cd507U,0x3070dd17U,0xf70e5939U,
    0xffc00b31U,0x68581511U,0x64f98fa7U,0xbefa4fa4U
};

static void scalar_hash2(const unsigned char *in, size_t len,
                         unsigned char *out, const uint32_t iv[8],
                         size_t words)
{
    uint32_t state[8];
    unsigned char tail[128];
    uint64_t bits = (uint64_t)len * 8U;
    size_t pos = 0, rem, count, i;

    memcpy(state, iv, sizeof(state));
    while (len - pos >= 64) {
        scalar_compress(state, in + pos);
        pos += 64;
    }
    rem = len - pos;
    count = rem <= 55 ? 64 : 128;
    memset(tail, 0, sizeof(tail));
    if (rem != 0)
        memcpy(tail, in + pos, rem);
    tail[rem] = 0x80;
    for (i = 0; i < 8; ++i)
        tail[count - 8 + i] = (unsigned char)(bits >> (56 - 8 * i));
    scalar_compress(state, tail);
    if (count == 128)
        scalar_compress(state, tail + 64);
    for (i = 0; i < words; ++i) {
        out[i*4] = (unsigned char)(state[i] >> 24);
        out[i*4+1] = (unsigned char)(state[i] >> 16);
        out[i*4+2] = (unsigned char)(state[i] >> 8);
        out[i*4+3] = (unsigned char)state[i];
    }
}
static void scalar_hash(const unsigned char *in, size_t len,
                        unsigned char out[32])
{
    scalar_hash2(in, len, out, iv_sha256, 8);
}
static void scalar_hash224(const unsigned char *in, size_t len,
                           unsigned char out[28])
{
    scalar_hash2(in, len, out, iv_sha224, 7);
}

#ifdef EE_MMI_HOST_TEST
/* Software emulator consumes the SAME W/K arrays as EE MMI assembly. */
void ossl_ee_sha256_compress4(uint32_t state[8][4],
                              const uint32_t schedule[64][4],
                              const uint32_t constants[64][4])
{
    unsigned int lane,t;
    for (lane=0; lane<4; ++lane) {
        uint32_t v[8], old[8];
        unsigned int i;
        for (i=0;i<8;++i)
            v[i]=old[i]=state[i][lane];
        for (t=0;t<64;++t) {
            uint32_t s0=rightrotate(v[0],2)^rightrotate(v[0],13)^rightrotate(v[0],22);
            uint32_t s1=rightrotate(v[4],6)^rightrotate(v[4],11)^rightrotate(v[4],25);
            uint32_t ch=v[6]^(v[4]&(v[5]^v[6]));
            uint32_t maj=(v[0]&v[1])^(v[2]&(v[0]^v[1]));
            uint32_t t1=v[7]+s1+ch+constants[t][lane]+schedule[t][lane];
            uint32_t t2=s0+maj;
            v[7]=v[6];v[6]=v[5];v[5]=v[4];v[4]=v[3]+t1;
            v[3]=v[2];v[2]=v[1];v[1]=v[0];v[0]=t1+t2;
        }
        for(i=0;i<8;++i)
            state[i][lane]=old[i]+v[i];
    }
}
#endif

static int decode_hex(unsigned char out[32], const char *hex)
{
    unsigned int j;
    for (j=0;j<32;++j) {
        unsigned int a,b;
        if (sscanf(hex + j*2, "%1x%1x", &a, &b) != 2)
            return 0;
        out[j]=(unsigned char)(16*a+b);
    }
    return 1;
}

static int known_answer(const char *label, const unsigned char *data,
                        size_t len, const char *digest)
{
    const unsigned char *inputs[4] = { data, data, data, data };
    unsigned char expected[32], output[4][32];
    size_t lane;
    if (!decode_hex(expected, digest)
        || !ossl_ee_sha256_hash4(output, inputs, len)) {
        fprintf(stderr, "FAIL: %s return/hex\n", label);
        return 0;
    }
    for (lane = 0; lane < 4; ++lane)
        if (memcmp(output[lane], expected, 32) != 0) {
            fprintf(stderr, "FAIL: %s lane %lu\n", label,
                    (unsigned long)lane);
            return 0;
        }
    return 1;
}

static int known_answer224(const char *label, const unsigned char *data,
                           size_t len, const char *hex)
{
    const unsigned char *inputs[4] = { data, data, data, data };
    unsigned char expected[28], output[4][28];
    size_t lane, index;
    for (index = 0; index < sizeof(expected); ++index) {
        unsigned int hi, lo;
        if (sscanf(hex + index * 2, "%1x%1x", &hi, &lo) != 2)
            return 0;
        expected[index] = (unsigned char)(hi * 16 + lo);
    }
    if (!ossl_ee_sha224_hash4(output, inputs, len)) {
        fprintf(stderr, "FAIL: SHA224 %s return\n", label);
        return 0;
    }
    for (lane = 0; lane < 4; ++lane)
        if (memcmp(output[lane], expected, 28) != 0) {
            fprintf(stderr, "FAIL: SHA224 %s lane %lu\n",
                    label, (unsigned long)lane);
            return 0;
        }
    return 1;
}

static int random_batch(size_t len, unsigned int iteration)
{
    const unsigned char *inputs[4];
    unsigned char output[4][32], output224[4][28], expected[32], expected224[28];
    size_t lane, i;
    for (lane=0; lane<4; ++lane) {
        size_t offset = (lane * 5 + iteration) & 15;
        for (i=0; i < sizeof(samples[lane]); ++i)
            samples[lane][i] = (unsigned char)next_random();
        inputs[lane] = samples[lane] + offset;
    }
    memcpy(original, samples, sizeof(samples));
    if (!ossl_ee_sha224_hash4(output224, inputs, len)) {
        fprintf(stderr, "FAIL: SHA224 batch rejected valid len %lu\n",
                (unsigned long)len);
        return 0;
    }
    if (!ossl_ee_sha256_hash4(output, inputs, len)) {
        fprintf(stderr, "FAIL: SHA256 batch rejected valid len %lu\n",
                (unsigned long)len);
        return 0;
    }
    if (memcmp(original, samples, sizeof(samples)) != 0) {
        fprintf(stderr, "FAIL: SHA256 batch changed input\n");
        return 0;
    }
    for (lane=0; lane<4; ++lane) {
        scalar_hash224(inputs[lane], len, expected224);
        if (memcmp(output224[lane], expected224, 28) != 0) {
            fprintf(stderr, "FAIL: SHA224 len=%lu lane=%lu iteration=%u\n",
                    (unsigned long)len, (unsigned long)lane, iteration);
            return 0;
        }
        scalar_hash(inputs[lane], len, expected);
        if (memcmp(output[lane], expected, 32) != 0) {
            fprintf(stderr, "FAIL: SHA256 len=%lu lane=%lu iteration=%u\n",
                    (unsigned long)len, (unsigned long)lane, iteration);
            return 0;
        }
    }
    return 1;
}

static void benchmark(void)
{
    const unsigned char *inputs[4];
    unsigned char digest[4][32];
    unsigned int i, lane, reps = 64;
    clock_t a,b,c;
    volatile unsigned int sink = 0;
    for (lane=0;lane<4;++lane)
        inputs[lane] = samples[lane];

    a = clock();
    for(i=0;i<reps;++i) {
        for(lane=0;lane<4;++lane)
            scalar_hash(inputs[lane], MAX_DATA, digest[lane]);
        sink ^= digest[i % 4][0];
    }
    b=clock();
    for(i=0;i<reps;++i) {
        ossl_ee_sha256_hash4(digest, inputs, MAX_DATA);
        sink ^= digest[i % 4][0];
    }
    c=clock();
    if (a == (clock_t)-1 || b == (clock_t)-1 || c == (clock_t)-1
        || b <= a || c <= b) {
        puts("SHA256 bench: clock() unavailable");
        return;
    }
    printf("SHA256 4x4096 bytes x %u: scalar4=%.4fs, MMI4=%.4fs, "
           "batch/scalar=%.2fx (sink=%u)\n", reps,
           (double)(b-a)/CLOCKS_PER_SEC, (double)(c-b)/CLOCKS_PER_SEC,
           (double)(b-a)/(double)(c-b), sink);
}

int main(int argc, char **argv)
{
    static const size_t sizes[] = {
        0,1,2,3,15,31,55,56,57,63,64,65,119,120,121,
        127,128,129,191,255,256,257,511,512,513,1024,4096
    };
    static const unsigned char multi[] =
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    const unsigned char *nulls[4] = {NULL,NULL,NULL,NULL};
    unsigned char digest[4][32];
    unsigned int i, count=0;
    size_t j;

    if (!known_answer("empty", NULL, 0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        || !known_answer("abc", (const unsigned char *)"abc", 3,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        || !known_answer("multi-block", multi, sizeof(multi)-1,
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1")
        || !known_answer224("empty", NULL, 0,
        "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f")
        || !known_answer224("abc", (const unsigned char *)"abc", 3,
        "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"))
        return EXIT_FAILURE;

    if (ossl_ee_sha256_hash4(NULL, nulls, 0) != 0
        || ossl_ee_sha256_hash4(digest, NULL, 0) != 0) {
        puts("FAIL: NULL output/input-array accepted");
        return EXIT_FAILURE;
    }
    nulls[0] = NULL;
    if (ossl_ee_sha256_hash4(digest, nulls, 1) != 0) {
        puts("FAIL: non-empty NULL message accepted");
        return EXIT_FAILURE;
    }

    for (j=0; j<sizeof(sizes)/sizeof(sizes[0]); ++j)
        for (i=0; i<5; ++i) {
            if (!random_batch(sizes[j], i))
                return EXIT_FAILURE;
            ++count;
        }
    for (i=0; i<128; ++i) {
        if (!random_batch(next_random() % (MAX_DATA + 1), i))
            return EXIT_FAILURE;
        ++count;
    }

    printf("PASS: SHA-224/SHA-256 4x batch, five NIST vectors, %u random differential cases\n",
           count);
#ifdef EE_MMI_HOST_TEST
    puts("HOST EMULATION ONLY: R5900 MMI assembly not exercised");
#else
    puts("REAL EE MMI compressor linked: console execution required");
#endif
    if (argc > 1 && strcmp(argv[1], "--bench") == 0)
        benchmark();
    return EXIT_SUCCESS;
}
