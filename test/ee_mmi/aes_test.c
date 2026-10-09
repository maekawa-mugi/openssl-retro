/*
 * Copyright 2026 openssl-retro contributors. Licensed under Apache-2.0.
 *
 * AES-128/192/256, AES-CTR32, four parallel independent block tests.
 * Reference cipher uses the standard 256-byte S-box and a separate
 * byte-oriented key schedule, unlike the production table-free SWAR.
 * Test reference is NOT used by the shipped cryptographic backend.
 */
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "crypto/ee_mmi.h"

static const unsigned char sbox[256] = {
  0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
  0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
  0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
  0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
  0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
  0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
  0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
  0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
  0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
  0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
  0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
  0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
  0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
  0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
  0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
  0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

static uint32_t rng_state = 0x9e3779b9U;
static uint32_t rand32(void)
{
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 17;
    rng_state ^= rng_state << 5;
    return rng_state;
}

static unsigned char ref_xtime(unsigned char a)
{
    return (unsigned char)(((unsigned int)a << 1)
                       ^ ((a & 0x80U) ? 0x1bU : 0U));
}
static void ref_shiftrows(unsigned char st[16])
{
    unsigned char old[16];
    unsigned int col, row;
    memcpy(old, st, sizeof(old));
    for (col = 0; col < 4; ++col)
        for (row = 0; row < 4; ++row)
            st[4*col+row] = old[4*((col+row)&3)+row];
}
static void ref_mixcolumn(unsigned char col[4])
{
    unsigned char a[4], t;
    unsigned int row;
    memcpy(a, col, sizeof(a));
    t = (unsigned char)(a[0]^a[1]^a[2]^a[3]);
    for (row = 0; row < 4; ++row)
        col[row] = (unsigned char)(a[row]^t
                      ^ref_xtime((unsigned char)(a[row]^a[(row+1)&3])));
}
#ifdef EE_MMI_HOST_TEST
#ifndef EE_MMI_AES_SCALAR_ROUND
/* Host replacement for R5900 MixColumns/ARK, not an MMI emulator. */
void ossl_ee_aes_mixcolumns_ark4(uint32_t state[4][4],
                                 const uint32_t round_key[4][4])
{
    unsigned int col, lane, byte;
    for (col = 0; col < 4; ++col)
        for (lane = 0; lane < 4; ++lane) {
            unsigned char v[4];
            for (byte = 0; byte < 4; ++byte)
                v[byte] = (unsigned char)(state[col][lane] >> (8*byte));
            ref_mixcolumn(v);
            state[col][lane] = 0;
            for (byte = 0; byte < 4; ++byte)
                state[col][lane] |= (uint32_t)v[byte] << (8*byte);
            state[col][lane] ^= round_key[col][lane];
        }
}
#endif
#endif

static void reference_key_schedule(unsigned char rk[240],
                                   const unsigned char *key,
                                   unsigned int bits)
{
    unsigned int nk = bits / 32, nr = nk + 6;
    unsigned int key_bytes = bits / 8, total = 16*(nr+1), n;
    unsigned char rcon = 1;
    unsigned char tmp[4];
    memcpy(rk, key, key_bytes);
    for (n = key_bytes; n < total; n += 4) {
        unsigned int i;
        memcpy(tmp, rk+n-4, 4);
        if (n % key_bytes == 0) {
            unsigned char first = tmp[0];
            tmp[0] = sbox[tmp[1]] ^ rcon;
            tmp[1] = sbox[tmp[2]];
            tmp[2] = sbox[tmp[3]];
            tmp[3] = sbox[first];
            rcon = ref_xtime(rcon);
        } else if (nk > 6 && n % key_bytes == 16) {
            for (i = 0; i < 4; ++i) tmp[i] = sbox[tmp[i]];
        }
        for (i = 0; i < 4; ++i)
            rk[n+i] = rk[n-key_bytes+i] ^ tmp[i];
    }
}

static void reference_encrypt(unsigned char out[16],
                              const unsigned char in[16],
                              const unsigned char *key,
                              unsigned int bits)
{
    unsigned char rk[240], st[16];
    unsigned int nr = bits/32 + 6, round, i, col;
    reference_key_schedule(rk, key, bits);
    memcpy(st, in, 16);
    for (i = 0; i < 16; ++i) st[i] ^= rk[i];
    for (round = 1; round < nr; ++round) {
        for (i = 0; i < 16; ++i) st[i] = sbox[st[i]];
        ref_shiftrows(st);
        for (col = 0; col < 4; ++col) ref_mixcolumn(st+4*col);
        for (i = 0; i < 16; ++i) st[i] ^= rk[16*round+i];
    }
    for (i = 0; i < 16; ++i) st[i] = sbox[st[i]];
    ref_shiftrows(st);
    for (i = 0; i < 16; ++i) out[i] = st[i]^rk[16*nr+i];
}

static unsigned int unhex(unsigned char a)
{
    if (a >= '0' && a <= '9') return a-'0';
    if (a >= 'a' && a <= 'f') return a-'a'+10;
    return 99;
}
static void fromhex(unsigned char *out,const char *hex,size_t bytes)
{
    size_t i;
    for (i = 0; i < bytes; ++i)
        out[i] = (unsigned char)(16*unhex(hex[2*i])
                                  + unhex(hex[2*i+1]));
}

static int nist_vectors(void)
{
    const struct {
        unsigned int bits;
        const char *key;
        const char *ciphertext;
    } cases[] = {
        {128, "000102030405060708090a0b0c0d0e0f",
              "69c4e0d86a7b0430d8cdb78070b4c55a"},
        {192, "000102030405060708090a0b0c0d0e0f"
              "1011121314151617",
              "dda97ca4864cdfe06eaf70a0ec0d7191"},
        {256, "000102030405060708090a0b0c0d0e0f"
              "101112131415161718191a1b1c1d1e1f",
              "8ea2b7ca516745bfeafc49904b496089"}
    };
    struct {
        unsigned char before[16];
        unsigned char output[4][16];
        unsigned char after[16];
    } result;
    unsigned char key[32], data[4][16], expect[16];
    unsigned int i, lane, j;
    ossl_ee_aes4_key ctx;
    fromhex(data[0],"00112233445566778899aabbccddeeff",16);
    for (lane = 1; lane < 4; ++lane)
        memcpy(data[lane],data[0],16);
    for (i = 0; i < sizeof(cases)/sizeof(cases[0]); ++i) {
        fromhex(key,cases[i].key,cases[i].bits/8);
        fromhex(expect,cases[i].ciphertext,16);
        memset(&result,0xa5,sizeof(result));
        if (!ossl_ee_aes_set_encrypt_key(&ctx,key,cases[i].bits)
            || !ossl_ee_aes_encrypt4(result.output,data,&ctx)) {
            puts("FAIL: AES NIST call rejected");
            return 0;
        }
        for (lane = 0; lane < 4; ++lane)
            if (memcmp(result.output[lane],expect,16) != 0) {
                fprintf(stderr,"FAIL: AES-%u NIST lane %u\n",
                        cases[i].bits,lane);
                return 0;
            }
        for (j = 0; j < 16; ++j)
            if (result.before[j] != 0xa5 || result.after[j] != 0xa5) {
                puts("FAIL: AES output guard");
                return 0;
            }
        ossl_ee_aes_clear_key(&ctx);
    }
    memset(key,0,16);
    memset(data,0,sizeof(data));
    if (!ossl_ee_aes_set_encrypt_key(&ctx,key,128)
        || !ossl_ee_aes_encrypt4(result.output,data,&ctx)) return 0;
    fromhex(expect,"66e94bd4ef8a2c3b884cfa59ca342b2e",16);
    for (lane=0;lane<4;++lane)
        if (memcmp(result.output[lane],expect,16)) {
            puts("FAIL: AES-128 zero block (GCM GHASH subkey)");
            return 0;
        }
    ossl_ee_aes_clear_key(&ctx);
    return 1;
}

static int random_differential(void)
{
    unsigned char key[32], data[4][16], original[4][16];
    unsigned char expected[4][16], out[4][16];
    ossl_ee_aes4_key ctx, snapshot;
    unsigned int bits, trial, i, lane;
    rng_state=0x01a35e99U;
    for (bits=128;bits<=256;bits+=64)
        for (trial=0;trial<32;++trial) {
            for (i=0;i<bits/8;++i) key[i]=(unsigned char)rand32();
            for (lane=0;lane<4;++lane) {
                for (i=0;i<16;++i)
                    data[lane][i]=(unsigned char)rand32();
                reference_encrypt(expected[lane],data[lane],key,bits);
            }
            memcpy(original,data,sizeof(data));
            if (!ossl_ee_aes_set_encrypt_key(&ctx,key,bits))
                return 0;
            memcpy(&snapshot,&ctx,sizeof(ctx));
            if (!ossl_ee_aes_encrypt4(out,data,&ctx)) return 0;
            if (memcmp(out,expected,sizeof(out))
                || memcmp(original,data,sizeof(data))
                || memcmp(&snapshot,&ctx,sizeof(ctx))) {
                fprintf(stderr,"FAIL: AES-%u 4-block differential %u\n",
                        bits,trial);
                return 0;
            }
            /* Exact same input/output storage is supported. */
            if (!ossl_ee_aes_encrypt4(data,data,&ctx)
                || memcmp(data,expected,sizeof(data))) {
                puts("FAIL: AES 4-block in-place");
                return 0;
            }
            ossl_ee_aes_clear_key(&ctx);
            for (i=0;i<sizeof(ctx);++i)
                if (((const unsigned char *)&ctx)[i]!=0) {
                    puts("FAIL: AES key round-buffer not cleared");
                    return 0;
                }
        }
    puts("PASS: AES-128/192/256 96 x 4 independent scalar references");
    return 1;
}

#ifndef EE_MMI_AES_SCALAR_ROUND
static int mixcolumns_differential(void)
{
    uint32_t st[4][4] __attribute__((aligned(16)));
    uint32_t rk[4][4] __attribute__((aligned(16)));
    uint32_t expect[4][4];
    unsigned int case_no, col, lane, row;
    rng_state=0xa5e55aaaU;
    for (case_no=0;case_no<256;++case_no) {
        for (col=0;col<4;++col)
            for (lane=0;lane<4;++lane) {
                unsigned char bytes[4];
                st[col][lane] = case_no==0?0U:
                                case_no==1?0xffffffffU:rand32();
                rk[col][lane] = rand32();
                for (row=0;row<4;++row)
                    bytes[row] = (unsigned char)(st[col][lane]>>(8*row));
                ref_mixcolumn(bytes);
                expect[col][lane] = rk[col][lane];
                for (row=0;row<4;++row)
                    expect[col][lane] ^= (uint32_t)bytes[row]<<(8*row);
            }
        ossl_ee_aes_mixcolumns_ark4(st,rk);
        if (memcmp(st,expect,sizeof(st))!=0) {
            fprintf(stderr,"FAIL: EE AES MMI MixColumns case %u\n",case_no);
            return 0;
        }
    }
    puts("PASS: 256 direct MMI MixColumns/AddRoundKey 4-lane cases");
    return 1;
}
#endif

static int ctr_vectors(void)
{
    static const char *plain =
        "6bc1bee22e409f96e93d7e117393172a"
        "ae2d8a571e03ac9c9eb76fac45af8e51"
        "30c81c46a35ce411e5fbc1191a0a52ef"
        "f69f2445df4f9b17ad2b417be66c3710";
    static const char *key128="2b7e151628aed2a6abf7158809cf4f3c";
    static const char *enc128=
        "874d6191b620e3261bef6864990db6ce"
        "9806f66b7970fdff8617187bb9fffdff"
        "5ae4df3edbd5d35e5b4f09020db03eab"
        "1e031dda2fbe03d1792170a0f3009cee";
    static const char *key256=
        "603deb1015ca71be2b73aef0857d7781"
        "1f352c073b6108d72d9810a30914dff4";
    static const char *enc256=
        "601ec313775789a5b7a7f504bbf3d228"
        "f443e3ca4d62b59aca84e990cacaf5c5"
        "2b0930daa23de94ce87017ba2d84988d"
        "dfc9c58db67aada613c2dd08457941a6";
    unsigned char key[32],iv[12],input[64],original[64],expected[64];
    unsigned char out[64],inplace[64];
    ossl_ee_aes4_key ctx;
    unsigned int mode;
    size_t len;
    fromhex(iv,"f0f1f2f3f4f5f6f7f8f9fafb",12);
    fromhex(input,plain,64);
    memcpy(original,input,64);
    for (mode=0;mode<2;++mode) {
        unsigned int bits=mode?256:128;
        fromhex(key,mode?key256:key128,bits/8);
        fromhex(expected,mode?enc256:enc128,64);
        if (!ossl_ee_aes_set_encrypt_key(&ctx,key,bits)
            || !ossl_ee_aes_ctr32_xor(out,input,64,&ctx,iv,0xfcfdfeffU)
            || memcmp(out,expected,64)!=0) {
            fprintf(stderr,"FAIL: NIST SP800-38A AES-%u CTR\n",bits);
            return 0;
        }
        for (len=0;len<=64;++len) {
            memcpy(inplace,input,64);
            if (!ossl_ee_aes_ctr32_xor(inplace,inplace,len,&ctx,iv,
                                         0xfcfdfeffU)
                || memcmp(inplace,expected,len)) {
                fprintf(stderr,"FAIL: AES-CTR partial len %lu\n",
                        (unsigned long)len);
                return 0;
            }
            if (memcmp(inplace+len,input+len,64-len)) {
                puts("FAIL: AES-CTR wrote beyond requested length");
                return 0;
            }
        }
        if (memcmp(input,original,sizeof(input))) {
            puts("FAIL: AES-CTR changed plaintext input");
            return 0;
        }
        ossl_ee_aes_clear_key(&ctx);
    }
    puts("PASS: NIST SP800-38A AES-128/256 CTR and partial lengths");
    return 1;
}

static int invalid_arguments(void)
{
    ossl_ee_aes4_key ctx;
    unsigned char key[32]={0}, input[4][16]={{0}};
    unsigned char output[4][16]={{0}}, iv[12]={0};
    if (ossl_ee_aes_set_encrypt_key(NULL,key,128)
        || ossl_ee_aes_set_encrypt_key(&ctx,NULL,128)
        || ossl_ee_aes_set_encrypt_key(&ctx,key,120)
        || ossl_ee_aes_set_encrypt_key(&ctx,key,512))
        return 0;
    memset(&ctx,0,sizeof(ctx));
    if (ossl_ee_aes_encrypt4(output,input,&ctx))
        return 0;
    if (!ossl_ee_aes_set_encrypt_key(&ctx,key,128)) return 0;
    if (ossl_ee_aes_encrypt4(NULL,input,&ctx)
        || ossl_ee_aes_encrypt4(output,NULL,&ctx)
        || ossl_ee_aes_encrypt4(output,input,NULL))
        return 0;
    if (ossl_ee_aes_ctr32_xor(NULL,input[0],16,&ctx,iv,2)
        || ossl_ee_aes_ctr32_xor(output[0],NULL,16,&ctx,iv,2)
        || ossl_ee_aes_ctr32_xor(output[0],input[0],16,NULL,iv,2)
        || ossl_ee_aes_ctr32_xor(output[0],input[0],16,&ctx,NULL,2))
        return 0;
    if (!ossl_ee_aes_ctr32_xor(NULL,NULL,0,&ctx,iv,2))
        return 0;
    /* One last counter is legal; two would cause reuse/wrap. */
    if (!ossl_ee_aes_ctr32_xor(output[0],input[0],16,&ctx,iv,
                               UINT32_MAX))
        return 0;
    if (ossl_ee_aes_ctr32_xor(output[0],input[0],32,&ctx,iv,
                              UINT32_MAX))
        return 0;
    ossl_ee_aes_clear_key(&ctx);
    return 1;
}

static void benchmark(void)
{
    unsigned char key[32]={0}, data[4][16]={{0}};
    unsigned char out[4][16];
    ossl_ee_aes4_key ctx;
    clock_t start,end;
    unsigned int i;
    if (!ossl_ee_aes_set_encrypt_key(&ctx,key,128))
        return;
    start=clock();
    for (i=0;i<256;++i)
        ossl_ee_aes_encrypt4(out,data,&ctx);
    end=clock();
    if (start!=(clock_t)-1 && end>start)
        printf("AES-128 four-block x256: %.3f s, %.0f blocks/s\n",
               (double)(end-start)/CLOCKS_PER_SEC,
               1024.0*CLOCKS_PER_SEC/(double)(end-start));
    else
        puts("AES benchmark: clock() unavailable");
    ossl_ee_aes_clear_key(&ctx);
}

int main(int argc,char **argv)
{
    if (!nist_vectors() || !random_differential()
        || !ctr_vectors() || !invalid_arguments())
        return EXIT_FAILURE;
#ifndef EE_MMI_AES_SCALAR_ROUND
    if (!mixcolumns_differential()) return EXIT_FAILURE;
#endif
    puts("PASS: AES-128/192/256 four-block encryption and CTR32");
#ifdef EE_MMI_HOST_TEST
    puts("HOST C emulator only: genuine R5900 MMI assembly NOT tested");
#elif defined(EE_MMI_AES_SCALAR_ROUND)
    puts("EE scalar MixColumns/AddRoundKey A/B variant");
#else
    puts("EE MMI packed MixColumns/AddRoundKey variant linked");
#endif
    if (argc>1 && strcmp(argv[1],"--bench")==0)
        benchmark();
    return EXIT_SUCCESS;
}
