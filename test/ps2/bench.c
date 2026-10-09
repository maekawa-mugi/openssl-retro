/*
 * PS2 EE MMI vs scalar crypto-only benchmark workload.
 * Copyright 2026 openssl-retro contributors. Apache License 2.0.
 *
 * Compiled once with MMI functions, once into the scalar namespace,
 * and a third time (Poly1305 only) with fused PMADDUW.
 * Inputs, output sizes and iteration counts are identical for all modes.
 *
 * No NIST vectors, guards, reference calculations, printf or validation
 * runs here; validation is done separately in test/ps2/main.c.
 * Timers and comparison of the resulting checksums are outside this file.
 */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "crypto/ee_mmi.h"

#ifndef PS2_BENCH_POLY_ONLY
#include "crypto/ee_bn_mont.h"
#include "crypto/ee_rsa_verify.h"
#include "crypto/ee_p256_ecdh.h"
#include "crypto/ee_aes_gcm.h"

void ChaCha20_ctr32(unsigned char *, const unsigned char *, size_t,
                    const unsigned int [8], const unsigned int [4]);

#define SHA_BYTES 1024
#define CHACHA_BYTES 4096
#define GHASH_BLOCKS 8
#define RSA_BYTES 256
#define BN_LIMBS 64
#define GCM_BYTES 256
#define GCM_AAD_BYTES 20
#endif
#define POLY_BYTES 1024

static unsigned char poly_in[4][POLY_BYTES];
static const unsigned char *poly_ptr[4];
static unsigned char poly_key[4][32], poly_out[4][16];

#ifndef PS2_BENCH_POLY_ONLY
static unsigned char chacha_in[CHACHA_BYTES], chacha_out[CHACHA_BYTES];
static unsigned int chacha_key[8], chacha_counter[4];
static unsigned char sha_in[4][SHA_BYTES], sha_out[4][32];
static const unsigned char *sha_ptr[4];
static ossl_ee_aes4_key aes_key;
static unsigned char aes_key_bytes[16], aes_in[4][16], aes_out[4][16];
static unsigned char ghash_in[4][GHASH_BLOCKS * 16], ghash_h[4][16];
static const unsigned char *ghash_ptr[4];
static unsigned char ghash_y[4][16];
static uint32_t bn_a[BN_LIMBS], bn_b[BN_LIMBS], bn_n[BN_LIMBS];
static uint32_t bn_out[BN_LIMBS];
static unsigned char x_scalar[4][32], x_point[4][32], x_out[4][32];
static unsigned char rsa_mod[4][RSA_BYTES], rsa_in[4][RSA_BYTES];
static unsigned char rsa_out[4][RSA_BYTES];
static unsigned char *rsa_out_ptr[4];
static const unsigned char *rsa_in_ptr[4], *rsa_mod_ptr[4];
static unsigned char p256_scalar[32], p256_public[65], p256_out[32];
static ossl_ee_aes_gcm4_key gcm_key;
static unsigned char gcm_in[4][GCM_BYTES], gcm_out[4][GCM_BYTES];
static unsigned char gcm_aad[4][GCM_AAD_BYTES], gcm_iv[4][12];
static unsigned char gcm_tags[4][16];
static unsigned char *gcm_out_ptr[4];
static const unsigned char *gcm_in_ptr[4], *gcm_aad_ptr[4];

static const unsigned char generator_p256[65] = {
    0x04,
    0x6b,0x17,0xd1,0xf2,0xe1,0x2c,0x42,0x47,
    0xf8,0xbc,0xe6,0xe5,0x63,0xa4,0x40,0xf2,
    0x77,0x03,0x7d,0x81,0x2d,0xeb,0x33,0xa0,
    0xf4,0xa1,0x39,0x45,0xd8,0x98,0xc2,0x96,
    0x4f,0xe3,0x42,0xe2,0xfe,0x1a,0x7f,0x9b,
    0x8e,0xe7,0xeb,0x4a,0x7c,0x0f,0x9e,0x16,
    0x2b,0xce,0x33,0x57,0x6b,0x31,0x5e,0xce,
    0xcb,0xb6,0x40,0x68,0x37,0xbf,0x51,0xf5
};
#endif

int ps2_bench_prepare(void)
{
    size_t lane, i;
    for (lane = 0; lane < 4; ++lane) {
        poly_ptr[lane] = poly_in[lane];
        for (i = 0; i < POLY_BYTES; ++i)
            poly_in[lane][i] = (unsigned char)(i * 13U + lane * 37U + 5U);
        for (i = 0; i < 32; ++i)
            poly_key[lane][i] = (unsigned char)(i * 7U + lane * 23U + 1U);
    }
#ifndef PS2_BENCH_POLY_ONLY
    for (i = 0; i < CHACHA_BYTES; ++i)
        chacha_in[i] = (unsigned char)(i * 3U + 11U);
    for (i = 0; i < 8; ++i)
        chacha_key[i] = (unsigned int)(0x01020304U ^ (i * 0x10203040U));
    for (i = 0; i < 4; ++i)
        chacha_counter[i] = (unsigned int)(0x10301020U + i);
    for (lane = 0; lane < 4; ++lane) {
        sha_ptr[lane] = sha_in[lane];
        ghash_ptr[lane] = ghash_in[lane];
        rsa_in_ptr[lane] = rsa_in[lane];
        rsa_mod_ptr[lane] = rsa_mod[lane];
        rsa_out_ptr[lane] = rsa_out[lane];
        gcm_in_ptr[lane] = gcm_in[lane];
        gcm_out_ptr[lane] = gcm_out[lane];
        gcm_aad_ptr[lane] = gcm_aad[lane];
        for (i = 0; i < GCM_BYTES; ++i)
            gcm_in[lane][i] = (unsigned char)(i * 17U + lane * 37U + 5U);
        for (i = 0; i < GCM_AAD_BYTES; ++i)
            gcm_aad[lane][i] = (unsigned char)(i * 29U + lane * 11U);
        for (i = 0; i < 12; ++i)
            gcm_iv[lane][i] = (unsigned char)(i * 13U + lane * 43U);
        for (i = 0; i < SHA_BYTES; ++i)
            sha_in[lane][i] = (unsigned char)(i * 17U + lane * 19U + 3U);
        for (i = 0; i < GHASH_BLOCKS * 16; ++i)
            ghash_in[lane][i] = (unsigned char)(i * 31U + lane * 9U);
        for (i = 0; i < 16; ++i) {
            aes_in[lane][i] = (unsigned char)(i * 11U + lane * 53U);
            ghash_h[lane][i] = (unsigned char)(i * 7U + lane * 3U + 1U);
        }
        for (i = 0; i < 32; ++i) {
            x_scalar[lane][i] = (unsigned char)(i * 7U + lane * 5U + 13U);
            x_point[lane][i] = 0;
        }
        x_point[lane][0] = 9;
        for (i = 0; i < RSA_BYTES; ++i) {
            rsa_mod[lane][i] = 0xff;
            rsa_in[lane][i] = 0;
        }
        rsa_mod[lane][RSA_BYTES-1] = (unsigned char)(0xf3U + lane * 2U);
        rsa_in[lane][RSA_BYTES-1] = (unsigned char)(2U + lane);
    }
    for (i = 0; i < 16; ++i)
        aes_key_bytes[i] = (unsigned char)(7U + i * 13U);
    if (!ossl_ee_aes_set_encrypt_key(&aes_key, aes_key_bytes, 128))
        return 0;
    if (!ossl_ee_aes_gcm4_init(&gcm_key, aes_key_bytes, 128))
        return 0;
    for (i = 0; i < BN_LIMBS; ++i) {
        bn_n[i] = 0xffffffffU;
        bn_a[i] = (uint32_t)(0x10203040U + i * 0x01010101U);
        bn_b[i] = (uint32_t)(0x31415926U + i * 0x01020304U);
    }
    memset(p256_scalar, 0, sizeof(p256_scalar));
    p256_scalar[31] = 2;
    memcpy(p256_public, generator_p256, sizeof(p256_public));
#endif
    return 1;
}

void ps2_bench_reset(unsigned int suite)
{
#ifndef PS2_BENCH_POLY_ONLY
    if (suite == 4)
        memset(ghash_y, 0, sizeof(ghash_y));
#else
    (void)suite;
#endif
}

/*
 * One equivalent crypto workload in the selected namespace.
 * The caller measures the entire run; it hashes the results AFTER
 * stopping the timer. Outputs are not validated within this function.
 */
int ps2_bench_run(unsigned int suite, unsigned int repetitions)
{
    unsigned int i;
    if (repetitions == 0)
        return 0;
#ifdef PS2_BENCH_POLY_ONLY
    if (suite != 2)
        return 0;
#endif
    for (i = 0; i < repetitions; ++i) {
        switch (suite) {
#ifndef PS2_BENCH_POLY_ONLY
        case 0:
            ChaCha20_ctr32(chacha_out, chacha_in, CHACHA_BYTES,
                           chacha_key, chacha_counter);
            break;
        case 1:
            if (!ossl_ee_sha256_hash4(sha_out, sha_ptr, SHA_BYTES))
                return 0;
            break;
#endif
        case 2:
            if (!ossl_ee_poly1305_auth4(poly_out, poly_ptr,
                                        POLY_BYTES, poly_key))
                return 0;
            break;
#ifndef PS2_BENCH_POLY_ONLY
        case 3:
            if (!ossl_ee_aes_encrypt4(aes_out, aes_in, &aes_key))
                return 0;
            break;
        case 4:
            if (!ossl_ee_ghash_update4(ghash_y, ghash_h,
                                       ghash_ptr, GHASH_BLOCKS))
                return 0;
            break;
        case 5:
            if (!ossl_ee_bn_mont32(bn_out, bn_a, bn_b, bn_n,
                                   1U, BN_LIMBS))
                return 0;
            break;
        case 6:
            if (!ossl_ee_x25519_scalar_mult4(x_out, x_scalar, x_point))
                return 0;
            break;
        case 7:
            if (!ossl_ee_rsa_public65537_4(rsa_out_ptr, rsa_in_ptr,
                                           rsa_mod_ptr, RSA_BYTES))
                return 0;
            break;
        case 8:
            if (!ossl_ee_p256_ecdh(p256_out, p256_scalar, p256_public))
                return 0;
            break;
        case 9:
            if (!ossl_ee_aes_gcm4_seal(&gcm_key, gcm_out_ptr, gcm_tags,
                                        gcm_in_ptr, GCM_BYTES,
                                        gcm_aad_ptr, GCM_AAD_BYTES, gcm_iv))
                return 0;
            break;
#endif
        default:
            return 0;
        }
    }
    return 1;
}

/* FNV-1a checksum of the complete output, outside the timed interval.
 * A/B/F must agree bit-for-bit for the EXACT benchmark inputs. */
uint32_t ps2_bench_digest(unsigned int suite)
{
    const unsigned char *ptr = NULL;
    size_t len = 0, i;
    uint32_t result = 2166136261U;
    switch (suite) {
#ifndef PS2_BENCH_POLY_ONLY
    case 0: ptr = chacha_out; len = sizeof(chacha_out); break;
    case 1: ptr = &sha_out[0][0]; len = sizeof(sha_out); break;
#endif
    case 2: ptr = &poly_out[0][0]; len = sizeof(poly_out); break;
#ifndef PS2_BENCH_POLY_ONLY
    case 3: ptr = &aes_out[0][0]; len = sizeof(aes_out); break;
    case 4: ptr = &ghash_y[0][0]; len = sizeof(ghash_y); break;
    case 5: ptr = (const unsigned char *)bn_out; len = sizeof(bn_out); break;
    case 6: ptr = &x_out[0][0]; len = sizeof(x_out); break;
    case 7: ptr = &rsa_out[0][0]; len = sizeof(rsa_out); break;
    case 8: ptr = p256_out; len = sizeof(p256_out); break;
    case 9: ptr = &gcm_out[0][0]; len = sizeof(gcm_out); break;
#endif
    default: return 0;
    }
    for (i = 0; i < len; ++i) {
        result ^= ptr[i];
        result *= 16777619U;
    }
#ifndef PS2_BENCH_POLY_ONLY
    if (suite == 9)
        for (i = 0; i < sizeof(gcm_tags); ++i) {
            result ^= ((const unsigned char *)gcm_tags)[i];
            result *= 16777619U;
        }
#endif
    return result;
}
