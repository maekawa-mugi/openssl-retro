/*
 * Experimental R5900 ECDSA P-256 signature verification tests.
 * Copyright 2026 openssl-retro contributors. Apache-2.0.
 *
 * The three independently generated vectors use fixed private keys
 * d=(1,123456789,0x123456789abcdef123456789abcdef) and fixed signing
 * nonces k=(2,987654321,0xdeadbeefcafebabe123456789).
 * This test uses only public key verification; no RNG is needed on EE.
 * Input digests are SHA-256 of distinct static test labels.
 *
 * The signatures were generated using Python arbitrary-precision
 * modular arithmetic and cryptography's independent P-256 public
 * point computation. The nonce values are for TESTING ONLY.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include "crypto/ee_ecdsa_p256.h"

static const struct {
    const char *pub;
    const char *digest;
    const char *sig;
} vectors[3] = {
    {
        "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
        "c6d102df1b793d086c3f05aa99fa0693c34ac6886598ff4440f0d13ca803d300",
        "7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978a1e1befbd43e46437b489ed6cf5790abc1ea18356ec58d3cf37e0d1c77b5363c"
    },
    {
        "04fb50388f29498d0a93ad25ec4c34037b9d3cc3cca4787eb6fedabe2b3003eac89f7765ca9d6288e6ff734f5cd08f3a5921cf54b21bb398b50ac0d2577fa07472",
        "a310bc5d73fdae86e05db3bd5b69200109b02e64a09908f6f8d4870e29d26ffa",
        "e13800beaf6a7dede4dddf874e4adcc271bf069e8cfc2c5ef989084bec33b260fa648c67c30a75bf748791f3ef6402669213f852285ffdd29dd8d0597317ea27"
    },
    {
        "04b6740219176abf28fe635a3f10112b252619e0e98c5cc06f1c7b2b7495ed832fe00e33d8309f89e551d3b1209c74ac87d7141bfa76278b7e9961527e7fff36c5",
        "98f342502afed365e0ae1931658ec4535cfd8f4a0d73af88ec400d83c724c8fa",
        "6f78b24b1a2f04eca4d549ea2b367e3a736ccf728ef5d87b1ad62b9785b18067881c6bd995c6c0d1040d7617a8891a226d757c29c103e36159d312fffba676ea"
    },
};

static unsigned int nybble(char c)
{
    if (c >= '0' && c <= '9') return (unsigned int)(c - '0');
    if (c >= 'a' && c <= 'f') return (unsigned int)(c - 'a') + 10U;
    return 16U;
}

static int fromhex(unsigned char *dst, size_t len, const char *hex)
{
    size_t i;
    for (i = 0; i < len; ++i) {
        unsigned int hi = nybble(hex[2*i]), lo = nybble(hex[2*i+1]);
        if (hi >= 16 || lo >= 16) return 0;
        dst[i] = (unsigned char)((hi << 4) | lo);
    }
    return hex[2*len] == '\0';
}

static int one_vector(unsigned int index)
{
    static const char order_hex[] =
        "ffffffff00000000ffffffffffffffff"
        "bce6faada7179e84f3b9cac2fc632551";
    unsigned char pub[65], digest[32], sig[64], oldpub[65], oldhash[32];
    unsigned char oldsig[64], order[32];
    int result;
    if (!fromhex(pub, 65, vectors[index].pub)
            || !fromhex(digest, 32, vectors[index].digest)
            || !fromhex(sig, 64, vectors[index].sig)
            || !fromhex(order, 32, order_hex)) {
        fprintf(stderr, "FAIL: invalid ECDSA known-answer vector %u\n",
                index);
        return 0;
    }
    memcpy(oldpub, pub, 65);
    memcpy(oldhash, digest, 32);
    memcpy(oldsig, sig, 64);
    result = ossl_ee_ecdsa_p256_verify(pub, digest, sig);
    if (result != 1) {
        fprintf(stderr, "FAIL: valid ECDSA vector %u returned %d\n",
                index, result);
        return 0;
    }
    if (memcmp(pub, oldpub, 65) || memcmp(digest, oldhash, 32)
            || memcmp(sig, oldsig, 64)) {
        puts("FAIL: ECDSA verification mutated inputs");
        return 0;
    }

#define MUST_REJECT(what) do {                                           \
        result = ossl_ee_ecdsa_p256_verify(pub, digest, sig);           \
        if (result != 0) {                                               \
            fprintf(stderr,"FAIL: %s for case %u gave %d\n", what,       \
                    index, result);                                      \
            return 0;                                                    \
        }                                                                \
    } while (0)

    digest[31] ^= 1U;
    MUST_REJECT("changed digest");
    memcpy(digest, oldhash, sizeof(digest));

    sig[31] ^= 1U;
    MUST_REJECT("changed r");
    memcpy(sig, oldsig, sizeof(sig));

    sig[63] ^= 1U;
    MUST_REJECT("changed s");
    memcpy(sig, oldsig, sizeof(sig));

    memset(sig, 0, 32);
    MUST_REJECT("zero r");
    memcpy(sig, oldsig, sizeof(sig));

    memset(sig + 32, 0, 32);
    MUST_REJECT("zero s");
    memcpy(sig, oldsig, sizeof(sig));

    memcpy(sig, order, 32);
    MUST_REJECT("r equals group order");
    memcpy(sig, oldsig, sizeof(sig));

    memcpy(sig + 32, order, 32);
    MUST_REJECT("s equals group order");
    memcpy(sig, oldsig, sizeof(sig));

    pub[0] = 0x02;
    MUST_REJECT("compressed EC point unsupported");
    memcpy(pub, oldpub, sizeof(pub));

    memset(pub + 1, 0xff, 64);
    MUST_REJECT("invalid P-256 public point");
    memcpy(pub, oldpub, sizeof(pub));

#undef MUST_REJECT
    return 1;
}

static void benchmark(void)
{
    unsigned char pub[65], digest[32], sig[64];
    unsigned int i, count = 16, valid = 0;
    clock_t begin, end;
    if (!fromhex(pub, 65, vectors[0].pub)
            || !fromhex(digest, 32, vectors[0].digest)
            || !fromhex(sig, 64, vectors[0].sig)) {
        puts("ECDSA bench input error");
        return;
    }
    begin = clock();
    for (i = 0; i < count; ++i)
        valid += (ossl_ee_ecdsa_p256_verify(pub, digest, sig) == 1);
    end = clock();
    if (begin == (clock_t)-1 || end <= begin)
        puts("ECDSA timing unavailable");
    else
        printf("ECDSA P-256 %u verifies: %.4fs, %.2f verifications/s "
               "(passed=%u)\n", count,
               (double)(end-begin)/CLOCKS_PER_SEC,
               (double)count*CLOCKS_PER_SEC/(double)(end-begin), valid);
}

int main(int argc, char **argv)
{
    unsigned int i;
    unsigned char p[65] = {0}, h[32] = {0}, rs[64] = {0};
    if (ossl_ee_ecdsa_p256_verify(NULL,h,rs) != 0
            || ossl_ee_ecdsa_p256_verify(p,NULL,rs) != 0
            || ossl_ee_ecdsa_p256_verify(p,h,NULL) != 0) {
        puts("FAIL: NULL argument accepted");
        return EXIT_FAILURE;
    }
    for (i = 0; i < 3; ++i)
        if (!one_vector(i))
            return EXIT_FAILURE;
    puts("PASS: ECDSA P-256 SHA-256 three valid public vectors, "
         "27 tampering/range/point rejections and NULL arguments");
#ifdef EE_MMI_ECDSA_SCALAR
    puts("ECDSA scalar BN_mod_mul verification baseline");
#else
    puts("ECDSA two EE-style Montgomery scalar multiplications");
#endif
    if (argc > 1 && strcmp(argv[1], "--bench") == 0)
        benchmark();
    return EXIT_SUCCESS;
}
