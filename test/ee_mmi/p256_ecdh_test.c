/*
 * Copyright 2026 openssl-retro contributors. Apache License 2.0.
 *
 * ECDHE NIST P-256 test, with independent BigInt affine point
 * arithmetic vectors. Experimental R5900 MMI in the BN 8-word
 * Montgomery helper. C host mode substitutes only two full-width
 * unsigned 32x32 products, not the point algorithm under test.
 *
 * DO NOT reuse these known deterministic test scalars as secret keys.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "crypto/ee_p256_ecdh.h"

static const struct {
    const char *scalar;
    const char *public_key;
    const char *shared_with_next;
} vectors[10] = {
    {"0000000000000000000000000000000000000000000000000000000000000001",
     "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
     "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
     "7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978"},
    {"0000000000000000000000000000000000000000000000000000000000000002",
     "047cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978"
     "07775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1",
     "b01a172a76a4602c92d3242cb897dde3024c740debb215b4c6b0aae93c2291a9"},
    {"0000000000000000000000000000000000000000000000000000000000000003",
     "045ecbe4d1a6330a44c8f7ef951d4bf165e6c6b721efada985fb41661bc6e7fd6c"
     "8734640c4998ff7e374b06ce1a64a2ecd82ab036384fb83d9a79b127a27d5032",
     "741dd5bda817d95e4626537320e5d55179983028b2f82c99d500c5ee8624e3c4"},
    {"0000000000000000000000000000000000000000000000000000000000000004",
     "04e2534a3532d08fbba02dde659ee62bd0031fe2db785596ef509302446b030852"
     "e0f1575a4c633cc719dfee5fda862d764efc96c3f30ee0055c42c23f184ed8c6",
     "83a01a9378395bab9bcd6a0ad03cc56d56e6b19250465a94a234dc4c6b28da9a"},
    {"0000000000000000000000000000000000000000000000000000000000000005",
     "0451590b7a515140d2d784c85608668fdfef8c82fd1f5be52421554a0dc3d033ed"
     "e0c17da8904a727d8ae1bf36bf8a79260d012f00d4d80888d1d0bb44fda16da4",
     "d58d4a589ed27d168ffa3ad7326c48ca94e8e1fe92af9700a12d389033bb291a"},
    {"0000000000000000000000000000000000000000000000000000000000000007",
     "048e533b6fa0bf7b4625bb30667c01fb607ef9f8b8a80fef5b300628703187b2a3"
     "73eb1dbde03318366d069f83a6f5900053c73633cb041b21c55e1a86c1f400b4",
     "3f53a2e061a6f7306cf2ca298f96c9d7e2e162fee67d2d2228d83237856bcca4"},
    {"00000000000000000000000000000000000000000000000000000000075bcd15",
     "04fb50388f29498d0a93ad25ec4c34037b9d3cc3cca4787eb6fedabe2b3003eac8"
     "9f7765ca9d6288e6ff734f5cd08f3a5921cf54b21bb398b50ac0d2577fa07472",
     "45ec7443808a514da4d820d322dc78e58e57e7e5b9d29271d0cf69630f0a64ee"},
    {"0000000000000000000000000000000000123456789abcdef123456789abcdef",
     "04b6740219176abf28fe635a3f10112b252619e0e98c5cc06f1c7b2b7495ed832f"
     "e00e33d8309f89e551d3b1209c74ac87d7141bfa76278b7e9961527e7fff36c5",
     "b6740219176abf28fe635a3f10112b252619e0e98c5cc06f1c7b2b7495ed832f"},
    {"ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550",
     "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
     "b01cbd1c01e58065711814b583f061e9d431cca994cea1313449bf97c840ae0a",
     "7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978"},
    {"ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc63254f",
     "047cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978"
     "f888aaee24712fc0d6c26539608bcf244582521ac3167dd661fb4862dd878c2e",
     "7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978"}
};

#ifdef EE_MMI_BN_HOST_TEST
/* Supplied in host mode only; actual PS2 build links bn-ee-mmi.S. */
void ossl_ee_bn_mul2(uint64_t out[2], const uint32_t x[4],
                      const uint32_t y[4])
{
    out[0] = (uint64_t)x[0]*y[0];
    out[1] = (uint64_t)x[1]*y[1];
}
#endif

static unsigned char digit(unsigned char c)
{
    if (c>='0' && c<='9') return (unsigned char)(c-'0');
    if (c>='a' && c<='f') return (unsigned char)(c-'a'+10);
    return 0xffU;
}
static void decode(unsigned char *dst,const char *hex,size_t size)
{
    size_t i;
    for (i=0;i<size;++i)
        dst[i]=(unsigned char)(16*digit(hex[2*i])+digit(hex[2*i+1]));
}

static int known_vectors(void)
{
    unsigned char scalar[10][32], original[10][32];
    unsigned char pub[10][65], expected[65], shared[32];
    unsigned char peer_copy[65];
    unsigned int i;
    for (i=0;i<10;++i) {
        decode(scalar[i],vectors[i].scalar,32);
        decode(expected,vectors[i].public_key,65);
        if (!ossl_ee_p256_public_from_private(pub[i],scalar[i])
            || memcmp(pub[i],expected,65)!=0) {
            fprintf(stderr,"FAIL: P256 generator multiple %u\n",i);
            return 0;
        }
    }
    memcpy(original,scalar,sizeof(scalar));
    for (i=0;i<10;++i) {
        unsigned int next=(i+1)%10;
        memcpy(peer_copy,pub[next],65);
        if (!ossl_ee_p256_ecdh(shared,scalar[i],pub[next])
            || memcmp(peer_copy,pub[next],65)!=0) {
            fprintf(stderr,"FAIL: P256 ECDH function %u\n",i);
            return 0;
        }
        decode(expected,vectors[i].shared_with_next,32);
        if (memcmp(shared,expected,32)!=0) {
            fprintf(stderr,"FAIL: P256 ECDH BigInt vector %u\n",i);
            return 0;
        }
        /* ECDH commutativity: d_i * Q_j == d_j * Q_i. */
        if (!ossl_ee_p256_ecdh(shared,scalar[next],pub[i])
            || memcmp(shared,expected,32)!=0) {
            fprintf(stderr,"FAIL: P256 ECDH reverse agreement %u\n",i);
            return 0;
        }
    }
    if (memcmp(scalar,original,sizeof(scalar))!=0) {
        puts("FAIL: P-256 scalar buffer modified");
        return 0;
    }
    puts("PASS: P-256 10 independent public keys + 20 shared secrets");
    return 1;
}
static int invalid_inputs(void)
{
    static const char order[] =
        "ffffffff00000000ffffffffffffffff"
        "bce6faada7179e84f3b9cac2fc632551";
    static const char p[] =
        "ffffffff000000010000000000000000"
        "00000000ffffffffffffffffffffffff";
    unsigned char scalar[32]={0},pub[65],bad[65],out[65],zero[65]={0};
    unsigned char shared[32],zero32[32]={0};
    unsigned int i;
    decode(pub,vectors[1].public_key,65);
    memset(out,0x5a,sizeof(out));
    if (ossl_ee_p256_public_from_private(NULL,scalar)
        || ossl_ee_p256_public_from_private(out,NULL)
        || ossl_ee_p256_ecdh(NULL,scalar,pub)
        || ossl_ee_p256_ecdh(shared,NULL,pub)
        || ossl_ee_p256_ecdh(shared,scalar,NULL))
        return 0;
    if (ossl_ee_p256_public_from_private(out,scalar)
        || memcmp(out,zero,65)!=0
        || ossl_ee_p256_ecdh(shared,scalar,pub)
        || memcmp(shared,zero32,32)!=0)
        return 0;
    decode(scalar,order,32);
    if (ossl_ee_p256_public_from_private(out,scalar)
        || memcmp(out,zero,65)!=0)
        return 0;
    memset(scalar,0,32);
    scalar[31]=1;
    memcpy(bad,pub,65);
    bad[0]=2; /* compressed points not supported */
    if (ossl_ee_p256_ecdh(shared,scalar,bad)
        || memcmp(shared,zero32,32))
        return 0;
    memcpy(bad,pub,65);
    decode(bad+1,p,32); /* x >= p */
    if (ossl_ee_p256_ecdh(shared,scalar,bad)) return 0;
    memcpy(bad,pub,65);
    decode(bad+33,p,32); /* y >= p */
    if (ossl_ee_p256_ecdh(shared,scalar,bad)) return 0;
    memcpy(bad,pub,65);
    bad[20]^=0x01; /* on-curve validation */
    if (ossl_ee_p256_ecdh(shared,scalar,bad)) return 0;
    memset(bad,0,65);
    bad[0]=4; /* point (0,0) is not on P-256 */
    if (ossl_ee_p256_ecdh(shared,scalar,bad)) return 0;
    for (i=0;i<32;++i)
        if (shared[i]!=0) {
            puts("FAIL: bad ECDH output not cleared");
            return 0;
        }
    puts("PASS: P-256 scalar range and peer validation");
    return 1;
}

static void bench(void)
{
    unsigned char scalar[32],pub[65],out[32];
    clock_t start,end;
    decode(scalar,vectors[6].scalar,32);
    decode(pub,vectors[7].public_key,65);
    start=clock();
    if (!ossl_ee_p256_ecdh(out,scalar,pub)) return;
    end=clock();
    if (end>start)
        printf("P-256 1 ECDH shared-x: %.3f sec\n",
               (double)(end-start)/CLOCKS_PER_SEC);
    else
        puts("P-256 timing unavailable");
}

int main(int argc,char **argv)
{
    if (!known_vectors() || !invalid_inputs()) return EXIT_FAILURE;
#ifdef EE_MMI_BN_HOST_TEST
    puts("Host model: EE PMULTUW assembly and timing NOT exercised");
#elif defined(EE_MMI_BN_SCALAR_MUL)
    puts("EE P-256 C scalar multiplication baseline");
#else
    puts("EE P-256 PMULTUW Montgomery multiplier linked");
#endif
    if (argc>1 && strcmp(argv[1],"--bench")==0) bench();
    return EXIT_SUCCESS;
}
