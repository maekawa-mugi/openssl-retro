/*
 * Copyright 2026 openssl-retro contributors. Apache License 2.0.
 *
 * Deterministic independent RSA-2048 test keys generated with
 * a separate BigInt prime generator and modular inverse.
 * Only PUBLIC moduli, signatures and SHA-256 digests are embedded.
 * No private keys or primes are stored in this test.
 *
 * This test evaluates four independent RSA public moduli, e=65537,
 * strict PKCS#1 v1.5 SHA256 padding and invalid signature handling.
 */
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "crypto/ee_rsa_verify.h"

#ifdef EE_MMI_BN_HOST_TEST
/* Host-only two-product model; the PS2 runner links bn-ee-mmi.S. */
void ossl_ee_bn_mul2(uint64_t out[2], const uint32_t x[4],
                     const uint32_t y[4])
{
    out[0] = (uint64_t)x[0] * y[0];
    out[1] = (uint64_t)x[1] * y[1];
}
#endif

#define K 256
static const struct {
    const char *mod;
    const char *sig;
    const char *dig;
} fixture[4] = {
    {
        "f42b416abb3762af7cb185d1de22fb8c0dda7b1c5e9e07b50e78eb39f5d88bf9"
        "7a7dc65d301488bd25271ac336898355ef7406f922ff5a76ef5361417b71e6cc"
        "7c14f8179d4e650d76205f5e72076059f1599436a3c9162752888f00303d1a1a"
        "9e68836a2e5ac2cf02516085adb8d7b0e3aeeb4c21f9fa8bcc1e0ecef312ce31"
        "0207c5c740773e1fbb9134974e7b3483126d8e5ebca0a4c7bc15057901889fd2"
        "4d8003c6103dec87166cc7ec16ff6cd245396817034e2d891ad5eea17224745a"
        "e3b797e8dd31ecdc852c5f014003bcc829ccb86e15c4d313bcddd71ee2970f86"
        "f864a9d0edaeb61d99795301d84f93458b98b9bbe194198a87264cb7367d53cf",
        "f1fed798729d332388603631f7a1ee14b083aebd61c8175655cb14f92f5046bc"
        "f3b46594d0e8ad5b6ee756f4d2486cd239c1374dbbed3eede63c018ccf96273e"
        "45754266888ec18b3bf41869dc92b710bcea614502dc44c00b553090d2a405df"
        "f8a928b1f2cbf8696f8e9d4dd1f33402aabf65fb5eb9816c8e24536e415615f1"
        "e300c518d33efc389b29b00bb2426698a572fc3f238deed303a178e6f7e29079"
        "f9d6b2d91be21786e216a1ca7d28966bae6428b3efd2a3f81e52dd4b0653384c"
        "fa30503f7db015b6547ce085c11f25782496474b1b271c90d60406a906212931"
        "f4e495311eed059d20d202f7b5ff8d5a833e58eeebb6ff9c166c58b915ca30ee",
        "f02a2aace30bc103988415dea30d0d88239131dec3d56868aaeb49f721d044b1"
    },
    {
        "b3e3d9a11f7ff594dbbac946e083492d2435f4e7fdbea3f00dab6ec789c1b81f"
        "d8cdbf79a30a48483590590b28f1810f8885581d27608b3f493b0940009628e5"
        "daa8ff337e33694a8f58d399fbd8510037dcdd7cb7aee9ecfd9454995e6f5904"
        "b23919f94499f52a6bbbf34db015661cecac12b7498588604bf4dd6ea92a1ea3"
        "1aaf82c4cbb86cf46000bc0367d44ae43118f5305f3d547b8e592c7bcc299530"
        "2800aac8ddf88c4875c251a36faed5caaca47187ca6f69b9ae9ff9d6bfbd1265"
        "ef074449bb1f9412b683050739ab7db4a615d9a5f56a8947fea32a90c73a53a3"
        "1f5b19efb880e16e9091229e456c23bcdd3eb9f0fa1c81c958ab3818dfca02f9",
        "7c06ac2f6c6ba1395aa7cfe039ebae04375460702a95880836cc3774e9ad83eb"
        "dd57eac708c5d91d1f83a6d20aa54840c93553683c5ecdba42c520cf4ff5c968"
        "2c4b7ac6ea9b80c863b392fbc844102317a9b0403dd34869de3edb2288d28365"
        "95488deb1454f2900eb4ed7efb53c35f7ba355d848f5a89f9fd96377ffdb977c"
        "6f24f72fc381a3ba4bf785b1d0061a39096df47f1a81df252501ca128cfc0d8c"
        "e5520d39c4f8ef783cf06c53a9d4ebb9696651764afc1680e7a337ebf2893cf9"
        "40294aff396f63bf707f2db0c68e54f6d3a673d972a0bbd42593d436d3feeb83"
        "d76e4b4516ef5b277642a34994bf1d22eaf0aeba4da98f4d6cd450693edfb6c4",
        "b11975a9a3b811101507a8a5be945ffdf4c1ac0d643e5e4c3236f10d4ca3ac9d"
    },
    {
        "c0e4db4c67cf84d2e6db0e3e9e16e1f87735acc1acf743c11c83df13697b51a6"
        "b29990f01f505b18d338be9a7fe2afb60cdfbd84231a1bb6e20e9e643bfc8b37"
        "505ec166a5e5fec43215c28be327ac95c348f5b12626fb943c5c6209e564ca99"
        "985e99846202e1d7bc89e397af3ebcaab275276602dc873dc95ad23f8fd1f365"
        "a80db82ce18906ff4baafd9af1211a1b4ebae3ef3576e65263d75ad0b3c80671"
        "0600acc9336c457f1133951d7a01636bf66755247752f720018bc19e81e6a249"
        "584ea23ad51981460fc4b4b75ce2593fa70336b0c819c90f3bb56f24fee12d9b"
        "3170244e9e86318f96c41e729a65095257b36a8ffc95125dcbcd9fe49aae6399",
        "98debc02607b1b6fd6c9eaa26f933ca33be4121e5fda46f402e15bcde5eb761b"
        "859c273da0605afa294b77a1bf3d039c504072b9d0f62e8341b7c40ad3a8fa0d"
        "6ee8d8360c4635c56fa24f297ff751d3f25e341c4ce33e2e9a608b2f3bff2a43"
        "e2dbc76dc5092d089bc37c6b8108e29575f42b33152fb42c9cad500e5f6f2835"
        "06474236beabf6e981faa050c0ab21d17ddbeb075ad61b208bf0eab2cb24cac4"
        "7efbd195fd30c93b72701def4c62648db24c85896bc8e81b4a4ea8baf2ecefec"
        "59eded74feea1460cd9a85881de335e376fff2f6d736e66aba7664ca7e3066df"
        "b0f9dbd9903370d7efb13a545ed0a1a8a45ef753d6610169cbc8f39ca15fb938",
        "a8ff42470c7e3b86926158cee5be10fdeaaf63f154c494100a26a706e4850c48"
    },
    {
        "cf5ee3c9d78797055b7440852fadb6ab611d6940e09f37ba244215c4d011ae41"
        "3a64c7d22886c24a330ef1e00fe1d663513326d1c4173b3c11a872c227950bdf"
        "24d5da72a631b27c16c60490ba12e77703b5f174daf6361a3fe0b96e74d93380"
        "31bb9e44ec2e851fbdae482ba59aed6e1a3204f4df6ada176dc8b86b32718bba"
        "7606fbbcfc486ae0c35b7c1804706a0e5e13f810e7ac89ef9533726d55c1f5f4"
        "a8c8bcc71638c4ff806aac056982709c1c505f0482cc2529409673c00e3dc263"
        "dcbc62e3aa4d537e61967b2cc3e45354217e630dc296f797f2acdd128e0f61dd"
        "e9ca767ff1529d68ba1043fd6cacce4984e5daa9481dce1620bfe12105a40d41",
        "8d35176bab0b327ad5c57bfe8eeb8eed07ea0c2f5ee9151cd8771399833835f5"
        "89ab56df51dfcc2637a81b572ee94c93de8282e39f00bbb16c0a231536fbe999"
        "1b3523c332da7b7c425e83a4b803ce5050cae4d2b7c3430a53366eba02b7cd90"
        "4df56b45bec6b137ee0a79745c5b60130a47cad3d0441b5717f42ed6164cfd28"
        "6baf1742490aebdb5d3fae80ea3e4677280394fe5de44deab18d157842b1433a"
        "6d2f4a2bcfab51f000adb6c6f5894107f1367ee3bc82c3b0295e51c45b72e6e3"
        "5c11c581a50d07ed95be7a3d11fc9af9e41cdc198e3201982ef2a01f4013d471"
        "cdc783b5e9bcfac96b4755d8f450ba4f9724dd51c5016cd48bf34c09f43dd613",
        "d86d8a4d216ad85c9ffc4e5aafc899875ce139d0a3a10c58d76b14abeb22292d"
    }
};

static unsigned char nibble(unsigned char c)
{
    if (c >= '0' && c <= '9') return (unsigned char)(c-'0');
    if (c >= 'a' && c <= 'f') return (unsigned char)(c-'a'+10);
    return 255;
}
static void unhex(unsigned char *dst, const char *src, size_t count)
{
    size_t i;
    for (i=0;i<count;++i)
        dst[i] = (unsigned char)(16*nibble(src[i*2])
                                + nibble(src[i*2+1]));
}

static int fixtures_test(void)
{
    static const unsigned char der[] = {
        0x30,0x31,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,
        0x65,0x03,0x04,0x02,0x01,0x05,0x00,0x04,0x20
    };
    unsigned char n[4][K], s[4][K], old_s[4][K];
    unsigned char d[4][32], recovered[4][K], old_n[4][K];
    unsigned char expected[K], valid[4];
    unsigned char *out[4];
    const unsigned char *sig[4], *mod[4];
    size_t lane,i;
    for (lane=0;lane<4;lane++) {
        unhex(n[lane],fixture[lane].mod,K);
        unhex(s[lane],fixture[lane].sig,K);
        unhex(d[lane],fixture[lane].dig,32);
        out[lane] = recovered[lane];
        sig[lane] = s[lane];
        mod[lane] = n[lane];
    }
    memcpy(old_n,n,sizeof(n));
    memcpy(old_s,s,sizeof(s));
    memset(expected,0xff,K);
    expected[0]=0;
    expected[1]=1;
    expected[K-52]=0;
    memcpy(expected+K-51,der,sizeof(der));

    if (!ossl_ee_rsa_public65537_4(out,sig,mod,K)) {
        puts("FAIL: RSA public exponentiation");
        return 0;
    }
    for (lane=0;lane<4;lane++) {
        memcpy(expected+K-32,d[lane],32);
        if (memcmp(recovered[lane],expected,K)) {
            fprintf(stderr,"FAIL: RSA-2048 e65537 representative lane %lu\n",
                    (unsigned long)lane);
            return 0;
        }
    }
    if (!ossl_ee_rsa_pkcs1_sha256_verify4(valid,sig,mod,d,K)) {
        puts("FAIL: RSA PKCS1 SHA256 call");
        return 0;
    }
    for (lane=0;lane<4;lane++)
        if (valid[lane] != 1) {
            puts("FAIL: valid RSA signatures rejected");
            return 0;
        }

    /* Change a signature in lane 0, and digest in lane 1.
     * Put signature >= modulus in lane 2. Lane 3 stays valid. */
    s[0][K-1] ^= 1U;
    d[1][0] ^= 0x80U;
    memcpy(s[2],n[2],K);
    if (!ossl_ee_rsa_pkcs1_sha256_verify4(valid,sig,mod,d,K)
        || valid[0] || valid[1] || valid[2] || valid[3]!=1) {
        puts("FAIL: RSA invalid signature/digest/range detection");
        return 0;
    }

    /* Out-of-range representatives must fail in raw public API. */
    if (ossl_ee_rsa_public65537_4(out,sig,mod,K)) {
        puts("FAIL: RSA input >= modulus accepted");
        return 0;
    }
    memcpy(s,old_s,sizeof(s));
    unhex(d[1],fixture[1].dig,32);
    if (memcmp(n,old_n,sizeof(n)) || memcmp(s,old_s,sizeof(s))) {
        puts("FAIL: RSA changed caller's modulus/signature");
        return 0;
    }

    /* Alias input and output is supported by public exponent API. */
    for (lane=0;lane<4;lane++) out[lane] = s[lane];
    if (!ossl_ee_rsa_public65537_4(out,sig,mod,K)) {
        puts("FAIL: RSA in-place public exponent");
        return 0;
    }
    for (lane=0;lane<4;lane++) {
        memcpy(expected+K-32,d[lane],32);
        if (memcmp(s[lane],expected,K)) {
            puts("FAIL: RSA in-place result mismatch");
            return 0;
        }
    }

    for (i=0;i<4;++i) valid[i]=0xa5;
    if (ossl_ee_rsa_pkcs1_sha256_verify4(NULL,sig,mod,d,K)
        || ossl_ee_rsa_pkcs1_sha256_verify4(valid,NULL,mod,d,K)
        || ossl_ee_rsa_pkcs1_sha256_verify4(valid,sig,NULL,d,K)
        || ossl_ee_rsa_pkcs1_sha256_verify4(valid,sig,mod,NULL,K)
        || ossl_ee_rsa_pkcs1_sha256_verify4(valid,sig,mod,d,129)
        || ossl_ee_rsa_public65537_4(NULL,sig,mod,K)
        || ossl_ee_rsa_public65537_4(out,sig,mod,128+4))
        return 0;
    for (i=0;i<4;++i)
        if (valid[i]!=0xa5) {
            puts("FAIL: invalid RSA arguments modified result flags");
            return 0;
        }
    puts("PASS: four distinct RSA-2048 e65537 / PKCS1 SHA256 signatures");
    return 1;
}

static int prepared_key_test(void)
{
    static ossl_ee_rsa_public_key keys[4];
    const ossl_ee_rsa_public_key *keyptr[4];
    unsigned char moduli[4][K], in[4][K], reference[4][K];
    unsigned char prepared[4][K], sentinel[4][K];
    unsigned char *out[4];
    const unsigned char *input[4], *mods[4];
    size_t lane, i;

    for (lane = 0; lane < 4; ++lane) {
        unhex(moduli[lane], fixture[lane].mod, K);
        unhex(in[lane], fixture[lane].sig, K);
        input[lane] = in[lane];
        mods[lane] = moduli[lane];
        out[lane] = reference[lane];
        if (!ossl_ee_rsa_public_key_init(&keys[lane], moduli[lane], K)) {
            puts("FAIL: RSA prepared-key initialization");
            return 0;
        }
        keyptr[lane] = &keys[lane];
    }
    if (!ossl_ee_rsa_public65537_4(out, input, mods, K)) {
        puts("FAIL: legacy RSA reference for prepared-key test");
        return 0;
    }
    for (lane = 0; lane < 4; ++lane)
        out[lane] = prepared[lane];
    /* Two repeated public operations must work with one initialized
     * key context and return identical bytes as the legacy function. */
    for (i = 0; i < 2; ++i) {
        if (!ossl_ee_rsa_public65537_prepared4(out, input, keyptr)) {
            puts("FAIL: prepared RSA execution");
            return 0;
        }
        for (lane = 0; lane < 4; ++lane)
            if (memcmp(prepared[lane], reference[lane], K)) {
                puts("FAIL: cached R2 differs from legacy exponent");
                return 0;
            }
    }

    /* An invalid input in lane 2 must prevent ANY output changes. */
    memcpy(in[2], moduli[2], K);
    memset(sentinel, 0xa5, sizeof(sentinel));
    for (lane = 0; lane < 4; ++lane)
        out[lane] = sentinel[lane];
    if (ossl_ee_rsa_public65537_prepared4(out, input, keyptr)) {
        puts("FAIL: prepared RSA accepted representative >= modulus");
        return 0;
    }
    for (lane = 0; lane < 4; ++lane)
        for (i = 0; i < K; ++i)
            if (sentinel[lane][i] != 0xa5) {
                puts("FAIL: prepared RSA touched output on invalid input");
                return 0;
            }
    unhex(in[2], fixture[2].sig, K);

    /* Exact in-place output and input aliases, and no recalculation. */
    for (lane = 0; lane < 4; ++lane)
        out[lane] = in[lane];
    if (!ossl_ee_rsa_public65537_prepared4(out, input, keyptr))
        return 0;
    for (lane = 0; lane < 4; ++lane)
        if (memcmp(in[lane], reference[lane], K))
            return 0;
    if (ossl_ee_rsa_public_key_init(&keys[0], moduli[0], 129)
        || ossl_ee_rsa_public65537_prepared4(NULL, input, keyptr)
        || ossl_ee_rsa_public65537_prepared4(out, NULL, keyptr)
        || ossl_ee_rsa_public65537_prepared4(out, input, NULL))
        return 0;
    for (lane = 0; lane < 4; ++lane) {
        const unsigned char *p;
        ossl_ee_rsa_public_key_clear(&keys[lane]);
        p = (const unsigned char *)&keys[lane];
        for (i = 0; i < sizeof(keys[lane]); ++i)
            if (p[i] != 0)
                return 0;
    }
    puts("PASS: reusable RSA prepared R2, four keys, in-place and invalid input");
    return 1;
}

static int sizes_test(int extended)
{
    static const size_t sizes[] = {128,256,384,512};
    unsigned char n[4][512], in[4][512], outbuf[4][512];
    unsigned char *out[4];
    const unsigned char *inputs[4], *mods[4];
    size_t k,lane,j,i,ncases = extended?4:2;
    for (j=0;j<ncases;++j) {
        k=sizes[j];
        for (lane=0;lane<4;++lane) {
            /* Distinct, odd, full-size public moduli and representatives
             * equal to one. 1^65537 mod n must remain 1. */
            for (i=0;i<k;++i) n[lane][i]=(unsigned char)(
                0x50U + (unsigned int)i*29U + (unsigned int)lane*13U);
            n[lane][0] |= 0x80U;
            n[lane][k-1] |= 1U;
            memset(in[lane],0,k);
            in[lane][k-1]=1;
            memset(outbuf[lane],0x5a,sizeof(outbuf[lane]));
            out[lane]=outbuf[lane];
            inputs[lane]=in[lane];
            mods[lane]=n[lane];
        }
        if (!ossl_ee_rsa_public65537_4(out,inputs,mods,k)) {
            fprintf(stderr,"FAIL: RSA-%lu-bit public one\n",
                    (unsigned long)(8*k));
            return 0;
        }
        for (lane=0;lane<4;++lane) {
            if (memcmp(outbuf[lane],in[lane],k)) {
                puts("FAIL: RSA exponent(1) != 1");
                return 0;
            }
            for (i=k;i<512;++i)
                if (outbuf[lane][i] != 0x5a) {
                    puts("FAIL: RSA output overrun");
                    return 0;
                }
        }
    }
    puts("PASS: RSA-1024/2048 public 1 (3072/4096 with --extended)");
    return 1;
}

static void benchmark(void)
{
    unsigned char n[4][K], s[4][K], outbuf[4][K];
    unsigned char *outputs[4];
    const unsigned char *sig[4], *mod[4];
    clock_t start, end;
    unsigned int i, lane;
    for (lane=0;lane<4;++lane) {
        unhex(n[lane],fixture[lane].mod,K);
        unhex(s[lane],fixture[lane].sig,K);
        outputs[lane]=outbuf[lane];
        sig[lane]=s[lane];
        mod[lane]=n[lane];
    }
    start=clock();
    for (i=0;i<2;++i)
        if (!ossl_ee_rsa_public65537_4(outputs,sig,mod,K)) {
            puts("FAIL: RSA benchmark exponentiation");
            return;
        }
    end=clock();
    if (start == (clock_t)-1 || end <= start)
        puts("RSA-2048 benchmark: clock() unavailable");
    else
        printf("RSA-2048 e65537 4 lanes x2: %.3f sec, %.1f public ops/sec\n",
               (double)(end-start)/CLOCKS_PER_SEC,
               8.0*CLOCKS_PER_SEC/(double)(end-start));
}

int main(int argc,char **argv)
{
    int extended = argc>1 && strcmp(argv[1],"--extended")==0;
    int run_bench = argc>1 && strcmp(argv[1],"--bench")==0;
    if (!fixtures_test() || !prepared_key_test() || !sizes_test(extended))
        return EXIT_FAILURE;
#ifdef EE_MMI_BN_SCALAR_MUL
    puts("RSA portable Montgomery multiplication baseline");
#elif defined(EE_MMI_BN_HOST_TEST)
    puts("RSA HOST C emulation, no EE PMULTUW executed");
#else
    puts("RSA R5900 PMULTUW core linked, hardware still unverified");
#endif
    if (run_bench) benchmark();
    return EXIT_SUCCESS;
}
