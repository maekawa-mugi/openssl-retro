/*
 * Copyright 2026 openssl-retro contributors. Licensed under Apache-2.0.
 * RFC 7748 X25519 4-way batch tests, independent BigInt oracle vectors,
 * exact fused convolution sums and basic input/output guard checks.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "crypto/ee_mmi.h"

static uint32_t randstate;
static uint32_t rand32(void)
{
    randstate ^= randstate << 13;
    randstate ^= randstate >> 17;
    randstate ^= randstate << 5;
    return randstate;
}
#ifdef EE_MMI_HOST_TEST
/* Portable reference for the EE PMULTUW/PMADDUW convolution kernel.
 * It is NOT an instruction emulator and cannot verify the EE ABI. */
void ossl_ee_x25519_mul_sums4(uint64_t sums[10][4],
                              const uint32_t a[10][4],
                              const uint32_t b[40][4])
{
    unsigned int k, i, lane;
    for (k = 0; k < 10; ++k) {
        for (lane = 0; lane < 4; ++lane)
            sums[k][lane] = 0;
        for (i = 0; i < 10; ++i) {
            unsigned int j = (k + 10 - i) % 10;
            unsigned int m = (i > k ? 20 : 0)
                           + ((i & j & 1U) ? 10 : 0);
            for (lane = 0; lane < 4; ++lane)
                sums[k][lane] += (uint64_t)a[i][lane]
                                               * b[m+j][lane];
        }
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
    for (i = 0; i < 32; ++i)
        out[i] = (unsigned char)(unhex(hex[2*i])*16
                              + unhex(hex[2*i+1]));
}
static int match(const unsigned char *out, const char *hex)
{
    unsigned int i;
    for (i = 0; i < 32; ++i)
        if (out[i] != (unsigned char)(unhex(hex[2*i])*16
                                   + unhex(hex[2*i+1])))
            return 0;
    return 1;
}
static const char *golden[8][4] = {
    { "c83f5acf8430780afd3700913b522246bacff15ae878acf16731befc6e15d560", "7ce7e44bc8f30497510c3412f9fc69e6e47592ead293499197701d8e6fa31128", "68ef5c2745b051ad9d970a71e6014400096ef627d53c87f38a983526d0226d6f", "3fbfb7d773e10c47112856e36cf6dd77f5904c972fe1a165d258ad2808eb5d47" },
    { "29a58d6079979a6f642af6cd0a10aac9e367ab2e23e3d11cd1059e665057c00b", "d75ebe863db7b1c3a1b3480157b8f53f1ce2b47733508a7bc01de892bfcd1438", "569907aa9c06ecfccea7868d42f533ff0857421bccacf3020c3052398e0cf34a", "b4b267ea1bae908623f18a96b049b8cb6c3eb141b1e6027465067bceb8fd617c" },
    { "74dc8f5ee27e692b54f3cd4efe17aa7e6a34252cd222e4bedf4a5d2a55ae0019", "088c6389e915e8862d37addaa18ef066dc2744764559603456c320b8df416e0b", "4b99324b731b28cd298b29f510e06bc74cc85074dcd2a4eea3a293fe242f4a77", "a1e36da03bd285e2057b0adf73c7db90123f52a86fed315850c93764f9c2653f" },
    { "4940131841151646fcb30752352afe22bdd5cfdd03a44baefff3afc224b6b871", "88f39fb0c576110a73dd935c2363c3fd909b6c669ec968496b92850ceb26965a", "749162a889966680322c8c1296149891fd8e601f1b64670eed179c039f04650d", "7698cd3ab8e8d362e5d9331633c2deaba24996fe4c52bb4e6e34d7dccdeb9d11" },
    { "4aae28e32908872d1c04fc70d17f231bf81c2f369012edf61bf1a8852743e247", "09fea08fc9d84fb3e178b7a7bc5048aa73bd6108f9c31ea2313996df7a010d29", "b9bd1b0fd96e001b06486e1a4cdf3cee3ecff1ab9a24ff35df24c6b8ffa61120", "47cad41599b6aa2020b6faa57054f2b97e1b96f30cd90d7791108a57e1918624" },
    { "5673f122ff572780a94ea407ff4c0ce28ba13a31299f45458a358dcc92c5cf09", "52a291cbebb06bd6cb938649ce8ff05a3275bd1d75c08ab6fbf2bf8dbb21d059", "845b7ef9c04b966625639d7d8fea1876aeb464bf6e36adbfa208beff50f38e53", "4003c39d12cdf75873c33ec9fe73eb4bc433969980070d5d54938e5288338104" },
    { "84272b5b7c96e34c09dab01b47e538c158108bb7a773a4f047760297c05b4a0a", "78c1584eeb84b988966f60267154c038985bf2b292163664ec50eb0422102d64", "ce176a92ca5683094f9836d84f360fd348656a85905e8270642f9bc98dc6f202", "89c530b26055263296ee0f15254081e4b94a17f66cd2236fdfd61eef5014125f" },
    { "3d13d8f760b67eca6224bc8b17ee2d044d93d1b9e2e52ac61ae5664b6a73b965", "e29f9ba886985757d1ff02daab2d291ac3242326476907e2bba281737ad53735", "d6db3e1b53d97e9164fd531956c0b9c47642bd02da25e33a4a65de093bbf4b33", "0157aed193e87e27f02dc107effc2a541a4a8ce0ba125df36f23791fbffb623b" },
};

static int rfc7748(void)
{
    static const char alice_key[] =
        "77076d0a7318a57d3c16c17251b2664"
        "5df4c2f87ebc0992ab177fba51db92c2a";
    static const char bob_key[] =
        "5dab087e624a8a4b79e17f8b83800ee6"
        "6f3bb1292618b6fd1c2f8b27ff88e0eb";
    static const char alice_pub[] =
        "8520f0098930a754748b7ddcb43ef75a"
        "0dbf3a0d26381af4eba4a98eaa9b4e6a";
    static const char bob_pub[] =
        "de9edb7d7b7dc1b4d35b61c2ece43537"
        "3f8343c85b78674dadfc7e146f882b4f";
    static const char shared[] =
        "4a5d9d5ba4ce2de1728e3bf480350f25"
        "e07e21c947d19e3376f09b3c1e161742";
    unsigned char scalar[4][32], point[4][32]={{0}}, out[4][32];
    unsigned char original_scalar[4][32], original_point[4][32];
    unsigned int i;
    decode(scalar[0], alice_key);
    decode(scalar[1], bob_key);
    decode(scalar[2], alice_key);
    decode(scalar[3], bob_key);
    point[0][0] = 9;
    point[1][0] = 9;
    decode(point[2], bob_pub);
    decode(point[3], alice_pub);
    memcpy(original_scalar, scalar, sizeof(scalar));
    memcpy(original_point, point, sizeof(point));

    if (!ossl_ee_x25519_scalar_mult4(out, scalar, point)
        || !match(out[0], alice_pub)
        || !match(out[1], bob_pub)
        || !match(out[2], shared)
        || !match(out[3], shared)) {
        puts("FAIL: RFC 7748 Alice/Bob/public/shared");
        return 0;
    }
    if (memcmp(scalar, original_scalar, sizeof(scalar)) != 0
        || memcmp(point, original_point, sizeof(point)) != 0) {
        puts("FAIL: X25519 modified input scalar or point");
        return 0;
    }
    /* RFC 7748 ignores topmost bit of the u-coordinate. */
    for (i = 0; i < 4; ++i)
        point[i][31] ^= 0x80;
    if (!ossl_ee_x25519_scalar_mult4(out, scalar, point)
        || !match(out[0], alice_pub)
        || !match(out[1], bob_pub)
        || !match(out[2], shared)
        || !match(out[3], shared)) {
        puts("FAIL: X25519 point top-bit masking");
        return 0;
    }
    return 1;
}

static int random_oracle_vectors(void)
{
    unsigned char scalar[4][32], point[4][32], out[4][32];
    unsigned char original_scalar[4][32], original_point[4][32];
    unsigned int iteration, i, lane;
    randstate = 0x25519ee1U;

    for (iteration = 0; iteration < 8; ++iteration) {
        for (lane = 0; lane < 4; ++lane)
            for (i = 0; i < 32; ++i)
                scalar[lane][i] = (unsigned char)rand32();
        for (lane = 0; lane < 4; ++lane)
            for (i = 0; i < 32; ++i)
                point[lane][i] = (unsigned char)rand32();
        memcpy(original_scalar, scalar, sizeof(scalar));
        memcpy(original_point, point, sizeof(point));

        if (!ossl_ee_x25519_scalar_mult4(out, scalar, point)) {
            puts("FAIL: X25519 rejected non-null inputs");
            return 0;
        }
        for (lane = 0; lane < 4; ++lane)
            if (!match(out[lane], golden[iteration][lane])) {
                fprintf(stderr, "FAIL: X25519 BigInt golden %u lane %u\n",
                        iteration, lane);
                return 0;
            }
        if (memcmp(scalar, original_scalar, sizeof(scalar)) != 0
            || memcmp(point, original_point, sizeof(point)) != 0) {
            puts("FAIL: X25519 changed randomly generated input");
            return 0;
        }
    }
    return 1;
}

static int invalid_and_zero(void)
{
    unsigned char scalar[4][32]={{0}};
    unsigned char point[4][32]={{0}}, out[4][32];
    unsigned int i, j;
    if (ossl_ee_x25519_scalar_mult4(NULL, scalar, point)
        || ossl_ee_x25519_scalar_mult4(out, NULL, point)
        || ossl_ee_x25519_scalar_mult4(out, scalar, NULL))
        return 0;
    /* Zero coordinate is a low-order point. Pure RFC X25519 maps
     * it to zero; protocols must reject all-zero shared secrets. */
    for (i = 0; i < 4; ++i)
        for (j = 0; j < 32; ++j)
            scalar[i][j] = (unsigned char)(0x55U + i + j);
    if (!ossl_ee_x25519_scalar_mult4(out, scalar, point))
        return 0;
    for (i = 0; i < 4; ++i)
        for (j = 0; j < 32; ++j)
            if (out[i][j] != 0) {
                puts("FAIL: X25519 low-order point handling");
                return 0;
            }
    return 1;
}

#ifndef EE_MMI_X25519_SCALAR_MULTIPLY
static int sums_check(void)
{
    struct {
        uint32_t before[4];
        uint64_t sums[10][4];
        uint32_t after[4];
    } __attribute__((aligned(16))) buffer;
    uint32_t a[10][4] __attribute__((aligned(16)));
    uint32_t b[40][4] __attribute__((aligned(16)));
    uint32_t orig_a[10][4], orig_b[40][4];
    unsigned int iteration,i,k,lane;
    randstate = 0x58eedd01U;
    for (iteration = 0; iteration < 128; ++iteration) {
        for (i = 0; i < 10; ++i)
            for (lane = 0; lane < 4; ++lane) {
                uint32_t max = (i & 1U) ? 0x1ffffffU : 0x3ffffffU;
                uint32_t v = iteration == 0 ? 0U
                           : iteration == 1 ? max
                           : rand32() & max;
                uint32_t f = iteration == 0 ? 0U
                           : iteration == 1 ? max
                           : rand32() & max;
                a[i][lane] = f;
                b[i][lane] = v;
                b[i+10][lane] = 2U*v;
                b[i+20][lane] = 19U*v;
                b[i+30][lane] = 38U*v;
            }
        memcpy(orig_a,a,sizeof(a));
        memcpy(orig_b,b,sizeof(b));
        memset(&buffer,0xa5,sizeof(buffer));
        ossl_ee_x25519_mul_sums4(buffer.sums,a,b);
        for (k = 0; k < 10; ++k)
            for (lane = 0; lane < 4; ++lane) {
                uint64_t expected = 0;
                for (i = 0; i < 10; ++i) {
                    unsigned int j = (k + 10 - i) % 10;
                    unsigned int factor = (i > k ? 19U : 1U)
                                        * ((i & j & 1U) ? 2U : 1U);
                    expected += (uint64_t)a[i][lane] * b[j][lane] * factor;
                }
                if (buffer.sums[k][lane] != expected) {
                    fprintf(stderr,"FAIL: X25519 field sum [%u][%u] case %u\n",
                            k,lane,iteration);
                    return 0;
                }
            }
        for (i = 0; i < 4; ++i)
            if (buffer.before[i] != 0xa5a5a5a5U
                || buffer.after[i] != 0xa5a5a5a5U) {
                puts("FAIL: X25519 fused convolution memory sentinel");
                return 0;
            }
        if (memcmp(a,orig_a,sizeof(a)) || memcmp(b,orig_b,sizeof(b))) {
            puts("FAIL: X25519 convolution modified input");
            return 0;
        }
    }
    puts("PASS: X25519 MMI 128 x 10 x 4 exact 64-bit convolution sums");
    return 1;
}
#endif

static void benchmark(void)
{
    unsigned char scalar[4][32]={{0}};
    unsigned char point[4][32]={{0}};
    unsigned char out[4][32];
    clock_t start,end;
    unsigned int i,lane;
    for (lane = 0; lane < 4; ++lane) {
        point[lane][0] = 9;
        for (i = 0; i < 32; ++i)
            scalar[lane][i] = (unsigned char)(i + lane);
    }
    start=clock();
    for (i = 0; i < 8; ++i)
        ossl_ee_x25519_scalar_mult4(out,scalar,point);
    end=clock();
    if (start != (clock_t)-1 && end > start)
        printf("X25519 4-way x8: %.3f s (%.3f ops/s)\n",
               (double)(end-start)/CLOCKS_PER_SEC,
               32.0*CLOCKS_PER_SEC/(double)(end-start));
    else
        puts("X25519 benchmark: clock() unavailable");
}

int main(int argc, char **argv)
{
    if (!rfc7748() || !random_oracle_vectors() || !invalid_and_zero())
        return EXIT_FAILURE;
#ifndef EE_MMI_X25519_SCALAR_MULTIPLY
    if (!sums_check())
        return EXIT_FAILURE;
#endif
    puts("PASS: X25519 RFC 7748 + 32 BigInt golden tests");
#ifdef EE_MMI_HOST_TEST
    puts("HOST EMULATION ONLY: EE R5900 instruction execution is not tested");
#elif defined(EE_MMI_X25519_SCALAR_MULTIPLY)
    puts("EE SCALAR FIELD MULTIPLICATION BASELINE");
#else
    puts("EE PMULTUW/PMADDUW field convolution linked");
#endif
    if (argc > 1 && strcmp(argv[1],"--bench") == 0)
        benchmark();
    return EXIT_SUCCESS;
}
