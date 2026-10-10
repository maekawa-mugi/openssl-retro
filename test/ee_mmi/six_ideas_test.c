/* Independent primitive checks for the six optional EE candidates.
 * Apache-2.0. No timing: full suites are run separately by the harness. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "crypto/ee_mmi.h"
#include "crypto/ee_bn_mont.h"

static uint32_t rng_state=0x5900a65U;
static uint32_t random_word(void)
{
    rng_state^=rng_state<<13; rng_state^=rng_state>>17;
    rng_state^=rng_state<<5; return rng_state;
}
#ifdef EE_MMI_AES_VECTOR_SBOX
extern void ossl_ee_aes_subbytes16_mmi(uint32_t column[4]);
static unsigned int gf_mul(unsigned int a,unsigned int b)
{
    unsigned int r=0,i;
    for (i=0;i<8;++i) {
        if (b&1U) r^=a;
        a=(a<<1)^((a&128U)?0x11bU:0U); b>>=1;
    }
    return r;
}
static unsigned int sbox(unsigned int x)
{
    unsigned int n=254,v=1,a=x,r;
    while (n) { if (n&1U) v=gf_mul(v,a); a=gf_mul(a,a); n>>=1; }
    r=v;
    for (n=1;n<5;++n) r^=((v<<n)|(v>>(8-n)))&255U;
    return r^0x63U;
}
static int primitive_check(void)
{
    struct __attribute__((aligned(16))) { uint32_t pre[4],x[4],post[4]; } b;
    unsigned int t,l,j;
    for (t=0;t<512;++t) {
        uint32_t expected[4];
        memset(&b,0xa5,sizeof(b));
        for (l=0;l<4;++l) {
            b.x[l]=t<256 ? t*0x01010101U : random_word(); expected[l]=0;
            for (j=0;j<4;++j) expected[l]|=sbox((b.x[l]>>(8*j))&255U)<<(8*j);
        }
        ossl_ee_aes_subbytes16_mmi(b.x);
        if (memcmp(b.x,expected,sizeof(expected))) return 0;
        for (l=0;l<4;++l) if (b.pre[l]!=0xa5a5a5a5U || b.post[l]!=0xa5a5a5a5U) return 0;
    }
    return 1;
}
#elif defined(EE_MMI_P256_MUL8) || defined(EE_MMI_P256_SQUARE)
extern void ossl_ee_p256_mul8_mmi(uint32_t out[8],const uint32_t a[8],const uint32_t b[8]);
extern void ossl_ee_p256_square8_mmi(uint32_t out[8],const uint32_t a[8]);
static int primitive_check(void)
{
    const uint32_t p[8]={0xffffffffU,0xffffffffU,0xffffffffU,0,0,0,1,0xffffffffU};
    uint32_t a[8],b[8],orig[8],expected[8],diff[8];
    struct {uint32_t before,out[8],after;} result;
    unsigned int t,j,which;
    for (t=0;t<256;++t) {
        for (which=0;which<2;++which) {
            uint32_t *v=which?b:a,borrow=0;
            for (j=0;j<8;++j) v[j]=t==0?0:t==1?p[j]:random_word();
            if (t==1) --v[0];
            for (j=0;j<8;++j) {
                uint64_t sub=(uint64_t)p[j]+borrow;
                diff[j]=(uint32_t)((uint64_t)v[j]-sub); borrow=(uint32_t)((uint64_t)v[j]<sub);
            }
            if (!borrow) memcpy(v,diff,sizeof(diff));
        }
#ifdef EE_MMI_P256_SQUARE
        if (!ossl_ee_bn_mont32(expected,a,a,p,1,8)) return 0;
#else
        if (!ossl_ee_bn_mont32(expected,a,b,p,1,8)) return 0;
#endif
        result.before=result.after=0xa5a5a5a5U;
        memcpy(orig,a,sizeof(a));
#ifdef EE_MMI_P256_SQUARE
        ossl_ee_p256_square8_mmi(result.out,a);
        ossl_ee_p256_square8_mmi(a,a);
#else
        ossl_ee_p256_mul8_mmi(result.out,a,b);
        ossl_ee_p256_mul8_mmi(a,a,b);
#endif
        if (memcmp(result.out,expected,sizeof(expected)) || memcmp(a,expected,sizeof(expected))
            || result.before!=0xa5a5a5a5U || result.after!=0xa5a5a5a5U) return 0;
#ifdef EE_MMI_P256_MUL8
        ossl_ee_p256_mul8_mmi(b,orig,b);
        if (memcmp(b,expected,sizeof(expected))) return 0;
#endif
    }
    return 1;
}
#elif defined(EE_MMI_X25519_FUSED_REDUCE)
extern void ossl_ee_x25519_mul_reduce4(uint32_t out[10][4],const uint32_t a[10][4],const uint32_t scaled[40][4]);
static int primitive_check(void)
{
    uint32_t a[10][4] __attribute__((aligned(16))),b[10][4],expected[10][4];
    uint32_t scaled[40][4] __attribute__((aligned(16))),alias[10][4] __attribute__((aligned(16)));
    struct __attribute__((aligned(16))) {uint32_t before[4],out[10][4],after[4];} r;
    uint64_t sums[10][4];
    unsigned int t,i,j,l,pass;
    for (t=0;t<256;++t) {
        memset(sums,0,sizeof(sums)); memset(&r,0xa5,sizeof(r));
        for (i=0;i<10;++i) for (l=0;l<4;++l) {
            uint32_t mask=(1U<<((i&1U)?25:26))-1U;
            a[i][l]=t==0?0:t==1?mask:random_word()&mask;
            b[i][l]=t==0?0:t==1?mask:random_word()&mask;
            scaled[i][l]=b[i][l]; scaled[i+10][l]=2*b[i][l];
            scaled[i+20][l]=19*b[i][l]; scaled[i+30][l]=(i&1U)?38*b[i][l]:0;
        }
        for (i=0;i<10;++i) for (j=0;j<10;++j) for (l=0;l<4;++l)
            sums[(i+j)%10][l]+=(uint64_t)a[i][l]*b[j][l]
                               *(i+j>=10?19U:1U)*((i&j&1U)?2U:1U);
        for (l=0;l<4;++l) {
            for (pass=0;pass<3;++pass) {
                for (i=0;i<9;++i) {
                    unsigned int width=(i&1U)?25:26;
                    sums[i+1][l]+=sums[i][l]>>width; sums[i][l]&=(1U<<width)-1U;
                }
                sums[0][l]+=19*(sums[9][l]>>25); sums[9][l]&=(1U<<25)-1U;
            }
            for (i=0;i<10;++i) expected[i][l]=(uint32_t)sums[i][l];
        }
        memcpy(alias,a,sizeof(a));
        ossl_ee_x25519_mul_reduce4(r.out,a,scaled);
        ossl_ee_x25519_mul_reduce4(alias,alias,scaled);
        if (memcmp(r.out,expected,sizeof(expected)) || memcmp(alias,expected,sizeof(expected))) return 0;
        for (l=0;l<4;++l) if (r.before[l]!=0xa5a5a5a5U || r.after[l]!=0xa5a5a5a5U) return 0;
    }
    return 1;
}
#elif defined(EE_MMI_GCM_WORD_CORE)
static int primitive_check(void)
{
    unsigned char key[32],in[4][16],expected[4][16];
    uint32_t words[4][4] __attribute__((aligned(16)));
    ossl_ee_aes4_key ctx;
    unsigned int t,j,l,bits;
    for (t=0;t<96;++t) {
        bits=128+64*(t%3);
        for (j=0;j<sizeof(key);++j) key[j]=(unsigned char)random_word();
        for (l=0;l<4;++l) for (j=0;j<16;++j) in[l][j]=(unsigned char)random_word();
        if (!ossl_ee_aes_set_encrypt_key(&ctx,key,bits) || !ossl_ee_aes_encrypt4(expected,in,&ctx)) return 0;
        for (j=0;j<4;++j) for (l=0;l<4;++l) {
            const unsigned char *p=in[l]+4*j;
            words[j][l]=(uint32_t)p[0]|((uint32_t)p[1]<<8)|((uint32_t)p[2]<<16)|((uint32_t)p[3]<<24);
        }
        if (!ossl_ee_aes_encrypt_words4(words,&ctx)) return 0;
        for (j=0;j<16;++j) for (l=0;l<4;++l)
            if ((unsigned char)(words[j/4][l]>>(8*(j%4)))!=expected[l][j]) return 0;
        ossl_ee_aes_clear_key(&ctx);
    }
    return 1;
}
#else
#error "six_ideas_test must select a primitive experiment"
#endif

int main(int argc,char **argv)
{
    (void)argc; (void)argv;
    if (!primitive_check()) { puts("FAIL: optional EE primitive differential/alias/guard checks"); return EXIT_FAILURE; }
    puts("PASS: optional EE primitive differential/alias/guard checks");
    return EXIT_SUCCESS;
}
