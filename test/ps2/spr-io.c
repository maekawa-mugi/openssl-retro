/* Benchmark-only SPR placement for existing EE crypto primitives.
 * AES4, SHA256x4 and ChaCha20; same algorithms, only storage moves.
 * No product dispatch change. Exclusive 16KiB SPR, no DMA.
 * Apache-2.0.
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <timer.h>
#include <debug.h>
#include "crypto/ee_mmi.h"

void ChaCha20_ctr32(unsigned char *, const unsigned char *, size_t,
                    const unsigned int [8], const unsigned int [4]);

#define SPR_IO_SAMPLES 6u
#define SPR_IO_REPS 8u
#define SPR_HALF 8192u
static unsigned char input_ram[SPR_HALF] __attribute__((aligned(16)));
static unsigned char output_ram[SPR_HALF] __attribute__((aligned(16)));
static unsigned char expected[SPR_HALF] __attribute__((aligned(16)));
static unsigned int chacha_key[8], chacha_count[4];
static ossl_ee_aes4_key aes_ctx;
static volatile uint32_t escape_sink;

static uint64_t median6(const uint64_t src[SPR_IO_SAMPLES])
{
    uint64_t a[SPR_IO_SAMPLES], value;
    unsigned int i,j;
    for(i=0;i<SPR_IO_SAMPLES;i++)a[i]=src[i];
    for(i=1;i<SPR_IO_SAMPLES;i++){
        value=a[i];j=i;
        while(j && a[j-1]>value){a[j]=a[j-1];--j;}
        a[j]=value;
    }
    return (a[2]+a[3])/2u;
}

static int process(unsigned kind, unsigned n,
                   const unsigned char *src,unsigned char *dst,
                   const ossl_ee_aes4_key *key)
{
    unsigned int i;
    if(kind==0)
        return ossl_ee_aes_encrypt4(
            (unsigned char (*)[16])dst,
            (const unsigned char (*)[16])src,key);
    if(kind==1){
        const unsigned char *ptr[4];
        for(i=0;i<4;i++)ptr[i]=src+i*n;
        return ossl_ee_sha256_hash4((unsigned char (*)[32])dst,ptr,n);
    }
    ChaCha20_ctr32(dst,src,n,chacha_key,chacha_count);
    return 1;
}

/* kind AES4 (64B), SHA256x4 (4*n bytes) or ChaCha (n bytes).
 * Modes RAM / SPR input / SPR output / both / inclusive copies.
 * AES also tests warm and per-call copied round-key schedules. */
static uint64_t run_one(unsigned kind,unsigned n,unsigned mode,
                        unsigned reps,int *ok)
{
    unsigned char *si=(unsigned char *)(uintptr_t)0x70000000u;
    unsigned char *so=(unsigned char *)(uintptr_t)0x70002000u;
    ossl_ee_aes4_key *sk=(ossl_ee_aes4_key *)(uintptr_t)0x70001000u;
    unsigned in_bytes=kind==0?64u:kind==1?4u*n:n;
    unsigned out_bytes=kind==0?64u:kind==1?128u:n;
    unsigned char *dst=(mode==2||mode==3)?so:output_ram;
    const unsigned char *src=(mode==1||mode==3)?si:input_ram;
    const ossl_ee_aes4_key *key=(mode>=5)?sk:&aes_ctx;
    unsigned rep;
    uint64_t begin, elapsed;
    memset(output_ram,0xA5,out_bytes);
    if(mode==1||mode==3)memcpy(si,input_ram,in_bytes);
    if(mode==2||mode==3)memset(so,0xA5,out_bytes);
    if(mode==5)memcpy(sk,&aes_ctx,sizeof(aes_ctx));
    *ok=1;
    begin=GetTimerSystemTime();
    for(rep=0;rep<reps;rep++){
        if(mode==4){
            memcpy(si,input_ram,in_bytes);
            memcpy(so,output_ram,out_bytes);
            if(!process(kind,n,si,so,&aes_ctx))*ok=0;
            memcpy(output_ram,so,out_bytes);
        }else if(mode==6){
            memcpy(sk,&aes_ctx,sizeof(aes_ctx));
            if(!process(kind,n,input_ram,output_ram,sk))*ok=0;
        }else if(!process(kind,n,src,dst,key))*ok=0;
    }
    elapsed=GetTimerSystemTime()-begin;
    if(mode==2||mode==3)memcpy(output_ram,so,out_bytes);
    escape_sink^=output_ram[out_bytes-1u];
    return elapsed;
}

int ps2_spr_io_benchmark(void)
{
    static const char *const kinds[]={"AES4","SHA256x4","ChaCha20"};
    static const char *const modes[]={
        "RAM","SPR_IN","SPR_OUT","SPR_BOTH","SPR_XFER",
        "SPR_AES_KEY","SPR_AES_KEY_COLD"
    };
    static const unsigned sizes[][4]={
        {64u,0u,0u,0u},{64u,256u,1024u,2048u},
        {64u,1024u,4096u,8192u}
    };
    uint64_t samples[7][SPR_IO_SAMPLES], med[7];
    double summary[3]={0,0,0};
    unsigned char key[16];
    unsigned kind,ci,n,bytes,mode,count,trial,step,i,pass=0;
    int ok;
    for(i=0;i<SPR_HALF;i++)input_ram[i]=(unsigned char)(i*29u+(i>>3)+17u);
    for(i=0;i<16;i++)key[i]=(unsigned char)(i*7u+11u);
    for(i=0;i<8;i++)chacha_key[i]=0x10203040u+i*0x01010101u;
    for(i=0;i<4;i++)chacha_count[i]=0x31415926u+i;
    if(!ossl_ee_aes_set_encrypt_key(&aes_ctx,key,128))return 0;
    puts("CRYPTO_SPR_META,R5900,AES_SHA256_CHACHA,SPR16KiB,6samples,8reps");
    for(kind=0;kind<3;kind++)for(ci=0;ci<4;ci++){
        n=sizes[kind][ci];
        if(!n)continue;
        bytes=kind==0?64u:kind==1?128u:n;
        count=kind==0?7u:5u;
        run_one(kind,n,0,SPR_IO_REPS,&ok);
        if(!ok)return 0;
        memcpy(expected,output_ram,bytes);
        for(mode=1;mode<count;mode++){
            run_one(kind,n,mode,SPR_IO_REPS,&ok);
            if(!ok||memcmp(expected,output_ram,bytes)){
                printf("CRYPTO_SPR_FAIL,%s,%u,%s,correctness\n",
                       kinds[kind],n,modes[mode]);
                return 0;
            }
        }
        for(trial=0;trial<SPR_IO_SAMPLES;trial++)
            for(step=0;step<count;step++){
                mode=(trial+step)%count;
                samples[mode][trial]=run_one(kind,n,mode,SPR_IO_REPS,&ok);
                if(!ok||!samples[mode][trial]||
                   memcmp(expected,output_ram,bytes)){
                    printf("CRYPTO_SPR_FAIL,%s,%u,%s,sample%u\n",
                           kinds[kind],n,modes[mode],trial);
                    return 0;
                }
            }
        for(mode=0;mode<count;mode++){
            med[mode]=median6(samples[mode]);
            printf("CRYPTO_SPR,%s,%u,%s,%llu,%.5f\n",kinds[kind],n,
                   modes[mode],(unsigned long long)med[mode],
                   (double)med[0]/(double)med[mode]);
        }
        if((kind==0 && n==64u)||(kind==1 && n==1024u)||
           (kind==2 && n==4096u))
            summary[kind]=(double)med[0]/(double)med[3];
        ++pass;
    }
    scr_setXY(0,18);
    scr_setfontcolor(0x00ffffff);
    scr_printf("RAM/SPR both  AES:%4.2fx SHA:%4.2fx ChaCha:%4.2fx",
               summary[0],summary[1],summary[2]);
    ossl_ee_aes_clear_key(&aes_ctx);
    memset((void *)(uintptr_t)0x70001000u,0,sizeof(aes_ctx));
    printf("CRYPTO_SPR_RESULT,PASS,cases=%u,sink=%lu\n",
           pass,(unsigned long)escape_sink);
    return 1;
}
