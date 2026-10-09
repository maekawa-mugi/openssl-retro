/*
 * Copyright 2026 openssl-retro contributors. Licensed under Apache-2.0.
 * Experimental P-256 Jacobian scalar multiplication using the EE/R5900
 * PMULTUW two-product backend via ossl_ee_bn_mont32().
 *
 * NO implicit EVP, ECDH, EC_METHOD or TLS registration. Even when
 * point operations follow a fixed schedule for valid private scalars,
 * the R5900 ABI, compiler side channels and operand-dependent timings
 * have NOT been audited. Never deploy with private production keys.
 *
 * The P-256 prime is fixed. Every field value is a reduced 8x32-bit
 * Montgomery residue (R=2^256) modulo p. No OpenSSL BN/EC linkage is
 * needed, so the standalone EE test can run without libcrypto.
 */
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "crypto/ee_p256_ecdh.h"
#include "crypto/ee_bn_mont.h"

typedef struct { uint32_t v[8]; } ee_fe;
typedef struct { ee_fe x, y, z; } ee_point;

/* NIST P-256: p = 2^256-2^224+2^192+2^96-1. */
static const uint32_t P[8] = {
    0xffffffffU,0xffffffffU,0xffffffffU,0x00000000U,
    0x00000000U,0x00000000U,0x00000001U,0xffffffffU
};
static const uint32_t ORDER[8] = {
    0xfc632551U,0xf3b9cac2U,0xa7179e84U,0xbce6faadU,
    0xffffffffU,0xffffffffU,0x00000000U,0xffffffffU
};
/* R mod p, R^2 mod p, and affine P-256 generator (normal coords). */
static const uint32_t ONE_MONT[8] = {
    0x00000001U,0,0,0xffffffffU,
    0xffffffffU,0xffffffffU,0xfffffffeU,0
};
static const uint32_t R2[8] = {
    0x00000003U,0,0xffffffffU,0xfffffffbU,
    0xfffffffeU,0xffffffffU,0xfffffffdU,0x00000004U
};
static const uint32_t GX[8] = {
    0xd898c296U,0xf4a13945U,0x2deb33a0U,0x77037d81U,
    0x63a440f2U,0xf8bce6e5U,0xe12c4247U,0x6b17d1f2U
};
static const uint32_t GY[8] = {
    0x37bf51f5U,0xcbb64068U,0x6b315eceU,0x2bce3357U,
    0x7c0f9e16U,0x8ee7eb4aU,0xfe1a7f9bU,0x4fe342e2U
};
static const uint32_t CURVE_B[8] = {
    0x27d2604bU,0x3bce3c3eU,0xcc53b0f6U,0x651d06b0U,
    0x769886bcU,0xb3ebbd55U,0xaa3a93e7U,0x5ac635d8U
};
static const uint32_t P_MINUS_2[8] = {
    0xfffffffdU,0xffffffffU,0xffffffffU,0x00000000U,
    0x00000000U,0x00000000U,0x00000001U,0xffffffffU
};
static const uint32_t NORMAL_ONE[8] = {1U,0,0,0,0,0,0,0};

static void ee_wipe(void *ptr, size_t size)
{
    volatile unsigned char *p=(volatile unsigned char *)ptr;
    while (size--) *p++=0;
}

static void to_words(uint32_t w[8], const unsigned char in[32])
{
    unsigned int i;
    for (i=0;i<8;++i) {
        const unsigned char *p=in+28-4*i;
        w[i]=((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)
            |((uint32_t)p[2]<<8)|(uint32_t)p[3];
    }
}
static void from_words(unsigned char out[32], const uint32_t w[8])
{
    unsigned int i;
    for (i=0;i<8;++i) {
        unsigned char *p=out+28-4*i;
        p[0]=(unsigned char)(w[i]>>24);
        p[1]=(unsigned char)(w[i]>>16);
        p[2]=(unsigned char)(w[i]>>8);
        p[3]=(unsigned char)w[i];
    }
}
static int less_words(const uint32_t *a, const uint32_t *b)
{
    unsigned int i;
    for (i=8;i--!=0;)
        if (a[i]!=b[i]) return a[i]<b[i];
    return 0;
}
static uint32_t iszero(const ee_fe *a)
{
    uint32_t v=0;
    unsigned int i;
    for (i=0;i<8;++i) v|=a->v[i];
    return 1U ^ ((v | (0U-v)) >> 31);
}
static void fe_copy(ee_fe *r,const ee_fe *a)
{
    memcpy(r,a,sizeof(*r));
}
static void fe_one(ee_fe *r)
{
    memcpy(r->v,ONE_MONT,sizeof(r->v));
}
static void fe_zero(ee_fe *r)
{
    memset(r,0,sizeof(*r));
}
static void fe_cmov(ee_fe *r,const ee_fe *src,uint32_t choice)
{
    uint32_t mask=0U-(choice&1U);
    unsigned int i;
    for (i=0;i<8;++i)
        r->v[i]=(r->v[i]&~mask)|(src->v[i]&mask);
}
static void fe_add(ee_fe *r,const ee_fe *a,const ee_fe *b)
{
    uint32_t sum[8],diff[8],carry=0,borrow=0,mask;
    uint64_t v;
    unsigned int i;
    for (i=0;i<8;++i) {
        v=(uint64_t)a->v[i]+b->v[i]+carry;
        sum[i]=(uint32_t)v;
        carry=(uint32_t)(v>>32);
    }
    for (i=0;i<8;++i) {
        uint64_t sub=(uint64_t)P[i]+borrow;
        diff[i]=(uint32_t)((uint64_t)sum[i]-sub);
        borrow=(uint32_t)((uint64_t)sum[i]<sub);
    }
    mask=0U-(carry|(borrow^1U));
    for (i=0;i<8;++i)
        r->v[i]=(sum[i]&~mask)|(diff[i]&mask);
    ee_wipe(sum,sizeof(sum));
    ee_wipe(diff,sizeof(diff));
}
static void fe_sub(ee_fe *r,const ee_fe *a,const ee_fe *b)
{
    uint32_t diff[8],borrow=0,mask;
    uint64_t v;
    unsigned int i;
    for (i=0;i<8;++i) {
        uint64_t sub=(uint64_t)b->v[i]+borrow;
        diff[i]=(uint32_t)((uint64_t)a->v[i]-sub);
        borrow=(uint32_t)((uint64_t)a->v[i]<sub);
    }
    mask=0U-borrow;
    borrow=0;
    for (i=0;i<8;++i) {
        v=(uint64_t)diff[i]+(P[i]&mask)+borrow;
        r->v[i]=(uint32_t)v;
        borrow=(uint32_t)(v>>32);
    }
    ee_wipe(diff,sizeof(diff));
}
static void fe_mul(ee_fe *r,const ee_fe *a,const ee_fe *b)
{
    /* n0=1 because -p[0]^-1 = 1 modulo 2^32.
     * Alias of output and input is supported by ee_bn_mont32(). */
    (void)ossl_ee_bn_mont32(r->v,a->v,b->v,P,1U,8);
}
static void fe_sq(ee_fe *r,const ee_fe *a)
{
    fe_mul(r,a,a);
}
static void fe_double(ee_fe *r,const ee_fe *a)
{
    fe_add(r,a,a);
}
static void fe_triple(ee_fe *r,const ee_fe *a)
{
    ee_fe t;
    fe_double(&t,a);
    fe_add(r,&t,a);
    ee_wipe(&t,sizeof(t));
}
static void fe_from_normal(ee_fe *r,const uint32_t normal[8])
{
    ee_fe raw,mult;
    memcpy(raw.v,normal,sizeof(raw.v));
    memcpy(mult.v,R2,sizeof(mult.v));
    fe_mul(r,&raw,&mult);
    ee_wipe(&raw,sizeof(raw));
    ee_wipe(&mult,sizeof(mult));
}
static void fe_to_normal(uint32_t out[8],const ee_fe *r)
{
    ee_fe one,normal;
    memcpy(one.v,NORMAL_ONE,sizeof(one.v));
    fe_mul(&normal,r,&one);
    memcpy(out,normal.v,sizeof(normal.v));
    ee_wipe(&normal,sizeof(normal));
    ee_wipe(&one,sizeof(one));
}
static void fe_inv(ee_fe *r,const ee_fe *z)
{
    ee_fe powers[16],result;
    int nib;
    unsigned int j;
    /* p-2 is PUBLIC and fixed. Four-bit fixed windows turn many
     * repeated Montgomery products into a table of 16 powers.
     * The window-indexed loads depend only on P_MINUS_2, never on
     * the private scalar or on the field element being inverted.
     * Exactly 256 field squarings + at most 64 field multiplications
     * plus 14 setup products replace 256 squarings + ~128 products.
     * All field values are in the Montgomery representation.
     */
    fe_one(&powers[0]);
    fe_copy(&powers[1],z);
    for (j=2;j<16;++j)
        fe_mul(&powers[j],&powers[j-1],z);
    fe_one(&result);
    for (nib=63;nib>=0;--nib) {
        unsigned int digit=(P_MINUS_2[nib>>3] >> (4*(nib&7))) & 15U;
        for (j=0;j<4;++j)
            fe_sq(&result,&result);
        if (digit != 0)
            fe_mul(&result,&result,&powers[digit]);
    }
    fe_copy(r,&result);
    ee_wipe(powers,sizeof(powers));
    ee_wipe(&result,sizeof(result));
}
static void pt_cmov(ee_point *r,const ee_point *src,uint32_t choice)
{
    fe_cmov(&r->x,&src->x,choice);
    fe_cmov(&r->y,&src->y,choice);
    fe_cmov(&r->z,&src->z,choice);
}
static void pt_cswap(ee_point *a,ee_point *b,uint32_t choice)
{
    unsigned int i,j;
    uint32_t mask=0U-(choice&1U);
    ee_fe *av[3]={&a->x,&a->y,&a->z};
    ee_fe *bv[3]={&b->x,&b->y,&b->z};
    for (j=0;j<3;++j) for (i=0;i<8;++i) {
        uint32_t t=mask&(av[j]->v[i]^bv[j]->v[i]);
        av[j]->v[i]^=t;
        bv[j]->v[i]^=t;
    }
}
static void pt_infinity(ee_point *p)
{
    fe_zero(&p->x);
    fe_one(&p->y);
    fe_zero(&p->z);
}
static void pt_double(ee_point *r,const ee_point *p)
{
    ee_fe delta,gamma,beta,alpha,t0,t1,t2;
    ee_point result;
    /* Jacobian short-Weierstrass doubling specialized to a=-3:
     * delta=Z²; gamma=Y²; beta=X*gamma;
     * alpha=3*(X-delta)*(X+delta);
     * X3=alpha²-8beta;
     * Z3=(Y+Z)²-gamma-delta;
     * Y3=alpha*(4beta-X3)-8gamma². */
    fe_sq(&delta,&p->z);
    fe_sq(&gamma,&p->y);
    fe_mul(&beta,&p->x,&gamma);
    fe_sub(&t0,&p->x,&delta);
    fe_add(&t1,&p->x,&delta);
    fe_mul(&alpha,&t0,&t1);
    fe_triple(&alpha,&alpha);
    fe_sq(&t0,&alpha);
    fe_double(&t1,&beta);
    fe_double(&t1,&t1);
    fe_double(&t1,&t1);
    fe_sub(&result.x,&t0,&t1);
    fe_add(&t0,&p->y,&p->z);
    fe_sq(&t0,&t0);
    fe_sub(&t0,&t0,&gamma);
    fe_sub(&result.z,&t0,&delta);
    fe_double(&t1,&beta);
    fe_double(&t1,&t1);
    fe_sub(&t1,&t1,&result.x);
    fe_mul(&t2,&alpha,&t1);
    fe_sq(&t0,&gamma);
    fe_double(&t0,&t0);
    fe_double(&t0,&t0);
    fe_double(&t0,&t0);
    fe_sub(&result.y,&t2,&t0);
    memcpy(r,&result,sizeof(result));
    ee_wipe(&result,sizeof(result));
    ee_wipe(&delta,sizeof(delta));
    ee_wipe(&gamma,sizeof(gamma));
    ee_wipe(&beta,sizeof(beta));
    ee_wipe(&alpha,sizeof(alpha));
    ee_wipe(&t0,sizeof(t0));
    ee_wipe(&t1,sizeof(t1));
    ee_wipe(&t2,sizeof(t2));
}
static void pt_add(ee_point *r,const ee_point *p,const ee_point *q)
{
    ee_fe zz1,zz2,u1,u2,s1,s2,h,ii,j,r2,v,t0,t1;
    ee_point result;
    uint32_t inf_p=iszero(&p->z),inf_q=iszero(&q->z);
    /* General Jacobian-Jacobian addition, distinct finite points:
     * difference between ladder operands is always nonzero P.
     * The infinity cases are fixed afterward with constant-time
     * conditional moves (no secret-data-dependent branches).
     */
    fe_sq(&zz1,&p->z);
    fe_sq(&zz2,&q->z);
    fe_mul(&u1,&p->x,&zz2);
    fe_mul(&u2,&q->x,&zz1);
    fe_mul(&t0,&zz2,&q->z);
    fe_mul(&s1,&p->y,&t0);
    fe_mul(&t0,&zz1,&p->z);
    fe_mul(&s2,&q->y,&t0);
    fe_sub(&h,&u2,&u1);
    fe_double(&t0,&h);
    fe_sq(&ii,&t0);
    fe_mul(&j,&h,&ii);
    fe_sub(&t0,&s2,&s1);
    fe_double(&r2,&t0);
    fe_mul(&v,&u1,&ii);
    fe_sq(&t0,&r2);
    fe_double(&t1,&v);
    fe_sub(&t0,&t0,&j);
    fe_sub(&result.x,&t0,&t1);
    fe_sub(&t0,&v,&result.x);
    fe_mul(&t1,&r2,&t0);
    fe_mul(&t0,&s1,&j);
    fe_double(&t0,&t0);
    fe_sub(&result.y,&t1,&t0);
    fe_add(&t0,&p->z,&q->z);
    fe_sq(&t0,&t0);
    fe_sub(&t0,&t0,&zz1);
    fe_sub(&t0,&t0,&zz2);
    fe_mul(&result.z,&t0,&h);
    pt_cmov(&result,q,inf_p);
    pt_cmov(&result,p,inf_q);
    memcpy(r,&result,sizeof(result));
    ee_wipe(&result,sizeof(result));
    ee_wipe(&zz1,sizeof(zz1)); ee_wipe(&zz2,sizeof(zz2));
    ee_wipe(&u1,sizeof(u1)); ee_wipe(&u2,sizeof(u2));
    ee_wipe(&s1,sizeof(s1)); ee_wipe(&s2,sizeof(s2));
    ee_wipe(&h,sizeof(h)); ee_wipe(&ii,sizeof(ii));
    ee_wipe(&j,sizeof(j)); ee_wipe(&r2,sizeof(r2));
    ee_wipe(&v,sizeof(v)); ee_wipe(&t0,sizeof(t0));
    ee_wipe(&t1,sizeof(t1));
    /* Point formulas are for a fixed valid prime-order P-256 point.
     * The ladder's finite operands cannot coincide while P != O. */
}

static void point_from_xy(ee_point *point,const uint32_t x[8],
                           const uint32_t y[8])
{
    fe_from_normal(&point->x,x);
    fe_from_normal(&point->y,y);
    fe_one(&point->z);
}
static uint32_t point_oncurve(const ee_point *p)
{
    ee_fe lhs,rhs,t0,b;
    uint32_t diff=0;
    unsigned int i;
    fe_sq(&lhs,&p->y);
    fe_sq(&rhs,&p->x);
    fe_mul(&rhs,&rhs,&p->x);
    fe_triple(&t0,&p->x);
    fe_sub(&rhs,&rhs,&t0);
    fe_from_normal(&b,CURVE_B);
    fe_add(&rhs,&rhs,&b);
    for (i=0;i<8;++i) diff|=lhs.v[i]^rhs.v[i];
    ee_wipe(&lhs,sizeof(lhs));
    ee_wipe(&rhs,sizeof(rhs));
    ee_wipe(&t0,sizeof(t0));
    ee_wipe(&b,sizeof(b));
    return 1U ^ ((diff|(0U-diff))>>31);
}
static int load_peer(ee_point *point,const unsigned char peer[65])
{
    uint32_t x[8],y[8];
    int valid;
    if (peer[0]!=0x04U) return 0;
    to_words(x,peer+1);
    to_words(y,peer+33);
    valid=less_words(x,P) && less_words(y,P);
    if (valid) {
        point_from_xy(point,x,y);
        valid=(int)point_oncurve(point);
    }
    ee_wipe(x,sizeof(x));
    ee_wipe(y,sizeof(y));
    return valid;
}
static int scalar_valid(const unsigned char key[32])
{
    uint32_t d[8], any=0, borrow=0;
    unsigned int i;
    int valid;
    to_words(d,key);
    /* No early-exit comparison on secret scalar magnitude. */
    for (i=0;i<8;++i) {
        uint64_t v=(uint64_t)d[i]-ORDER[i]-borrow;
        borrow=(uint32_t)(v>>63);
        any|=d[i];
    }
    valid=(any!=0U) & (borrow!=0U);
    ee_wipe(d,sizeof(d));
    return valid;
}
static void point_ladder(ee_point *out,const ee_point *base,
                          const unsigned char scalar[32])
{
    ee_point r0,r1;
    uint32_t swap=0;
    int bit;
    pt_infinity(&r0);
    memcpy(&r1,base,sizeof(r1));
    for (bit=255;bit>=0;--bit) {
        uint32_t b=(scalar[31-(bit>>3)]>>(bit&7))&1U;
        swap^=b;
        pt_cswap(&r0,&r1,swap);
        swap=b;
        pt_add(&r1,&r0,&r1);
        pt_double(&r0,&r0);
    }
    pt_cswap(&r0,&r1,swap);
    memcpy(out,&r0,sizeof(*out));
    ee_wipe(&r0,sizeof(r0));
    ee_wipe(&r1,sizeof(r1));
}
static int point_affine(unsigned char x_out[32],unsigned char *y_out,
                         const ee_point *point)
{
    ee_fe inv,z2,z3,xx,yy;
    uint32_t x[8],y[8];
    if (iszero(&point->z)) return 0;
    fe_inv(&inv,&point->z);
    fe_sq(&z2,&inv);
    fe_mul(&xx,&point->x,&z2);
    fe_to_normal(x,&xx);
    from_words(x_out,x);
    if (y_out!=NULL) {
        fe_mul(&z3,&z2,&inv);
        fe_mul(&yy,&point->y,&z3);
        fe_to_normal(y,&yy);
        from_words(y_out,y);
        ee_wipe(y,sizeof(y));
        ee_wipe(&z3,sizeof(z3));
        ee_wipe(&yy,sizeof(yy));
    }
    ee_wipe(x,sizeof(x));
    ee_wipe(&inv,sizeof(inv));
    ee_wipe(&z2,sizeof(z2));
    ee_wipe(&xx,sizeof(xx));
    return 1;
}
int ossl_ee_p256_public_from_private(unsigned char public_key[65],
                                      const unsigned char scalar[32])
{
    ee_point base,result;
    int ok=0;
    if (public_key==NULL || scalar==NULL) return 0;
    memset(public_key,0,65);
    if (!scalar_valid(scalar)) return 0;
    point_from_xy(&base,GX,GY);
    point_ladder(&result,&base,scalar);
    public_key[0]=0x04U;
    ok=point_affine(public_key+1,public_key+33,&result);
    if (!ok) memset(public_key,0,65);
    ee_wipe(&base,sizeof(base));
    ee_wipe(&result,sizeof(result));
    return ok;
}
int ossl_ee_p256_ecdh(unsigned char shared_x[32],
                       const unsigned char scalar[32],
                       const unsigned char peer_public[65])
{
    ee_point peer,result;
    int ok=0;
    if (shared_x==NULL || scalar==NULL || peer_public==NULL) return 0;
    memset(shared_x,0,32);
    if (!scalar_valid(scalar) || !load_peer(&peer,peer_public))
        return 0;
    point_ladder(&result,&peer,scalar);
    ok=point_affine(shared_x,NULL,&result);
    if (!ok) memset(shared_x,0,32);
    ee_wipe(&peer,sizeof(peer));
    ee_wipe(&result,sizeof(result));
    return ok;
}
