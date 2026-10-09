/*
 * Experimental P-256 ECDSA verify using EE/R5900 32-bit Montgomery MMI.
 * Copyright 2026 openssl-retro contributors. Apache-2.0.
 *
 * Existing OpenSSL point arithmetic and modular inversion stay intact.
 * Only the two scalar products u1 = digest*s^-1 and u2 = r*s^-1
 * are computed by the experimental EE BN Montgomery kernel.
 *
 * This explicit verification entry point is not an EVP/EC_METHOD hook.
 * It is intended for verification of public signatures, not signing.
 */
#include <stdint.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include "crypto/ee_ecdsa_p256.h"

#ifndef EE_MMI_ECDSA_SCALAR
# include "crypto/ee_bn_mont.h"
#endif

#ifndef EE_MMI_ECDSA_SCALAR
static void wipe_words(void *buffer, size_t len)
{
    volatile unsigned char *p = (volatile unsigned char *)buffer;
    size_t i;
    for (i = 0; i < len; ++i)
        p[i] = 0;
}

static uint32_t load_le32(const unsigned char *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void put_le32(unsigned char *p, uint32_t v)
{
    p[0] = (unsigned char)v;
    p[1] = (unsigned char)(v >> 8);
    p[2] = (unsigned char)(v >> 16);
    p[3] = (unsigned char)(v >> 24);
}

/* -n[0]^-1 mod 2^32. n must be odd. Fixed five Newton iterations. */
static uint32_t mont_n0(uint32_t lo)
{
    uint32_t x = 1U;
    unsigned int i;
    for (i = 0; i < 5; ++i)
        x *= 2U - lo * x;
    return 0U - x;
}

/*
 * For P-256 ECDSA the modulus is the GROUP ORDER, not the field prime.
 * a,b are already reduced modulo n and are public verification values.
 */
static int mul_mod_n_ee(BIGNUM *result, const BIGNUM *a, const BIGNUM *b,
                        const BIGNUM *order, BN_MONT_CTX *mont, BN_CTX *ctx)
{
    unsigned char encoding[32];
    uint32_t aa[8], bb[8], nn[8], zz[8];
    BIGNUM *am, *bm, *zm;
    uint32_t n0;
    unsigned int i;
    int ok = 0;

    BN_CTX_start(ctx);
    am = BN_CTX_get(ctx);
    bm = BN_CTX_get(ctx);
    zm = BN_CTX_get(ctx);
    if (zm == NULL)
        goto end;
    if (!BN_to_montgomery(am, a, mont, ctx)
            || !BN_to_montgomery(bm, b, mont, ctx))
        goto end;
    if (BN_bn2lebinpad(am, encoding, 32) != 32)
        goto end;
    for (i = 0; i < 8; ++i)
        aa[i] = load_le32(encoding + 4*i);
    if (BN_bn2lebinpad(bm, encoding, 32) != 32)
        goto end;
    for (i = 0; i < 8; ++i)
        bb[i] = load_le32(encoding + 4*i);
    if (BN_bn2lebinpad(order, encoding, 32) != 32)
        goto end;
    for (i = 0; i < 8; ++i)
        nn[i] = load_le32(encoding + 4*i);

    n0 = mont_n0(nn[0]);
    if (!ossl_ee_bn_mont32(zz, aa, bb, nn, n0, 8))
        goto end;
    for (i = 0; i < 8; ++i)
        put_le32(encoding + i*4, zz[i]);
    if (BN_lebin2bn(encoding, 32, zm) == NULL
            || !BN_from_montgomery(result, zm, mont, ctx))
        goto end;
    ok = 1;
end:
    wipe_words(encoding, sizeof(encoding));
    wipe_words(aa, sizeof(aa));
    wipe_words(bb, sizeof(bb));
    wipe_words(nn, sizeof(nn));
    wipe_words(zz, sizeof(zz));
    BN_CTX_end(ctx);
    return ok;
}
#endif

int ossl_ee_ecdsa_p256_verify(const uint8_t public_key[65],
                              const uint8_t digest_sha256[32],
                              const uint8_t signature_rs[64])
{
    BN_CTX *ctx = NULL;
    BN_MONT_CTX *mont = NULL;
    EC_GROUP *group = NULL;
    EC_POINT *q = NULL, *sum = NULL;
    BIGNUM *n, *r, *s, *e, *w, *u1, *u2, *x;
    int on_curve, result = -1;

    if (public_key == NULL || digest_sha256 == NULL || signature_rs == NULL)
        return 0;
    if (public_key[0] != 4)
        return 0;

    ctx = BN_CTX_new();
    group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    if (ctx == NULL || group == NULL)
        goto end;
    q = EC_POINT_new(group);
    sum = EC_POINT_new(group);
    if (q == NULL || sum == NULL)
        goto end;

    BN_CTX_start(ctx);
    n = BN_CTX_get(ctx);
    r = BN_CTX_get(ctx);
    s = BN_CTX_get(ctx);
    e = BN_CTX_get(ctx);
    w = BN_CTX_get(ctx);
    u1 = BN_CTX_get(ctx);
    u2 = BN_CTX_get(ctx);
    x = BN_CTX_get(ctx);
    if (x == NULL)
        goto end_ctx;

    if (!EC_GROUP_get_order(group, n, ctx)
            || BN_bin2bn(signature_rs, 32, r) == NULL
            || BN_bin2bn(signature_rs + 32, 32, s) == NULL
            || BN_bin2bn(digest_sha256, 32, e) == NULL)
        goto end_ctx;

    /* ECDSA signature ranges are 1 <= r,s < group order. */
    if (BN_is_zero(r) || BN_is_zero(s)
            || BN_cmp(r, n) >= 0 || BN_cmp(s, n) >= 0) {
        result = 0;
        goto end_ctx;
    }
    if (!EC_POINT_oct2point(group, q, public_key, 65, ctx)) {
        result = 0;
        goto end_ctx;
    }
    on_curve = EC_POINT_is_on_curve(group, q, ctx);
    if (on_curve < 0)
        goto end_ctx;
    if (on_curve == 0 || EC_POINT_is_at_infinity(group, q)) {
        result = 0;
        goto end_ctx;
    }

    if (!BN_nnmod(e, e, n, ctx) || BN_mod_inverse(w, s, n, ctx) == NULL)
        goto end_ctx;
#ifdef EE_MMI_ECDSA_SCALAR
    if (!BN_mod_mul(u1, e, w, n, ctx)
            || !BN_mod_mul(u2, r, w, n, ctx))
        goto end_ctx;
#else
    mont = BN_MONT_CTX_new();
    if (mont == NULL || !BN_MONT_CTX_set(mont, n, ctx))
        goto end_ctx;
    if (!mul_mod_n_ee(u1, e, w, n, mont, ctx)
            || !mul_mod_n_ee(u2, r, w, n, mont, ctx))
        goto end_ctx;
#endif

    if (!EC_POINT_mul(group, sum, u1, q, u2, ctx))
        goto end_ctx;
    if (EC_POINT_is_at_infinity(group, sum)) {
        result = 0;
        goto end_ctx;
    }
    if (!EC_POINT_get_affine_coordinates(group, sum, x, NULL, ctx)
            || !BN_nnmod(x, x, n, ctx))
        goto end_ctx;
    result = (BN_cmp(x, r) == 0);
end_ctx:
    BN_CTX_end(ctx);
end:
    BN_MONT_CTX_free(mont);
    EC_POINT_free(q);
    EC_POINT_free(sum);
    EC_GROUP_free(group);
    BN_CTX_free(ctx);
    return result;
}
