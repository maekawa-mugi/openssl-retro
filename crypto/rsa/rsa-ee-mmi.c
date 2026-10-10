/*
 * Copyright 2026 openssl-retro contributors. Apache License 2.0.
 *
 * Experimental public-only RSA-65537 modular exponentiation and
 * strict PKCS#1 v1.5 SHA256 signature verification for PS2 EE MMI.
 *
 * Reuses the already implemented, separately tested EE 32-bit CIOS
 * Montgomery backend ossl_ee_bn_mont32(), which uses PMULTUW to
 * perform two full-width unsigned 32x32 products per instruction.
 *
 * Four separate public moduli and inputs are processed sequentially.
 * This implementation deliberately does NOT handle RSA private keys,
 * CRT, OAEP, PSS, X.509 decoding or TLS/EVP dispatch. No random
 * blinding is needed because these operations use public exponents
 * and public inputs only. Never repurpose the code for private RSA.
 */
#include <stddef.h>
#include <stdint.h>
#include <limits.h>
#include <string.h>
#include "crypto/ee_bn_mont.h"
#include "crypto/ee_rsa_verify.h"

#if UINT_MAX != 0xffffffffU
# error "RSA EE MMI requires 32-bit unsigned int"
#endif

#define RSA_MAX_WORDS OSSL_EE_BN_MONT_MAX_WORDS

static void rsa_wipe(void *addr, size_t n)
{
    volatile unsigned char *p = (volatile unsigned char *)addr;
    while (n-- != 0)
        *p++ = 0;
}

static void rsa_be_to_words(uint32_t *words, const unsigned char *bytes,
                            size_t k)
{
    size_t i, count = k / 4;
    for (i = 0; i < count; ++i) {
        const unsigned char *p = bytes + k - (i+1)*4;
        words[i] = ((uint32_t)p[0] << 24)
                 | ((uint32_t)p[1] << 16)
                 | ((uint32_t)p[2] << 8)
                 | (uint32_t)p[3];
    }
}

static void rsa_words_to_be(unsigned char *bytes, const uint32_t *w,
                            size_t k)
{
    size_t i, count = k / 4;
    for (i = 0; i < count; ++i) {
        unsigned char *p = bytes + k - (i+1)*4;
        p[0] = (unsigned char)(w[i] >> 24);
        p[1] = (unsigned char)(w[i] >> 16);
        p[2] = (unsigned char)(w[i] >> 8);
        p[3] = (unsigned char)w[i];
    }
}

static int rsa_less(const uint32_t *a, const uint32_t *b, size_t num)
{
    size_t i;
    for (i = num; i-- != 0;) {
        if (a[i] != b[i])
            return a[i] < b[i];
    }
    return 0;
}

static uint32_t rsa_neg_inv32(uint32_t n)
{
    uint32_t x = 1U;
    unsigned int i;
    /* Newton's modular inverse for odd n modulo 2^32. */
    for (i = 0; i < 5; ++i)
        x *= 2U - n*x;
    return 0U - x;
}

/* v is reduced and modulus has its highest bit set.
 * v <- (2*v) mod modulus, using a fixed-size conditional subtraction.
 * Called 64*num times to compute R^2 mod modulus without divisions.
 * The intermediate 2*v < 2*modulus, so subtract at most once. */
static void rsa_double_mod(uint32_t *v, const uint32_t *mod,
                            size_t num, uint32_t *diff)
{
    uint32_t carry = 0, borrow = 0, use_diff, mask;
    size_t i;
    for (i = 0; i < num; ++i) {
        uint64_t w = ((uint64_t)v[i] << 1) + carry;
        v[i] = (uint32_t)w;
        carry = (uint32_t)(w >> 32);
    }
    for (i = 0; i < num; ++i) {
        uint64_t sub = (uint64_t)mod[i] + borrow;
        uint64_t a = v[i];
        diff[i] = (uint32_t)(a - sub);
        borrow = (uint32_t)(a < sub);
    }
    use_diff = carry | (borrow ^ 1U);
    mask = 0U - use_diff;
    for (i = 0; i < num; ++i)
        v[i] = (v[i] & ~mask) | (diff[i] & mask);
}

static int rsa_size_ok(size_t bytes)
{
    return bytes == 128 || bytes == 256 ||
           bytes == 384 || bytes == 512;
}

void ossl_ee_rsa_public_key_clear(ossl_ee_rsa_public_key *key)
{
    if (key != NULL)
        rsa_wipe(key, sizeof(*key));
}

int ossl_ee_rsa_public_key_init(ossl_ee_rsa_public_key *key,
                                const unsigned char *modulus,
                                size_t mod_bytes)
{
    uint32_t diff[RSA_MAX_WORDS];
    size_t i;
    if (key == NULL || modulus == NULL || !rsa_size_ok(mod_bytes))
        return 0;
    /* The caller owns the context; clear it on failure or before reuse.
     * Only public modulus data is held in this structure. */
    ossl_ee_rsa_public_key_clear(key);
    key->num = mod_bytes / 4;
    rsa_be_to_words(key->mod, modulus, mod_bytes);
    if ((key->mod[0] & 1U) == 0
        || (key->mod[key->num-1] & 0x80000000U) == 0) {
        ossl_ee_rsa_public_key_clear(key);
        return 0;
    }
    key->n0 = rsa_neg_inv32(key->mod[0]);
    key->r2[0] = 1U;
    for (i = 0; i < 64 * key->num; ++i)
        rsa_double_mod(key->r2, key->mod, key->num, diff);
    rsa_wipe(diff, sizeof(diff));
    return 1;
}

int ossl_ee_rsa_public65537_prepared4(
    unsigned char *const out[OSSL_EE_RSA_LANES],
    const unsigned char *const input[OSSL_EE_RSA_LANES],
    const ossl_ee_rsa_public_key *const keys[OSSL_EE_RSA_LANES])
{
    uint32_t a[RSA_MAX_WORDS], base[RSA_MAX_WORDS];
    uint32_t power[RSA_MAX_WORDS], temp[RSA_MAX_WORDS];
    uint32_t one[RSA_MAX_WORDS] = {0};
    unsigned int j;
    size_t lane, num;
    int ok = 0;

    if (out == NULL || input == NULL || keys == NULL)
        return 0;
    /* Validate ALL four inputs before writing any output lane. */
    for (lane = 0; lane < OSSL_EE_RSA_LANES; ++lane) {
        const ossl_ee_rsa_public_key *key = keys[lane];
        if (out[lane] == NULL || input[lane] == NULL || key == NULL)
            goto done;
        num = key->num;
        if (num == 0 || num > RSA_MAX_WORDS
            || !rsa_size_ok(num * 4)
            || (key->mod[0] & 1U) == 0
            || (key->mod[num-1] & 0x80000000U) == 0
            || (uint32_t)(key->mod[0] * key->n0) != UINT32_MAX)
            goto done;
        rsa_be_to_words(a, input[lane], num * 4);
        if (!rsa_less(a, key->mod, num))
            goto done;
    }
    one[0] = 1;
    for (lane = 0; lane < OSSL_EE_RSA_LANES; ++lane) {
        const ossl_ee_rsa_public_key *key = keys[lane];
        num = key->num;
        rsa_be_to_words(a, input[lane], num * 4);
        if (!ossl_ee_bn_mont32(base, a, key->r2,
                               key->mod, key->n0, num))
            goto done;
        memcpy(power, base, num * sizeof(uint32_t));
#ifdef EE_MMI_RSA_SWAP_POWERS
        {
            uint32_t *current = power, *next = temp, *swap;
            /* Alternate buffers instead of copying every square.
             * Both arrays are still wiped at the common exit. */
            for (j = 0; j < 16; ++j) {
#ifdef EE_MMI_BN_PUBLIC_SQUARE
                if (!ossl_ee_bn_mont_sqr32(next, current, key->mod,
                                           key->n0, num))
#else
                if (!ossl_ee_bn_mont32(next, current, current, key->mod,
                                       key->n0, num))
#endif
                    goto done;
                swap = current;
                current = next;
                next = swap;
            }
            if (!ossl_ee_bn_mont32(next, current, base, key->mod, key->n0, num)
                || !ossl_ee_bn_mont32(current, next, one, key->mod,
                                       key->n0, num))
                goto done;
            rsa_words_to_be(out[lane], current, num * 4);
        }
#else
        for (j = 0; j < 16; ++j) {
            if (!ossl_ee_bn_mont32(temp, power, power, key->mod,
                                   key->n0, num))
                goto done;
            memcpy(power, temp, num * sizeof(uint32_t));
        }
        if (!ossl_ee_bn_mont32(temp, power, base, key->mod, key->n0, num)
            || !ossl_ee_bn_mont32(power, temp, one, key->mod,
                                   key->n0, num))
            goto done;
        rsa_words_to_be(out[lane], power, num * 4);
#endif
    }
    ok = 1;
done:
    rsa_wipe(a, sizeof(a));
    rsa_wipe(base, sizeof(base));
    rsa_wipe(power, sizeof(power));
    rsa_wipe(temp, sizeof(temp));
    rsa_wipe(one, sizeof(one));
    return ok;
}

static int rsa_public_one(unsigned char *out, const unsigned char *in,
                           const unsigned char *mod_bytes, size_t k)
{
    uint32_t mod[RSA_MAX_WORDS], a[RSA_MAX_WORDS];
    uint32_t r2[RSA_MAX_WORDS] = {0}, diff[RSA_MAX_WORDS];
    uint32_t base[RSA_MAX_WORDS], power[RSA_MAX_WORDS];
    uint32_t temp[RSA_MAX_WORDS], one[RSA_MAX_WORDS] = {0};
    uint32_t n0;
    size_t num = k / 4, i;
    unsigned int j;
    int ok = 0;

    rsa_be_to_words(mod, mod_bytes, k);
    rsa_be_to_words(a, in, k);
    if ((mod[0] & 1U) == 0 || (mod[num-1] & 0x80000000U) == 0
        || !rsa_less(a, mod, num))
        goto done;

    n0 = rsa_neg_inv32(mod[0]);
    r2[0] = 1;
    for (i = 0; i < 64 * num; ++i)
        rsa_double_mod(r2, mod, num, diff);
    one[0] = 1;

    /* Montgomery form: base = a*R, since R2 = R^2 mod modulus. */
    if (!ossl_ee_bn_mont32(base, a, r2, mod, n0, num))
        goto done;
    memcpy(power, base, num * sizeof(uint32_t));

    /* e = 65537 = 2^16+1. Exactly 16 squares + one multiply. */
    for (j = 0; j < 16; ++j) {
        if (!ossl_ee_bn_mont32(temp, power, power, mod, n0, num))
            goto done;
        memcpy(power, temp, num * sizeof(uint32_t));
    }
    if (!ossl_ee_bn_mont32(temp, power, base, mod, n0, num))
        goto done;
    if (!ossl_ee_bn_mont32(power, temp, one, mod, n0, num))
        goto done;

    rsa_words_to_be(out, power, k);
    ok = 1;
done:
    rsa_wipe(mod, sizeof(mod));
    rsa_wipe(a, sizeof(a));
    rsa_wipe(r2, sizeof(r2));
    rsa_wipe(diff, sizeof(diff));
    rsa_wipe(base, sizeof(base));
    rsa_wipe(power, sizeof(power));
    rsa_wipe(temp, sizeof(temp));
    rsa_wipe(one, sizeof(one));
    return ok;
}

int ossl_ee_rsa_public65537_4(
    unsigned char *const out[OSSL_EE_RSA_LANES],
    const unsigned char *const input[OSSL_EE_RSA_LANES],
    const unsigned char *const modulus[OSSL_EE_RSA_LANES],
    size_t mod_bytes)
{
    uint32_t a[RSA_MAX_WORDS], n[RSA_MAX_WORDS];
    size_t lane, num;
    int ok = 0;

    if (out == NULL || input == NULL || modulus == NULL
        || !rsa_size_ok(mod_bytes))
        return 0;

    num = mod_bytes / 4;
    /* Validate ALL lanes before writing any output. */
    for (lane = 0; lane < OSSL_EE_RSA_LANES; ++lane) {
        if (out[lane] == NULL || input[lane] == NULL
            || modulus[lane] == NULL)
            goto done;
        rsa_be_to_words(a, input[lane], mod_bytes);
        rsa_be_to_words(n, modulus[lane], mod_bytes);
        if ((n[0] & 1U) == 0 || (n[num-1] & 0x80000000U) == 0
            || !rsa_less(a, n, num))
            goto done;
    }
    /* Four independent RSA jobs; PMULTUW packs adjacent limb products. */
    for (lane = 0; lane < OSSL_EE_RSA_LANES; ++lane)
        if (!rsa_public_one(out[lane], input[lane],
                            modulus[lane], mod_bytes))
            goto done;
    ok = 1;
done:
    rsa_wipe(a, sizeof(a));
    rsa_wipe(n, sizeof(n));
    return ok;
}

int ossl_ee_rsa_pkcs1_sha256_verify4(
    unsigned char valid[OSSL_EE_RSA_LANES],
    const unsigned char *const signatures[OSSL_EE_RSA_LANES],
    const unsigned char *const modulus[OSSL_EE_RSA_LANES],
    const unsigned char digests[OSSL_EE_RSA_LANES][32],
    size_t mod_bytes)
{
    /* DER DigestInfo prefix for SHA-256 with AlgorithmIdentifier NULL:
     * SEQUENCE{ SEQUENCE{sha256 OID, NULL}, OCTET STRING(32) }. */
    static const unsigned char sha256_der[19] = {
        0x30,0x31,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,
        0x65,0x03,0x04,0x02,0x01,0x05,0x00,0x04,0x20
    };
    unsigned char recovered[OSSL_EE_RSA_LANES][OSSL_EE_RSA_MAX_BYTES];
    unsigned char checked[OSSL_EE_RSA_LANES][OSSL_EE_RSA_MAX_BYTES];
    unsigned char *out[OSSL_EE_RSA_LANES];
    const unsigned char *input[OSSL_EE_RSA_LANES];
    uint32_t a[RSA_MAX_WORDS], n[RSA_MAX_WORDS];
    unsigned int in_range[OSSL_EE_RSA_LANES];
    size_t lane, i, num;
    int ok = 0;

    if (valid == NULL || signatures == NULL || modulus == NULL
        || digests == NULL || !rsa_size_ok(mod_bytes))
        return 0;
    num = mod_bytes / 4;
    for (lane = 0; lane < OSSL_EE_RSA_LANES; ++lane) {
        if (signatures[lane] == NULL || modulus[lane] == NULL)
            goto done;
        rsa_be_to_words(n, modulus[lane], mod_bytes);
        rsa_be_to_words(a, signatures[lane], mod_bytes);
        if (!(n[0] & 1U) || !(n[num-1] & 0x80000000U))
            goto done;
        in_range[lane] = (unsigned int)rsa_less(a, n, num);
        memcpy(checked[lane], signatures[lane], mod_bytes);
        /* A signature representative >= n is invalid, not a
         * failure to verify the other three public signatures. */
        if (!in_range[lane])
            memset(checked[lane], 0, mod_bytes);
        out[lane] = recovered[lane];
        input[lane] = checked[lane];
    }

    if (!ossl_ee_rsa_public65537_4(out, input, modulus, mod_bytes))
        goto done;

    for (lane = 0; lane < OSSL_EE_RSA_LANES; ++lane) {
        unsigned int diff = (unsigned int)(in_range[lane] ^ 1U);
        size_t ps_end = mod_bytes - sizeof(sha256_der) - 32U - 1U;
        diff |= recovered[lane][0];
        diff |= (unsigned int)(recovered[lane][1] ^ 1U);
        for (i = 2; i < ps_end; ++i)
            diff |= (unsigned int)(recovered[lane][i] ^ 0xffU);
        diff |= recovered[lane][ps_end];
        for (i = 0; i < sizeof(sha256_der); ++i)
            diff |= (unsigned int)(recovered[lane][ps_end+1+i]
                                ^ sha256_der[i]);
        for (i = 0; i < 32; ++i)
            diff |= (unsigned int)(
                recovered[lane][mod_bytes-32+i] ^ digests[lane][i]);
        valid[lane] = (unsigned char)(diff == 0U);
    }
    ok = 1;
done:
    rsa_wipe(recovered, sizeof(recovered));
    rsa_wipe(checked, sizeof(checked));
    rsa_wipe(a, sizeof(a));
    rsa_wipe(n, sizeof(n));
    return ok;
}
