/*
 * Experimental PS2 EE four-lane AES-GCM. Apache-2.0.
 * Not wired into OpenSSL EVP, TLS, or FIPS.
 */
#ifndef OSSL_EE_AES_GCM_H
#define OSSL_EE_AES_GCM_H
#include <stddef.h>
#include <stdint.h>
#include "crypto/ee_mmi.h"

typedef struct {
    ossl_ee_aes4_key aes;
    /* GHASH hash-subkey in word-major big-endian word order. */
    uint32_t h[4][4] __attribute__((aligned(16)));
} ossl_ee_aes_gcm4_key;

/* All streams share one AES-128/192/256 key but use independent
 * 96-bit IVs. Derive H=E_K(0^128) and expand key once.
 * Do not reuse any IV with this key. 1=success, 0=bad arguments.
 */
int ossl_ee_aes_gcm4_init(ossl_ee_aes_gcm4_key *ctx,
                           const unsigned char *key, unsigned int bits);
void ossl_ee_aes_gcm4_clear(ossl_ee_aes_gcm4_key *ctx);

/*
 * Four independent AES-GCM messages of identical byte length and four
 * AAD strings of identical byte length. IV is [4][12]. Tag is [4][16].
 * Input/output pointers may alias their corresponding lane EXACTLY.
 * Other partial overlaps, cross-lane overlaps and overlap with AAD,
 * IV or tags are unsupported. len==0 accepts NULL in/out entries;
 * aad_len==0 accepts NULL aad entries. No heap use.
 *
 * The encrypting path streams CTR ciphertext directly into the GHASH
 * state, without staging an extra copy or calling GHASH once per
 * message. AAD -> ciphertext -> SP 800-38D length block.
 *
 * The decrypting path verifies all 4 tags in constant-time comparison
 * before writing any plaintext. On authentication failure no output
 * bytes are written. All-or-nothing across four streams.
 *
 * Lengths must satisfy the 2^32-2 GCM block counter bound and
 * 64-bit GHASH bit-length encoding. Full 128-bit tags only.
 * 1=success, 0=invalid argument/authentication failed.
 */
int ossl_ee_aes_gcm4_seal(const ossl_ee_aes_gcm4_key *ctx,
                           unsigned char *const out[4],
                           unsigned char tags[4][16],
                           const unsigned char *const in[4], size_t len,
                           const unsigned char *const aad[4], size_t aad_len,
                           const unsigned char iv[4][12]);
int ossl_ee_aes_gcm4_open(const ossl_ee_aes_gcm4_key *ctx,
                           unsigned char *const out[4],
                           const unsigned char tags[4][16],
                           const unsigned char *const in[4], size_t len,
                           const unsigned char *const aad[4], size_t aad_len,
                           const unsigned char iv[4][12]);
#endif
