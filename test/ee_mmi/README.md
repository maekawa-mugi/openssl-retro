# Experimental PS2 EE MMI crypto paths

This branch adds **experimental** four-block ChaCha20, four-message
SHA-224/SHA-256, four-message Poly1305, four-stream X25519,
four-stream GHASH, four-block AES-128/192/256, public RSA
verification, and P-256 ECDHE primitives for the PS2
Emotion Engine (R5900). None has been assembled or executed on a
real EE yet. Do not treat the cryptographic code as production-ready
until cross-compilation, real-hardware differential and timing tests pass.

## AES-GCM integrated four-stream EE experiment

The new internal-only API in include/crypto/ee_aes_gcm.h supplies
four independent AES-GCM encrypt/decrypt streams sharing one AES key,
using independent 96-bit IVs. Length and AAD length are equal across
the four streams. AES-128/192/256 is supported.

crypto/modes/aes-gcm-ee-mmi.c precomputes the AES round keys and
H=E(K,0) only once per key, retains the four GHASH states in 16-byte
aligned word-major arrays and pushes CTR ciphertext directly into
GHASH multiplication within the same loop. There is no additional
ciphertext staging buffer or ossl_ee_ghash_update4 per-message
conversion, and no dynamic memory. AAD is padded separately from
ciphertext and GCM's two 64-bit big-endian bit lengths are hashed last.

This is a **four-stream integrated C orchestrator using the existing
R5900 AES + GHASH MMI assembly**, NOT a new single-instruction
fused AES/GHASH primitive, not an EVP hook and not yet shown to be
faster than EVP's software GCM. GHASH remains bit-serial (128 bit
rounds) and AES SubBytes remains table-free scalar C.

Decrypt authenticates **all four lanes** with full 16-byte tags
before writing **any** plaintext. One bad tag fails the entire batch
without releasing any lane's plaintext. Input/output may alias within
each lane; partial or cross-lane overlaps are unsupported.
IV reuse under the same key is forbidden outside synthetic benchmarks.
Nonce must be exactly 12 bytes, tags exactly 16 bytes, and the total
GCM block count is bounded by 2^32-2.

~~~sh
sh test/ee_mmi/run-aes-gcm-host.sh
EE_GCM_SCALAR=1 sh test/ee_mmi/run-aes-gcm-host.sh
sh test/ee_mmi/build-aes-gcm-ee.sh
EE_GCM_SCALAR=1 sh test/ee_mmi/build-aes-gcm-ee.sh
~~~

test/ee_mmi/aes_gcm_test.c covers published NIST SP 800-38D AES-GCM
zero-length, 16-byte and 60-byte/AAD20 cases, 315 randomized
length/AAD/key-size combinations with four distinct IVs, partial
blocks, tag/AAD tampering, in-place encryption/decryption,
output guards and invalid-input cases.

Both normal and scalar AES/GHASH backends are tested on host and
in PS2 A/B mode. The tenth suite ("AES-GCM") is measured only after
validation, with four 256-byte messages and 20-byte AAD, comparing
ciphertext **and tags** after timer stop. Only the ps2-ee-mmi
libcrypto build includes the new module; FIPS and EVP stay unchanged.

## Experimental RSA-65537 / SHA-256 certificate signature verification

Public-key RSA verification is an important HTTPS operation. This
prototype reuses the existing 32-bit EE Montgomery CIOS implementation:
\`ossl_ee_bn_mont32()\` in crypto/bn/bn-ee-mmi.c together with R5900
\`PMULTUW\` in crypto/bn/bn-ee-mmi.S, which computes two full-width
unsigned 32x32->64 products at a time. Do **not** use this code for
RSA private-key operations, decrypting, key generation or signing.

- crypto/rsa/rsa-ee-mmi.c implements the fixed public exponent
  \`e=65537\` with 16 Montgomery squarings, one multiplication, and
  a final conversion out of the Montgomery domain.
- The Montgomery constant \`R^2 mod n\` is derived by repeated fixed
  32-bit modular doubling (no dependence on OpenSSL BN internals).
- Supports 1024/2048/3072/4096-bit odd, full-width RSA moduli, with
  four **independent RSA jobs** at each call, each having its own
  signature and public modulus. Four jobs are executed sequentially:
  the MMI instruction pairs two adjacent **limb multiplications**,
  not four entire RSA-2048 exponentiations simultaneously.
- \`ossl_ee_rsa_public65537_4\` returns fixed-width big-endian
  \`s^65537 mod n\`, rejecting representatives outside \`[0,n)\`.
- \`ossl_ee_rsa_pkcs1_sha256_verify4\` checks **strict**
  RSASSA-PKCS1-v1_5 padding and the canonical SHA-256 DigestInfo,
  including 0x00 0x01, at least 8 0xff bytes, separator 0x00, OID
  and a supplied 32-byte SHA-256 digest. It independently reports
  valid/invalid status for four signatures, including representatives
  at or above the modulus.
- Both public-only internal APIs are declared in
  include/crypto/ee_rsa_verify.h. The existing RSA_METHOD, EVP,
  OpenSSL providers and FIPS library are deliberately unchanged.
- The 2048-bit test includes **four distinct RSA public moduli,
  four actual PKCS#1 v1.5 SHA-256 signatures**, successful verification,
  tampered signature, tampered digest, out-of-range signature, and
  raw/in-place public exponentiation.
- test/ee_mmi/check-rsa.py independently recomputes the four RSA
  signatures with Python BigInt \`pow(sig,65537,n)\`, and 96 random
  Montgomery input conversion/exponentiation arithmetic models.

Host checks (these DO NOT execute R5900 MMI instructions):

~~~sh
python3 test/ee_mmi/check-rsa.py
sh test/ee_mmi/run-rsa-host.sh
CFLAGS="-O2 -DEE_MMI_BN_SCALAR_MUL" sh test/ee_mmi/run-rsa-host.sh
~~~

PS2 standalone builds (link only C and R5900 MMI, not full OpenSSL):

~~~sh
sh test/ee_mmi/build-rsa-ee.sh
# => ee_rsa_pmultuw_test.elf

EE_RSA_SCALAR=1 sh test/ee_mmi/build-rsa-ee.sh
# => ee_rsa_scalar_test.elf
~~~

Run both on a real PS2 and require all known signatures to verify
before benchmarking. Passing \`--extended\` also exercises 3072- and
4096-bit moduli but takes additional time.

**HTTPS/TLS limitations:** TLS 1.3 RSA signatures use RSA-PSS, which
this prototype does NOT implement. This code verifies only PKCS#1
v1.5 SHA-256 (useful for some certificate signatures and TLS 1.2).
It does not parse ASN.1 certificates, hash the signed message, or
check public-key certificate chains. This implementation is not
connected to the OpenSSL standard EVP/TLS RSA verification path.
It must not be used in production without actual EE hardware
validation, timing review, and verification against OpenSSL vectors.

## Experimental P-256 ECDHE key agreement using EE PMULTUW

This is a standalone **NIST P-256 (secp256r1) ECDH and public-key
generation** prototype relevant to HTTPS/TLS ECDHE key exchange.
It uses the existing R5900 two-word \`PMULTUW\` backend in
crypto/bn/bn-ee-mmi.S through the 8-limb
\`ossl_ee_bn_mont32()\` 32-bit Montgomery multiplication kernel.
No new P-256-specific vector assembly instructions are claimed:
the MMI acceleration is on **two 32x32-bit limb products at a time**.

Files:
- crypto/ec/p256-ee-mmi.c: 8x32-bit Montgomery field arithmetic modulo
  \`p=2^256-2^224+2^192+2^96-1\`, fixed 256-step Jacobian
  Montgomery ladder, independent point validation, SEC1 encoding,
  and p-2 field inversion. Point arithmetic uses \`a=-3\` formulas.
- include/crypto/ee_p256_ecdh.h: independent opt-in
  \`ossl_ee_p256_public_from_private\` and \`ossl_ee_p256_ecdh\`
  signatures and constraints.
- crypto/ec/build.info: EE-only independent source; no changes to
  normal ECDH / EC_POINT_mul / EC_METHOD / EVP / provider selection.
- test/ee_mmi/p256_ecdh_test.c: 10 independent P-256 public key
  known answers, 20 shared-secret agreements, invalid scalar
  and off-curve peer rejection, zero-output-on-error checks.
- test/ee_mmi/check-p256.py: independent BigInt affine-point
  oracle and 64 additional random group-law checks.

Host-only portable verification (NO R5900 instruction execution):

~~~sh
python3 test/ee_mmi/check-p256.py
sh test/ee_mmi/run-p256-host.sh
CFLAGS="-O2 -DEE_MMI_BN_SCALAR_MUL" sh test/ee_mmi/run-p256-host.sh
~~~

Standalone PS2 ELF comparison (PS2SDK gcc required):

~~~sh
sh test/ee_mmi/build-p256-ee.sh
# => ee_p256_ecdh_mmi_test.elf

EE_P256_SCALAR=1 sh test/ee_mmi/build-p256-ee.sh
# => ee_p256_ecdh_scalar_test.elf
~~~

After correctness is confirmed on a real EE, pass \`--bench\` to either
ELF to compare a single ECDH public key agreement. There is no
validated speedup result yet.

**Security:** This prototype accepts canonical big-endian scalars in
the range 1..n-1 and uncompressed \`04||X||Y\` public points only.
It rejects noncanonical coordinates and points not on the curve.
The scalar ladder uses fixed 256-bit iterations and conditional
swaps instead of scalar-bit branches. However, the EE assembly ABI,
compiler output, cache accesses, instruction latency, exceptional
points, side channels and stack erasure are **not audited**.
**Never use this experimental routine with real TLS/private keys.**
No production TLS/ECDHE integration or FIPS claim is made.

ECDSA-P256 signature verification is a **different existing EE
prototype**, implemented in crypto/ec/ee-ecdsa-p256.c: it currently
calls the regular OpenSSL EC point multiplication and uses MMI
only for two modulo-group-order scalar products. The new ECDHE
prototype instead performs its own P-256 point arithmetic modulo
the *field prime* and is independent of OpenSSL's EC implementation.

## Experimental ECDSA P-256 signature verification (SHA-256)

This is a verification-only prototype for an important HTTPS certificate
signature format: **ECDSA with NIST P-256 and SHA-256**. It is an
**explicit internal entry point**, NOT an OpenSSL EVP, ECDSA_do_verify
or EC_METHOD replacement. Production TLS certificate verification
will not automatically use this path.

- crypto/ec/ee-ecdsa-p256.c: verifies a 32-byte SHA-256 digest using a
  65-byte SEC1 uncompressed P-256 public key and a 64-byte IEEE P1363
  signature (big-endian r||s).
- include/crypto/ee_ecdsa_p256.h: documents the verification function
  \`ossl_ee_ecdsa_p256_verify()\` and its return values.
- ECDSA scalar arithmetic: s^-1 and curve point operations use the
  existing OpenSSL BIGNUM/EC functions; u1=e*s^-1 mod n and
  u2=r*s^-1 mod n use the EE MMI 32-bit Montgomery kernel already
  in crypto/bn/bn-ee-mmi.c / bn-ee-mmi.S.
- The modulus is the **P-256 group order n, not the field prime p**.
  Each MMI multiplication receives two Montgomery-domain 256-bit
  operands and is converted back to an ordinary BIGNUM.
- The portable comparison build uses OpenSSL BN_mod_mul instead of
  the two MMI-backed Montgomery multiplications.
- crypto/ec/build.info: links the internal verifier into EE libcrypto
  only with assembly enabled. Original generic ECDSA and EVP paths
  remain unchanged.
- test/ee_mmi/ecdsa_p256_test.c: three deterministic positive vectors,
  27 tampered signature/digest/key/range checks and NULL inputs.
  Test private keys and fixed nonces are NEVER for production signing.
- test/ee_mmi/check-ecdsa.py: independent pure Python BigInt point
  arithmetic and ECDSA signing/verification oracle, no third-party
  dependencies.

Host validation requires installed OpenSSL development headers
and libcrypto (e.g. libssl-dev on Linux):

~~~sh
python3 test/ee_mmi/check-ecdsa.py
sh test/ee_mmi/run-ecdsa-host.sh
EE_ECDSA_SCALAR=1 sh test/ee_mmi/run-ecdsa-host.sh
sh test/ee_mmi/run-ecdsa-host.sh --bench
~~~

The host "MMI" runner tests the exact C Montgomery kernel using
portable 32x32->64 multiplication instead of the R5900 assembler.

EE verification requires a previously built **static libcrypto.a**
containing the ee_mmi EC and BN backends, and SDK-compatible
OpenSSL APIs. First make the normal EE libcrypto build work;
ECDSA needs EC_GROUP/EC_POINT_mul/BIGNUM functionality:

~~~sh
sh test/ee_mmi/build-ecdsa-ee.sh
# => ee_ecdsa_p256_mmi_test.elf

EE_ECDSA_SCALAR=1 sh test/ee_mmi/build-ecdsa-ee.sh
# => ee_ecdsa_p256_scalar_test.elf
~~~

Run the ELFs on a real PS2. Compare correctness before \`--bench\`.
The two extra modular multiplications are only a small part of
P-256 signature verification. Conversion to/from Montgomery
representation may eliminate any speed benefit. Timing must be
measured rather than assumed.

Security limitations: only **verification**, no signing or private
keys; input signatures use fixed-width IEEE P1363 and are NOT DER;
the 32-byte digest must already be computed by the caller.
The function accepts conventional high-S ECDSA signatures. All-zero,
malformed or off-curve input public keys are rejected. No FIPS
validation or constant-time/hardware side-channel review is claimed.
Production use requires a real EE port, differential testing, and
integration into an appropriate existing OpenSSL verification path.

## Experimental OpenSSL BN Montgomery (R5900 PMULTUW)

The bounded, fixed-loop 32-bit Montgomery CIOS kernel is in
crypto/bn/bn-ee-mmi.c and crypto/bn/bn-ee-mmi.S, with the standalone
header include/crypto/ee_bn_mont.h. It supports 1..128 limbs, or
32..4096-bit moduli. The modulus must be odd and inputs must be
reduced, a < N and b < N. Output may alias a or b.

**MMI bit31 safety:** arbitrary 32-bit BIGNUM limbs can have their
sign bit set. PMULTUW performs unsigned multiplication but the R5900
ISA still requires sign-extended 32-bit word-value operands.
PSRAW by 31 followed by PEXTLW interleaves each scalar operand with
its correct all-zero or all-one extension. Passing Poly1305-style
always-zero extensions here would be undefined for bit31-set values.

Each call performs two exact unsigned 32x32 -> 64 products. The
kernel implements integrated operand-scanning Montgomery REDC and
one constant-time final subtraction. This first-cut implementation
prioritizes compatibility and testability over speed:
each pair product is sent through a small aligned temporary. That
overhead may make it **slower** than normal scalar multiplication.

Build the host-emulated differential and full-width arithmetic tests:

~~~sh
python3 test/ee_mmi/check-bn-mont.py
sh test/ee_mmi/run-bn-mont-host.sh
CFLAGS="-O2 -DEE_MMI_BN_SCALAR_MUL" \
  sh test/ee_mmi/run-bn-mont-host.sh
~~~

Build two separate PS2 ELF test variants:

~~~sh
sh test/ee_mmi/build-bn-mont-ee.sh
# => ee_bn_mont_pmultuw_test.elf

EE_BN_SCALAR=1 sh test/ee_mmi/build-bn-mont-ee.sh
# => ee_bn_mont_scalar_test.elf
~~~

Both ELFs use the independent schoolbook+REDC test reference, 512
full-width unsigned multiplication checks, random and maximal limb
vectors, output/input-alias tests, plus guard sentinels. Run both
on the real console, optionally with --bench. Confirm identical
results and record timings before selecting MMI.

### OpenSSL integration is opt-in

crypto/bn/build.info adds bn-ee-mmi.c and bn-ee-mmi.S **only** to
libcrypto under ps2-ee-mmi with assembly enabled; it does not add
them to the FIPS provider. The existing BN_mod_mul_montgomery() path
remains unchanged unless an explicit no-fips EE experimental build
defines OPENSSL_BN_ASM_MONT:

~~~sh
./Configure ps2-ee-mmi -DOPENSSL_BN_ASM_MONT \
    no-fips no-shared no-threads no-dso no-tests no-module \
    no-async no-sock no-ui-console
make -j2 build_libs
~~~

This Configure command is a **starting point, not a verified SDK
recipe**. Avoid passing OPENSSL_BN_ASM_MONT to other CPU targets or
FIPS builds. The wrapper returns zero for unsupported sizes and the
OpenSSL bn_mont.c dispatcher then uses its established generic path.
The BIGNUM backend is not an optimized full assembly kernel:
MMI accelerates only the paired 32-bit products, while carry chains
and final reduction remain scalar. Performance and constant-time
behavior must be checked on hardware before any production use.

## Implemented

- Configurations/50-ee-mmi.conf: the ps2-ee-mmi build target using the
  PS2SDK mips64r5900el-ps2-elf-gcc toolchain.
- crypto/chacha/chacha-ee-mmi.S: a genuine EE MMI path with four
  independent 32-bit ChaCha state words per 128-bit GPR. It executes
  20 rounds using PADDW, PXOR, PSLLW, PSRLW and POR.
- crypto/chacha/chacha-ee-mmi.c: 256-byte batches, feed-forward and
  bytewise XOR, arbitrary byte alignment and in-place support.
  Non-batch remainder uses the scalar ChaCha20_ctr32_c fallback.
- The 32-bit block counter wraps without carry into the nonce, matching
  the existing OpenSSL ChaCha20_ctr32 API.
- crypto/chacha/build.info: enables this backend **only** for the new
  ee_mmi asm architecture when assembly is enabled.
- test/ee_mmi/chacha20_test.c: RFC 8439 known-answer, independent
  scalar comparison, buffer/input/key immutability guards, in-place,
  alignment, boundary lengths, split-call equivalence, counter wrap
  and optional scalar-versus-MMI throughput comparison.

- crypto/sha/sha256-ee-mmi.S: four independent SHA-256 compression
  states processed in four packed 32-bit lanes with R5900 MMI.
  The 64 round constants and message schedule use 16-byte aligned,
  word-major arrays.
- crypto/sha/sha256-ee-mmi.c: complete SHA-224/SHA-256 for four
  independent input buffers of the **same length**, with standard
  padding and byte-order handling, via the internal
  ossl_ee_sha256_hash4() and ossl_ee_sha224_hash4() functions in
  include/crypto/ee_mmi.h. Both share the same MMI compressor,
  using distinct initial values and 32/28-byte digest lengths.
- crypto/sha/build.info: builds SHA-256 MMI support into libcrypto
  **only for ee_mmi with assembly enabled** (not into FIPS provider).
- test/ee_mmi/sha256_test.c: SHA-224 and SHA-256 known-answer
  vectors, randomized per-lane inputs, message-length boundaries,
  invalid arguments and throughput comparisons.

- crypto/poly1305/poly1305-ee-mmi.S: genuine EE MMI PADDW
  absorption for five 26-bit limbs across four separate authenticators.
- crypto/poly1305/poly1305-ee-pmultuw.S: exact 32x32->64-bit
  packed unsigned integer products for four streams (two per PMULTUW),
  using PEXTLW/PEXTUW with zeros in each unused upper 32-bit word.
  All 25 five-limb convolution terms and all four output lanes are
  covered; output is a temporary 5 x 5 x 4 array of 64-bit products.
- crypto/poly1305/poly1305-ee-pmadduw.S: optional experimental
  PMULTUW + PMADDUW fused 64-bit accumulation in the EE HI/LO
  registers. The five exact sums per message occupy a 160-byte
  temporary buffer instead of 800 bytes of individual products.
- test/ee_mmi/check-pmadduw.py: independent Python arithmetic and
  packing model for the 64-bit fused accumulation, with boundary
  cases, all five convolution limbs and four lanes.
- crypto/poly1305/poly1305-ee-mmi.c: four equal-length messages,
  independent 32-byte one-time Poly1305 keys; default 2x32->64
  PMULTUW products, with exact shared scalar 64-bit accumulation,
  modular carry/reduction and fixed-time tag emit. An explicit
  scalar multiplication compile-time alternative is provided.
  This is an **internal opt-in batch API** via
  ossl_ee_poly1305_auth4() in include/crypto/ee_mmi.h.
- crypto/poly1305/build.info: only links this internal API on EE
  with assembly; the existing OpenSSL Poly1305_Init/Update/Final
  behavior is untouched.
- test/ee_mmi/poly1305_test.c: RFC 7539 known answer, 84 tags from
  an independent Python big-integer oracle, boundary sizes,
  unaligned message pointers and input/key/output guard checks.
  In the PMULTUW build it also tests 256 full 25-term/four-lane product
  matrices, including high 64-bit halves and memory sentinels.
  The golden vectors are reproducible with poly1305-oracle.py.

- crypto/ec/x25519-ee-mmi.S: 4 independent finite-field
  multiplications over 2^255-19, with 10 alternating 26/25-bit
  limbs, 200 PMULTUW/PMADDUW operations per multiply, and a
  320-byte exact 64-bit convolution output (10 sums x 4 lanes).
- crypto/ec/x25519-ee-mmi.c: complete RFC 7748 Montgomery ladder
  including scalar clamping, constant-time conditional swaps,
  fixed-exponent addition-chain inversion, canonical serialization
  and input high-bit masking.
  Each lane accepts an independent 32-byte private scalar and
  32-byte public u-coordinate.
- include/crypto/ee_mmi.h: ossl_ee_x25519_scalar_mult4()
  is an experimental internal opt-in batch API. **It does not replace
  any EVP_X25519 implementation or establish a TLS key exchange.**
- crypto/ec/build.info: compiles the standalone X25519 batch
  backend only for ee_mmi when assembly and ecx are enabled.
  The original curve25519.c remains unmodified.
- test/ee_mmi/x25519_test.c: RFC 7748 Alice/Bob public key and shared
  secret vectors, independent 32-tag BigInt oracle cross-checks,
  null arguments, masking of the high bit of input u, zero inputs,
  secret-key immutability, and direct 128-case PMADDUW product sums.
- test/ee_mmi/check-x25519.py: independent BigInt X25519 reference,
  4096 finite-field multiply/add/sub/constant arithmetic checks
  and all 200 MMI convolution-term offsets.

- crypto/modes/ghash-ee-mmi.S: four simultaneous independent
  GHASH field multiplications (GF(2^128)) implemented in 128
  fixed iterations with PAND, PXOR, PSRAW, PSLLW, PSRLW and POR.
  Each EE 128-bit register contains four independent 32-bit lanes.
  No carryless-multiply instruction is required.
- crypto/modes/ghash-ee-mmi.c: independent GHASH update for four
  input streams with separate 128-bit authentication subkeys and
  separate rolling 128-bit state. Supports incremental blocks,
  arbitrary byte alignment and an explicit scalar A/B alternative.
- crypto/modes/build.info: EE-only opt-in internal library source.
  The existing AES-GCM GHASH selection remains unchanged.
- test/ee_mmi/ghash_test.c: NIST AES-GCM derived GHASH test, 32
  independently generated 128-bit oracle states, split-stream
  equivalence, independent keys, unaligned input, mutation guards,
  256 direct four-lane product tests, and optional throughput.
- test/ee_mmi/check-ghash.py: independent GF(2^128) BigInt
  oracle, 1024 algebra checks, NIST known answer, golden vectors,
  plus static validation of the packed MMI right-shift direction.

- crypto/aes/aes-ee-mmi.S: four independent 128-bit AES blocks
  transposed across R5900 MMI 32-bit lanes, with packed
  table-free MixColumns and AddRoundKey. The 4x32-bit packed
  bytewise xtime implementation uses PSLLW/PSRLW/PAND/PXOR/POR.
- crypto/aes/aes-ee-mmi.c: AES-128/192/256 key expansion,
  four-block AES encryption with a **shared key** (the common TLS
  record shape), fixed-time algebraic S-box, ShiftRows, and
  an AES-CTR32 XOR wrapper for arbitrary lengths and in-place input.
  The 96-bit nonce prefix + big-endian 32-bit counter is supplied
  by the caller and counter wrap is rejected.
- crypto/aes/build.info: enables the new internal source only
  on ee_mmi, without redefining AES_ASM/AES_CTR_ASM or changing
  existing AES_encrypt, EVP AES, and AES-GCM dispatch.
- test/ee_mmi/aes_test.c: NIST AES-128/192/256 FIPS-197 encrypt,
  NIST SP 800-38A AES-128/256 CTR known answers, 96 independent
  4-block reference encryptions, in-place, partial CTR blocks,
  key round-data wiping, wrap rejection, and direct MMI-round tests.
- test/ee_mmi/check-aes.py: AES S-box algebra plus 8192
  independent packed MixColumns/ARK test cases and assembly
  offset/build-isolation checks.

Other CPU backends remain unchanged.

**X25519 security note:** The RFC 7748 core accepts low-order points,
so an all-zero shared-secret result must be checked and rejected by
protocol-level callers. This batch primitive does not perform that
policy check. No constant-time analysis or real-EE correctness proof
has been completed. Do not use this experimental path for production
private keys.


**Important:** the SHA-224/SHA-256 4-message internal APIs are opt-in. They
do NOT replace SHA256_Update(), SHA224_Update(), EVP_Digest(), or
sha256_block_data_order(), which are serial-chain algorithms.
The MMI path is useful when the application has four independent
SHA-256 messages to hash concurrently, not when it hashes one
message. This is not a general SHA-2 provider acceleration claim.

## Preliminary host test (no PS2 toolchain)

~~~sh
python3 test/ee_mmi/check-asm.py
python3 test/ee_mmi/check-pmultuw.py
python3 test/ee_mmi/check-pmadduw.py
python3 test/ee_mmi/check-x25519.py
python3 test/ee_mmi/check-ghash.py
python3 test/ee_mmi/check-aes.py
sh test/ee_mmi/run-aes-host.sh
CFLAGS="-O2 -DEE_MMI_AES_SCALAR_ROUND" sh test/ee_mmi/run-aes-host.sh
sh test/ee_mmi/run-aes-host.sh --bench
sh test/ee_mmi/run-ghash-host.sh
CFLAGS="-O2 -DEE_MMI_GHASH_SCALAR_MULTIPLY" sh test/ee_mmi/run-ghash-host.sh
sh test/ee_mmi/run-ghash-host.sh --bench
sh test/ee_mmi/run-x25519-host.sh
CFLAGS="-O2 -DEE_MMI_X25519_SCALAR_MULTIPLY" sh test/ee_mmi/run-x25519-host.sh
sh test/ee_mmi/run-x25519-host.sh --bench
sh test/ee_mmi/run-host.sh
sh test/ee_mmi/run-host.sh --bench
sh test/ee_mmi/run-sha256-host.sh
sh test/ee_mmi/run-sha256-host.sh --bench
python3 test/ee_mmi/poly1305-oracle.py
sh test/ee_mmi/run-poly1305-host.sh
sh test/ee_mmi/run-poly1305-host.sh --bench
CFLAGS="-O2 -DEE_MMI_POLY1305_FUSED_MADD" sh test/ee_mmi/run-poly1305-host.sh
~~~

The Python checkers validate assembly register mapping, quarter-round
ordering, stack-save rules and backend selection, and independently
model PEXTLW/PEXTUW/PMULTUW's two 64-bit results plus all 25 four-lane
Poly1305 convolution terms. The host
binary compiles the actual C dispatcher against a **portable replacement**
for the MMI round routine. CI also uses GCC/Clang and ASan/UBSan. These
tests cover dispatcher edge conditions, but **host PASS is not proof
that R5900 assembly works**.

## Standalone EE ELF: fastest way to test real MMI

This variant links only the dispatcher, the actual EE MMI assembler
and the self-contained test reference. It does **not** link against
libcrypto or depend on generated OpenSSL headers. This is preferable
for the initial EE instruction/ABI verification.

~~~sh
sh test/ee_mmi/build-ee-standalone.sh
# Transfer ee_mmi_chacha20_test.elf to the real PS2 and run it.
sh test/ee_mmi/build-sha256-ee.sh
# Transfer ee_mmi_sha256_test.elf to the real PS2 and run it.
# PADDW absorption + PMULTUW multiplication (default):
sh test/ee_mmi/build-poly1305-ee.sh
# => ee_mmi_poly1305_test.elf

# PADDW + fused PMULTUW/PMADDUW accumulation:
EE_POLY_FUSED_MADD=1 sh test/ee_mmi/build-poly1305-ee.sh
# => ee_poly1305_fused_madd_test.elf

# PADDW absorption + scalar multiplication:
EE_POLY_MULT_SCALAR=1 sh test/ee_mmi/build-poly1305-ee.sh
# => ee_poly1305_paddw_test.elf

# Fully scalar, no EE assembly:
EE_POLY_SCALAR=1 sh test/ee_mmi/build-poly1305-ee.sh
# => ee_poly1305_scalar_test.elf

# Transfer all four .elf files to PS2. Run --bench on each.
# Compare correctness first and timings second.
# If your runtime accepts arguments, use --bench for comparisons.
~~~

Override CC, CFLAGS, LDFLAGS and OUT as appropriate for your PS2SDK
installation. The default CFLAGS are -O2 -march=r5900 -G0.
The linker still requires a functioning EE libc and startup CRT.
The target uses MMI instructions so the binary is only safe to run on EE.

The standalone build defines EE_MMI_STANDALONE so the test supplies
ChaCha20_ctr32_c as its independent scalar tail fallback; the MMI code
for messages of at least 256 bytes is the exact production assembly.

The standalone SHA-224/SHA-256 test links the exact MMI compressor against the
SHA-256 batch wrapper and scalar reference, without the wider OpenSSL
platform port. All standalone builds are **unverified on real EE**.

## PS2 build, for verification with your PS2SDK

Prerequisites: Perl, a PS2SDK EE cross toolchain, compatible libc and
the required headers. This is an *unverified starting point*, not a
confirmed complete SDK recipe:

~~~sh
./Configure ps2-ee-mmi \
    no-shared no-threads no-dso no-tests no-module \
    no-async no-sock no-ui-console
make -j2 build_libs
~~~

If those features or build steps aren't supported by your particular
SDK / OpenSSL revision, adjust the configuration. Static libcrypto.a
is the initial target. libssl, entropy sources, sockets and other
platform support are outside this first optimization patch.
The assembly assumes the default EE SDK ABI and 16-byte stack
alignment. Validate both.

Once libcrypto.a builds, compile the standalone harness and run it
**on the EE** with your PS2SDK launch setup:

~~~sh
mips64r5900el-ps2-elf-gcc -O2 -Iinclude -I. \
  test/ee_mmi/chacha20_test.c ./libcrypto.a \
  -o ee_mmi_chacha20_test.elf
# Upload and run the .elf on an actual PlayStation 2.
# Pass --bench if the runtime implements clock().
~~~

The test calls OpenSSL's internal ChaCha20_ctr32 symbol, so a static
build with that symbol available is required. The SDK may require
additional linker flags, startup objects or supporting libraries.

## X25519 PS2 standalone verification

~~~sh
# MMI 4-stream field multiplication:
sh test/ee_mmi/build-x25519-ee.sh
# => ee_x25519_mmi_test.elf

# Pure 64-bit scalar field multiplication, otherwise same ladder:
EE_X25519_SCALAR=1 sh test/ee_mmi/build-x25519-ee.sh
# => ee_x25519_scalar_test.elf
~~~

Transfer both ELF files to the real PS2. Check the RFC 7748
Alice/Bob test vectors first, then the independent BigInt vectors
and exact 64-bit field convolution tests. Run with `--bench` only
after correctness is established. The host replacement for MMI
convolution does not test the assembler, CPU registers or EE ABI.

The fused MMI kernel folds all 100 ten-by-ten convolution products
per field multiplication with PMULTUW/PMADDUW and produces 40 exact
64-bit sums.
The inversion follows the fixed OpenSSL X25519 addition chain for
p-2 = 2^255-21, using 254 squares and only 11 non-square
multiplications. All loop counts depend only on public constants. This implementation favors easily auditable data flow
over throughput. It currently constructs the 640-byte scaled operand
table on every field multiplication; this and the MMI accumulator
dependency chains may substantially reduce performance. Standard
OpenSSL X25519 continues to use its original backend.

## AES-128/192/256 four-block EE prototype

~~~sh
# Real R5900 MMI MixColumns/ARK variant:
sh test/ee_mmi/build-aes-ee.sh
# => ee_aes_mmi_test.elf

# Same AES S-box, key schedule and ShiftRows; scalar round core:
EE_AES_SCALAR=1 sh test/ee_mmi/build-aes-ee.sh
# => ee_aes_scalar_test.elf

# Portable host emulator and independent math checks:
python3 test/ee_mmi/check-aes.py
sh test/ee_mmi/run-aes-host.sh
~~~

The shared-key 4-way AES function is
`ossl_ee_aes_encrypt4(out[4][16], in[4][16], ctx)`. Set the
round keys with `ossl_ee_aes_set_encrypt_key(ctx, key, bits)`
where bits is 128, 192 or 256, and explicitly erase the context
with `ossl_ee_aes_clear_key(ctx)` afterward. The context is
approximately 1 KiB. Both the round-key context and the interleaved
four-column state require 16-byte alignment in the EE backend.

`ossl_ee_aes_ctr32_xor(out, in, len, ctx, nonce12, counter32)`
uses a caller-supplied 96-bit prefix and 32-bit big-endian counter.
It encrypts four consecutive counter blocks together, supports
arbitrary byte lengths and identical in/out pointers, and rejects
operations that would consume a wrapped 32-bit counter.
**Never reuse a nonce+counter range with the same AES key.**

The S-box is currently a table-free, fixed-operation GF(2^8)
calculation in C. The packed MMI operations implement only
MixColumns and AddRoundKey, not the full AES round. This gives a
constant-time design baseline with easy testability but is likely
much slower than a well-optimized scalar or bitsliced implementation.
Do not claim a performance win until EE hardware measurements.

This is AES encryption/CTR only, NOT AES-GCM: it does not derive
the GHASH subkey or combine AES-CTR with authenticated ciphertext.
The separate GHASH prototype cannot be substituted into EVP without
proper AAD, final length block and tag validation. All current
AES and GHASH functions remain internal experimental APIs, and
OpenSSL's standard TLS/EVP paths are unchanged.

## GHASH four-stream EE experiment

~~~sh
# Four independent GHASH streams with MMI bit-serial multiply:
sh test/ee_mmi/build-ghash-ee.sh
# => ee_ghash_mmi_test.elf

# Same GHASH algorithm using only scalar C:
EE_GHASH_SCALAR=1 sh test/ee_mmi/build-ghash-ee.sh
# => ee_ghash_scalar_test.elf

# PC reference model and host C-emulation tests:
python3 test/ee_mmi/check-ghash.py
sh test/ee_mmi/run-ghash-host.sh
~~~

Run both ELFs on real PS2 hardware and require NIST and BigInt
vectors to pass before comparing `--bench` results. No R5900 build
or hardware verification has been completed.

The internal API is
`ossl_ee_ghash_update4(y, h, in, blocks)`. All inputs are
**whole 16-byte GHASH blocks**, four independent equal block counts,
with independent H and initial Y. Y is updated in place. The caller
handles AES-GCM's AAD/ciphertext padding, length-block construction
and authentication-tag XOR with E(K,J0). This backend does not
provide AES encryption and does not change existing OpenSSL EVP
AES-GCM dispatch. Only set H values produced by a suitable block
cipher key; do not reuse mismatched states or length encodings.

GHASH is polynomial multiplication in GF(2^128). Unlike ordinary
PMULTUW integer products, field multiplication omits integer carries.
The current EE implementation therefore uses 128 constant-time
bit-serial iterations, processing four messages together using
packed XOR, AND, and word shifts. It is deliberately simple, and
might be slower than the existing scalar GHASH or the normal
OpenSSL table implementation. No speedup is claimed.

## About floating-point Poly1305

The upstream crypto/poly1305/poly1305.c comments explicitly
acknowledge D. J. Bernstein's historical floating-point Poly1305
implementations. These were useful especially when scalar integer
multiplication was slow or nonconstant-time.

**Do not transpose an x87/double implementation verbatim to the EE.**
The PS2 EE and VU floating-point registers use approximately
24-bit-significand single precision, unlike the 53-bit significand
of IEEE binary64 (or x87's extended precision). A product of two
12-bit nonnegative integers fits exactly within 24 bits, but summing
many such products can exceed 24 significant bits. To safely exploit
EE FPU/VU, a different narrower-limb representation, normalization
schedule, explicit rounding/error proof, and extensive randomized
cross-checking would be required. The PS2's nonstandard handling of
denormals and rounding is an additional consideration.

The default Poly1305 MMI path now performs packed PADDW block
absorption **and genuine unsigned PMULTUW multiplication**. As
documented for the R5900, each PMULTUW executes exactly two unsigned
32x32->64 products. The four message lanes are split into two pairs
using PEXTLW/PEXTUW with zero upper 32-bit slots, fulfilling the EE
instruction's word-value constraint for all 26-bit limbs and 5*r
values. Both products are read from the destination 128-bit register
and stored as complete 64-bit values. The instruction also modifies
EE HI/LO; those are caller-clobbered here.

All 25 convolution terms per message are explicitly calculated with
PMULTUW and written into an 800-byte temporary product matrix.
The following 64-bit sums, carry normalization, prime-field reduction
and authentication-tag emission remain scalar and exact.

The fused PMADDUW variant is selected with
`EE_POLY_FUSED_MADD=1` for the standalone ELF, or
`-DEE_MMI_POLY1305_FUSED_MADD` as a C define in a full EE build.
For each of the five limbs and each pair of lanes, one PMULTUW clears
and seeds HI/LO, followed by four PMADDUW operations accumulating
exact 64-bit products. This produces five output sums per message,
written in a 160-byte buffer. The reduction and tag output remain
the same as in all comparison builds. Both MMI multiplication modes
also construct their word-major r and 5*r operands **once per
authentication key**, outside the 16-byte message-block loop, and
explicitly wipe these key-dependent arrays at completion. All input limbs are
nonnegative and less than 2^31, so the zero-extension used by
PEXTLW/PEXTUW satisfies the input word-value restriction.
The maximum sum fits in 59 bits, with no signed or unsigned wrap.

The fused assembler includes a direct 256-case sum test using
independent 64-bit scalar products and guard sentinels. The Python
model checks another 512 zero, maximal-value and random cases across
all four lanes, without executing hardware instructions. It has not
been tested on actual EE hardware; PMADDUW HI/LO interlocks may
offset or outweigh reduced memory traffic. Do not assume a speedup.

**Performance is not established.** This initial PMULTUW version
prioritizes straightforward validation over scheduling. The temporary
product matrix, two PMULTUW instructions per convolution term, and
interlocks may be slower than the scalar implementation. The EE
assembler must accept PMULTUW/PEXTLW/PEXTUW and the default ABI must
permit clobbering HI/LO. To quantify costs, compile all four modes:
PADDW+PMULTUW, PADDW+scalar multiplication and fully scalar (see
commands above). The host emulator does not execute MMI instructions,
so host timing is not a valid PS2 speed comparison.

The independent PMULTUW packing model is runnable with
`python3 test/ee_mmi/check-pmultuw.py`. It checks 256 randomized
four-stream input sets plus zero and maximal-limb cases. The standalone
C harness additionally compares all 64-bit product high halves and
sentinels directly against scalar products, when PMULTUW is enabled.

Four-way Poly1305 is exposed only as a new internal one-shot
function. Standard EVP_MAC, Poly1305_Init/Update/Final and
ChaCha20-Poly1305 TLS/AEAD paths continue using their existing
backend. Never reuse a Poly1305 key across different messages
unless it was generated independently for each message.

## Verification checklist

1. Confirm the assembly macros, 128-bit LQ/SQ and MMI instructions
   assemble for your exact GCC/binutils version.
2. Check 16-byte stack alignment and preservation of all 128 bits
   of callee-saved s0-s3, which are saved/restored with SQ/LQ.
3. Run ChaCha20 RFC 8439 and SHA-256 known-answer vectors and
   differential checks on the real console, with EE MMI assembly enabled.
4. Cross-check with a no-asm build and EVP ChaCha20 known-answer tests.
5. Benchmark both scalar and MMI modes for 64, 256, 1024 and 4096
   byte messages. No speedup has yet been measured or claimed.
6. Review constant-time behavior, alignment, code size and EE ABI
   correctness before using the accelerated backend outside testing.

The scalar test reference is intentionally independent of OpenSSL's
implementation. In standalone mode it is also used to supply only
the scalar remainder path. The host emulator reuses the round function
for convenience and cannot validate the MMI instruction encodings,
timings or calling convention.

Security note: no FIPS validation is claimed for these changes.
