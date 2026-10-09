# PS2 EE MMI dependency and scheduling experiments

These are **opt-in alternatives** for the PS2 A/B/F standalone harness
on the codex/ps2-ee-mmi-test branch. All original A kernels remain
unchanged. The scalar B and Poly1305 fused F comparison paths are
unchanged between builds. New kernels are not enabled by default in
libcrypto, EVP, TLS, or the FIPS provider.

## Hardware basis

The supplied EE Core User Manual section 2.12 gives these broad,
nominal values (cycles):

| Instruction class | Latency | Throughput |
| --- | ---: | ---: |
| Integer add, shift, Boolean ops | 1 | 1 |
| Load (cache hit) | 1 | 1 |
| Multimedia multiply / accumulate (PMULTUW/PMADDUW) | 4 | 2 |
| Store | Not specified | 1 |

EE is a two-issue **in-order** core with interlocks for GPR and
HI/LO dependencies. Multimedia multiplication engages both integer
pipelines. Loads immediately followed by their consumers can stall;
cache misses and issue restrictions invalidate simple cycle summation.
The table does not promise a particular cycle count for LQ, PADDW,
or GHASH loops in a real cache/call environment. Measure hardware.

## Existing A and alternative variants

| Suite | Original A | Candidate | Change and expected bottleneck |
| --- | --- | --- | --- |
| ChaCha20 | chacha-ee-mmi.S | C: chacha-ee-mmi-interleave.S | Interleave four **disjoint** quarter rounds step-by-step to increase dependency separation; more I-cache pressure |
| SHA-224/256 | sha256-ee-mmi.S | S1: sha256-ee-mmi-sched.S | Compute Ch(E,F,G) before Sigma1; W/K load-use delay overlap; SHA schedule C cost unchanged |
| SHA-224/256 | sha256-ee-mmi.S | S2: sha256-ee-mmi-unroll2.S | S1 with two rounds per branch, 64 -> 32 loop iterations; larger inner-loop footprint |
| Poly1305 | poly1305-ee-pmultuw.S | F: poly1305-ee-pmadduw.S | Fused PMULTUW+PMADDUW accumulates exact terms in HI/LO; 800 -> 160 bytes of intermediate results (existing test F) |
| AES | aes-ee-mmi.S | K: aes-ee-mmi-keyearly.S | Load round key before MixColumns; **scalar C S-box still dominates** |
| AES-GCM | aes-gcm-ee-mmi.c + AES/GHASH MMI | Integrated four-lane CTR/GHASH | Reuses one key schedule and GHASH H, passes ciphertext straight into packed GHASH, handles padded AAD and length blocks; A/B tests 256-byte authenticated messages |
| GHASH | ghash-ee-mmi.S | G1: ghash-ee-mmi-sched.S | Calculate independent low-bit reduction mask ahead of Z update and advance X bit early |
| GHASH | ghash-ee-mmi.S | G2: ghash-ee-mmi-unroll4.S | G1 with four bit rounds per branch, reducing 128 -> 32 loop branches per 128-bit multiply; no carry-less hardware multiply |
| BN Montgomery | bn-ee-mmi.S | existing scalar B | PMULTUW products and scalar carry/REDC; inner-loop function calls and HI/LO dependencies dominate, so safe scheduling alone is unlikely to help much |
| X25519 | x25519-ee-mmi.S | existing scalar B | Ten dependent PMADDUW products per limb; operand LQs and PEXTs are already interleaved before each multiply (four intervening instructions), limiting simple reordering gains |
| RSA | rsa-ee-mmi.c | reusable R²/n0 public-key contexts | A/B now time repeated RSA-65537 exponentiation with keys precomputed outside measurement; legacy uncached API kept for compatibility and correctness tests |
| P-256 ECDH | p256-ee-mmi.c | 4-bit public exponent inversion windows | The fixed p−2 exponent now uses a 16-entry table of Montgomery powers, reducing field products; generic Montgomery inner loop remains |

All candidate code is new and **unverified on real EE**. Instruction
reordering and loop unrolling can make things **slower**, especially in
the 16KB EE instruction cache. The AES S-box now uses a fixed inversion addition-chain with
4 general GF multiplications and 7 linear bitwise squares; GHASH bit
serial algorithm, and RSA/P-256 higher-level work are still scalar.

## Build and compare

Build all **eight** A/B/F ELF configurations with the same flags, SDK,
and source revision:

~~~sh
export PS2DEV=/usr/local/ps2dev
export PS2SDK=/usr/local/ps2dev/ps2sdk
bash test/ps2/build-variants.sh build-ps2-schedules
~~~

Output is one \`openssl_mmi_test.elf\` inside each folder:

* \`reference\`
* \`chacha_interleave\` (PS2_SCHED_CHACHA=1)
* \`sha_ch_first\` (PS2_SCHED_SHA=1)
* \`sha_unroll2\` (PS2_SCHED_SHA=2)
* \`ghash_mask_first\` (PS2_SCHED_GHASH=1)
* \`ghash_unroll4\` (PS2_SCHED_GHASH=2)
* \`aes_key_early\` (PS2_SCHED_AES=1)
* \`all_scheduled\` (C+S1+G1+K)

The result screen displays C/S/G/K numeric IDs (ChaCha/SHA/GHASH/AES)
and logs the same IDs as "PS2 SCHEDULE". C=0/1,
S=0/1/2, G=0/1/2, K=0/1. They change only the A code path.
B remains the scalar reference and F remains fused Poly1305.
Keep the IDs in every screenshot and measurement log.

For one alternative only, set PS2_AB=1 plus its PS2_SCHED flag
and call test/ps2/build.sh with an isolated output directory.
Do not link multiple variants for the **same public symbol** in one
ELF: the script selects exactly one A definition, and the original
C reference is kept as a separate prefixed B object. Poly1305 F
remains a separate prefixed third implementation.

Each executable first runs **all correctness tests** for A and B,
plus F for Poly1305. If any test fails, no timing is attempted.
The benchmark runs equal inputs/workload counts, alternating A/B order,
with six samples and the median. Checksums are compared after timer
stop. Compare **B/A for the corresponding suite** against the
reference ELF; the ratio removes some run-to-run clock/noise effects.
For genuine optimization claims, repeat each run, alternate ELF
execution order, and compare median timings on the *same hardware*.
One-off PCSX2 emulator timing is not a hardware performance guarantee.

## Independent portable checks

~~~sh
python3 test/ps2/check-schedules.py
bash test/ps2/verify-bench-host.sh
CC=clang bash test/ps2/verify-bench-host.sh
~~~

The ChaCha20 checker replays one complete double round for 160 random
register states using each instruction trace and compares all 16
state words. GHASH checks 260 single-bit comparisons, plus 180 sets
of four-bit unrolled updates against the base. SHA S1 is guarded by
the exact Ch expression transformation; SHA S2 reuses that round body
twice. AES K is guarded against key-dependent algebra changes.
These checks **do not assemble the EE macros or model pipeline stalls**.
The existing console differential/NIST tests remain the hardware gate.

## Next deeper optimization steps

1. **GHASH**: replace bit-serial multiply by a new provably constant-time
   nibble-window or other polynomial multiplication algorithm. Branch
   unrolling only reduces loop control, not 128 carry-less bit steps.
2. **AES**: optimize S-box via a proven compact bitslice circuit, which
   is more expensive to engineer but attacks the present scalar hotpath.
3. **Montgomery/BN**: combine multiple PMULTUW results and carry
   propagation into a bounded full-assembly inner loop; individual
   two-product helper calls waste instruction issue and stack traffic.
4. **X25519**: investigate block-level prefetch / pre-packed terms,
   but benchmark register pressure and cache misses before adopting.
5. **Poly1305**: schedule existing F's PMADDUW HI/LO chain against
   independent next-operand loads; no safe extra accumulator exists.

AES-GCM is now an additional tenth A/B suite. Its integrated
C orchestrator uses the *currently selected* AES/GHASH MMI assembly
(so K and G1/G2 scheduling affect both their individual rows and
the composite GCM row). The B backend uses the same orchestration
with portable scalar AES and GHASH. A/B timing includes full
authenticated encryption but excludes key setup, input creation,
result checksums and validation tests. The integration is not a
single new MMI instruction: GHASH remains bit-serial and the AES
S-box remains scalar, so speedups are empirical, not guaranteed.

Only take a faster candidate if correctness, ABI, constant-time
properties and secret-key zeroization survive independent verification.
