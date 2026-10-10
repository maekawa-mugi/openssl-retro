# PS2 EE MMI dependency and scheduling experiments

These are isolated A/B/F standalone benchmark variants on the
ps2-ee-mmi branch. The former A implementations remain selectable;
A now defaults to fused Poly1305, K2 tower-field AES and BN1 fused-row
Montgomery. Scalar B and the independent Poly1305 F control are retained.
No new backend is enabled in libcrypto, EVP, TLS or the FIPS provider.

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
| Poly1305 | old 800-byte products | A/F: poly1305-ee-pmadduw.S | Fused PMULTUW+PMADDUW produces 160 bytes of exact 64-bit sums; old products remain an isolated correctness oracle |
| AES | aes-ee-mmi.S | K1: aes-ee-mmi-keyearly.S | Load key before MixColumns; original packed GF(256) S-box still shared with scalar B |
| AES | packed GF(256) | K2: constant-time GF(16) tower S-box | New fixed linear input/output basis, branch-free four-byte arithmetic, no secret-indexed tables; full S-box and host NIST vectors independently checked |
| AES-GCM | aes-gcm-ee-mmi.c + AES/GHASH MMI | Integrated four-lane CTR/GHASH | Reuses one key schedule and GHASH H, passes ciphertext straight into packed GHASH, handles padded AAD and length blocks; A/B tests 256-byte authenticated messages |
| GHASH | ghash-ee-mmi.S | G1: ghash-ee-mmi-sched.S | Calculate independent low-bit reduction mask ahead of Z update and advance X bit early |
| GHASH | ghash-ee-mmi.S | G2: ghash-ee-mmi-unroll4.S | G1 with four bit rounds per branch, reducing 128 -> 32 loop branches per 128-bit multiply; no carry-less hardware multiply |
| GHASH | ghash-ee-mmi.S | G3: ghash-ee-window.c + ghash-ee-window-mmi.S | Four-bit fixed-scan nibble tables using PCEQW/PAND/PXOR across four streams, no data-dependent addresses |
| GHASH | ghash-ee-mmi.S | G4: same windows with width=8 | 8-bit reverse-Horner with two constant-address 16-entry scans per byte |
| BN Montgomery | bn-ee-mmi.S | B1: bn-ee-row-mmi.S | Single PMULTUW assembly call per addmul row with inline carry, rather than one call per product pair. REDC q and limb shift stay in C. |
| X25519 | x25519-ee-mmi.S | existing scalar B | Ten dependent PMADDUW products per limb; operand LQs and PEXTs are already interleaved before each multiply (four intervening instructions), limiting simple reordering gains |
| RSA | rsa-ee-mmi.c | reusable R²/n0 public-key contexts | A/B now time repeated RSA-65537 exponentiation with keys precomputed outside measurement; legacy uncached API kept for compatibility and correctness tests |
| P-256 ECDH | p256-ee-mmi.c | 4-bit public exponent inversion windows | The fixed p−2 exponent now uses a 16-entry table of Montgomery powers, reducing field products; generic Montgomery inner loop remains |

All candidate code is new and **unverified on real EE**. Instruction
reordering and loop unrolling can make things **slower**, especially in
the 16KB EE instruction cache. AES K0/K1 retain a fixed GF(256) inversion addition chain (four
multiplications and seven squarings). AES K2 replaces it with GF(16)
tower arithmetic but has not yet been timed on real EE. P-256 now has
fixed-modulus reduction combined with the BN1 row helper.

## Build and compare

Build all **twelve** A/B/F ELF configurations with the same flags, SDK,
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

* ghash_window4 (PS2_SCHED_GHASH=3)
* ghash_window8 (PS2_SCHED_GHASH=4)
* bn_fused_row (PS2_SCHED_BN=1)

The result screen displays C/S/G/K/BN numeric IDs (ChaCha/SHA/GHASH/AES)
and logs the same IDs as "PS2 SCHEDULE". C=0/1,
S=0/1/2, G=0/1/2/3/4, K=0/1, BN=0/1. They change only the A code path.
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

## BN row and GHASH 4/8-bit window experiments

B1 (PS2_SCHED_BN=1) uses a single R5900 PMULTUW assembly
function per FULL addmul row, incorporating carry propagation and
operand pairing; the outer CIOS q calculation and 32-bit REDC
word shift remain in C. This reduces assembly call count but
is **not** an all-assembly Montgomery function, nor a guaranteed
speedup. Reference BIGNUM A and scalar B remain available.

G3 (PS2_SCHED_GHASH=3) implements a 4-bit window; G4
(PS2_SCHED_GHASH=4) implements 8-bit windows as two 4-bit
tables. An R5900 MMI PCEQW/PAND/PXOR kernel scans ALL 16
table entries at fixed addresses; selector values NEVER choose
a cache-visible table address. Window tables are now constructed ONCE per multi-block GHASH update
and ONCE per AES-GCM seal/open operation, then securely wiped. Both
retain constant-address scans. This reduces redundant work, but real
EE timings may still favor the bit-serial G0 implementation.

Host model/correctness commands:

~~~sh
python3 test/ee_mmi/check-bn-row.py
python3 test/ee_mmi/check-ghash-windows.py
EE_BN_ROW=1 sh test/ee_mmi/run-bn-mont-host.sh
EE_GHASH_WINDOW=4 sh test/ee_mmi/run-ghash-host.sh
EE_GHASH_WINDOW=8 sh test/ee_mmi/run-ghash-host.sh
~~~

Single-kernel EE test ELF builds:

~~~sh
EE_BN_ROW=1 sh test/ee_mmi/build-bn-mont-ee.sh
EE_GHASH_WINDOW=4 sh test/ee_mmi/build-ghash-ee.sh
EE_GHASH_WINDOW=8 sh test/ee_mmi/build-ghash-ee.sh
~~~

These are opt-in performance experiments until the PS2SDK
assembler/ELF and hardware regression tests pass, followed by
repeated same-input median timings. A/B validity tests run
before every benchmark, and mismatched output digests abort
the corresponding measured row.

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

### Implemented additional rows (PS2_EXPERIMENTS=1)

The ordinary A/B/F build now appends BN reg, RSA reg, P256 reg,
Poly hybrid, SHA u4, GHASH u8, AES K2early, GCM u8, BN shift and
RSA shift in the same ELF.
Poly preload and RSA tight are now appended as rows 21 and 22.
The ten original rows and selected C/S/G/K/BN schedules remain.
For these fifteen rows the optimized backend is fixed by the row name;
the scalar comparison reuses B's corresponding original workload ID.
Every row retains independent correctness gating and digest checks.

* BN reg removes the original 80-byte scratch allocation and SW/LQ/SQ/LD
  product roundtrips. It uses sign-extended LW values and PCPYLD to
  form the two full-width PMULTUW operand slots. PCPYUD extracts the
  second 64-bit product; carry handling and the SLL return convention
  remain exact. The temporary GPRs are cleared on return. RSA reg and
  P256 reg apply this change to the same existing higher-level APIs.
* Poly hybrid keeps the fused PMULTUW/PMADDUW product sum kernel and
  scalar reduction, but replaces the per-block PADDW helper call by
  scalar absorption. It isolates call/packing costs from multiplication.
* SHA u4 and GHASH u8 use identical verified step bodies with larger
  unroll factors. Their expected benefit is loop-control reduction;
  a larger instruction footprint can offset it. These do not introduce
  new hash arithmetic or change any secret-dependent address behavior.
* AES K2early combines the existing tower S-box with the existing
  key-early MixColumns assembler. Its row compares the combination
  against B; the original AES row still measures the selected K0/K1/K2.
* GCM u8 applies the same eight-step GHASH kernel to the full AES-GCM
  seal/open implementation with K2 AES. It has no GHASH window tables;
  the existing GCM regression suite covers AAD, partial lengths, tags,
  different AES key sizes, tampering and in-place operation. The original
  AES-GCM row continues to use its selected G/K settings.
* BN shift keeps the register-only addmul row and replaces the REDC row
  by ossl_ee_bn_redc_shift_row_mmi. That helper discards the canceled low
  word and stores every later result directly at t[j-1], so the C shift
  loop and its extra loads/stores disappear. The high word and overflow
  remain in C. RSA shift uses the same primitive. P-256's fixed-prime
  reduction already performs this shift in its existing C loop.
* Poly preload attacks redundant operand loads/packing in the fused
  sums helper: 28 input LQ/PEXT pairs instead of 100 per message block.
  It keeps h and nine used r/5r terms in registers for each two-lane
  pair. GPR16..19 are saved/restored in full 128-bit form using aligned
  private scratch. Sums retain the same 160-byte ABI and scalar fold.
  Scratch, temporary operands and HI/LO accumulators are cleared on
  return. Saving registers and a tighter dependent PMADDUW chain add
  costs, so the output row must establish the actual net speedup.
* RSA tight builds on RSA shift. Prepared exponentiation alternates two
  power buffers instead of copying after every square. The generic BN
  primitive initializes/wipes t[0..num+1] and wipes diff[0..num-1]; unused
  scratch words never hold input-dependent state. Volatile wipes cover
  every used word, and RSA still wipes both full power buffers on exit.
  This reduces housekeeping rather than the multiplication count.

`test/ps2/check-experiments.py` replays the actual new BN assembly
instruction sequence, including branch delay slots, bounded accesses,
packed products, full-GPR return convention and register cleanup. It
compares 2048 cases against a whole-integer row oracle. SHA/GHASH checks
enforce identical step bodies and complete 64-round/128-bit coverage.
These models do not assemble instructions or model cache/pipeline timing.
PCPYLD/PCPYUD semantics were cross-checked with the
[PCSX2 interpreter](https://github.com/PCSX2/pcsx2/blob/master/pcsx2/MMI.cpp).

Set `PS2_EXPERIMENTS=0` to omit the extra namespaces. The existing
separate-ELF schedule matrix uses that setting by default. The
first seven candidates passed the supplied PCSX2 run (17/17 overall).
GCM u8, BN shift and RSA shift are newly added and await user-built
ELF validation and timings. The instruction model covers another 2048
shifted-row cases and 104 complete CIOS cases against BigInt arithmetic,
including odd sizes, cancellation, top-word overflow and final reduction.
The target BN shift suite adds direct shifted-row guards to the existing
2200 Montgomery differential/alias tests. No build was run for this patch.

The subsequent supplied screen passed all 20 rows: GCM u8 was 22.853 ms,
BN shift 4.877 ms and RSA shift 46.514 ms. Poly preload/RSA tight are
newer experiments. `check-poly-rsa.py` replays 256 preload instruction
traces, verifying all 20 sums, stack alignment, saved registers and
cleanup; 96 modular-exponent models verify the alternating-buffer flow.
These checks do not replace target regression or predict performance.

### Supplied PCSX2 run: C0/S0/G3/K2/BN1

The supplied log reports BN_ROW_FAIL at n=1/trial=0 with both carries
printed as ffffffff and diff_or=00000000. The row helper previously
returned the zero-extended carry via DADDU. GCC's MIPS C interface
requires a sign-extended 32-bit return in the 64-bit GPR, including
unsigned returns. Thus 00000000ffffffff can compare unequal to
ffffffffffffffff while a 32-bit printf conversion prints the same
value. The epilogue now uses SLL v0,carry,0; the internal carry stays
zero-extended for arithmetic. This also explains why changing memcmp
to limb XOR did not resolve the failure. The Python row checker now
checks the actual return instruction's full GPR representation, with
six carry boundaries and 2048 row cases. It does not execute EE code.

GCC sources for the convention: [PROMOTE_MODE](https://github.com/gcc-mirror/gcc/blob/master/gcc/config/mips/mips.h)
and [mips_promote_function_mode](https://github.com/gcc-mirror/gcc/blob/master/gcc/config/mips/mips.cc).
Re-run the BN direct and complete Montgomery tests in the rebuilt ELF
before interpreting any BN1 benchmark. Existing RSA/P-256 passes do
not prove this return convention is correct for every carry value.

Further candidates, in priority order after correctness validation:

* **BN1/RSA**: the row loop still constructs operands with SW/LQ and
  spills each packed product with SQ followed by two LDs. Investigate
  PCPYLD to pack sign-extended LW operands and PCPYUD to extract the
  second product directly in registers. Preserve full unsigned 64-bit
  products, odd-limb bounds, caller register rules and cleanup. This
  should be a separately selectable experiment with an instruction
  oracle, rather than mixed into the return-convention fix. RSA's
  reported B/A=0.7911 indicates the current row path needs measurement
  against both scalar B and BN0, even after reducing call count.
* **BN REDC**: combine the reduction row with its one-word output shift
  to avoid the extra C loop and rereading/storing the accumulator.
  Keep the general addmul row API available for P-256 and direct tests.
* **Poly1305**: the reported B/A=0.7996 and A/F=1.0001 show that the
  fused path is still slower than scalar on this workload. Its macro
  reloads and repacks the same h/r limbs for each output sum. Compare
  prepacking/reusing operands and a scalar-absorb/MMI-multiply hybrid,
  while measuring stack traffic and register pressure. F is a control
  for the same fused kernel, not a faster alternative in this run.
* **AES/GHASH**: K2 and G3 give modest gains (1.2100 and 1.0921).
  Compare G0/G2/G3/G4 on short and long updates: fixed 16-entry scans
  and table setup can dominate short messages. For AES, measure S-box
  time separately from MixColumns before choosing a bitslice circuit
  or assembly tower-field implementation.

These are candidates, not measured improvements. Keep the same emulator
speed settings for every sample: the supplied log switches target speed
to unlimited during RSA validation and restores it after the suite.
Confirm results with repeated hardware runs before selecting defaults.

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


### Poly reduction and public RSA square candidates

The supplied 22-row screen passes every regression. Poly preload is
5.667 ms (scalar 4.948 ms); RSA tight is 45.896 ms (scalar 52.416 ms).
Rows 23/24 append Poly reduce and RSA square without replacing the
previous controls. A two-line header leaves both footer lines visible.

Poly reduce reuses the preload operands and keeps each exact two-lane
sum in GPRs while applying the radix-2^26 carry chain and final carry*5
wrap. It writes the 80-byte h state directly, including out==h, instead
of writing/reading/wiping the 160-byte sums buffer. It saves seven full
128-bit GPRs on aligned private scratch and restores/wipes those slots.
The PMADDUW dependencies and register-save costs remain; timing decides
whether the removed memory traffic pays for the added assembly work.

RSA square builds on RSA tight for the prepared public exponent 65537.
It computes each off-diagonal product once and adds it twice in a
96-bit Comba accumulator, reducing the square's multiply count from
n*n to n*(n+1)/2. REDC uses the existing register-only whole-row helper.
The full-product scratch and extra carry propagation add overhead;
this is a separate experiment, not a prediction of a speedup. It has
fixed public loop bounds, supports aliased outputs, and wipes used
scratch. Its candidate BN suite compares against independent reference
Montgomery squaring with output guards and aliases before RSA timing.

The supplied `PS2_EE_GS_VU_ABE5A5Markdown.zip` was consulted as reference
data. EE Core Instructions, PMULTUW/PMADDUW entries, require sign-extended
word operands and describe asynchronous multiply with interlocks on
result reads. The Poly operands stay below bit31 and PEXT inserts zero
upper words; BN uses LW sign extension before packing. DSLL/DSRL's
0..31 immediate range is respected: 38-bit masks use DSLL32/DSRL32 by 6.
No instructions embedded in that archive were used as task directives.

No compilation was run. `check-poly-rsa.py` checks 512 fused-reduction
instruction traces with independent carry math and out==h coverage.
`check-public-square.py` checks 180 full square/REDC traces from 32 to
4096 bits, including all-one/near-power-of-two/small moduli, against
BigInt. These models do not validate compiled C, hardware latency or
actual EE execution; the user-built ELF supplies those checks.


### ChaCha wrapper (row 25)

The existing screen's 10.00 MB/s is 49152 bytes / roughly 4.917 ms,
including state expansion, feed-forward and output XOR, not the round
ASM alone. The new `ChaCha wrap` namespace w holds the round ASM fixed
at C0 and tests two changes: expand fixed vectors once per invocation,
and perform alias-safe four-byte input/output XOR via memcpy. Only the
four counter words change between 256-byte groups. Input/output retain
arbitrary alignment, exact in-place operation and scalar tails; counter
wrap affects word 12 only. The compiler's memcpy lowering and remaining
round dependencies determine the actual gain.

All 25 rows plus two footer lines fit with FIRST_TEST_ROW=1. The single
column-header line includes schedule flags; title/median/A/B/F metadata
remain in stdout. Validation-only mode still starts at row 4. The new
row has the original 4096-byte/12-repeat workload and full ChaCha tests.
Python model checks passed 408 edge/unaligned/alias/wrap cases and RFC's
known-answer vector. Models and mocked build plans run without a compiler;
target correctness and speed remain to be checked by the user's build.


### Real-console selection supersedes the default candidate list

Normal PS2_AB=1 runs now use PS2_PROFILE=selected (ten algorithms),
with PS2_PROFILE=all retaining the historical 25 rows and legacy retaining
the original ten A/B/F rows. Build-variants uses legacy by default. All
measurements before this paragraph describe the archived comparison.
See REAL_EE_RESULTS.md for console numbers and next priorities. Scalar
full validation is executed once per workload, with failures cached;
per-candidate checks and post-timer sample digest comparisons remain.
