# PCSX2 / PS2 EE MMI regression ELF

## Default: ten real-EE-selected algorithms

A normal `PS2_AB=1` build now selects ten rows based on the supplied
real-console log. Each optimized candidate runs its full correctness
suite, compares against the unchanged scalar B, and checks output digests
outside the timing region. Unchanged workloads, six alternating samples
and median timing permit comparison with the archived run.

```sh
PS2_AB=1 bash test/ps2/build.sh
# equivalent: PS2_AB=1 PS2_PROFILE=selected bash test/ps2/build.sh
# old 25-row comparison:
PS2_AB=1 PS2_PROFILE=all PS2_SCHED_GHASH=3 bash test/ps2/build.sh
# old ten baseline algorithms with optional historical Poly F:
PS2_AB=1 PS2_PROFILE=legacy bash test/ps2/build.sh
```

| Workload | Selected optimized row |
| --- | --- |
| ChaCha20 | ChaCha wrap |
| SHA224/256 | Original compressor (default S0) |
| Poly1305 | Poly reduce |
| AES | Original tower S-box build (default K2) |
| GHASH | GHASH u8 |
| BN Montgomery | BN shift |
| X25519 | Original MMI field convolution |
| RSA-65537 | RSA tight |
| P256 ECDH | P256 reg |
| AES-GCM | GCM u8 |

Selected mode omits the duplicate Poly F namespace and builds seven
private candidate namespaces (r/g/c/d/q/e/w), instead of twelve. Sparse
backend slots keep the archive's IDs stable; absent slots are not prepared.
The normal screen returns to four header lines and ten algorithm rows.
The existing schedule matrix still defaults to the legacy profile.

In all profiles scalar validation is cached once per workload. A failed
scalar result remains a failure for every candidate; candidate-specific
validation and every timed-sample digest comparison remain enabled.
RSA tight retains its BN preflight. P256 reg gains its own BN preflight
in selected mode because the former standalone BN reg row is absent.
Poly reduce now directly tests mul_reduce4 against independent scalar
carry math in 512 separate-output/in-place/guard cases; it no longer
reports an older sums4 helper's direct test as its own kernel validation.
Existing RFC/NIST/BigInt vectors, boundary and tamper tests are retained.

No compilation was run by the agent. Shell syntax, mocked selected/all
namespace plans and Python models were checked. Run the user-built ELF
for C/ASM correctness and target speed. See [real-EE results and next
optimization priorities](REAL_EE_RESULTS.md).

## Archived comparison rows (`PS2_PROFILE=all`)

`PS2_AB=1 PS2_PROFILE=all` keeps the original ten rows and appends fifteen candidates.
Each extra row runs the corresponding full regression suite first, then
compares the same workload against the existing scalar B with alternating
order, six samples, post-timer output digests and the median. A means the
named candidate on that row. The original Poly1305 F control is retained.

| Added row | Candidate |
| --- | --- |
| BN reg | Register-only PMULTUW row: PCPYLD packs LW operands, PCPYUD extracts the second product; eliminates operand/product stack traffic |
| RSA reg | Same register-only BN kernel in prepared-key RSA-65537 |
| P256 reg | Same row kernel with the existing fixed-prime reduction and inversion windows |
| Poly hybrid | Scalar block absorption with the existing fused MMI product sums |
| SHA u4 | Existing Ch-first step repeated four times per branch, 16 iterations |
| GHASH u8 | Existing scheduled bit step repeated eight times per branch, 16 branches per product |
| AES K2early | Tower-field S-box combined with early round-key loading |
| GCM u8 | AES-GCM with tower S-box and the eight-step GHASH kernel, including AAD/payload/tag authentication |
| BN shift | Register-only multiply rows and a REDC row that writes directly to the shifted accumulator |
| RSA shift | Same shifted REDC in prepared-key RSA-65537 |
| Poly preload | Load and pack h/r once per lane pair, reusing them for all five fused sums |
| RSA tight | Shifted REDC, used-size BN scratch initialization/wipe, and alternating square buffers |
| Poly reduce | Preloaded fused sums with radix-2^26 reduction in assembly; removes the 160-byte sums buffer |
| RSA square | RSA tight plus symmetric Comba squaring and separate MMI REDC for the 16 prepared-key squares |
| ChaCha wrap | Expand the fixed state once per call, reuse it for each 256 bytes, and use alias-safe four-byte XOR; original C0 round ASM |

For the same C0/S0/G3/K2/BN1 baseline as the supplied screenshot:

```sh
PS2_AB=1 PS2_PROFILE=all PS2_SCHED_GHASH=3 bash test/ps2/build.sh
# build-ps2-mmi/openssl_mmi.elf: original 10 + extra 15 rows
```

`PS2_PROFILE=legacy` (or `PS2_EXPERIMENTS=0` without an explicit profile) restores the ten-row A/B/F build. The existing
`build-variants.sh` matrix defaults to that mode to avoid repeating the
same appended experiments in all twelve ELFs; explicitly set
`PS2_EXPERIMENTS=1` there if desired. The fifteen extra rows use fixed
candidates independent of the selected schedules for the original rows.
They link in twelve private namespaces (r/h/s/g/k/c/d/p/q/e/n/w), including independent
benchmark buffers and setup. Build time and ELF size increase.

No speedup is assumed. Python instruction-trace/math checks and shell
syntax checks have passed; these new kernels still need a user-built
ELF and PCSX2/EE regression and timing runs. The supplied follow-up
screen confirms the previous BN1 return-ABI fix passes in PCSX2.

Portable checks without compiling:

```sh
python3 test/ps2/check-experiments.py
python3 test/ps2/check-redc-shift.py
python3 test/ps2/check-poly-rsa.py
python3 test/ps2/check-public-square.py
python3 test/ps2/check-chacha-wrap.py
python3 test/ps2/check-bench.py
bash test/ps2/check-experiment-plan.sh
```

The latest supplied PCSX2 screen passed all 22 previous rows: Poly preload
5.667 ms versus scalar 4.948 ms, RSA tight 45.896 ms versus scalar
52.416 ms. Poly reduce and RSA square are new, with no target build or
timing yet. A compact single-line header fits all 25 rows and both footer
lines on the GS screen. Schedule flags remain in the header; the title
and median6/A/B/F legend are printed to stdout. RSA tight and RSA square each run their candidate
BN regressions before the RSA regression and timing.

`python test/ps2/check-poly-rsa.py` checks the fused reduction's instruction
trace, aliased outputs, saved registers and scratch cleanup. Run
`python test/ps2/check-public-square.py` for symmetric square + actual MMI
REDC traces against BigInt, including odd sizes and final subtraction.
For an optional native C test, `EE_BN_PUBLIC_SQUARE=1 sh test/ee_mmi/run-bn-mont-host.sh` selects the new square backend. These
compilation commands are for the user; no build was run by the agent.

## October 2026 real-EE performance repair

The SPR experiment and all its PS2 fixed-address accesses have been
removed. No scratchpad option, scratchpad runner, or SPR GS row remains.

In the PS2 A/B/F runner, the MMI **A** candidate now uses the fused
PMULTUW/PMADDUW Poly1305 sums backend (160 bytes of intermediates
instead of the old 800-byte product matrix). The full scalar **B** and
independent fused **F** checks remain. The previous 5x Poly1305
regression was observed on the old unfused A kernel; speed of the new
default still requires a real-EE retest.

The whole-row PMULTUW Montgomery backend is now the default in the
standalone PS2 build (`BN1`), affecting BN, RSA and P-256. For P-256,
a fixed-prime reduction exploits the three zero 32-bit limbs of the
NIST modulus without secret-dependent memory accesses. Pass
`PS2_SCHED_BN=0` to benchmark the old two-product baseline.
This selection is not a proof of speedup until measured on real EE.
The GHASH G3/G4 fixed-scan window backend now prepares H only once
per multi-block update and reuses the same table through AES-GCM
AAD, payload authentication, and tag calculation. For the original
bit-serial GHASH baseline, explicitly use `PS2_SCHED_GHASH=0`.

The AES K2 candidate is a new constant-address GF(16) tower S-box:
no secret-indexed lookup table and no input-dependent branches. It is
the PS2 build default (`PS2_SCHED_AES=2`), while `K0` restores the
original packed GF(256) exponentiation and `K1` retains the earlier
round-key scheduling experiment. Host NIST/vector verification covers
both old and new AES paths; hardware speed still needs measurement.

The PS2 GS UI uses white text, except for the status word PASS in
green. The B/A column is **always** scalar-time / MMI-time, even
when MMI loses (ratios under 1.00x); a separate candidate winner and
true MMI bytes/second or ops/second are shown. The stdout BENCH_RATE
records retain more precision. The 6-sample median and the
correctness-first gating are unchanged.

Build the complete A/B/F ELF from the repo root:

```sh
PS2_AB=1 bash test/ps2/build.sh
# build-ps2-mmi/openssl_mmi.elf
```

Do not deploy the experimental crypto backends to real secrets:
constant-time and side-channel properties of the full R5900 toolchain
have not been audited. GHASH cached fixed-scan schedule and fused
Poly1305 preserve fixed-loop behavior, but that is not a substitute
for security verification.

`openssl_mmi_test.elf` runs ten regression suites from
`test/ee_mmi` with their real R5900 assembly backends: ChaCha20,
SHA-224/SHA-256, Poly1305 (PADDW + PMULTUW), AES-128/192/256, GHASH,
BN Montgomery multiplication, X25519, RSA public verification,
P-256 ECDH and four-stream AES-GCM. The existing test entry points are renamed per object;
their known-answer, differential, alignment and invalid-input checks
are retained. No benchmark arguments are passed.

The PS2SDK debug screen shows RUNNING followed by PASS/FAIL and each
suite's return code. Only if all ten return zero does the runner show
`TEST: OK! failures=0`. Otherwise it shows `TEST: FAIL! failures=N`.
Detailed diagnostics go to stdout. `SleepThread()` keeps the final
screen visible until the emulator stops. A stalled RUNNING label is
not a passing result.

This tests the branch's standalone crypto primitives. It does not
test full libcrypto, EVP/providers, TLS, certificate parsing or the
ECDSA P-256 prototype, which depends on OpenSSL BN/EC and libcrypto.
The Poly1305 fused PMADDUW variant is not selected in this ELF.

## Build

### Scheduled MMI kernel candidates

In addition to the original A/B/F comparator, use
`bash test/ps2/build-variants.sh build-ps2-schedules` to build
**twelve** independently selected A kernels: the original reference,
ChaCha20 interleaved quarter rounds, SHA Ch-first, SHA two-round
unrolled, GHASH mask-first, GHASH four-bit-unrolled,
AES round-key-early, a constant-time four-bit and eight-bit
GHASH window, a fused Montgomery addmul-row (PMULTUW), and
an all-scheduled combination.
Every ELF retains the same scalar B and fused Poly1305 F controls,
correctness gating, output digest checks and median timing.
The ordinary PS2 build now defaults to **AES K2** and **BN1**;
`PS2_SCHED_AES=0 PS2_SCHED_BN=0` restores the previous baseline.
`PS2_SCHED_GHASH=3` selects the 4-bit MMI masked lookup;
`PS2_SCHED_GHASH=4` selects the 8-bit split-table lookup;
`PS2_SCHED_BN=1` selects the fused PMULTUW addmul-row.
These are experiments, not guaranteed speedups; A/B comparison
remains tied to the same correctness-first 10-suite harness.

See [SCHEDULING.md](SCHEDULING.md) for the uploaded EE manual's
nominal 1-cycle ALU/4-cycle MMI-multiply latency context, individual
environment flags, performance hypotheses, independent register-trace
models, and limits of the comparisons.

### Correctness-first A/B/F cryptographic benchmark

The original A/B screen timed regression suites, including A-only
checks (256 Poly1305 products, 256 GHASH multipliers, 128 X25519
fused sums, AES round tests). Those numbers were NOT comparable kernel
measurements. The new runner separates all validation from timing.

Build the new A/B/F ELF:

~~~sh
export PS2DEV=/usr/local/ps2dev
export PS2SDK=/usr/local/ps2dev/ps2sdk
PS2_AB=1 bash test/ps2/build.sh build-ps2-ab
# => build-ps2-ab/openssl_mmi_test.elf
~~~

The new screen has two independent phases.

1. Correctness: run all 10 full suites with MMI (A) and scalar (B).
   Run the full Poly1305 fused PMADDUW suite (F). Any failure means
   no timing proceeds. All KATs/differential checks are outside timing.
2. Crypto timing: run identical deterministic inputs through the same
   calls and repetitions, with no reference algorithm, diagnostics or
   screen output in the measured interval. Check and compare output
   checksums after stopping each timer; differences count as failures.

A = MMI (fused PMULTUW/PMADDUW Poly1305 accumulation by default);
B = scalar C for ChaCha/SHA/Poly/AES/GHASH/BN/X25519/RSA/P-256;
F = Poly1305 PADDW + fused PMULTUW/PMADDUW, built from the genuine
poly1305-ee-pmadduw.S. A/B/F have separate symbol namespaces.

Each suite uses 6 timer samples, reporting the median of the middle
two. For two backends the order is AB, BA, AB, BA, AB, BA.
Poly1305 cycles ABF/BFA/FAB twice. Timer boundaries wrap only the
cryptographic function loop; resetting mutable state, computing
checksums, validation, and text output are outside timing.

| Suite | Per-call timed crypto workload | Reps/sample |
| --- | --- | ---: |
| ChaCha20 | 4096-byte stream XOR | 12 |
| SHA-224/256 | four 1024-byte SHA-256 messages | 6 |
| Poly1305 | four 1024-byte independent MACs | 12 |
| AES | four 16-byte AES-128 blocks, pre-expanded key | 5 |
| GHASH | four streams, eight 16-byte blocks | 4 |
| BN Montgomery | 64 limbs, 2048-bit | 8 |
| X25519 | four independent scalar multiplications | 1 |
| RSA | four e=65537 public operations, 2048-bit | 1 |
| P-256 ECDH | one valid shared secret | 1 |
| AES-GCM | four 256-byte AES-GCM messages, 20-byte AAD | 2 |

AES key setup and all input creation are done before timing.
AES-GCM uses cached H=E(K,0), four separate 96-bit IVs, 20-byte AAD,
and a combined CTR/GHASH loop. Timed output includes four ciphertexts
and authentication tags, both checked against scalar output afterward.
Benchmark IV reuse is only for deterministic synthetic comparisons;
never reuse nonces for real encryption. GHASH
mutable state is reset before each sample. RSA's public-operation benchmark now uses the public-key PREPARED
API on BOTH A and B. Four independent modulus-dependent R²/n0 values
are calculated once in ps2_bench_prepare(), OUTSIDE the timed interval.
The legacy uncached RSA API remains covered by its standalone correctness
suite, but the RSA benchmark row measures the cached-key hot path. Comparisons are WITHIN each row, not between rows.
B/A > 1 means MMI is faster; B/F > 1 means fused Poly1305 is faster
than scalar. The benchmark is not a full libcrypto/EVP/TLS benchmark.

Host-only syntax and linker-plan checks:

~~~sh
bash test/ps2/verify-bench-host.sh
CC=clang bash test/ps2/verify-bench-host.sh
bash test/ps2/verify-host.sh
~~~

The new ELF has NOT yet been built or timed in PCSX2 or on real PS2
by this patch. The PCSX2 PASS below refers to the older
regression-only ELF; it does not validate this new A/B/F timing code.

From the repository root in Linux/WSL, using an installed modern
PS2DEV compiler and PS2SDK:

```sh
export PS2DEV=/usr/local/ps2dev
export PS2SDK=/mnt/c/Users/mugi/Documents/GitHub/PS2-OtherOS/build/modern-deps/ps2sdk
bash test/ps2/build.sh
# Output: build-ps2-mmi/openssl_mmi_test.elf
```

An optional first argument selects the output directory. `CC` overrides
the compiler and `PS2EE_CRT_DIR` overrides the directory containing
`crt0.o`; the script also checks `$PS2SDK/../ee/mips64r5900el-ps2-elf/lib`.
The script links the SDK startup script, libdebug, newlib and SDK runtime
libraries and writes a link map beside the ELF.

The assembly uses physical register numbers 8..15 for the original
o32 temporary allocation. Modern PS2SDK defaults to n32 register names,
where t0..t3 map differently and t4..t7 are unavailable. Explicit numbers
avoid rejection and accidental register aliasing. The static layout
checks normalize these numbers to the original allocation labels.

For portable checks (these do not execute R5900 instructions):

```sh
bash test/ps2/verify-host.sh
```

## Local artifact and emulator run

Built from `origin/EEMMI` commit `da96faa6a2` plus this runner and fixes, using
WSL GCC 15.1.0 and the SDK path above. Inspection confirms ELF32 little
endian, R5900/MIPS III flags, entry point `0x00101090`, a load segment
starting at `0x00100000`, no undefined symbols, and linked MMI instructions.
The user ran this ELF in PCSX2 on 2026-10-09 and reported all nine
suites passing with `TEST: OK! failures=0`. Real PS2 hardware execution
remains unverified. The PCSX2 version and BIOS version were not recorded.
The tested local ELF's SHA-256 is
`921c450b5bf855a7eefbcf3d84f8e78ea56621416f8bcaf07b9343eae62fa53e`.

| Suite | Reported PCSX2 result |
| --- | --- |
| ChaCha20 | RFC 8439 + 788 differential/guard cases; PASS (code 0) |
| SHA-224/SHA-256 | Five NIST vectors + 263 differential cases; PASS (code 0) |
| Poly1305 | 256 direct product checks + RFC 7539 and 21 four-lane BigInt cases; PASS (code 0) |
| AES | AES-128/192/256, NIST CTR vectors, 256 direct MMI round cases; PASS (code 0) |
| GHASH | 256 four-stream products, NIST GCM and 32 BigInt states; PASS (code 0) |
| BN Montgomery | 2,200 differential/alias/guard cases + 512 unsigned product checks; PASS (code 0) |
| X25519 | 128 convolution batches, RFC 7748 and 32 BigInt cases; PASS (code 0) |
| RSA | Four distinct RSA-2048 signatures + RSA-1024/2048 public-operation checks; PASS (code 0) |
| P-256 ECDH | 10 public keys, 20 shared secrets and input validation; PASS (code 0) |

The run used the default runner: RSA-3072/4096 extended cases,
benchmarks, and ECDSA were not exercised. Some existing test diagnostic
strings still request console/hardware verification; the result above
records the actual emulator run, without claiming real-hardware validation.

All nine portable regression suites and the existing Python layout/math
checks pass. This verification exposed two missing SHA-256 round constants
(`d5a79147`, `06ca6351`), now restored in the four-lane table, and a missing
host-only BN two-product model in the RSA harness, now supplied. The ELF
includes the corrected SHA-256 constants. Cross-compilation still emits
existing warnings about a size-range check and BN test initialization/timer
comparisons; no compilation or link errors remain.

Open `build-ps2-mmi/openssl_mmi_test.elf` in PCSX2 using its ELF boot
action and your configured BIOS. Wait for all nine suite results and
the final summary. X25519, RSA and P-256 may take longer than the
symmetric crypto suites. If a suite fails, retain its name/return code
and the emulator stdout diagnostics for follow-up.


### ChaCha wrapper experiment

The reported 10.00 MB/s corresponds to 4096*12 bytes / 4.917 ms.
`ChaCha wrap` uses identical workload size, repetitions, scalar comparison,
samples and digests. It keeps the original C0 ASM so differences come
from the wrapper. Constants/key/nonce expand into word-major vectors once
per invocation; only the counter vector changes per 256-byte batch.
A 256-byte template is copied into the round state instead of constructing
both state and original afresh for every batch. Input XOR uses 4-byte
`memcpy` operations, allowing unaligned and in-place buffers without
casting byte pointers to uint32_t pointers. The path is little-endian EE
only, with the same scalar tail and CTR32 wrap behavior.

This tests whether wrapper setup and bytewise output cost explain part
of the gap. A compiler may leave memcpy overhead, and the ASM round cost
remains, so no speedup is assumed. `check-chacha-wrap.py` checks a Python
model against RFC and independent scalar output in 408 cases (0..16384
bytes, alignment offsets, in-place, tails and counter wraps). The row
runs the full existing target ChaCha regression before timing. No C/ASM
build or performance run was performed by the agent.
