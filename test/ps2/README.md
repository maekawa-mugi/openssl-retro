# PCSX2 / PS2 EE MMI regression ELF

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
**eight** independently selected A kernels: the original reference,
ChaCha20 interleaved quarter rounds, SHA Ch-first, SHA two-round
unrolled, GHASH mask-first, GHASH four-bit-unrolled,
AES round-key-early, and an all-scheduled combination.
Every ELF retains the same scalar B and fused Poly1305 F controls,
correctness gating, output digest checks and median timing.
All schedule variants default to **off**.

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

A = default MMI (unfused Poly1305 PMULTUW product matrix);
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
