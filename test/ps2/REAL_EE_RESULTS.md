# Real EE results and optimization priorities

Source: user-supplied `openssl_mmi (1).txt` and console photograph.
The log reports C0/S0/G3/K2/BN1, median6, 25 complete suites, zero
failures. Results are workload-specific; timing spread per individual
sample is not provided. Normal selected mode keeps these ten rows:

| Selected row | A ms | B ms | B/A |
| --- | ---: | ---: | ---: |
| ChaCha wrap | 2.488715 | 5.128472 | 2.0607x |
| SHA224/256 | 2.925347 | 4.306424 | 1.4721x |
| Poly reduce | 1.496528 | 2.741319 | 1.8318x |
| AES | 2.097222 | 2.102431 | 1.0025x |
| GHASH u8 | 0.399306 | 2.598958 | 6.5087x |
| BN shift | 2.980903 | 4.295139 | 1.4409x |
| X25519 | 78.689236 | 194.295139 | 2.4691x |
| RSA tight | 28.048611 | 40.916667 | 1.4588x |
| P256 reg | 78.781250 | 167.000868 | 2.1198x |
| GCM u8 | 14.876736 | 17.542535 | 1.1792x |

## What the hardware changed

ChaCha wrap reduces elapsed time by 24.55% versus the original wrapper.
Poly reduce saves 60.48% versus original fused sums; its 32.84 MB/s
beats scalar by 1.83x. BN shift saves 35.04% versus the stack-row backend.
These results support testing less state reconstruction/intermediate
memory traffic, although no instruction-level profiling was performed.

RSA square is 5.13% slower than RSA tight on hardware (29.489 vs
28.049 ms), reversing the PCSX2 ranking. RSA tight is 1.31% faster than
RSA shift. SHA u4 is only 0.24% faster than S0 and AES K2early ties K2;
these small/tied differences do not justify normal extra rows.
GHASH u8 beats the selected G3 window4 path by 6.69x. This comparison
changes the algorithm, not just the unroll count: window4 scans all 16
entries for each masked lookup and has setup/cleanup costs. Different
long-message/setup-reuse workloads could change the result.

## Candidates retained only in the archive

Poly hybrid/preload, BN reg/RSA reg, RSA shift/square, SHA u4 and AES
K2early are absent from the selected rows. Previous originals remain
available in the all profile. Poly F is identical to the current Poly A
configuration; selected mode does not compile it. The benchmark rows
are archived rather than deleting useful independent reference tests.

## Next optimization hypotheses, in priority order

1. **AES S-box/ShiftRows and state lifetime.** The encrypt4 path invokes
   scalar packed-four-byte tower S-box logic for 16 words per round;
   MMI currently accelerates MixColumns/AddRoundKey only. AES A/B is
   effectively tied, so moving round-key loads is not the next priority.
   Measure S-box, ShiftRows and packed-state conversion separately.
   Candidate designs include the same tower equations across 128-bit
   lanes, fixed-mask ShiftRows without old/shifted arrays, and a private
   word-major AES core so GCM avoids repeated input/output conversion.
   Preserve constant-address behavior and all 128/192/256-bit vectors.

2. **GCM full-block path after AES measurements.** For 256 bytes per
   lane, each seal uses 16 payload encrypt4 calls plus one J0 tag-mask
   call; repetitions=2 means 34 encrypt4 calls. The AES row times five
   calls at 2.097222 ms: 34/5 * 2.097222 = 14.261110 ms, close to
   GCM u8's 14.876736 ms. This is an estimate from different call sites,
   not a profiler result, but makes AES a strong priority. gcm_ctr4 also
   copies IVs, zeros a cipher buffer and XORs bytes on every iteration.
   A full-block path could initialize IVs once, change counters only,
   use alias-safe word XOR and authenticate the complete output blocks
   directly. Preserve partial-block zero padding and verify-before-release
   in open; never wipe caller output as temporary storage.

3. **P256/BN integration.** P256 reg is 78.781 ms versus original
   87.642 ms. Test shifted REDC with the P256 integration independently;
   its prime-specific arithmetic and inversion path mean BN/RSA gains
   cannot be assumed to transfer. A dedicated fixed-size eight-word
   helper could also reduce call/loop overhead. Retain scalar-range,
   invalid-peer and shared-secret golden tests.

4. **ChaCha and Poly after AES.** ChaCha wrap plus the already existing
   interleaved C1 round kernel is unmeasured on this workload. Another
   option is register-level feed-forward/transposition/word XOR, retaining
   nonaligned and in-place behavior. Poly reduce still performs dependent
   PMADDUW chains and saves seven full GPRs; fewer temporaries/register
   saves could help, but do not sacrifice exact 64-bit carries or cleanup.
   The input bounds and multiplier interlocks require careful verification.

RSA symmetric squaring remains archived until its scalar product/carry
cost is isolated or an MMI square design is available. Further generic
unrolling is lower priority than the above measured bottleneck candidates.
No new optimization kernel was enabled by this cleanup, and no build
was run. Benchmark different lengths and RSA sizes before deleting the
archived implementations outright.
