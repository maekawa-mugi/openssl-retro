#!/usr/bin/env python3
"""Guard the PS2 A/B/F crypto-only benchmark's source and linker layout.

This does not replace a cross-compiled ELF run on PS2 or PCSX2.
"""
from pathlib import Path
import re

root = Path(__file__).resolve().parents[2]
builder = (root / "test/ps2/build.sh").read_text()
runner = (root / "test/ps2/main.c").read_text()
bench = (root / "test/ps2/bench.c").read_text()

assert "#define SAMPLES 6" in runner
assert "static double median6(" in runner
assert "median6(samples[mode])" in runner
assert "(step + sample) & 1U" in runner
assert "(step + sample) % 3U" in runner
assert re.search(r"if\s*\(\s*!validate_one\(i\)\s*\)", runner)
assert "b_ps2_bench_run" in runner and "f_ps2_bench_run" in runner
assert "selected->reset(workload);" in runner
assert "GetTimerSystemTime() - start" in runner
assert runner.index("GetTimerSystemTime() - start") < runner.index(
    "digests[mode] = selected->digest(workload)")
assert "digests[mode] != canonical" in runner
assert "f_ps2_test_poly1305" in runner
assert "ee_print_status(" in runner
assert "med[1]/med[0]" in runner
assert "BENCH_RATE," in runner
assert "EE_GREEN" in runner
assert "PS2_SPR_BENCH" not in runner and "PS2_SPR_BENCH" not in builder

suite_names = ("ChaCha20", "SHA224/256", "Poly1305", "AES",
               "GHASH", "BN Mont", "X25519", "RSA", "P256 ECDH", "AES-GCM")
for name in suite_names:
    assert '"'+name+'"' in runner, name
for entry in ("ps2_bench_prepare", "ps2_bench_reset",
              "ps2_bench_run", "ps2_bench_digest"):
    assert entry in bench
# Both benchmark execution and post-timer digest switches have 10 arms.
assert len(re.findall(r"^\s*case (?:[0-9]):", bench, re.MULTILINE)) == 20
assert "printf(" not in bench
assert "clock(" not in bench
assert "GetTimerSystemTime" not in bench

for target in ("test/ps2/bench.c", "poly1305-ee-pmadduw.S",
               "poly1305_test.c", "fused.o", "scalar.o",
               "fused-symbols.txt", "scalar-symbols.txt"):
    assert target in builder, target
assert "PS2_BENCH_POLY_ONLY" in builder
assert "EE_MMI_POLY1305_FUSED_MADD" in builder
assert "PS2_SCHED_BN:-1" in builder
assert "crypto/poly1305/poly1305-ee-pmadduw.S" in builder
assert "compile test/ps2/bench.c" in builder
assert "PS2_AB" in builder
assert "crypto/modes/aes-gcm-ee-mmi.c" in builder
assert "aes_gcm_test.c" not in builder or "aes_gcm" in builder
assert "ossl_ee_aes_gcm4_seal" in bench
assert "sizeof(gcm_tags)" in bench
assert "ps2_test_aes_gcm" in runner
assert "ossl_ee_rsa_public65537_prepared4(" in bench
assert "ossl_ee_rsa_public_key_init(" in bench
assert bench.index("ossl_ee_rsa_public_key_init(") < bench.index(
    "int ps2_bench_run(")
assert "ossl_ee_rsa_public65537_4(" not in bench
print("PASS: ten isolated A/B workloads, fused Poly1305,"
      " alternating median and post-timer output digest checks")
