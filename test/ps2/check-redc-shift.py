#!/usr/bin/env python3
"""Replay fused REDC/shift instructions against independent BigInt math.

Uses the existing register trace interpreter, never assembles EE code.
Checks the complete CIOS flow as well as the standalone shifted row.
"""
import random
import runpy
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
model = runpy.run_path(str(ROOT / "test/ps2/check-experiments.py"))
execute_row = model["execute_row"]
assemble_trace = model["assemble_trace"]
sx = model["sx"]
MASK = (1 << 32) - 1
source = (ROOT / "crypto/bn/bn-ee-redc-shift-mmi.S").read_text()
trace = assemble_trace(source)
rng = random.Random(0x5900edc5)

for n in range(1, 129):
    for trial in range(16):
        b = MASK if trial == 0 else 0x80000000 if trial == 1 else rng.getrandbits(32)
        a = [MASK if trial == 0 else rng.getrandbits(32) for _ in range(n)]
        t = [MASK if trial == 0 else rng.getrandbits(32) for _ in range(n)]
        value = sum(w << (32*j) for j, w in enumerate(t))
        value += b * sum(w << (32*j) for j, w in enumerate(a))
        words, carry = execute_row(a, t, b, trace)
        expected = [(value >> (32*(j+1))) & MASK for j in range(n-1)] + [t[-1]]
        assert words == expected, (n, trial)
        assert carry == sx(value >> (32*n)), (n, trial, "carry ABI")
print("PASS: REDC shifted-row instruction trace 2048 exact word/carry/bounds cases")

# Regression: storing the first discarded limb at -4 would corrupt a guard.
broken = source.replace("bnez    $15, .Lee_bn_shift_skip_low", "nop")
try:
    execute_row([MASK], [MASK], MASK, assemble_trace(broken))
except AssertionError as error:
    assert "out-of-range access" in str(error), str(error)
else:
    raise AssertionError("missing first-word guard was not detected")

def mont(a, b, modulus, n):
    al = [(a >> (32*j)) & MASK for j in range(n)]
    bl = [(b >> (32*j)) & MASK for j in range(n)]
    nl = [(modulus >> (32*j)) & MASK for j in range(n)]
    n0 = -pow(nl[0], -1, 1 << 32) & MASK
    t = [0] * (n+2)
    for i in range(n):
        words, carry = execute_row(al, t[:n], bl[i])
        t[:n] = words
        z = t[n] + (carry & MASK)
        t[n] = z & MASK
        t[n+1] += z >> 32
        q = t[0] * n0 & MASK
        assert (t[0] + nl[0]*q) & MASK == 0
        words, carry = execute_row(nl, t[:n], q, trace)
        t[:n] = words
        z = t[n] + (carry & MASK)
        t[n-1] = z & MASK
        t[n] = t[n+1] + (z >> 32)
        t[n+1] = 0
        assert t[n] <= 1
    value = sum(w << (32*j) for j, w in enumerate(t[:n+1]))
    if value >= modulus:
        value -= modulus
    assert 0 <= value < modulus
    return value

count = 0
for n in (1, 2, 3, 4, 5, 7, 8, 16, 32, 64, 128):
    for trial in range(12 if n < 16 else 5):
        modulus = rng.getrandbits(32*n) | (1 << (32*n-1)) | 1
        a, b = rng.randrange(modulus), rng.randrange(modulus)
        if trial == 0:
            a = b = modulus-1
        elif trial == 1:
            a = b = 0
        elif trial == 2:
            a = b = 1
        expected = a*b*pow(1 << (32*n), -1, modulus) % modulus
        assert mont(a,b,modulus,n) == expected, (n,trial)
        count += 1
print("PASS: complete register-row + shifted REDC CIOS trace", count,
      "BigInt cases, 32..4096-bit, including final overflow/subtraction")

c = (ROOT / "crypto/bn/bn-ee-mmi.c").read_text()
assert "ossl_ee_bn_redc_shift_row_mmi(t, mod, q, num)" in c
assert "#ifndef EE_MMI_BN_REDC_SHIFT\n        /* The first REDC" in c
assert "#endif\n        t[num - 1] = (uint32_t)z;" in c
assert "pxor    $15, $15, $15" in source
print("NOTE: assembly/ABI/latency still require the user-built PS2 ELF")
