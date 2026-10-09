#!/usr/bin/env python3
"""Independent Python big-integer oracle for EE R5900 Montgomery CIOS.

Models the *word* algorithm and compares it against exact arbitrary-size
integer arithmetic. Separately checks how PSRAW+PEXTLW creates proper
sign-extended word values for unsigned PMULTUW. This does NOT execute
R5900 MMI instructions.
"""
import random
import re
from pathlib import Path
from asm_layout import read_asm

ROOT = Path(__file__).resolve().parents[2]
asm = read_asm((ROOT / "crypto/bn/bn-ee-mmi.S"))
cc = (ROOT / "crypto/bn/bn-ee-mmi.c").read_text()
build = (ROOT / "crypto/bn/build.info").read_text()

assert re.search(r"psraw\s+\$t2,\s*\$t0,\s*31", asm)
assert re.search(r"psraw\s+\$t3,\s*\$t1,\s*31", asm)
assert re.search(r"pextlw\s+\$t4,\s*\$t2,\s*\$t0", asm)
assert re.search(r"pextlw\s+\$t5,\s*\$t3,\s*\$t1", asm)
assert re.search(r"pmultuw\s+\$t6,\s*\$t4,\s*\$t5", asm)
assert "OPENSSL_BN_ASM_MONT" in cc
assert 'asm_arch} eq "ee_mmi"' in build
assert "SOURCE[../../libcrypto]=bn-ee-mmi.c bn-ee-mmi.S" in build
assert "SOURCE[../../providers/libfips.a]=$COMMON $BNASM" in build

MASK = (1 << 32) - 1
BASE = 1 << 32
RNG = random.Random(0x59001313)


def packed_word(value):
    """A sign-extended 32-bit word, valid for R5900 PMULTUW."""
    return value | ((MASK if value >> 31 else 0) << 32)


for i in range(2000):
    a = RNG.getrandbits(32)
    b = RNG.getrandbits(32)
    if i == 0:
        a = b = MASK
    if i == 1:
        a, b = 0x80000000, MASK
    assert (packed_word(a) & MASK) == a
    assert (packed_word(a) >> 32) == (MASK if a & 0x80000000 else 0)
    assert (packed_word(a) & MASK) * (packed_word(b) & MASK) == a*b


def mont_cios(a, b, n, limbs):
    nn = [(n >> (32*j)) & MASK for j in range(limbs)]
    aa = [(a >> (32*j)) & MASK for j in range(limbs)]
    bb = [(b >> (32*j)) & MASK for j in range(limbs)]
    n0 = (-pow(nn[0], -1, BASE)) & MASK
    t = [0] * (limbs + 2)

    for i in range(limbs):
        carry = 0
        for j in range(limbs):
            z = t[j] + aa[j]*bb[i] + carry
            assert z < (1 << 64)
            t[j], carry = z & MASK, z >> 32
        z = t[limbs] + carry
        t[limbs] = z & MASK
        t[limbs+1] += z >> 32

        m = (t[0] * n0) & MASK
        carry = 0
        for j in range(limbs):
            z = t[j] + m*nn[j] + carry
            assert z < (1 << 64)
            if j:
                t[j-1] = z & MASK
            else:
                assert z & MASK == 0
            carry = z >> 32

        z = t[limbs] + carry
        t[limbs-1] = z & MASK
        t[limbs] = t[limbs+1] + (z >> 32)
        t[limbs+1] = 0
        assert t[limbs] <= 1

    value = sum(w << (32*j) for j, w in enumerate(t[:limbs]))
    value += t[limbs] << (32*limbs)
    if value >= n:
        value -= n
    assert 0 <= value < n
    return value


cases = 0
for limbs in (1, 2, 3, 4, 5, 7, 8, 16, 32, 64, 128):
    for t in range(300 if limbs < 16 else 75):
        n = RNG.getrandbits(32 * limbs - 1) | (1 << (32 * limbs - 1)) | 1
        a = RNG.randrange(n)
        b = RNG.randrange(n)
        if t % 11 == 0:
            a = b = n-1
        if t % 13 == 0:
            a = b = 0
        observed = mont_cios(a, b, n, limbs)
        expected = a*b*pow(BASE**limbs, -1, n) % n
        assert observed == expected, (limbs, t, observed, expected)
        cases += 1

print("PASS: EE Montgomery %d exact BigInt cases, 2000 unsigned "
      "PMULTUW sign-extension models" % cases)
