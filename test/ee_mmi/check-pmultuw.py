#!/usr/bin/env python3
"""Portable model of the R5900 PEXTLW/PEXTUW + PMULTUW lane convention.

The EE manuals specify two unsigned 32x32->64 products in a 128-bit
destination GPR, not four 32-bit products. PMULTUW requires each
64-bit half of both operands to hold a sign-extended 32-bit word.

Our Poly1305 inputs are <2^31, so upper words MUST be zero. This
test models both packing instructions, the two multiplies and the
SQ output layout, then compares with independent Python integers.
It does NOT execute actual R5900 instructions or prove assembler ABI.
"""
import random
import re
from pathlib import Path
from asm_layout import read_asm

ROOT = Path(__file__).resolve().parents[2]
asm = read_asm((ROOT / "crypto/poly1305/poly1305-ee-pmultuw.S"))
macro_calls = [
    tuple(map(int, x)) for x in re.findall(
        r"^\s*EE_POLY_MUL2\s+(\d+),\s*(\d+),\s*(\d+),\s*(\d+)",
        asm, re.MULTILINE
    )
]
assert len(macro_calls) == 25

def pack_lanes(words, base):
    """PEXT(L|U)W dst,$zero,src: 64-bit slots with zero high words."""
    return words[base] | (words[base + 1] << 64)

def valid_word(value):
    low = value & 0xffffffff
    high = (value >> 32) & 0xffffffff
    return high == (0xffffffff if low & 0x80000000 else 0)

def pmultuw(a, b):
    assert valid_word(a) and valid_word(a >> 64)
    assert valid_word(b) and valid_word(b >> 64)
    lo = (a & 0xffffffff) * (b & 0xffffffff)
    hi = ((a >> 64) & 0xffffffff) * ((b >> 64) & 0xffffffff)
    assert lo < (1 << 64) and hi < (1 << 64)
    return lo | (hi << 64)

rng = random.Random(0x59001305)
for iteration in range(256):
    a = [[rng.randrange(1 << 27) for _ in range(4)] for _ in range(5)]
    r = [[rng.randrange(1 << 26) for _ in range(4)] for _ in range(5)]
    if iteration == 0:
        a = [[0] * 4 for _ in range(5)]
        r = [[0] * 4 for _ in range(5)]
    if iteration == 1:
        a = [[(1 << 27) - 1] * 4 for _ in range(5)]
        r = [[(1 << 26) - 1] * 4 for _ in range(5)]
    b = r + [[5 * x for x in row] for row in r]
    for row in a + b:
        assert all(x < (1 << 31) for x in row)

    output = bytearray([0xa5] * 800)
    for k in range(5):
        for i in range(5):
            aoff, boff, out0, out1 = macro_calls[k * 5 + i]
            j = (k - i + 5) % 5 + (5 if i > k else 0)
            assert (aoff, boff, out0, out1) == (
                i*16, j*16, (k*5 + i)*32, (k*5 + i)*32 + 16
            )
            lo_pair = pmultuw(pack_lanes(a[i], 0),
                              pack_lanes(b[j], 0))
            hi_pair = pmultuw(pack_lanes(a[i], 2),
                              pack_lanes(b[j], 2))
            output[out0:out0 + 16] = lo_pair.to_bytes(16, "little")
            output[out1:out1 + 16] = hi_pair.to_bytes(16, "little")
            for lane in range(4):
                start = (k*5 + i)*32 + lane*8
                actual = int.from_bytes(output[start:start+8], "little")
                expected = a[i][lane] * b[j][lane]
                assert actual == expected, (iteration, k, i, lane)

    # Reconstruct the complete five-limb convolution for every stream.
    for lane in range(4):
        for k in range(5):
            total = sum(
                int.from_bytes(output[(k*5+i)*32 + lane*8:
                                      (k*5+i)*32 + lane*8 + 8], "little")
                for i in range(5)
            )
            reference = sum(
                a[i][lane] * r[(k-i) % 5][lane] *
                (5 if i > k else 1)
                for i in range(5)
            )
            assert total == reference, (iteration, lane, k)

print("PASS: 256 PMULTUW layout models, 25 terms x 4 streams "
      "and exact five-limb convolutions")
