#!/usr/bin/env python3
"""Static and arithmetic model of the R5900 PMULTUW + PMADDUW kernel.

Checks each 64-bit lane's exact five-product sum, 160-byte memory
layout and PEXTLW/PEXTUW zero-extension. Uses Python integers and
does NOT assemble, execute or time an EE MMI instruction.
"""
from pathlib import Path
from asm_layout import read_asm
import random
import re

ROOT = Path(__file__).resolve().parents[2]
asm = read_asm((ROOT / "crypto/poly1305/poly1305-ee-pmadduw.S"))
calls = re.findall(
    r"^\s*EE_POLY_ACC\s+(pmultuw|pmadduw),\s*(pextlw|pextuw),"
    r"\s*(\d+),\s*(\d+)", asm, re.MULTILINE)
store_offsets = list(map(int, re.findall(
    r"^\s*sq\s+\$t4,\s*(\d+)\(\$a0\)", asm, re.MULTILINE
)))
assert len(calls) == 50 and len(store_offsets) == 10
assert store_offsets == [k*32+p*16 for k in range(5)
                         for p in range(2)]
for k in range(5):
    for pair in range(2):
        for i in range(5):
            op, extract, ao, bo = calls[k*10+pair*5+i]
            j = (k-i+5) % 5 + (5 if i > k else 0)
            assert op == ("pmultuw" if i == 0 else "pmadduw")
            assert extract == ("pextlw" if pair == 0 else "pextuw")
            assert int(ao) == i*16
            assert int(bo) == j*16

rng = random.Random(0x5900add0)
cases = 512
for iteration in range(cases):
    # 27-bit loose accumulator limbs, clamped 26-bit r plus 5*r.
    a = [[rng.randrange(1 << 27) for _ in range(4)]
         for _ in range(5)]
    r = [[rng.randrange(1 << 26) for _ in range(4)]
         for _ in range(5)]
    if iteration == 0:
        a = [[0]*4 for _ in range(5)]
        r = [[0]*4 for _ in range(5)]
    elif iteration == 1:
        a = [[(1 << 27)-1]*4 for _ in range(5)]
        r = [[(1 << 26)-1]*4 for _ in range(5)]
    b = r + [[5*x for x in row] for row in r]
    assert all(x < (1 << 31) for row in a+b for x in row)

    output = bytearray([0xa5]*160)
    for k in range(5):
        for pair in range(2):
            accum = [0, 0]     # models two 64-bit EE HI/LO lanes
            for i in range(5):
                op, extract, ao, bo = calls[k*10+pair*5+i]
                j = int(bo)//16
                word = int(ao)//16
                # PEXTLW or PEXTUW with rs=$zero creates two
                # sign-extended 32-bit operands (zero for positive).
                lane0 = pair*2
                lane1 = lane0 + 1
                for offset, lane in enumerate((lane0, lane1)):
                    lhs, rhs = a[word][lane], b[j][lane]
                    assert lhs < (1 << 31) and rhs < (1 << 31)
                    product = lhs * rhs
                    assert product < (1 << 64)
                    if op == "pmultuw":
                        accum[offset] = product
                    else:
                        accum[offset] += product
                        assert accum[offset] < (1 << 64)
            base = store_offsets[k*2+pair]
            for offset, value in enumerate(accum):
                output[base+offset*8:base+(offset+1)*8] = (
                    value.to_bytes(8, "little")
                )
                lane = pair*2+offset
                reference = sum(
                    a[i][lane] * r[(k-i)%5][lane] *
                    (5 if i > k else 1)
                    for i in range(5)
                )
                assert value == reference, (iteration, k, lane)
                assert int.from_bytes(
                    output[base+offset*8:base+(offset+1)*8], "little"
                ) == reference
assert max(store_offsets) == 144
print("PASS: %d fused PMADDUW cases, 20 exact 64-bit sums/case, "
      "zero extension and 160-byte layout" % cases)
