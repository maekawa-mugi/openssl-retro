#!/usr/bin/env python3
"""Recompute golden Poly1305 vectors with Python arbitrary-size integers.

This oracle does not import or execute the optimized backend. It makes
the C test vectors reproducible and checks the RFC 7539 known-answer.
"""
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[2]
source = (ROOT / "test/ee_mmi/poly1305_test.c").read_text()
lengths_match = re.search(r"static const size_t lengths\[\] = \{ ([0-9, ]+) \};", source)
assert lengths_match, "length table missing"
lengths = [int(i) for i in lengths_match.group(1).split(",")]
rows = re.findall(r'^\s*\{ ((?:"[0-9a-f]{32}"(?:, )?){4}) \},$',
                  source, re.MULTILINE)
golden = [re.findall(r'"([0-9a-f]{32})"', row) for row in rows]
assert len(golden) == len(lengths), (len(golden), len(lengths))

MASK = (1 << 32) - 1

def stream(seed):
    s = seed & MASK
    while True:
        s ^= (s << 13) & MASK
        s ^= s >> 17
        s ^= (s << 5) & MASK
        s &= MASK
        yield s & 255

def poly1305(key, data):
    r = int.from_bytes(key[:16], "little") & 0x0ffffffc0ffffffc0ffffffc0fffffff
    s = int.from_bytes(key[16:], "little")
    h = 0
    mod = (1 << 130) - 5
    for offset in range(0, len(data), 16):
        block = data[offset:offset + 16]
        h = ((h + int.from_bytes(block + b"\x01", "little")) * r) % mod
    return ((h + s) % (1 << 128)).to_bytes(16, "little").hex()

assert poly1305(
    bytes.fromhex(
        "85d6be7857556d337f4452fe42d506a8"
        "0103808afb0db2fd4abff6af4149f51b"),
    b"Cryptographic Forum Research Group"
) == "a8061dc1305136c6c22b8baf0c0127a9"

for idx, length in enumerate(lengths):
    rng = stream(0x61707865 ^ ((length * 0x9e3779b9) & MASK))
    for lane in range(4):
        key = bytes(next(rng) for _ in range(32))
        data = bytes(next(rng) for _ in range(length))
        value = poly1305(key, data)
        assert value == golden[idx][lane], (length, lane, value,
                                                golden[idx][lane])
print("PASS: %d Poly1305 BigInt oracle tags plus RFC 7539" %
      (len(lengths) * 4))
