#!/usr/bin/env python3
"""Independent GHASH GF(2^128) BigInt reference and EE layout checker.

This script is not a R5900 instruction emulator. It checks the
algorithm, big-endian word/bit convention and static macro registers.
Actual MMI assembly and HI/LO behavior must be tested on a PS2.
"""
from pathlib import Path
from asm_layout import read_asm
import random
import re

ROOT = Path(__file__).resolve().parents[2]
asm = read_asm((ROOT / "crypto/modes/ghash-ee-mmi.S"))
c = (ROOT / "crypto/modes/ghash-ee-mmi.c").read_text()
build = (ROOT / "crypto/modes/build.info").read_text()
test = (ROOT / "test/ee_mmi/ghash_test.c").read_text()

assert re.findall(r"^\s*EE_GHASH_WORD\s+(\d+)", asm, re.M) == [
    "0", "16", "32", "48"
]
assert re.findall(r"^\s*lq\s+\$(t[0-3]),\s*(\d+)\(\$a2\)",
                  asm, re.M) == [
    ("t0","0"), ("t1","16"), ("t2","32"), ("t3","48")
]
assert re.findall(r"^\s*sq\s+\$(t[4-7]),\s*(\d+)\(\$a0\)",
                  asm, re.M) == [
    ("t4","0"),("t5","16"),("t6","32"),("t7","48")
]
assert "psraw   $t9, $t8, 31" in asm
assert "psllw   $t8, $t8, 1" in asm
assert "addiu   $a2, $zero, 32" in asm
assert "bnez    $a2, .Lghash_loop\\@" in asm
assert ".word 0xe1000000, 0xe1000000, 0xe1000000, 0xe1000000" in asm
for v,t in zip(("t0","t1","t2","t3"),("t4","t5","t6","t7")):
    assert ("pand    $a3, $%s, $t9" % v) in asm
    assert ("pxor    $%s, $%s, $a3" % (t,t)) in asm
# Carries MUST originate from the more significant original word:
assert asm.index("psllw   $a3, $t2, 31") < asm.index(
    "psrlw   $t2, $t2, 1")
assert asm.index("psllw   $a3, $t1, 31") < asm.index(
    "psrlw   $t1, $t1, 1")
assert asm.index("psllw   $a3, $t0, 31") < asm.index(
    "psrlw   $t0, $t0, 1")
assert "ghash-ee-mmi.c ghash-ee-mmi.S" in build
assert 'asm_arch} eq "ee_mmi"' in build
assert "$MODESASM_ee_mmi" not in build
assert "ossl_ee_ghash_mul4(result, x, key);" in c
assert "EE_MMI_GHASH_SCALAR_MULTIPLY" in c

R = 0xe1000000000000000000000000000000
MASK = (1 << 128) - 1

def gf(x,h):
    v=h
    z=0
    for bit in range(127,-1,-1):
        z ^= v if (x >> bit) & 1 else 0
        v = (v >> 1) ^ (R if v & 1 else 0)
    return z

def ghash(y,h,data):
    assert len(data)%16 == 0
    for p in range(0,len(data),16):
        y=gf(y^int.from_bytes(data[p:p+16],"big"),h)
    return y

H = int("66e94bd4ef8a2c3b884cfa59ca342b2e",16)
cipher = bytes.fromhex("0388dace60b6a392f328c2b971b2fe78")
length = bytes.fromhex("00000000000000000000000000000080")
assert ghash(0,H,cipher+length) == int(
    "f38cbb1ad69223dcc3457ae5b6b0f885",16
)
assert gf(0,H)==0
assert gf(H,1<<127)==H          # GHASH multiplicative identity

rng=random.Random(0x37401338)
for idx in range(1024):
    x=rng.getrandbits(128)
    h=rng.getrandbits(128)
    z=gf(x,h)
    # independent polynomial property under XOR.
    y=rng.getrandbits(128)
    assert gf(x^y,h)==(z^gf(y,h))
    assert gf(x,h)==gf(h,x)
    assert gf(z,1<<127)==z

lengths_match = re.search(
    r"static const size_t lengths\[8\] = \{([^}]+)\};",test)
assert lengths_match
lengths=[int(s) for s in lengths_match.group(1).split(",")]
rows=re.findall(r'^\s*\{ ((?:"[0-9a-f]{32}"(?:, )?){4}) \},$',
                test,re.M)
golden=[re.findall(r'"([0-9a-f]{32})"',row) for row in rows]
assert len(golden)==len(lengths)==8

def stream(seed):
    s=seed&0xffffffff
    while True:
        s^=(s<<13)&0xffffffff
        s^=s>>17
        s^=(s<<5)&0xffffffff
        s&=0xffffffff
        yield s&255

for idx,blocks in enumerate(lengths):
    r=stream(0x61707865 ^ ((blocks*0x9e3779b9)&0xffffffff))
    for lane in range(4):
        h=int.from_bytes(bytes(next(r) for _ in range(16)),"big")
        y=int.from_bytes(bytes(next(r) for _ in range(16)),"big")
        data=bytes(next(r) for _ in range(blocks*16))
        actual=ghash(y,h,data)
        assert actual.to_bytes(16,"big").hex()==golden[idx][lane],(
            blocks,lane
        )
print("PASS: GHASH MMI static four-stream bit layout and build isolation")
print("PASS: GHASH NIST AES-GCM, 1024 GF(2^128) algebra checks, "
      "32 independent BigInt final states")
