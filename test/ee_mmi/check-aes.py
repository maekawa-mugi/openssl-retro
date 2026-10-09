#!/usr/bin/env python3
"""Check the AES four-way MMI round layout and independent math model.

Does NOT assemble or execute Emotion Engine instructions. The S-box
model checks its algebraic definition against the known Rijndael table.
The MixColumns model uses an independent byte-oriented reference.
"""
from pathlib import Path
from asm_layout import read_asm
import random
import re

root = Path(__file__).resolve().parents[2]
asm = read_asm((root / "crypto/aes/aes-ee-mmi.S"))
src = (root / "crypto/aes/aes-ee-mmi.c").read_text()
test = (root / "test/ee_mmi/aes_test.c").read_text()
build = (root / "crypto/aes/build.info").read_text()
head = (root / "include/crypto/ee_mmi.h").read_text()

assert re.findall(r"^\s*EE_AES_COL\s+(\d+)", asm, re.M) == [
    "0", "16", "32", "48"
]
assert ".word 0xfefefefe, 0xfefefefe, 0xfefefefe, 0xfefefefe" in asm
assert ".word 0x01010101, 0x01010101, 0x01010101, 0x01010101" in asm
assert "psrlw   $t1, $t0, 8" in asm
assert "psllw   $t2, $t0, 24" in asm
assert "pand    $t7, $t7, $t8" in asm
assert "pand    $t6, $t6, $t9" in asm
assert "pxor    $t5, $t5, $t6" in asm
assert "sq      $t5, \\off($a0)" in asm
assert "ossl_ee_aes_mixcolumns_ark4(state, ctx->round_key[round]);" in src
assert "EE_MMI_AES_SCALAR_ROUND" in src
assert "ghash" not in src.lower()
assert 'asm_arch} eq "ee_mmi"' in build
assert "aes-ee-mmi.c aes-ee-mmi.S" in build
assert "$AESDEF_ee_mmi" not in build
assert "ossl_ee_aes_ctr32_xor" in head

table_section = test.split("static const unsigned char sbox[256] = {", 1)[1]
table_section = table_section.split("};", 1)[0]
sbox = [int(x, 16) for x in re.findall(r"0x([0-9a-f]{2})", table_section)]
assert len(sbox) == 256

def xtime(x):
    return ((x << 1) & 255) ^ (0x1b if x & 128 else 0)

def gfmul(a,b):
    out=0
    for _ in range(8):
        if b & 1: out ^= a
        a=xtime(a)
        b >>= 1
    return out

def inv(x):
    # Exponent 254; zero automatically maps to zero.
    a = x
    y = 1
    for _ in range(8):
        if 254 & (1 << _):
            y = gfmul(y, a)
        a = gfmul(a,a)
    return y

def rot8(x, n):
    return ((x << n) | (x >> (8-n))) & 255

def subs(x):
    y=inv(x)
    return y ^ rot8(y,1) ^ rot8(y,2) ^ rot8(y,3) ^ rot8(y,4) ^ 0x63

for x in range(256):
    assert subs(x) == sbox[x], ("AES S-box",x)

def mix_bytes(c):
    t=c[0]^c[1]^c[2]^c[3]
    return [c[r]^t^xtime(c[r]^c[(r+1)%4]) for r in range(4)]

def packed_xtime(x):
    hi=(x>>7)&0x01010101
    return (((x<<1)&0xfefefefe) ^ hi ^ (hi<<1)
            ^ (hi<<3) ^ (hi<<4)) & 0xffffffff

def rotr(x,b):
    return ((x>>b)|(x<<(32-b)))&0xffffffff

def mix_word(x):
    r8=rotr(x,8)
    return (r8 ^ rotr(x,16) ^ rotr(x,24)
            ^ packed_xtime(x^r8)) & 0xffffffff

rng = random.Random(0x0ae59aee)
for iteration in range(8192):
    x=rng.getrandbits(32)
    rk=rng.getrandbits(32)
    if iteration == 0: x = 0
    if iteration == 1: x = 0xffffffff
    a=list(x.to_bytes(4,"little"))
    expected=int.from_bytes(bytes(mix_bytes(a)),"little") ^ rk
    assert mix_word(x)^rk == expected, ("AES packed MixColumns",iteration)

# The scalar and assembly backends use the same column/word layout.
assert "state[col][lane] = load_le32(in[lane] + 4*col)" in src
assert "for (row = 0; row < 4; ++row)" in src
assert "old[(col+row)&3]" in src
assert "(ctx->rounds != 10 && ctx->rounds != 12" in src
assert "needed > (uint64_t)UINT32_MAX - counter + 1U" in src

# The optimized EE AES S-box no longer uses thirteen general GF
# multiplications. Independently check the GF(2^8) linear square
# residues and the exact x^254 exponent addition chain for all bytes.
assert "static uint32_t aes_gfsquare4(uint32_t x)" in src
assert "x2 = aes_gfsquare4(x);" in src
assert "inverse = aes_gfsquare4(t);" in src
assert src.count("t = aes_gfsquare4(") == 5
assert "aes_wipe(&inverse, sizeof(inverse));" in src

def packed_square(x):
    r = (x & 0x01010101) ^ ((x & 0x02020202) << 1)
    r ^= ((x & 0x04040404) << 2) ^ ((x & 0x08080808) << 3)
    b = (x >> 4) & 0x01010101
    r ^= b ^ (b << 1) ^ (b << 3) ^ (b << 4)
    b = (x >> 5) & 0x01010101
    r ^= (b << 2) ^ (b << 3) ^ (b << 5) ^ (b << 6)
    b = (x >> 6) & 0x01010101
    r ^= b ^ (b << 1) ^ (b << 3) ^ (b << 5) ^ (b << 7)
    b = (x >> 7) & 0x01010101
    r ^= (b << 1) ^ (b << 3) ^ (b << 4) ^ (b << 7)
    return r & 0xffffffff

def chain_inverse(x):
    x2 = packed_square(x)
    t = gfmul(x2, x)
    t = packed_square(t)
    x7 = gfmul(t, x)
    t = packed_square(x7)
    t = gfmul(t, x)
    t = packed_square(t)
    t = packed_square(t)
    t = packed_square(t)
    t = gfmul(t, x7)
    return packed_square(t)

for x in range(256):
    assert packed_square(x) == gfmul(x,x)
    assert chain_inverse(x) == inv(x), ("EE S-box inverse",x)
for _ in range(4096):
    x = rng.getrandbits(32)
    result = packed_square(x)
    expected = sum(gfmul((x >> (8*j)) & 255,
                         (x >> (8*j)) & 255) << (8*j)
                   for j in range(4))
    assert result == expected, ("EE 4-byte GF square",x)
print("PASS: optimized AES S-box, 256 inverse chains and 4096 packed squares")

print("PASS: AES EE MMI four columns, constant-time packed xtime and build isolation")
print("PASS: 256 algebraic S-box values and 8192 independent MixColumns/ARK cases")
print("NOTE: static arithmetic model only; real EE assembly and speed unverified")
