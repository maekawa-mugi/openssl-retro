#!/usr/bin/env python3
"""Independent P-256 public key and ECDH vector generator/validator.

BigInt affine-point arithmetic (inversions in GF(p)) is deliberately
independent of the R5900 backend's Jacobian coordinates and Montgomery
8x32-bit CIOS implementation. Does NOT test R5900 machine instructions.
"""
from pathlib import Path
from asm_layout import read_asm
import re
import random

ROOT = Path(__file__).resolve().parents[2]
code = (ROOT / "crypto/ec/p256-ee-mmi.c").read_text()
test = (ROOT / "test/ee_mmi/p256_ecdh_test.c").read_text()
bn = read_asm((ROOT / "crypto/bn/bn-ee-mmi.S"))
build = (ROOT / "crypto/ec/build.info").read_text()
header = (ROOT / "include/crypto/ee_p256_ecdh.h").read_text()

p = int("ffffffff00000001000000000000000000000000"
        "ffffffffffffffffffffffff", 16)
n = int("ffffffff00000000ffffffffffffffff"
        "bce6faada7179e84f3b9cac2fc632551", 16)
B = int("5ac635d8aa3a93e7b3ebbd55769886bc"
        "651d06b0cc53b0f63bce3c3e27d2604b", 16)
G = (int("6b17d1f2e12c4247f8bce6e563a440"
         "f277037d812deb33a0f4a13945d898c296", 16),
     int("4fe342e2fe1a7f9b8ee7eb4a7c0f9e"
         "162bce33576b315ececbb6406837bf51f5", 16))

def ec_add(P, Q):
    if P is None: return Q
    if Q is None: return P
    x,y = P
    xx,yy = Q
    if x == xx and (y+yy) % p == 0:
        return None
    if P == Q:
        slope = ((3*x*x-3) * pow(2*y, -1, p)) % p
    else:
        slope = ((yy-y) * pow(xx-x, -1, p)) % p
    rx = (slope*slope-x-xx) % p
    ry = (slope*(x-rx)-y) % p
    return (rx,ry)

def ec_mul(k, P):
    Q = None
    while k:
        if k & 1: Q = ec_add(Q,P)
        P = ec_add(P,P)
        k >>= 1
    return Q

def hex64(v):
    return v.to_bytes(32,"big").hex()

def encode(Q):
    assert Q is not None
    return "04" + hex64(Q[0]) + hex64(Q[1])

rows = re.findall(
    r'\{\s*"([a-f0-9]{64})"\s*,\s*'
    r'"([a-f0-9]{66})"\s*"([a-f0-9]{64})"\s*,\s*'
    r'"([a-f0-9]{64})"\s*\}', test, re.S
)
assert len(rows) == 10, "10 independent ECDH fixtures"
keys = [int(d,16) for d,_,_,_ in rows]
points = [ec_mul(d,G) for d in keys]
for i,(d,prefix,suffix,secret) in enumerate(rows):
    assert 0 < keys[i] < n, ("bad private scalar",i)
    assert encode(points[i]) == prefix+suffix, ("P-256 pub",i)
    peer=points[(i+1)%len(rows)]
    shared=ec_mul(keys[i],peer)
    assert shared is not None
    assert hex64(shared[0]) == secret, ("P-256 ECDH",i)
    assert ec_mul(keys[(i+1)%len(rows)],points[i]) == shared
    assert (points[i][1]**2 - points[i][0]**3
            + 3*points[i][0]-B) % p == 0
assert ec_mul(n,G) is None, "generator order"

# Montgomery field constant values in little-endian 32-bit words.
def parse_words(name):
    match = re.search(
        r"static const uint32_t " + re.escape(name) +
        r"\[8\] = \{(.*?)\};",code,re.S)
    assert match, name
    words = re.findall(r"(?:0x[0-9a-f]+|0)(?:U)?",match.group(1))
    assert len(words)==8, (name, words)
    return sum(int(w.rstrip("Uu"),0)<<(32*i) for i,w in enumerate(words))
assert parse_words("P") == p
assert parse_words("ORDER") == n
assert parse_words("ONE_MONT") == (1<<256)%p
assert parse_words("R2") == (1<<512)%p
assert parse_words("GX") == G[0]
assert parse_words("GY") == G[1]
assert parse_words("CURVE_B") == B
assert parse_words("P_MINUS_2") == p-2
assert "ossl_ee_bn_mont32(r->v,a->v,b->v,P,1U,8)" in code
assert "pt_cswap(&r0,&r1,swap);" in code
assert "for (bit=255;bit>=0;--bit)" in code
assert "uint64_t v=(uint64_t)d[i]-ORDER[i]-borrow" in code
assert "p256-ee-mmi.c" in build and 'asm_arch} eq "ee_mmi"' in build
assert "ossl_ee_p256_ecdh" in header
assert "pmultuw $t6, $t4, $t5" in bn

rng = random.Random(0x5900256)
for i in range(64):
    a = rng.randrange(1,n)
    b = rng.randrange(1,n)
    A = ec_mul(a,G)
    AB = ec_mul(b,A)
    BA = ec_mul(a,ec_mul(b,G))
    assert AB == BA, ("ECDH symmetry",i)
    assert AB == ec_mul(a*b%n,G), ("group order",i)

print("PASS: 10 P-256 public keys, 20 directions of ECDH agreement")
print("PASS: P-256 field/Montgomery constants, 64 random group laws")
print("NOTE: BigInt arithmetic only; no R5900 execution or timing proof")
