#!/usr/bin/env python3
"""ECDSA P-256 signature test oracle, with no third-party dependencies.

Recomputes all three fixed-key, fixed-nonce P-256 signature vectors
from a separate affine-point implementation using Python BigInts.
Does NOT execute EE assembly, OpenSSL, or a real PS2.
"""
from pathlib import Path
import hashlib
import re

ROOT = Path(__file__).resolve().parents[2]
source = (ROOT / "test/ee_mmi/ecdsa_p256_test.c").read_text()
p = int("ffffffff00000001000000000000000000000000"
        "ffffffffffffffffffffffff", 16)
n = int("ffffffff00000000ffffffffffffffff"
        "bce6faada7179e84f3b9cac2fc632551", 16)
a = (p - 3) % p
b = int("5ac635d8aa3a93e7b3ebbd55769886bc"
        "651d06b0cc53b0f63bce3c3e27d2604b", 16)
G = (
    int("6b17d1f2e12c4247f8bce6e563a440"
        "f277037d812deb33a0f4a13945d898c296", 16),
    int("4fe342e2fe1a7f9b8ee7eb4a7c0f9e"
        "162bce33576b315ececbb6406837bf51f5", 16)
)

def add(P, Q):
    if P is None: return Q
    if Q is None: return P
    x1, y1 = P
    x2, y2 = Q
    if x1 == x2 and (y1 + y2) % p == 0:
        return None
    if P == Q:
        if y1 == 0:
            return None
        slope = ((3*x1*x1+a) * pow(2*y1, -1, p)) % p
    else:
        slope = ((y2-y1) * pow((x2-x1) % p, -1, p)) % p
    x = (slope*slope-x1-x2) % p
    y = (slope*(x1-x)-y1) % p
    return (x, y)

def mul(k, P):
    result = None
    while k:
        if k & 1:
            result = add(result, P)
        P = add(P, P)
        k >>= 1
    return result

def enc_point(P):
    assert P is not None
    return "04" + P[0].to_bytes(32, "big").hex() + P[1].to_bytes(32, "big").hex()

def sign(d, k, digest):
    z = int.from_bytes(digest, "big")
    x = mul(k, G)[0]
    r = x % n
    s = (pow(k, -1, n) * (z + r*d)) % n
    assert 0 < r < n and 0 < s < n
    return r.to_bytes(32, "big").hex() + s.to_bytes(32, "big").hex()

def verify(P, digest, signature):
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")
    if not (1 <= r < n and 1 <= s < n):
        return False
    if P is None or (P[1]*P[1]-P[0]**3-a*P[0]-b)%p:
        return False
    w = pow(s, -1, n)
    z = int.from_bytes(digest, "big")
    R = add(mul((z*w)%n, G), mul((r*w)%n, P))
    return R is not None and R[0]%n == r

# Fixed values are exclusively test data. NEVER use these test nonces
# to sign real data: reusing an ECDSA nonce reveals a private key.
testcases = (
    (1, 2, b"ECDSA EE MMI P256 test 1"),
    (123456789, 987654321, b"ECDSA EE MMI P256 test 2"),
    (0x123456789abcdef123456789abcdef,
     0xdeadbeefcafebabe123456789, b"ECDSA EE MMI P256 test 3"),
)
body = re.search(r"\}\s*vectors\[3\]\s*=\s*\{(.*?)\n\};", source, re.S)
assert body is not None, "test vector initializer not found"
rows = re.findall(r'\{\s*"([0-9a-f]{130})"\s*,\s*'
                  r'"([0-9a-f]{64})"\s*,\s*"([0-9a-f]{128})"\s*\}',
                  body.group(1), re.S)
assert len(rows) == 3, "expected three embedded ECDSA vectors"
for idx, (d, k, msg) in enumerate(testcases):
    point = mul(d, G)
    digest = hashlib.sha256(msg).digest()
    pub = enc_point(point)
    sig = sign(d, k, digest)
    assert (pub, digest.hex(), sig) == rows[idx], ("vector", idx)
    assert verify(point, digest, bytes.fromhex(sig))
    modified = bytearray.fromhex(sig)
    modified[-1] ^= 1
    assert not verify(point, digest, bytes(modified))
print("PASS: ECDSA P-256 3 deterministic signatures, public keys "
      "and independent point-arithmetic verifications")
