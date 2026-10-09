#!/usr/bin/env python3
"""Independent X25519 BigInt, radix-25.5 and EE MMI source-layout checks.

This is pure Python and does not assemble/execute PS2 hardware code.
The reference Montgomery ladder is separate from the EE C implementation.
"""
from pathlib import Path
from asm_layout import read_asm
import random
import re

ROOT = Path(__file__).resolve().parents[2]
asm = read_asm((ROOT / "crypto/ec/x25519-ee-mmi.S"))
src = (ROOT / "crypto/ec/x25519-ee-mmi.c").read_text()
test = (ROOT / "test/ee_mmi/x25519_test.c").read_text()
build = (ROOT / "crypto/ec/build.info").read_text()
p = (1 << 255) - 19
widths = [26 if i % 2 == 0 else 25 for i in range(10)]
assert sum(widths) == 255

ops = re.findall(
    r"^\s*EE_X25519_ACC\s+(pmultuw|pmadduw),\s*"
    r"(pextlw|pextuw),\s*(\d+),\s*(\d+)",
    asm, re.MULTILINE
)
expected = []
for k in range(10):
    for pair, extract in enumerate(("pextlw", "pextuw")):
        for i in range(10):
            j = (k + 10 - i) % 10
            variant = (20 if i > k else 0) + (10 if i & j & 1 else 0)
            expected.append(("pmultuw" if i == 0 else "pmadduw",
                             extract, str(i*16), str((j+variant)*16)))
assert ops == expected, "MMI multiply/accumulate convolution order"
stores = list(map(int, re.findall(
    r"^\s*sq\s+\$t4,\s*(\d+)\(\$a0\)", asm, re.MULTILINE
)))
assert stores == [k*32+pair*16 for k in range(10) for pair in range(2)]
assert "ossl_ee_x25519_mul_sums4(sums, a->x, scaled)" in src
assert "EE_MMI_X25519_SCALAR_MULTIPLY" in src
assert "x25519-ee-mmi.c x25519-ee-mmi.S" in build
assert "asm_arch} eq \"ee_mmi\"" in build

def decode_limbs(a):
    out = []
    for width in widths:
        out.append(a & ((1 << width)-1))
        a >>= width
    return out

def encode_limbs(h):
    result, shift = 0, 0
    for v, width in zip(h, widths):
        result += v << shift
        shift += width
    return result

def carry(t):
    t = list(t)
    for _ in range(3):
        for i, width in enumerate(widths[:-1]):
            t[i+1] += t[i] >> width
            t[i] &= (1 << width)-1
        t[0] += (t[9] >> 25)*19
        t[9] &= (1 << 25)-1
    assert all(0 <= v < (1 << width)
               for v,width in zip(t,widths)), "radix carry overflow"
    return t

def mul(a,b):
    f, g = decode_limbs(a), decode_limbs(b)
    t = [0]*10
    for i in range(10):
        for j in range(10):
            k=(i+j)%10
            factor=(19 if i+j>=10 else 1)*(2 if i&j&1 else 1)
            assert g[j]*factor < (1 << 31)
            t[k] += f[i]*g[j]*factor
    assert max(t) < (1 << 60)
    return encode_limbs(carry(t)) % p

rng = random.Random(0x25519e)
for iteration in range(4096):
    a = rng.randrange(p)
    b = rng.randrange(p)
    if iteration == 0: a=b=0
    if iteration == 1: a=b=p-1
    assert mul(a,b) == a*b % p, ("field multiplication", iteration)
    f = decode_limbs(a)
    g = decode_limbs(b)
    assert encode_limbs(carry([x+y for x,y in zip(f,g)])) % p == (
        a+b)%p
    bias = [2*((1<<26)-19)] + [
        2*((1<<width)-1) for width in widths[1:]
    ]
    assert encode_limbs(carry([x+v-y for x,y,v
                               in zip(f,g,bias)])) % p == (a-b)%p
    assert encode_limbs(carry([x*121665 for x in f])) % p == (
        a*121665)%p

def x25519(scalar, u):
    key = bytearray(scalar)
    key[0] &= 248
    key[31] = (key[31] & 127) | 64
    n = int.from_bytes(key, "little")
    v = bytearray(u)
    v[31] &= 127
    x1 = int.from_bytes(v, "little") % p
    x2,z2,x3,z3 = 1,0,x1,1
    sw=0
    for pos in range(254,-1,-1):
        bit=(n>>pos)&1
        sw ^= bit
        if sw:
            x2,x3=x3,x2
            z2,z3=z3,z2
        sw=bit
        A=(x2+z2)%p
        AA=A*A%p
        B=(x2-z2)%p
        BB=B*B%p
        E=(AA-BB)%p
        C=(x3+z3)%p
        D=(x3-z3)%p
        DA=D*A%p
        CB=C*B%p
        x3=(DA+CB)**2%p
        z3=x1*((DA-CB)**2%p)%p
        x2=AA*BB%p
        z2=E*(AA+121665*E)%p
    if sw:
        x2,x3=x3,x2
        z2,z3=z3,z2
    return (x2*pow(z2,p-2,p)%p).to_bytes(32,"little").hex()

def fromhex(value):
    return bytes.fromhex(value)

base = fromhex("09" + "00"*31)
alice = fromhex("77076d0a7318a57d3c16c17251b26645"
                "df4c2f87ebc0992ab177fba51db92c2a")
bob = fromhex("5dab087e624a8a4b79e17f8b83800ee6"
              "6f3bb1292618b6fd1c2f8b27ff88e0eb")
apub="8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
bpub="de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
shared="4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
assert x25519(alice,base) == apub
assert x25519(bob,base) == bpub
assert x25519(alice,fromhex(bpub)) == shared
assert x25519(bob,fromhex(apub)) == shared

golden_match = re.search(r"static const char \*golden\[8\]\[4\] = \{(.*?)\n\};",
                         test,re.DOTALL)
assert golden_match, "C golden table absent"
golden = [re.findall(r'"([0-9a-f]{64})"',row) for row in
          golden_match.group(1).splitlines() if '"' in row]
assert len(golden)==8 and all(len(row)==4 for row in golden)

def xorshift_bytes():
    seed=0x25519ee1
    while True:
        seed ^= (seed << 13) & 0xffffffff
        seed ^= seed >> 17
        seed ^= (seed << 5) & 0xffffffff
        seed &= 0xffffffff
        yield seed & 0xff

stream=xorshift_bytes()
for case in range(8):
    scalar=[bytes(next(stream) for _ in range(32)) for lane in range(4)]
    point=[bytes(next(stream) for _ in range(32)) for lane in range(4)]
    for lane in range(4):
        assert x25519(scalar[lane],point[lane])==golden[case][lane],(
            "X25519 golden",case,lane)

print("PASS: 200 R5900 MMI fused multiplication directives, 320B output")
print("PASS: 4096 radix-25.5 mul/add/sub/constant arithmetic cases")
print("PASS: RFC 7748 public keys and shared secret, 32 BigInt golden results")
