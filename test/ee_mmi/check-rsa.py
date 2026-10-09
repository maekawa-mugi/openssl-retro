#!/usr/bin/env python3
"""Standalone independent RSA-65537 / PKCS#1 SHA256 BigInt oracle.

Checks the exact 2048-bit fixtures used by rsa_test.c without OpenSSL,
cryptography packages or PS2 hardware. This does not execute the EE
PMULTUW assembly and is not a replacement for test ELFs on a real EE.
"""
from pathlib import Path
from asm_layout import read_asm
import re
import random

ROOT = Path(__file__).resolve().parents[2]
test = (ROOT / "test/ee_mmi/rsa_test.c").read_text()
source = (ROOT / "crypto/rsa/rsa-ee-mmi.c").read_text()
bn = (ROOT / "crypto/bn/bn-ee-mmi.c").read_text()
asm = read_asm((ROOT / "crypto/bn/bn-ee-mmi.S"))
build = (ROOT / "crypto/rsa/build.info").read_text()
header = (ROOT / "include/crypto/ee_rsa_verify.h").read_text()

fixture_match = re.search(
    r"fixture\[4\]\s*=\s*\{(.*?)\n\};", test, re.S
)
assert fixture_match, "RSA test fixtures are missing"
cases = re.findall(r"^\s{4}\{\s*(.*?)\n\s{4}\}", fixture_match.group(1),
                   re.S | re.M)
assert len(cases) == 4, "expected four independent 2048-bit signatures"
fixtures = []
for case in cases:
    pieces = re.findall(r'"([0-9a-f]+)"', case)
    assert len(pieces) == 17, "8 pieces each for modulus/signature plus SHA256"
    modulus, signature, digest = (
        "".join(pieces[:8]), "".join(pieces[8:16]), pieces[16]
    )
    assert len(modulus) == len(signature) == 512
    assert len(digest) == 64
    assert (int(modulus, 16) & 1) == 1
    assert int(modulus[0], 16) >= 8
    fixtures.append((int(modulus,16), int(signature,16), digest))

prefix = "3031300d060960864801650304020105000420"
assert len(prefix) == 19*2
expected_digest_info = bytes.fromhex(prefix)
assert len(set(n for n,_,_ in fixtures)) == 4

for lane, (n, sig, digest) in enumerate(fixtures):
    assert 0 < sig < n, ("input range", lane)
    em = pow(sig, 65537, n).to_bytes(256, "big")
    expected = b"\x00\x01" + b"\xff"*(256-3-19-32) + b"\x00"
    expected += expected_digest_info + bytes.fromhex(digest)
    assert em == expected, ("PKCS1 SHA256 signature",lane)
    assert pow(sig^1, 65537, n) != int.from_bytes(expected,"big")

def inverse32(n):
    x = 1
    for _ in range(5):
        x = (x*(2-n*x)) & 0xffffffff
    return (-x) & 0xffffffff

rng = random.Random(0x5900ee)
# Independent arithmetic check of n0 / R2 preparation for 1024-4096 bits.
for bits in (1024, 2048, 3072, 4096):
    for _ in range(24):
        n = rng.getrandbits(bits) | (1 << (bits-1)) | 1
        words = bits//32
        n0 = inverse32(n & 0xffffffff)
        assert (n*n0) & 0xffffffff == 0xffffffff
        r2 = 1
        for _ in range(bits*2):
            r2 *= 2
            if r2 >= n:
                r2 -= n
        assert r2 == pow(2,bits*2,n)
        a = rng.randrange(n)
        # This is exactly the exponentiation sequence used by C:
        # aR -> 16 squares -> multiply by aR -> un-Montgomery.
        R = pow(2,bits,n)
        Rinv = pow(R,-1,n)
        base = a*R%n
        power = base
        for _ in range(16):
            power = power*power*Rinv % n
        power = power*base*Rinv % n
        actual = power*Rinv % n
        assert actual == pow(a,65537,n)

assert "ossl_ee_bn_mont32" in source
assert "rsa_double_mod(r2, mod, num, diff)" in source
assert "ossl_ee_rsa_pkcs1_sha256_verify4(" in source
assert "EE_MMI_BN_SCALAR_MUL" in bn
assert "pmultuw $t6, $t4, $t5" in asm
assert "psraw   $t2, $t0, 31" in asm
assert 'asm_arch} eq "ee_mmi"' in build
assert "rsa-ee-mmi.c" in build
assert "OSSL_EE_RSA_MAX_BYTES 512" in header
assert "pow(" not in source
assert "rsa_double_mod(key->r2, key->mod, key->num, diff)" in source
assert "ossl_ee_rsa_public65537_prepared4(" in source
assert "ossl_ee_rsa_public_key_init(" in source
assert "ossl_ee_rsa_public_key_clear(" in header
assert "prepared_key_test()" in test
assert "rsa_public_key" in header
assert "ossl_ee_bn_mont32(base, a, key->r2," in source

print("PASS: four distinct RSA-2048 SHA256 PKCS#1 v1.5 signatures")
print("PASS: 96 RSA Montgomery R2+n0 preparations, 1024-4096 bit")
print("PASS: 96 RSA-65537 BigInt modular exponent comparisons")
print("NOTE: this is Python reference math, not PS2 execution")
