#!/usr/bin/env python3
"""Symmetric square + actual MMI REDC row trace, without building code."""
from pathlib import Path
import random
import runpy

ROOT = Path(__file__).resolve().parents[2]
model = runpy.run_path(str(ROOT / "test/ps2/check-experiments.py"))
row = model["execute_row"]
MASK, MASK64 = (1<<32)-1, (1<<64)-1
rng = random.Random(0x59005a)

def square(a, mod, n):
    al = [(a>>(32*i))&MASK for i in range(n)]
    ml = [(mod>>(32*i))&MASK for i in range(n)]
    n0 = -pow(ml[0],-1,1<<32)&MASK
    low,high = 0,0
    t = [0]*(2*n+2)
    products = 0
    for k in range(2*n-1):
        first = 0 if k<n else k+1-n
        for i in range(first,k//2+1):
            j = k-i
            product = al[i]*al[j]
            products += 1
            previous = low
            low = (low+product)&MASK64
            high += low<previous
            if i!=j:
                previous = low
                low = (low+product)&MASK64
                high += low<previous
        t[k] = low&MASK
        low = (low>>32)|(high<<32)
        assert low<=MASK64
        high = 0
    t[2*n-1] = low&MASK
    t[2*n] = low>>32
    assert sum(w<<(32*i) for i,w in enumerate(t)) == a*a
    assert products == n*(n+1)//2
    for i in range(n):
        q = t[i]*n0&MASK
        words,carry = row(ml,t[i:i+n],q)
        t[i:i+n] = words
        carry &= MASK
        assert t[i] == 0
        for j in range(i+n,2*n+2):
            z = t[j]+carry
            t[j],carry = z&MASK,z>>32
        assert carry == 0
    borrow = 0
    diff = []
    for i in range(n):
        word = t[n+i]
        subtrahend = ml[i]+borrow
        diff.append((word-subtrahend)&MASK)
        borrow = int(word<subtrahend)
    mask = MASK if t[2*n]==0 and borrow else 0
    result = [(t[n+i]&mask)|(diff[i]&(~mask&MASK)) for i in range(n)]
    assert t[2*n+1] == 0 and t[2*n]<=1
    return sum(w<<(32*i) for i,w in enumerate(result))

count = 0
for n in (1,2,3,4,5,7,8,15,16,31,32,63,64,127,128):
    for trial in range(12):
        mod = rng.getrandbits(32*n)|(1<<(32*n-1))|1
        if trial == 3: mod = (1<<(32*n))-1
        if trial == 4: mod = (1<<(32*n-1))+1
        if trial == 5: mod = 1
        if trial == 6: mod = 3
        a = rng.randrange(mod)
        if trial == 0: a = mod-1
        if trial == 1: a = 0
        if trial == 2: a = 1
        expected = a*a*pow(1<<(32*n),-1,mod)%mod
        assert square(a,mod,n) == expected,(n,trial)
        count += 1
print("PASS: symmetric square + MMI REDC trace",count,"32..4096-bit BigInt cases")

source = (ROOT / "crypto/bn/bn-ee-square.c").read_text()
for fragment in (
    "size_t first = k < num ? 0 : k + 1 - num;",
    "i <= k / 2", "product = (uint64_t)a[i] * a[j];",
    "high += (uint32_t)(low < previous);", "if (i != j)",
    "low = (low >> 32) | ((uint64_t)high << 32);",
    "ossl_ee_bn_muladd_row_mmi(t + i, mod, q, num)",
    "j < 2 * num + 2", "t[2 * num] == 0",
    "square_wipe(t, (2 * num + 2) * sizeof(t[0]));",
    "square_wipe(diff, num * sizeof(diff[0]));"):
    assert fragment in source,fragment
rsa = (ROOT / "crypto/rsa/rsa-ee-mmi.c").read_text()
assert "ossl_ee_bn_mont_sqr32(next, current, key->mod," in rsa
assert "#ifdef EE_MMI_BN_PUBLIC_SQUARE" in rsa
regression = (ROOT / "test/ee_mmi/bn_mont_test.c").read_text()
assert "ref_mont32(expected, a, a, n, n0, num)" in regression
assert "ossl_ee_bn_mont_sqr32(scratch, scratch, n, n0, num)" in regression
print("NOTE: Python math/row model only; C compilation and target timing are user-run")
