#!/usr/bin/env python3
"""Independent BigInt oracle for the fused R5900 BN addmul-row variant.

No PS2 instruction execution; target assembly must also pass the
full differential test/ee_mmi/bn_mont_test.c on real EE hardware.
"""
from pathlib import Path
import random
ROOT=Path(__file__).resolve().parents[2]
s=(ROOT/"crypto/bn/bn-ee-row-mmi.S").read_text()
c=(ROOT/"crypto/bn/bn-ee-mmi.c").read_text()
build=(ROOT/"test/ps2/build.sh").read_text()
MASK=(1<<32)-1
rng=random.Random(0x5900add1)
for t in ("pmultuw", "psraw", "pextlw", "lq", "sq", "ld",
          "lwu", "dsrl32", "daddu"):
    assert t in s,t
assert "ossl_ee_bn_muladd_row_mmi" in s
assert "EE_MMI_BN_ROW_FUSED" in c
assert "ossl_ee_bn_muladd_row_mmi(t, a, b[i], num)" in c
assert "ossl_ee_bn_muladd_row_mmi(t, mod, q, num)" in c
assert "bn-ee-row-mmi.S" in build
assert "PS2_SCHED_BN" in build
assert "-UEE_MMI_BN_ROW_FUSED" in build
# Cannot read a[j+1] if the limb count is odd.
assert "beqz    $10, .Lee_bn_row_odd" in s
assert "lw      $10, 4($a1)" in s
assert s.index("beqz    $10, .Lee_bn_row_odd") < s.index(
    "lw      $10, 4($a1)")
# Two consecutive 64-bit additions use exact unsigned products:
# carry is generated only AFTER both t[j] and prior carry are added.
assert "sq      $14, 0($sp)" in s
assert "daddu   $9, $9, $10" in s
assert "daddu   $9, $9, $8" in s

def addmul_row(t,a,b,n):
    carry=0
    for j in range(n):
        z=t[j]+a[j]*b+carry
        assert z < (1<<64)
        t[j]=z&MASK
        carry=z>>32
    return carry

def mont(a,b,mod,n):
    al=[(a>>(32*j))&MASK for j in range(n)]
    bl=[(b>>(32*j))&MASK for j in range(n)]
    nl=[(mod>>(32*j))&MASK for j in range(n)]
    t=[0]*(n+2)
    n0=(-pow(nl[0],-1,1<<32))&MASK
    for i in range(n):
        carry=addmul_row(t,al,bl[i],n)
        z=t[n]+carry
        t[n]=z&MASK
        t[n+1]+=z>>32
        q=(t[0]*n0)&MASK
        carry=addmul_row(t,nl,q,n)
        assert t[0]==0,"REDC low limb must cancel exactly"
        z=t[n]+carry
        for j in range(1,n):
            t[j-1]=t[j]
        t[n-1]=z&MASK
        t[n]=t[n+1]+(z>>32)
        t[n+1]=0
        assert t[n]<=1
    val=sum(t[j]<<(32*j) for j in range(n)) + (t[n]<<(32*n))
    if val>=mod: val-=mod
    return val

count=0
for n in (1,2,3,4,5,7,8,16,32,64,128):
    for trial in range(30 if n<=16 else 8):
        mod=rng.getrandbits(32*n-1)|(1<<(32*n-1))|1
        a=rng.randrange(mod)
        b=rng.randrange(mod)
        if trial%9==0: a=b=mod-1
        if trial%11==0: a=b=0
        if trial%13==0: a=b=1
        expected=a*b*pow(1<<(32*n),-1,mod)%mod
        assert mont(a,b,mod,n)==expected,(n,trial)
        count+=1

print("PASS: fused Montgomery whole-row model",count,
      "BigInt cases including odd limbs/bit31/full-width")
print("NOTE: real PMULTUW ABI/latency require PS2SDK and EE run")
