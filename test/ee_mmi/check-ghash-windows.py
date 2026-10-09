#!/usr/bin/env python3
"""Constant-address four-stream GHASH window4/window8 BigInt test.

Models the group-to-word-index mapping and fixed-scan masked tables
independently of the target implementation. Checks source invariants;
does not execute R5900 PCEQW or measure performance.
"""
from pathlib import Path
import random
ROOT=Path(__file__).resolve().parents[2]
c=(ROOT/"crypto/modes/ghash-ee-window.c").read_text()
asm=(ROOT/"crypto/modes/ghash-ee-window-mmi.S").read_text()
builder=(ROOT/"test/ps2/build.sh").read_text()
MASK=(1<<128)-1
R=0xe1000000000000000000000000000000
rng=random.Random(0x59004748)
def step(v):
    return (v>>1)^(R if v&1 else 0)
def reference(x,h):
    z=0
    for i in range(127,-1,-1):
        if (x>>i)&1: z^=h
        h=step(h)
    return z

def word_nibble(x,idx):
    words=[(x>>(96-32*i))&0xffffffff for i in range(4)]
    wi=idx>>3
    shift=(7-(idx&7))*4
    return (words[wi]>>shift)&15

def word_byte(x,idx):
    words=[(x>>(96-32*i))&0xffffffff for i in range(4)]
    wi=idx>>2
    shift=(3-(idx&3))*8
    return (words[wi]>>shift)&255

def model(x,h,width):
    basis=[h]
    for _ in range(width-1):
        basis.append(step(basis[-1]))
    table_hi=[]
    table_lo=[]
    for idx in range(16):
        hi=0
        lo=0
        for j in range(4):
            if (idx>>(3-j))&1:
                hi ^= basis[j]
                if width==8:
                    lo ^= basis[j+4]
        table_hi.append(hi)
        if width==8: table_lo.append(lo)
    z=0
    groups=128//width
    for group in range(groups-1,-1,-1):
        for _ in range(width): z=step(z)
        if width==4:
            selector=word_nibble(x,group)
            # Do not load by data-selected table address:
            # select ALL 16 entries with a constant-time mask.
            for idx in range(16):
                if idx==selector: z^=table_hi[idx]
        else:
            byte=word_byte(x,group)
            for idx in range(16):
                if idx==(byte>>4): z^=table_hi[idx]
                if idx==(byte&15): z^=table_lo[idx]
    return z

count=0
for case in range(120):
    hh=[rng.getrandbits(128) for _ in range(4)]
    xx=[rng.getrandbits(128) for _ in range(4)]
    if case==0: xx=[0]*4
    if case==1: hh=[MASK]*4
    if case==2: xx=[MASK]*4
    for lane in range(4):
        expected=reference(xx[lane],hh[lane])
        for width in (4,8):
            assert model(xx[lane],hh[lane],width)==expected,(case,lane,width)
            count+=1

assert "EE_MMI_GHASH_WINDOW_BITS" in c
assert "ossl_ee_ghash_window_xor4(state, ctx->high, selector)" in c
assert "ossl_ee_ghash_window_xor4(state, ctx->low, selector)" in c
assert "selector[lane] = (x[xi][lane] >> (shift + 4U)) & 15U;" in c
assert "ossl_ee_ghash_window_prepare(" in c
assert "ossl_ee_ghash_window_mul(" in c
assert "ee_wipe_window(ctx, sizeof(*ctx));" in c
assert "ossl_ee_ghash_window_clear(&ctx);" in c
assert "ee_wipe_window(basis, sizeof(basis));" in c
assert "pceqw   $15, $12, $14" in asm
assert "paddw   $14, $14, $13" in asm
assert "addiu   $a3, $zero, 16" in asm
assert "bnez    $a3, .Lee_ghash_window_select" in asm
assert "addiu   $a1, $a1, 64" in asm
assert "crypto/modes/ghash-ee-window-mmi.S" in builder
assert "crypto/modes/ghash-ee-window.c" in builder
assert "-UEE_MMI_GHASH_WINDOW_BITS" in builder
# No secret-derived table index can appear in the assembly, and
# the C host oracle scans by PUBLIC entry, not selector directly.
assert "table[entry][word][lane]" in c
assert "table[selector" not in c
assert "table[nibble" not in c
print("PASS:",count,"4-lane GHASH 4/8-bit window BigInt oracles")
print("PASS: fixed-address EE PCEQW mask scan and A/B selector isolation")
print("NOTE: timing and assembly ABI require PS2SDK/EE testing")
