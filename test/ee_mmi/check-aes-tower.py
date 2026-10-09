#!/usr/bin/env python3
"""Independent GF(16) tower-field AES S-box oracle; no PS2 required."""
from pathlib import Path
import random
import re

ROOT = Path(__file__).resolve().parents[2]
SRC = (ROOT / "crypto/aes/aes-ee-mmi.c").read_text()
INPUT = (0xA1,0x04,0xFC,0x18,0x70,0xD2,0xAC,0xA0)
OUTPUT = (0x45,0x3F,0x69,0x25,0x3B,0xEE,0xD0,0x06)
BASIS = (0x01,0x5C,0xE0,0x50,0xA2,0x02,0xB8,0xDB)
M = 0x01010101

def verify_matrix(label, name, masks):
    body = SRC.split("static uint32_t "+name+"(uint32_t x)",1)[1]
    body = body.split("return ",1)[0]
    for i, mask in enumerate(masks):
        match = re.search(r"uint32_t v"+str(i)+r"\\s*=\\s*([^;]+);",body)
        assert match, (label,i)
        terms = re.findall(r"p(\\d+)",match.group(1))
        reconstructed = sum(1 << int(j) for j in terms)
        assert reconstructed == mask, (label,i,mask,reconstructed)

def gf16mul(a,b):
    z=0
    for i in range(4):
        z ^= a * ((b>>i)&1)
        a=(a<<1) ^ (0x13 if (a&8) else 0)
    return z&15

def gf16pow(a,n):
    r=1
    while n:
        if n&1:r=gf16mul(r,a)
        a=gf16mul(a,a)
        n>>=1
    return r

def gf256mul(a,b):
    z=0
    for _ in range(8):
        if b&1:z ^= a
        a <<= 1
        if a&256:a ^= 0x11b
        b >>= 1
    return z

def gf256pow(a,n):
    z=1
    while n:
        if n&1:z=gf256mul(z,a)
        a=gf256mul(a,a)
        n>>=1
    return z

def affine(x):
    y=x
    for k in range(1,5):
        y ^= ((x<<k)|(x>>(8-k)))&255
    return y ^ 0x63

def linear(x,masks):
    return sum(((x&mask).bit_count()&1)<<i for i,mask in enumerate(masks))

def tower(x):
    t=linear(x,INPUT)
    a,b=t&15,t>>4
    n=gf16mul(a,a)^gf16mul(a,b)^gf16mul(8,gf16mul(b,b))
    inv=gf16pow(n,14)
    out=gf16mul(a^b,inv)|(gf16mul(b,inv)<<4)
    return linear(out,OUTPUT)^0x63

def packed_transform(x,masks):
    planes=[(x>>i)&M for i in range(8)]
    z=0
    for i,mask in enumerate(masks):
        v=0
        for j in range(8):
            if mask&(1<<j):v ^= planes[j]
        z ^= v<<i
    return z

def square16(x):
    p=[(x>>i)&M for i in range(4)]
    return p[0]^(p[1]<<2)^p[2]^(p[2]<<1)^(p[3]<<2)^(p[3]<<3)

def lambda16(x):
    p=[(x>>i)&M for i in range(4)]
    return (p[0]<<3)^p[1]^(p[1]<<1)^(p[2]<<1)^(p[2]<<2)^(p[3]<<2)^(p[3]<<3)

def mul16(x,y):
    z=0
    for i in range(4):
        z ^= x & (((y>>i)&M)*255)
        top=(x>>3)&M
        x=((x<<1)&0x0e0e0e0e)^top^(top<<1)
    return z

def packed_sbox(x):
    n=packed_transform(x,INPUT)
    a,b=n&0x0f0f0f0f,(n>>4)&0x0f0f0f0f
    norm=square16(a)^mul16(a,b)^lambda16(square16(b))
    n2=square16(norm); n3=mul16(n2,norm)
    inv=mul16(square16(square16(n3)),n2)
    y=mul16(a^b,inv)^(mul16(b,inv)<<4)
    return packed_transform(y,OUTPUT)^0x63636363

assert "EE_MMI_AES_TOWER_SBOX" in SRC
assert "bit*255U" in SRC
assert "aes_wipe(&t,sizeof(t));" in SRC
assert "aes_tower_mul16" in SRC
verify_matrix("input", "aes_tower_unpack", INPUT)
verify_matrix("output", "aes_tower_affine_pack", OUTPUT)
for value in range(256):
    expected=affine(gf256pow(value,254) if value else 0)
    assert tower(value)==expected,(value,tower(value),expected)
rng=random.Random(0x5900A357)
for trial in range(10000):
    x=rng.getrandbits(32)
    expect=sum(tower((x>>(8*lane))&255)<<(8*lane) for lane in range(4))
    assert packed_sbox(x)==expect,(trial,x)
print("PASS: AES tower 256 exact S-box values and 10000 packed SWAR words")
