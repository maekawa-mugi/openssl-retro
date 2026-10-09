#!/usr/bin/env python3
"""Portable equivalence models for PS2 EE scheduled MMI variants.

Models ChaCha quarter-rounds, GHASH packed word operations, and checks
SHA/AES dependency-preserving edits. Real EE assembly timing is not
measured or certified by these models.
"""
from pathlib import Path
import random
import re

ROOT = Path(__file__).resolve().parents[2]
def read(name):
    return (ROOT / name).read_text()

rng = random.Random(0x5900cafe)
MASK = 0xffffffff
def rotl(x, n):
    return ((x << n) | (x >> (32 - n))) & MASK

base = read("crypto/chacha/chacha-ee-mmi.S")
alt = read("crypto/chacha/chacha-ee-mmi-interleave.S")
qrs = [
    re.findall(r"\$[A-Za-z0-9]+", line)
    for line in base.splitlines()
    if re.match(r"^\s*EE_QR\s+\$", line)
]
assert len(qrs) == 8, qrs
regnames = ["$v0", "$v1", "$a1", "$a2", "$a3", "$8", "$9",
            "$10", "$11", "$12", "$13", "$14", "$15", "$t8",
            "$t9", "$s0"]
assert len(regnames) == len(set(regnames))
assert sorted(set(sum(qrs[:4], []))) == sorted(regnames)
assert sorted(set(sum(qrs[4:], []))) == sorted(regnames)

roundtext = alt.split(".Lee_chacha_round:\n", 1)[1].split(
    "    addiu   $s3", 1)[0]
program = []
for line in roundtext.splitlines():
    code = line.split("/*", 1)[0].strip()
    mm = re.match(r"^(paddw|pxor|EE_ROTL)\s+(.+?)\s*$", code)
    if mm:
        op, argstring = mm.groups()
        args = [a.strip() for a in argstring.split(",")]
        program.append((op, args))
assert len(program) == 96, len(program)

def qr(v, q):
    a,b,c,d = q
    v[a]=(v[a]+v[b])&MASK
    v[d]=rotl(v[d]^v[a],16)
    v[c]=(v[c]+v[d])&MASK
    v[b]=rotl(v[b]^v[c],12)
    v[a]=(v[a]+v[b])&MASK
    v[d]=rotl(v[d]^v[a],8)
    v[c]=(v[c]+v[d])&MASK
    v[b]=rotl(v[b]^v[c],7)

for case in range(160):
    before = {name: rng.getrandbits(32) for name in regnames}
    orig = dict(before)
    scheduled = dict(before)
    for q in qrs:
        qr(orig,q)
    for op, args in program:
        if op == "paddw":
            d,a,b = args
            scheduled[d] = (scheduled[a] + scheduled[b]) & MASK
        elif op == "pxor":
            d,a,b = args
            scheduled[d] = scheduled[a] ^ scheduled[b]
        else:
            dst,left,right = args
            assert int(left)+int(right)==32
            scheduled[dst] = rotl(scheduled[dst],int(left))
    assert orig == scheduled, (case, orig, scheduled)
print("PASS: ChaCha20 160 interleaved double-round equivalence cases")

def gh_body(path):
    text=read(path)
    return text.split("    .macro EE_GHASH_WORD off\n",1)[1].split(
        "    .endm",1)[0]

def gh_ops(code):
    instructions=[]
    for line in code.splitlines():
        line=line.split("/*",1)[0].strip()
        m=re.match(r"^(psraw|psllw|psrlw|pand|pxor|por)\s+(.+)$",line)
        if m:
            instructions.append((m.group(1),
                                 [x.strip() for x in m.group(2).split(",")]))
    return instructions

opsa=gh_ops(gh_body("crypto/modes/ghash-ee-mmi.S"))
opsg=gh_ops(gh_body("crypto/modes/ghash-ee-mmi-sched.S"))
assert len(opsa)==len(opsg)
for case in range(260):
    initial={"$"+str(i):rng.getrandbits(32) for i in range(8,16)}
    initial.update({"$t8":rng.getrandbits(32),"$t9":0,
                    "$a3":0,"$v0":0,"$v1":0xe1000000})
    def run(ops):
        v=dict(initial)
        for op,arr in ops:
            if op in ("psraw","psllw","psrlw"):
                dest,src,n=arr
                n=int(n)
                if op=="psraw":
                    val=v[src]
                    signed=val-(1<<32) if val & 0x80000000 else val
                    v[dest]=(signed>>n)&MASK
                elif op=="psllw":
                    v[dest]=(v[src]<<n)&MASK
                else:
                    v[dest]=v[src]>>n
            else:
                dest,left,right=arr
                if op=="pxor":
                    v[dest]=v[left]^v[right]
                elif op=="pand":
                    v[dest]=v[left]&v[right]
                else:
                    v[dest]=v[left]|v[right]
        return v
    a,g=run(opsa),run(opsg)
    for reg in ("$8","$9","$10","$11","$12","$13",
                "$14","$15","$t8"):
        assert a[reg]==g[reg],(case,reg,a[reg],g[reg])
print("PASS: GHASH 260 randomized packed-word bit-step equivalence cases")

# Variant U4: four complete single-bit steps in every inner loop
# iteration, 8 iterations per 32-bit input word instead of 32.
u4source=read("crypto/modes/ghash-ee-mmi-unroll4.S")
assert "addiu   $a2, $zero, 8" in u4source
unrolled=u4source.split("    .macro EE_GHASH_STEP\n",1)[1].split(
    "    .endm",1)[0]
u4body=u4source.split("    .macro EE_GHASH_WORD off\n",1)[1].split(
    "    .endm",1)[0]
opsu4=gh_ops(unrolled)
assert opsu4==opsg
assert len(re.findall(r"^\s*EE_GHASH_STEP\s*$",u4body,
                      re.MULTILINE)) == 4
for case in range(180):
    v={"$"+str(i):rng.getrandbits(32) for i in range(8,16)}
    v.update({"$t8":rng.getrandbits(32),"$t9":0,
              "$a3":0,"$v0":0,"$v1":0xe1000000})
    def step(state, instructions):
        state=dict(state)
        for opcode,args in instructions:
            if opcode in ("psraw","psllw","psrlw"):
                target,source,shift=args
                shift=int(shift)
                if opcode=="psraw":
                    x=state[source]
                    sign=x-(1<<32) if x & 0x80000000 else x
                    state[target]=(sign>>shift)&MASK
                elif opcode=="psllw":
                    state[target]=(state[source]<<shift)&MASK
                else:
                    state[target]=state[source]>>shift
            else:
                target,x,y=args
                if opcode=="pxor":
                    state[target]=state[x]^state[y]
                elif opcode=="pand":
                    state[target]=state[x]&state[y]
                else:
                    state[target]=state[x]|state[y]
        return state
    original=dict(v)
    candidate=dict(v)
    for _ in range(4):
        original=step(original,opsa)
        candidate=step(candidate,opsu4)
    for reg in ("$8","$9","$10","$11","$12","$13",
                "$14","$15","$t8"):
        assert original[reg]==candidate[reg],(case,reg)
print("PASS: GHASH U4 180 x 4-bit scheduled/unrolled equivalence cases")


shabase=read("crypto/sha/sha256-ee-mmi.S")
shaalt=read("crypto/sha/sha256-ee-mmi-sched.S")
assert shaalt.index("/* Ch(E,F,G)") < shaalt.index("/* Sigma1(E)")
assert shabase.index("/* Sigma1(E)") < shabase.index("/* Ch(E,F,G)")
assert "pxor    $15, $10, $11" in shaalt
assert "pand    $15, $15, $9" in shaalt
assert "pxor    $15, $15, $11" in shaalt
assert "paddw   $13, $13, $15" in shaalt
for _ in range(1500):
    e,f,g=(rng.getrandbits(32) for _ in range(3))
    assert (g ^ (e & (f ^ g))) == (((f ^ g) & e) ^ g)
print("PASS: SHA-256 hoisted Ch boolean equivalence")

# Variant S2 reuses exactly the Ch-first round body, twice per loop.
# No architectural register mapping, IV or W/K pointer step changes.
sha2=read("crypto/sha/sha256-ee-mmi-unroll2.S")
marker="    .macro EE_SHA_STEP\n"
assert marker in sha2
macro=sha2.split(marker,1)[1].split("    .endm",1)[0]
origround=shaalt.split(".Lee_sha256_round:\n",1)[1].split(
    "    addiu   $s1, $s1, -1",1)[0]
assert macro.strip() == origround.strip()
loop=sha2.split(".Lee_sha256_round:\n",1)[1].split(
    "    /* SHA-256 compression feed-forward",1)[0]
assert loop.count("    EE_SHA_STEP") == 2
assert "addiu   $s1, $zero, 32" in sha2
assert "addiu   $s1, $s1, -1" in loop
print("PASS: SHA-256 S2 calls unchanged round body twice per iteration")


aesbase=read("crypto/aes/aes-ee-mmi.S")
aesalt=read("crypto/aes/aes-ee-mmi-keyearly.S")
assert "lq      $a2, \\off($a1)" in aesalt
assert "pxor    $13, $13, $a2" in aesalt
assert "lq      $14, \\off($a1)" not in aesalt
assert aesalt.index("lq      $a2, \\off($a1)") < aesalt.index(
    "psrlw   $9, $8, 8")
assert aesbase.index("lq      $14, \\off($a1)") > aesbase.index(
    "psrlw   $9, $8, 8")
print("PASS: AES AddRoundKey moved before independent MixColumns")

build=read("test/ps2/build.sh")
for flag in ("PS2_SCHED_CHACHA","PS2_SCHED_SHA",
             "PS2_SCHED_GHASH","PS2_SCHED_AES"):
    assert flag in build
assert "ghash-ee-mmi-unroll4.S" in build
assert "sha256-ee-mmi-unroll2.S" in build
assert 'PS2_SCHED_SHA:-0} == 2' in build
assert 'PS2_SCHED_GHASH:-0} == 2' in build
for file in ("chacha-ee-mmi-interleave.S","sha256-ee-mmi-sched.S",
             "ghash-ee-mmi-sched.S","aes-ee-mmi-keyearly.S"):
    assert file in build
runner=read("test/ps2/main.c")
for setting in ("CHACHA","SHA","GHASH","AES"):
    assert "PS2_CONFIG_"+setting in runner
    assert "PS2_CONFIG_"+setting in build
assert "PS2 SCHEDULE C=" in runner
assert "PS2_SCHED_BN" in build
assert "bn-ee-row-mmi.S" in build
assert "ghash-ee-window.c" in build
assert "ghash-ee-window-mmi.S" in build
assert "PS2_CONFIG_BN" in runner
assert "PS2_CONFIG_BN" in build
assert "ghash_window4" in read("test/ps2/build-variants.sh")
assert "ghash_window8" in read("test/ps2/build-variants.sh")
assert "bn_fused_row" in read("test/ps2/build-variants.sh")
assert "-UEE_MMI_BN_ROW_FUSED" in build
assert "-UEE_MMI_GHASH_WINDOW_BITS" in build
print("PASS: all four scheduled A kernels + BN fused/GHASH windows selectable")
