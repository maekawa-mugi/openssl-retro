#!/usr/bin/env python3
"""Instruction/math oracles for Poly preload and RSA tight, no build."""
from pathlib import Path
import random
import re

ROOT = Path(__file__).resolve().parents[2]
MASK32, MASK64 = (1 << 32)-1, (1 << 64)-1
rng = random.Random(0x590013ea)
source = (ROOT / "crypto/poly1305/poly1305-ee-preload-mmi.S").read_text()

def program(text):
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    text = re.sub(r"\s*\.macro.*?\.endm", "", text, flags=re.S)
    ops = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(".") or line.endswith(":"):
            continue
        op, *rest = line.split(None, 1)
        args = rest[0].replace(" ", "").split(",") if rest else []
        if op == "EE_POLY_LOAD":
            dst, offset, base, extract = args
            ops.extend([("lq", ["$13", offset + "(" + base + ")"]),
                        (extract, [dst, "$zero", "$13"])])
        else:
            ops.append((op,args))
    return ops

def execute(h, r, code=source, alias=False):
    reduced = "ossl_ee_poly1305_mul_reduce4:" in code
    output = 0x1000 if alias else 0x3000
    save_end = 23 if reduced else 20
    stack_base = 0x8010 if reduced else 0x8040
    regs = {"$" + str(i): rng.getrandbits(128) for i in range(32)}
    for alias, number in (("$zero",0),("$v0",2),("$v1",3),("$a0",4),
                          ("$a1",5),("$a2",6),("$a3",7),("$t8",24),
                          ("$t9",25),("$sp",29),("$ra",31)):
        regs[alias] = regs["$" + str(number)]
    regs.update({"$zero":0,"$a0":output,"$a1":0x1000,"$a2":0x2000,"$sp":0x8088})
    saved = {"$"+str(i):regs["$"+str(i)] for i in range(16,save_end)}
    mem = {}
    scaled = r + [[5*w for w in row] for row in r]
    for base, rows in ((0x1000,h),(0x2000,scaled)):
        for i,row in enumerate(rows):
            mem[base+16*i] = sum(w << (32*j) for j,w in enumerate(row))
    inputs = dict(mem)
    accum = [0,0]
    for op,args in program(code):
        if op in ("lq","sq"):
            dst, address = args
            offset, base = re.fullmatch(r"(-?\d+)\((\$\w+)\)",address).groups()
            addr = (regs[base]&MASK64)+int(offset)
            assert addr % 16 == 0
            if op == "lq":
                assert addr in mem
                regs[dst] = mem[addr]
            else:
                assert (0x3000 <= addr < 0x30a0 or stack_base <= addr and addr+16 <= 0x8088)
                mem[addr] = regs[dst]
        elif op in ("pextlw","pextuw"):
            dst, zero, src = args
            assert zero == "$zero"
            base = 0 if op == "pextlw" else 64
            x = regs[src] >> base
            regs[dst] = (x&MASK32) | (((x>>32)&MASK32)<<64)
        elif op in ("pmultuw","pmadduw"):
            dst, lhs, rhs = args
            for lane in range(2):
                x = (regs[lhs]>>(64*lane))&MASK64
                y = (regs[rhs]>>(64*lane))&MASK64
                assert x < 1 << 31 and y < 1 << 31
                product = x*y
                accum[lane] = product if op == "pmultuw" else accum[lane]+product
                assert accum[lane] <= MASK64
            if dst != "$zero":
                regs[dst] = accum[0] | (accum[1]<<64)
        elif op in ("pcpyld","pcpyud"):
            dst,lhs,rhs = args
            regs[dst] = ((regs[rhs]&MASK64) | ((regs[lhs]&MASK64)<<64) if op == "pcpyld"
                         else ((regs[lhs]>>64)&MASK64) | ((regs[rhs]>>64)<<64))
        elif op == "daddu":
            dst,lhs,rhs = args
            regs[dst] = (regs[dst]&~MASK64) | ((regs[lhs]+regs[rhs])&MASK64)
        elif op in ("sw","lwu"):
            dst,address = args
            offset,base = re.fullmatch(r"(-?\d+)\((\$\w+)\)",address).groups()
            addr = (regs[base]&MASK64)+int(offset)
            assert output <= addr < output+80 and addr%4 == 0
            aligned,shift = addr&~15,(addr%16)*8
            if op == "lwu":
                regs[dst] = (regs[dst]&~MASK64) | ((mem[aligned]>>shift)&MASK32)
            else:
                mask = MASK32<<shift
                mem[aligned] = (mem.get(aligned,0)&~mask) | ((regs[dst]&MASK32)<<shift)
        elif op in ("daddiu","dsrl","dsll","dsrl32","dsll32"):
            dst,src,imm = args
            value = regs[src]&MASK64
            if op == "daddiu": value += int(imm)
            else:
                assert 0 <= int(imm) <= 31, "illegal shift immediate"
                shift = int(imm)+(32 if op.endswith("32") else 0)
                if op.startswith("dsrl"): value >>= shift
                else: value <<= shift
            regs[dst] = (regs[dst]&~MASK64) | (value&MASK64)
        elif op == "pxor":
            dst,lhs,rhs = args
            regs[dst] = regs[lhs]^regs[rhs]
        else:
            assert op in ("jr","nop"),op
    assert all(regs[reg] == value for reg,value in saved.items())
    assert regs["$sp"]&MASK64 == 0x8088
    assert all(mem[addr] == value for addr,value in inputs.items() if not (alias and addr < 0x2000))
    assert all(mem[addr] == 0 for addr in range(stack_base,stack_base+16*(save_end-16),16))
    assert accum == [0,0]
    assert all(regs[reg] == 0 for reg in ("$v0","$v1","$a3","$t8","$t9",
                                             "$8","$9","$10","$11","$12","$13","$14"))
    if reduced:
        return [[(mem[output+16*k]>>(32*lane))&MASK32 for lane in range(4)] for k in range(5)]
    return [[(mem[0x3000+32*k+16*(lane//2)]>>(64*(lane%2)))&MASK64
             for lane in range(4)] for k in range(5)]

for trial in range(256):
    h = [[rng.getrandbits(27) for _ in range(4)] for _ in range(5)]
    r = [[rng.getrandbits(26) for _ in range(4)] for _ in range(5)]
    if trial < 2:
        h = [[0 if trial==0 else (1<<27)-1]*4 for _ in range(5)]
        r = [[0 if trial==0 else (1<<26)-1]*4 for _ in range(5)]
    expected = [[sum(h[i][lane]*r[(k-i)%5][lane]*(5 if i>k else 1)
                     for i in range(5)) for lane in range(4)] for k in range(5)]
    assert execute(h,r) == expected,trial
assert source.count("    EE_POLY_LOAD ") == 28
print("PASS: Poly preload 256 instruction-trace cases, full sums, saved GPRs and cleanup")

reduce_source = (ROOT / "crypto/poly1305/poly1305-ee-reduce-mmi.S").read_text()
for trial in range(256):
    h = [[rng.getrandbits(27) for _ in range(4)] for _ in range(5)]
    r = [[rng.getrandbits(26) for _ in range(4)] for _ in range(5)]
    if trial < 2:
        h = [[0 if trial == 0 else (1<<27)-1]*4 for _ in range(5)]
        r = [[0 if trial == 0 else (1<<26)-1]*4 for _ in range(5)]
    expected = [[0]*4 for _ in range(5)]
    for lane in range(4):
        d = [sum(h[i][lane]*r[(k-i)%5][lane]*(5 if i>k else 1) for i in range(5)) for k in range(5)]
        carry = 0
        for k in range(5):
            d[k] += carry
            expected[k][lane],carry = d[k]&((1<<26)-1),d[k]>>26
        x = expected[0][lane]+carry*5
        expected[0][lane] = x&((1<<26)-1)
        expected[1][lane] += x>>26
    for alias in (False,True):
        assert execute(h,r,reduce_source,alias) == expected,(trial,alias)
print("PASS: Poly fused reduction 512 instruction traces, separate/aliased output and cleanup")

# Mirror the pointer exchange, with Montgomery multiplication independently
# defined in modular integer arithmetic. Full input/output RSA vectors are
# still run in the target's existing prepared-key regression suite.
for bits in (1024,2048,3072,4096):
    for trial in range(24):
        n = rng.getrandbits(bits) | (1<<(bits-1)) | 1
        a = rng.randrange(n)
        if trial == 0: a = 0
        if trial == 1: a = n-1
        radix = 1<<bits
        inv = pow(radix,-1,n)
        base = a*radix%n
        buffers = [base,0]
        current,next_index = 0,1
        for _ in range(16):
            buffers[next_index] = buffers[current]**2*inv%n
            current,next_index = next_index,current
        buffers[next_index] = buffers[current]*base*inv%n
        buffers[current] = buffers[next_index]*inv%n
        assert buffers[current] == pow(a,65537,n)
print("PASS: RSA alternating buffers 96 exact 1024..4096-bit exponentiation cases")
bn = (ROOT / "crypto/bn/bn-ee-mmi.c").read_text()
rsa = (ROOT / "crypto/rsa/rsa-ee-mmi.c").read_text()
assert "for (i = 0; i < num + 2; ++i)" in bn
assert "ee_mont_wipe(t, (num + 2) * sizeof(t[0]));" in bn
assert "ee_mont_wipe(diff, num * sizeof(diff[0]));" in bn
optimized = rsa.split("#ifdef EE_MMI_RSA_SWAP_POWERS",1)[1].split("    }\n    ok = 1;",1)[0].split("#else\n        for (j",1)[0]
assert "memcpy" not in optimized
assert "current = next;" in optimized and "next = swap;" in optimized
for name in ("power","temp"):
    assert f"rsa_wipe({name}, sizeof({name}));" in rsa
print("NOTE: no PS2 assembly, executable or timing run performed")

regression = (ROOT / "test/ee_mmi/poly1305_test.c").read_text()
assert "ossl_ee_poly1305_mul_reduce4(buffer.h, alias ? buffer.h : a, b)" in regression
assert "PASS: fused reduction 512 direct carry/alias/guard cases" in regression
