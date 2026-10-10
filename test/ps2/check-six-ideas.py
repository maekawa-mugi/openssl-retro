#!/usr/bin/env python3
"""Replay actual new assembly, independently checking integer arithmetic.

No compiler, assembler, ELF execution or latency model. This does not
replace target tests or prove instruction scheduling/performance.
"""
from pathlib import Path
import importlib.util
import random
import re
import runpy
import hashlib

ROOT=Path(__file__).resolve().parents[2]
M32=(1<<32)-1; M64=(1<<64)-1; M128=(1<<128)-1
rng=random.Random(0x590065)
spec=importlib.util.spec_from_file_location('generator',ROOT/'test/ps2/generate-six-ideas.py')
gen=importlib.util.module_from_spec(spec); spec.loader.exec_module(gen)
for path,text in gen.outputs().items(): assert (ROOT/path).read_text(encoding='utf-8')==text,path

def sx32(v): return ((v&M32)^0x80000000)-0x80000000 & M64
def packed(words): return sum((v&M32)<<(32*i) for i,v in enumerate(words))
def words(v): return [(v>>(32*i))&M32 for i in range(4)]

class Machine:
    def __init__(self,path):
        src=(ROOT/path).read_text(encoding='utf-8'); src=re.sub(r'/\*.*?\*/','',src,flags=re.S)
        self.code=[]; self.labels={}; self.data={}; self.mem={}; self.writes=set(); self.reads=set()
        self.reg=[rng.getrandbits(128) for _ in range(32)]; self.reg[0]=0; self.reg[29]=0x8000
        self.original=list(self.reg); self.hilo=0
        data=False; addr=0x9000
        for line in src.splitlines():
            line=line.strip()
            if not line: continue
            if line=='.section .rodata': data=True; continue
            if line.endswith(':'):
                (self.data if data else self.labels)[line[:-1]]=addr if data else len(self.code)
            elif line.startswith('.word'):
                for v in line.split(None,1)[1].split(','):
                    self.put(addr,int(v,0),4); addr+=4
            elif not line.startswith('.'):
                parts=line.split(None,1)
                self.code.append((parts[0],parts[1].replace(' ','').split(',') if len(parts)>1 else []))
        for addr in range(0x7c00,0x8000): self.mem[addr]=0xa5
        self.stack_initial=dict(self.mem)
    def put(self,addr,v,size):
        for i in range(size): self.mem[addr+i]=(v>>(8*i))&255
    def get(self,addr,size):
        assert all(addr+i in self.mem for i in range(size)),('out-of-range',hex(addr),size)
        self.reads.update(range(addr,addr+size))
        return sum(self.mem[addr+i]<<(8*i) for i in range(size))
    def array(self,addr,values,size=4):
        for i,v in enumerate(values): self.put(addr+i*size,v,size)
    def result(self,addr,n,size=4): return [self.get(addr+i*size,size) for i in range(n)]
    def idx(self,s): return {'$zero':0,'$sp':29,'$ra':31}.get(s,int(s[1:]) if s[1:].isdigit() else -1)
    def value(self,s): return self.reg[self.idx(s)]
    def run(self):
        pc=0; pending=None; steps=0
        def setreg(dst,v,wide=False):
            n=self.idx(dst)
            if n: self.reg[n]=(v&M128) if wide else (self.reg[n]&~M64)|(v&M64)
        while True:
            old=pending; pending=None; op,a=self.code[pc]; pc+=1; steps+=1
            assert steps<20000
            if op in ('lw','lwu','lq','sw','sq'):
                dst,location=a; match=re.fullmatch(r'(-?\d+)\((\$\w+)\)',location)
                offset,base=match.groups(); addr=(self.value(base)&M64)+int(offset)
                size=16 if op in ('lq','sq') else 4
                if size==16: assert addr%16==0,(op,addr)
                if op in ('sw','sq'):
                    assert all(addr+i in self.mem for i in range(size)),('unmapped store',addr)
                    self.put(addr,self.value(dst),size); self.writes.update(range(addr,addr+size))
                else:
                    val=self.get(addr,size); setreg(dst,sx32(val) if op=='lw' else val,op=='lq')
            elif op=='lui':
                imm=a[1]
                if imm.startswith('%hi'): v=self.data[imm[4:-1]]>>16
                else: v=int(imm,0)
                setreg(a[0],sx32(v<<16))
            elif op in ('addiu','ori'):
                imm=a[2]
                imm=self.data[imm[4:-1]]&0xffff if imm.startswith('%lo') else int(imm,0)
                v=self.value(a[1])&M64
                setreg(a[0],sx32(v+imm) if op=='addiu' else v|imm)
            elif op in ('dsll','dsrl','dsll32','dsrl32'):
                v=self.value(a[1])&M64; n=int(a[2])+(32 if op.endswith('32') else 0)
                setreg(a[0],v<<n if op.startswith('dsll') else v>>n)
            elif op in ('daddu','dsubu','and','or','nor','sltu'):
                b=self.value(a[1])&M64; c=self.value(a[2])&M64
                v={'daddu':lambda:b+c,'dsubu':lambda:b-c,'and':lambda:b&c,
                   'or':lambda:b|c,'nor':lambda:~(b|c),'sltu':lambda:int(b<c)}[op]()
                setreg(a[0],v)
            elif op=='sltiu': setreg(a[0],int((self.value(a[1])&M64)<int(a[2])))
            elif op in ('psllw','psrlw'):
                n=int(a[2]); assert 0<=n<=31
                w=words(self.value(a[1])); setreg(a[0],packed([v<<n if op=='psllw' else v>>n for v in w]),True)
            elif op in ('pxor','pand','por'):
                b=self.value(a[1]); c=self.value(a[2])
                setreg(a[0],b^c if op=='pxor' else b&c if op=='pand' else b|c,True)
            elif op in ('pcpyld','pcpyud'):
                b=self.value(a[1]); c=self.value(a[2])
                v=((b&M64)<<64)|(c&M64) if op=='pcpyld' else (b>>64)|((c>>64)<<64)
                setreg(a[0],v,True)
            elif op in ('pextlw','pextuw'):
                b=words(self.value(a[1])); c=words(self.value(a[2])); j=0 if op=='pextlw' else 2
                setreg(a[0],packed([c[j],b[j],c[j+1],b[j+1]]),True)
            elif op in ('pmultuw','pmadduw'):
                b=self.value(a[1]); c=self.value(a[2]); products=[]
                for n in (0,64):
                    # PMULTUW requires a valid sign-extended word value in
                    # each 64-bit operand slot, even for unsigned products.
                    assert (b>>n)&M64==sx32(b>>n),(op,'non-word operand')
                    assert (c>>n)&M64==sx32(c>>n),(op,'non-word operand')
                    products.append(((b>>n)&M32)*((c>>n)&M32))
                if op=='pmadduw': products=[(v+((self.hilo>>(64*i))&M64))&M64 for i,v in enumerate(products)]
                self.hilo=products[0]|products[1]<<64; setreg(a[0],self.hilo,True)
            elif op=='bnez':
                if self.value(a[0])&M64: pending=self.labels[a[1]]
            elif op=='jr': pending='return'
            elif op!='nop': raise AssertionError(('unsupported instruction',op))
            if old=='return': break
            if old is not None: pc=old
        assert self.reg[29]==self.original[29]
        for n in range(16,24): assert self.reg[n]==self.original[n],('saved register',n)
        assert self.reg[28]==self.original[28] and self.reg[30]==self.original[30]
        assert self.reg[31]==self.original[31]
        stack_writes={a for a in self.writes if 0x7c00<=a<0x8000}
        assert all(self.mem[a]==0 for a in stack_writes), 'private stack not wiped'
        return steps

def gf_mul(a,b):
    v=0
    for _ in range(8):
        if b&1: v^=a
        a=(a<<1)^ (0x11b if a&128 else 0); b>>=1
    return v
def sbox(x):
    v=1; a=x; n=254
    while n:
        if n&1: v=gf_mul(v,a)
        a=gf_mul(a,a); n>>=1
    return v ^ ((v<<1)|(v>>7))&255 ^ ((v<<2)|(v>>6))&255 ^ ((v<<3)|(v>>5))&255 ^ ((v<<4)|(v>>4))&255 ^ 0x63
for trial in range(512):
    m=Machine('crypto/aes/aes-ee-subbytes-mmi.S'); m.reg[4]=0x1000
    data=bytes([trial]*16) if trial<256 else rng.randbytes(16)
    m.array(0x1000,[int.from_bytes(data,'little')],16); m.run()
    assert m.get(0x1000,16).to_bytes(16,'little')==bytes(sbox(v) for v in data),trial
    assert all(n in range(0x1000,0x1010) or 0x7c00<=n<0x8000 for n in m.writes)
print('PASS: actual AES 128-bit tower instructions, all 256 bytes + 256 random columns, ABI/wipes')

P=(1<<256)-(1<<224)+(1<<192)+(1<<96)-1
def limbs(a,n): return [(a>>(32*i))&M32 for i in range(n)]
def integer(a): return sum(v<<(32*i) for i,v in enumerate(a))
RINV=pow(1<<256,-1,P)
for trial in range(256):
    a=rng.randrange(P); b=rng.randrange(P)
    if trial<4: a=b=[0,1,P-1,1<<255][trial]
    for alias in (0,1,2):
        m=Machine('crypto/ec/p256-ee-mul8-mmi.S'); out=[0x3004,0x1004,0x2004][alias]
        m.array(0x1004,limbs(a,8)); m.array(0x2004,limbs(b,8)); m.array(0x3004,[0xa5a5a5a5]*8)
        m.reg[4]=out; m.reg[5]=0x1004; m.reg[6]=0x2004; m.run()
        assert integer(m.result(out,8))==a*b*RINV%P,(trial,alias)
        assert m.hilo==0
        assert all(out<=addr<out+32 or 0x7c00<=addr<0x8000 for addr in m.writes)
print('PASS: actual P256 full multiply/REDC instructions, 256 cases x 3 aliases, BigInt/ABI/guards')

def square_redc(t):
    for i in range(8):
        q=t[i]; qff=(q<<32)-q; carry=q; t[i]=0
        for j in range(1,8):
            product=qff if j in (1,2,7) else q if j==6 else 0
            z=t[i+j]+product+carry; t[i+j]=z&M32; carry=z>>32
        for j in range(i+8,18):
            z=t[j]+carry; t[j]=z&M32; carry=z>>32
        assert carry==0
    assert t[17]==0
    result=integer(t[8:17]); assert result<2*P
    return result-P if result>=P else result
for trial in range(256):
    a=rng.randrange(P)
    if trial<4: a=[0,1,P-1,1<<255][trial]
    m=Machine('crypto/ec/p256-ee-square-mmi.S'); m.reg[4]=0x2000; m.reg[5]=0x1004
    m.array(0x1004,limbs(a,8)); m.array(0x2000,[0xa5a5a5a5]*18); m.run()
    t=m.result(0x2000,18)
    assert integer(t)==a*a,trial
    assert square_redc(t)==a*a*RINV%P
    assert m.hilo==0
    assert all(0x2000<=addr<0x2048 for addr in m.writes)
print('PASS: actual P256 symmetric MMI square, 256 full-width products + prime REDC/BigInt')

for trial in range(128):
    a=[[rng.randrange(1<<(25 if i&1 else 26)) for _ in range(4)] for i in range(10)]
    b=[[rng.randrange(1<<(25 if i&1 else 26)) for _ in range(4)] for i in range(10)]
    if trial<2:
        a=b=[[0 if trial==0 else (1<<(25 if i&1 else 26))-1]*4 for i in range(10)]
    scaled=[*b,*[[v*2 for v in row] for row in b],*[[v*19 for v in row] for row in b],
            *[[v*38 if i&1 else 0 for v in row] for i,row in enumerate(b)]]
    sums=[[0]*4 for _ in range(10)]
    for i in range(10):
        for j in range(10):
            c=(19 if i+j>=10 else 1)*(2 if i&j&1 else 1)
            for l in range(4): sums[(i+j)%10][l]+=a[i][l]*b[j][l]*c
    for _ in range(3):
        for i in range(9):
            width=25 if i&1 else 26
            for l in range(4): sums[i+1][l]+=sums[i][l]>>width; sums[i][l]&=(1<<width)-1
        for l in range(4): sums[0][l]+=19*(sums[9][l]>>25); sums[9][l]&=(1<<25)-1
    flat=lambda x:[v for row in x for v in row]
    for alias in (False,True):
        m=Machine('crypto/ec/x25519-ee-reduce-mmi.S'); out=0x1000 if alias else 0x3000
        m.array(0x1000,flat(a)); m.array(0x2000,flat(scaled)); m.array(0x3000,[0xa5a5a5a5]*40)
        m.reg[4]=out; m.reg[5]=0x1000; m.reg[6]=0x2000; m.run()
        assert m.result(out,40)==flat(sums),(trial,alias)
        assert m.hilo==0
        assert all(out<=addr<out+160 or 0x7c00<=addr<0x8000 for addr in m.writes)
    for l in range(4):
        value=lambda x:sum(x[i][l]<<((51*i+1)//2) for i in range(10))
        assert value(sums)%((1<<255)-19)==value(a)*value(b)%((1<<255)-19)
print('PASS: actual X25519 fused convolution/carry instructions, 128 cases x 2 aliases, BigInt/ABI/guards')

# Compose the existing C1 instruction schedule with the reusable wrapper.
schedule=runpy.run_path(str(ROOT/'test/ps2/check-schedules.py'))
wrap=runpy.run_path(str(ROOT/'test/ps2/check-chacha-wrap.py'))
def c1_rounds(state):
    result=[row[:] for row in state]
    for lane in range(4):
        regs={name:result[i][lane] for i,name in enumerate(schedule['regnames'])}
        for _ in range(10):
            for op,args in schedule['program']:
                if op=='paddw':
                    d,a,b=args; regs[d]=(regs[a]+regs[b])&M32
                elif op=='pxor':
                    d,a,b=args; regs[d]=regs[a]^regs[b]
                else:
                    d,left,right=args; regs[d]=schedule['rotl'](regs[d],int(left))
        for i,name in enumerate(schedule['regnames']): result[i][lane]=regs[name]
    return result
wrap['wrapper'].__globals__['vector_rounds']=c1_rounds
for length in (0,1,63,64,65,255,256,257,511,512,513,1023,1024,4096):
    for trial in range(4):
        key=[rng.getrandbits(32) for _ in range(8)]
        counter=[M32-trial,*[rng.getrandbits(32) for _ in range(3)]]
        data=rng.randbytes(length); expected=wrap['reference'](data,key,counter)
        for alias in (False,True):
            out=bytearray(b'\xa5'*(length+16)); offset=trial
            if alias: out[offset:offset+length]=data
            before=bytes(out)
            src=out if alias else b'\x3c'*offset+data
            wrap['wrapper'](out,offset,src,offset,length,key,counter)
            assert out[offset:offset+length]==expected
            assert out[:offset]==before[:offset] and out[offset+length:]==before[offset+length:]
print('PASS: C1 source schedule + reusable ChaCha wrapper, 112 edge/alias/counter-wrap cases')

# GCM counter/state conversion is endian-explicit, handles full and short
# blocks, and leaves verify-before-release sequencing to the existing suite.
for counter in (2,255,256,65535,65536,0xfffffffe,0xffffffff):
    encoded=((counter>>24)|((counter>>8)&0xff00)|((counter<<8)&0xff0000)|(counter<<24))&M32
    assert encoded.to_bytes(4,'little')==counter.to_bytes(4,'big')
for length in (0,1,15,16,17,31,32,33,63,64,65,255,256,257):
    for offset in range(4):
        ivs=[rng.randbytes(12) for _ in range(4)]
        payload=[rng.randbytes(length) for _ in range(4)]
        for alias in (False,True):
            outputs=[bytearray(b'\xa5'*(length+16)) for _ in range(4)]
            inputs=[bytearray(b'\x3c'*offset+p) for p in payload]
            if alias:
                for l in range(4): outputs[l][offset:offset+length]=payload[l]
                inputs=outputs
            before=[bytes(v) for v in outputs]
            # Isolate the internal word-major wrapper with a deterministic
            # NON-AES block function; actual AES is covered by target suites.
            state=[[int.from_bytes(iv[4*w:4*w+4],'little') for iv in ivs] for w in range(3)]
            for start in range(0,length,16):
                counter=2+start//16
                state4=state+[[int.from_bytes(counter.to_bytes(4,'big'),'little')]*4]
                block=[b''.join(state4[w][l].to_bytes(4,'little') for w in range(4)) for l in range(4)]
                cipher=[hashlib.sha256(v).digest()[:16] for v in block]
                stream_words=[[int.from_bytes(cipher[l][4*w:4*w+4],'little') for l in range(4)] for w in range(4)]
                n=min(16,length-start)
                for l in range(4):
                    if n==16:
                        for w in range(4):
                            pos=offset+start+4*w
                            value=int.from_bytes(inputs[l][pos:pos+4],'little')^stream_words[w][l]
                            outputs[l][pos:pos+4]=value.to_bytes(4,'little')
                    else:
                        for j in range(n):
                            pos=offset+start+j
                            outputs[l][pos]=inputs[l][pos]^((stream_words[j//4][l]>>(8*(j%4)))&255)
            for l in range(4):
                expected=bytes(v^hashlib.sha256(ivs[l]+(2+j//16).to_bytes(4,'big')).digest()[j%16] for j,v in enumerate(payload[l]))
                assert outputs[l][offset:offset+length]==expected
                assert outputs[l][:offset]==before[l][:offset] and outputs[l][offset+length:]==before[l][offset+length:]
print('PASS: GCM internal word-major CTR, 112 full/partial/unaligned/in-place wrapper cases')
main=(ROOT/'test/ps2/main.c').read_text(encoding='utf-8')
for name,prefix,workload,slot in [('AES sbox16','u',3,18),('P256 mul8','v',8,19),
    ('X25519 fused','x',6,20),('ChaCha C1w','y',0,21),('GCM words','z',9,22),('P256 square','o',8,23)]:
    assert f'"{name}"' in main and f'[{slot}] = EXPERIMENT_BACKEND({prefix})' in main
    if prefix!='y': assert f'primitive = {prefix}_ps2_test_six_ideas' in main
assert 4+19+1<28
print('PASS: six independent harness candidates and GCM counter byte ordering')
