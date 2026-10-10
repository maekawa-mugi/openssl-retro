#!/usr/bin/env python3
"""Source-driven ShiftRows/REDC and GCM wrapper models; no compilation."""
from pathlib import Path
import hashlib
import random
import re
import runpy

ROOT = Path(__file__).resolve().parents[2]
rng = random.Random(0x5900a6c)
MASK = (1 << 32)-1
aes = (ROOT/'crypto/aes/aes-ee-mmi.c').read_text(encoding='utf-8')
fixed = aes.split('#ifdef EE_MMI_AES_SHIFTROWS_FIXED',1)[1].split('#else',1)[0]
expressions = re.findall(r'state\[(\d)\]\[lane\] = (.*?);',fixed,re.S)
assert len(expressions) == 4
for trial in range(1024):
    words = [rng.getrandbits(32) for _ in range(4)]
    if trial == 0: words = [0]*4
    if trial == 1: words = [MASK]*4
    if trial == 2: words = [int.from_bytes(bytes(range(i,i+4)),'little') for i in range(0,16,4)]
    expected = [sum(((words[(col+row)%4]>>(8*row))&255)<<(8*row)
                    for row in range(4)) for col in range(4)]
    result = [0]*4
    for col,expr in expressions:
        expr = re.sub(r'(0x[0-9a-f]+)U',r'\1',expr)
        result[int(col)] = eval(' '.join(expr.split()),{'__builtins__':{}},dict(zip('abcd',words)))
    assert result == expected,trial
print('PASS: actual fixed ShiftRows expressions, 1024 distinct column/byte cases')

model = runpy.run_path(str(ROOT/'test/ps2/check-experiments.py'))
row = model['execute_row']
p256 = (ROOT/'crypto/ec/p256-ee-mmi.c').read_text(encoding='utf-8')
unroll = p256.split('#ifdef EE_MMI_P256_REDC_UNROLL',1)[1].split('#else',1)[0]
steps = re.findall(r'EE_P256_REDC_WORD\((\d), (qff|q|0U)\);',unroll)
assert [int(k) for k,_ in steps] == list(range(1,8))
for part in ('z = (uint64_t)t[index] + (product) + carry;',
             't[(index)-1] = (uint32_t)z;', 'carry = (uint32_t)(z >> 32);'):
    assert part in unroll
P = (1<<256)-(1<<224)+(1<<192)+(1<<96)-1
for trial in range(256):
    a,b = rng.randrange(P),rng.randrange(P)
    if trial == 0: a = b = P-1
    if trial == 1: a = b = 0
    if trial == 2: a = b = 1
    if trial == 3: a = b = 1<<255
    al = [(a>>(32*j))&MASK for j in range(8)]
    bl = [(b>>(32*j))&MASK for j in range(8)]
    t = [0]*10
    for i in range(8):
        words,carry = row(al,t[:8],bl[i])
        t[:8] = words
        z = t[8]+(carry&MASK)
        t[8] = z&MASK
        t[9] += z>>32
        q = t[0]
        carry = q
        product = {'qff':(q<<32)-q,'q':q,'0U':0}
        for index,kind in steps:
            j = int(index)
            z = t[j]+product[kind]+carry
            assert z < 1<<64
            t[j-1],carry = z&MASK,z>>32
        z = t[8]+carry
        t[7],t[8],t[9] = z&MASK,t[9]+(z>>32),0
    value = sum(w<<(32*j) for j,w in enumerate(t[:9]))
    result = value-P if value>=P else value
    assert result == a*b*pow(1<<256,-1,P)%P,trial
print('PASS: P256 source REDC schedule + MMI row trace, 256 independent BigInt cases')

gcm_model = runpy.run_path(str(ROOT/'test/ee_mmi/check-aes-gcm.py'))
multiply = gcm_model['multiply']
gcm = (ROOT/'crypto/modes/aes-gcm-ee-mmi.c').read_text(encoding='utf-8')
assert 'auth[lane] = out[lane] + offset;' in gcm
assert 'input_word ^= stream_word;' in gcm
assert 'gcm_wipe(auth' not in gcm
assert gcm.index('if (diff != 0)') < gcm.index('ok = gcm_ctr4(ctx, out, in, len, iv, state, 0 GCM_WIN_ROOT)')

def stream(iv, counter):
    # Deliberately not AES: isolate the changed CTR output/GHASH wrapper.
    return hashlib.sha256(iv+counter.to_bytes(4,'big')).digest()[:16]

count = 0
for length in (0,1,15,16,17,31,32,33,63,64,65,255,256,257,1024):
    for trial in range(8):
        data = [rng.randbytes(length) for _ in range(4)]
        ivs = [rng.randbytes(12) for _ in range(4)]
        hs = [rng.getrandbits(128) for _ in range(4)]
        expected = [bytes(x^stream(ivs[lane],2+j//16)[j%16] for j,x in enumerate(data[lane]))
                    for lane in range(4)]
        expected_hash = []
        for lane in range(4):
            y = 0
            for start in range(0,length,16):
                block = expected[lane][start:start+16].ljust(16,b'\0')
                y = multiply(y^int.from_bytes(block,'big'),hs[lane])
            expected_hash.append(y)
        offset = trial%4
        for alias in (False,True):
            outputs = [bytearray(b'\xa5'*(length+16)) for _ in range(4)]
            inputs = [bytearray(b'\x3c'*offset+d+b'\x3c'*16) for d in data]
            if alias:
                for lane in range(4): outputs[lane][offset:offset+length] = data[lane]
                inputs = outputs
            before = [bytes(v) for v in outputs]
            ys = [0]*4
            # Replay the full-block word path and original partial path.
            for start in range(0,length,16):
                n = min(16,length-start)
                for lane in range(4):
                    key_stream = stream(ivs[lane],2+start//16)
                    if n == 16:
                        for j in range(0,16,4):
                            pos = offset+start+j
                            word = int.from_bytes(inputs[lane][pos:pos+4],'little')
                            word ^= int.from_bytes(key_stream[j:j+4],'little')
                            outputs[lane][pos:pos+4] = word.to_bytes(4,'little')
                        auth = bytes(outputs[lane][offset+start:offset+start+16])
                    else:
                        auth = bytearray(16)
                        for j in range(n):
                            pos = offset+start+j
                            value = inputs[lane][pos]^key_stream[j]
                            outputs[lane][pos] = auth[j] = value
                    ys[lane] = multiply(ys[lane]^int.from_bytes(auth,'big'),hs[lane])
            for lane in range(4):
                assert outputs[lane][offset:offset+length] == expected[lane]
                assert outputs[lane][:offset] == before[lane][:offset]
                assert outputs[lane][offset+length:] == before[lane][offset+length:]
            assert ys == expected_hash
            count += 1
print('PASS: GCM full/partial output and GHASH wrapper',count,'unaligned/aliased four-lane cases')
print('NOTE: models only; compiled AES-128/192/256, GCM tamper/open, P256 vectors and timing are user-run')
