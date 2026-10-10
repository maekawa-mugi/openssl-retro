#!/usr/bin/env python3
"""Model the reusable-state/word-XOR wrapper, without compiling C or ASM."""
from pathlib import Path
import random
import re

ROOT = Path(__file__).resolve().parents[2]
MASK = (1 << 32) - 1
CONSTANTS = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]
rng = random.Random(0x5900c4)
QUADS = [(0,4,8,12),(1,5,9,13),(2,6,10,14),(3,7,11,15),
         (0,5,10,15),(1,6,11,12),(2,7,8,13),(3,4,9,14)]

def rol(x, n):
    return ((x << n) | (x >> (32-n))) & MASK

def block(key, counter):
    initial = CONSTANTS + key + counter
    x = initial[:]
    for _ in range(10):
        for a,b,c,d in QUADS:
            x[a] = (x[a]+x[b]) & MASK
            x[d] = rol(x[d]^x[a],16)
            x[c] = (x[c]+x[d]) & MASK
            x[b] = rol(x[b]^x[c],12)
            x[a] = (x[a]+x[b]) & MASK
            x[d] = rol(x[d]^x[a],8)
            x[c] = (x[c]+x[d]) & MASK
            x[b] = rol(x[b]^x[c],7)
    return b''.join(((v+w)&MASK).to_bytes(4,'little') for v,w in zip(x,initial))

def reference(data, key, counter):
    result = bytearray()
    counter = counter[:]
    for offset in range(0,len(data),64):
        stream = block(key,counter)
        result.extend(a^b for a,b in zip(data[offset:offset+64],stream))
        counter[0] = (counter[0]+1)&MASK
    return bytes(result)

def vector_rounds(state):
    # Word-major operations, including four independent additions/rotates.
    state = [row[:] for row in state]
    for _ in range(10):
        for a,b,c,d in QUADS:
            for dest,src,rotate,xor_src in (
                (a,b,16,d),(c,d,12,b),(a,b,8,d),(c,d,7,b)):
                state[dest] = [(x+y)&MASK for x,y in zip(state[dest],state[src])]
                state[xor_src] = [rol(x^y,rotate) for x,y in zip(state[xor_src],state[dest])]
    return state

def wrapper(output, out_offset, input_buf, in_offset, length, key, counter):
    if length == 0:
        return
    if length < 256:
        output[out_offset:out_offset+length] = reference(
            bytes(input_buf[in_offset:in_offset+length]),key,counter)
        return
    next_counter = counter[:]
    original = [[v]*4 for v in CONSTANTS+key+next_counter]
    while length >= 256:
        original[12] = [(next_counter[0]+lane)&MASK for lane in range(4)]
        state = vector_rounds(original)
        for lane in range(4):
            for word in range(16):
                offset = 64*lane+4*word
                input_word = int.from_bytes(input_buf[in_offset+offset:in_offset+offset+4],'little')
                result = input_word ^ ((state[word][lane]+original[word][lane])&MASK)
                output[out_offset+offset:out_offset+offset+4] = result.to_bytes(4,'little')
        next_counter[0] = (next_counter[0]+4)&MASK
        out_offset += 256
        in_offset += 256
        length -= 256
    if length:
        output[out_offset:out_offset+length] = reference(
            bytes(input_buf[in_offset:in_offset+length]),key,next_counter)

# Use the repository's RFC vector as an independent known-answer oracle.
test = (ROOT/'test/ee_mmi/chacha20_test.c').read_text()
known = test.split('static const unsigned char expected[64] = {',1)[1].split('};',1)[0]
expected = bytes(int(x,16) for x in re.findall(r'0x([0-9a-f]{2})',known))
key = [int.from_bytes(bytes(range(i,i+4)),'little') for i in range(0,32,4)]
counter = [1,0x09000000,0x4a000000,0]
out = bytearray(256)
wrapper(out,0,bytes(256),0,256,key,counter)
assert out[:64] == expected

count = 0
for length in (0,1,63,64,65,255,256,257,511,512,513,1023,1024,4095,4096,4097,16384):
    for trial in range(12):
        key = [rng.getrandbits(32) for _ in range(8)]
        counter = [rng.getrandbits(32) for _ in range(4)]
        counter[0] = (MASK-trial) if trial<6 else counter[0]
        data = rng.randbytes(length)
        expected = reference(data,key,counter)
        input_offset,out_offset = trial%4,(trial//4)%4
        input_buf = bytearray(b'\x3c'*16+data+b'\x3c'*16)
        # Offset all four ways without changing guards or payload.
        input_buf[input_offset:input_offset+length] = data
        input_before = input_buf[:]
        key_before,counter_before = key[:],counter[:]
        for inplace in (False,True):
            output = bytearray(b'\xa5'*(length+32))
            if inplace:
                output[out_offset:out_offset+length] = data
            before = output[:]
            wrapper(output,out_offset,output if inplace else input_buf,
                    out_offset if inplace else input_offset,length,key,counter)
            assert output[out_offset:out_offset+length] == expected,(length,trial,inplace)
            assert output[:out_offset] == before[:out_offset]
            assert output[out_offset+length:] == before[out_offset+length:]
            count += 1
        assert input_buf == input_before and key == key_before and counter == counter_before
print('PASS: ChaCha wrapper model',count,'RFC/edge/unaligned/in-place/counter-wrap cases')

source = (ROOT/'crypto/chacha/chacha-ee-wrap.c').read_text()
assert source.index('for (word = 0; word < 16; ++word)') < source.index('while (len >= 256)')
for fragment in ('memcpy(state, original, sizeof(state));',
                 'original[12][lane] = (uint32_t)next[0] + (uint32_t)lane;',
                 'memcpy(&input_word, in + offset, sizeof(input_word));',
                 'memcpy(out + offset, &input_word, sizeof(input_word));',
                 'next[0] = (uint32_t)next[0] + 4U;',
                 'ChaCha20_ctr32_c(out, in, len, key, next);'):
    assert fragment in source,fragment
assert 'uint32_t *' not in source # no unaligned typed pointer casts
print('NOTE: Python model only; user-built C/ASM regression and timing still required')
