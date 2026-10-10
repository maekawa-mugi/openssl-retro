#!/usr/bin/env python3
"""Replay the register-row instruction trace and check extra-row wiring.

Python only: no assembly, ELF build, EE execution or latency simulation.
PCPYLD/PCPYUD semantics follow PCSX2's pcsx2/MMI.cpp interpreter.
The independent oracle uses arbitrary-precision whole-row arithmetic.
"""
from pathlib import Path
import random
import re

ROOT = Path(__file__).resolve().parents[2]
MASK = (1 << 32) - 1
MASK64 = (1 << 64) - 1

def read(path):
    return (ROOT / path).read_text(encoding='utf-8')

def sx(value):
    value &= MASK
    return value | (0xffffffff00000000 if value & 0x80000000 else 0)

def assemble_trace(text):
    """Parse only supported instructions; reject unmodeled changes."""
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    instructions, labels = [], {}
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.endswith(":"):
            labels[line[:-1]] = len(instructions)
        elif not line.startswith("."):
            opcode, *args = line.split(None, 1)
            instructions.append((opcode, args[0].replace(" ", "").split(",")
                                 if args else []))
    return instructions, labels

TRACE = assemble_trace(read("crypto/bn/bn-ee-row-reg-mmi.S"))

def execute_row(a, t, b, trace=TRACE):
    instructions, labels = trace
    # Distinct word-aligned, deliberately not quadword-aligned addresses.
    a_addr, t_addr = 0x1004, 0x2004
    memory = {a_addr + 4 * j: w for j, w in enumerate(a)}
    memory.update({t_addr + 4 * j: w for j, w in enumerate(t)})
    regs = {"$zero": 0, "$a0": t_addr, "$a1": a_addr,
            "$a2": sx(b), "$a3": sx(len(a)), "$ra": 0}
    # Poison unused halves to catch accidental dependence on caller state.
    for j in range(8, 16):
        regs["$" + str(j)] = (0xdeadbeef01234567 << 64) | 0xabcdef0123456789
    regs["$v0"] = 0
    original_memory = dict(memory)
    pending, pc, steps = None, 0, 0
    while True:
        old_pending, pending = pending, None
        opcode, args = instructions[pc]
        pc += 1
        steps += 1
        assert steps < 10000, "unbounded row loop"
        if opcode in ("lw", "lwu", "sw"):
            target, address = args
            match = re.fullmatch(r"(-?\d+)\((\$\w+)\)", address)
            offset, base = match.groups()
            addr = (regs[base] & MASK64) + int(offset)
            assert addr in memory, (opcode, "out-of-range access", hex(addr))
            if opcode == "sw":
                assert t_addr <= addr < t_addr + len(t) * 4
                memory[addr] = regs[target] & MASK
            else:
                word = memory[addr]
                low = sx(word) if opcode == "lw" else word
                regs[target] = (regs[target] & ~MASK64) | low
        elif opcode in ("pcpyld", "pcpyud", "pmultuw", "pxor"):
            dst, left, right = args
            x, y = regs[left], regs[right]
            if opcode == "pcpyld":
                value = ((x & MASK64) << 64) | (y & MASK64)
            elif opcode == "pcpyud":
                value = ((y >> 64) << 64) | (x >> 64)
            elif opcode == "pxor":
                value = x ^ y
            else:
                for operand in (x & MASK64, x >> 64, y & MASK64, y >> 64):
                    assert operand == sx(operand), "invalid PMULTUW word value"
                value = ((x & MASK) * (y & MASK)
                         | (((x >> 64) & MASK) * ((y >> 64) & MASK) << 64))
            regs[dst] = value
        elif opcode in ("daddu", "addiu", "dsrl32", "sll"):
            dst, left, right = args
            x = regs[left] & MASK64
            if opcode == "daddu":
                value = (x + (regs[right] & MASK64)) & MASK64
            elif opcode == "addiu":
                value = sx(x + int(right))
            elif opcode == "dsrl32":
                value = x >> (32 + int(right))
            else:
                value = sx(x << int(right))
            regs[dst] = (regs[dst] & ~MASK64) | value
        elif opcode in ("beqz", "bnez"):
            register, label = args
            zero = (regs[register] & MASK64) == 0
            if zero == (opcode == "beqz"):
                pending = labels[label]
        elif opcode == "b":
            pending = labels[args[0]]
        elif opcode == "jr":
            assert args == ["$ra"]
            pending = "return"
        else:
            assert opcode == "nop", "unmodeled instruction: " + opcode
        if old_pending == "return":
            break
        if old_pending is not None:
            assert pending is None, "branch in delay slot"
            pc = old_pending
    assert all(memory[a_addr + 4*j] == w for j, w in enumerate(a))
    assert set(memory) == set(original_memory)
    assert all(regs["$" + str(j)] == 0 for j in range(8, 15))
    if ("pxor", ["$15", "$15", "$15"]) in instructions:
        assert regs["$15"] == 0
    return [memory[t_addr + 4*j] for j in range(len(t))], regs["$v0"] & MASK64

rng = random.Random(0x5900ee02)
count = 0
for n in range(1, 129):
    for trial in range(16):
        b = (MASK if trial == 0 else 0x80000000 if trial == 1
             else 0 if trial == 2 else rng.getrandbits(32))
        a = [MASK if trial == 0 else rng.getrandbits(32) for _ in range(n)]
        t = [MASK if trial == 0 else rng.getrandbits(32) for _ in range(n)]
        whole_a = sum(word << (32*j) for j, word in enumerate(a))
        whole_t = sum(word << (32*j) for j, word in enumerate(t))
        expected = whole_a * b + whole_t
        words, carry = execute_row(a, t, b)
        assert words == [(expected >> (32*j)) & MASK for j in range(n)]
        assert carry == sx(expected >> (32*n)), (n, trial, hex(carry))
        count += 1
print("PASS: register-only BN instruction trace", count,
      "odd/even, bit31, bounds, delay-slot, return ABI and register cleanup cases")

# Ensure the trace model detects the previously observed return ABI bug.
broken = read("crypto/bn/bn-ee-row-reg-mmi.S").replace(
    "sll     $v0, $8, 0", "daddu   $v0, $8, $zero")
assert execute_row([MASK], [MASK], MASK, assemble_trace(broken))[1] != sx(MASK)

def macro(text, name):
    return text.split("    .macro " + name + "\n", 1)[1].split("    .endm", 1)[0]

sha2 = read("crypto/sha/sha256-ee-mmi-unroll2.S")
sha4 = read("crypto/sha/sha256-ee-mmi-unroll4.S")
assert macro(sha2, "EE_SHA_STEP") == macro(sha4, "EE_SHA_STEP")
assert sha4.count("    EE_SHA_STEP\n") == 4
assert "addiu   $s1, $zero, 16" in sha4
assert sha2.replace("    EE_SHA_STEP\n" * 2, "    EE_SHA_STEP\n" * 4).replace(
    "addiu   $s1, $zero, 32", "addiu   $s1, $zero, 16").split("ossl_ee_sha256_compress4:")[1] == sha4.split(
    "ossl_ee_sha256_compress4:")[1].replace("Variant S4: four rounds per loop", "Variant S2: two rounds per loop").replace(
    "round macro repeated four times", "round macro repeated twice").replace("64 to 16", "64 to 32")
gh4 = read("crypto/modes/ghash-ee-mmi-unroll4.S")
gh8 = read("crypto/modes/ghash-ee-mmi-unroll8.S")
assert macro(gh4, "EE_GHASH_STEP") == macro(gh8, "EE_GHASH_STEP")
assert gh8.count("        EE_GHASH_STEP\n") == 8
assert "addiu   $a2, $zero, 4" in gh8
assert gh4.split("ossl_ee_ghash_mul4:")[1] == gh8.split("ossl_ee_ghash_mul4:")[1]
print("PASS: SHA 4x16 rounds and GHASH 8x4x4 bits retain proven step bodies")

main = read("test/ps2/main.c")
builder = read("test/ps2/build-experiments.sh")
expected_rows = (("BN reg", "r", "bn_mont", 8, 5, 3),
                 ("RSA reg", "r", "rsa", 1, 7, 3),
                 ("P256 reg", "r", "p256_ecdh", 1, 8, 3),
                 ("Poly hybrid", "h", "poly1305", 12, 2, 4),
                 ("SHA u4", "s", "sha256", 6, 1, 5),
                 ("GHASH u8", "g", "ghash", 4, 4, 6),
                 ("AES K2early", "k", "aes", 5, 3, 7),
                 ("GCM u8", "c", "aes_gcm", 2, 9, 8),
                 ("BN shift", "d", "bn_mont", 8, 5, 9),
                 ("RSA shift", "d", "rsa", 1, 7, 9),
                 ("Poly preload", "p", "poly1305", 12, 2, 10),
                 ("RSA tight", "q", "rsa", 1, 7, 11),
                 ("Poly reduce", "e", "poly1305", 12, 2, 12),
                 ("RSA square", "n", "rsa", 1, 7, 13),
                 ("ChaCha wrap", "w", "chacha20", 12, 0, 14))
for name, prefix, suite, reps, workload, backend in expected_rows:
    assert len(name) <= 12
    pattern = (r'\{"' + name + r'",\s*\{' + prefix + r'_ps2_test_' + suite
               + r',b_ps2_test_' + suite + r',NULL\},\s*'
               + f'{reps}, {workload}, {backend}' + r'\}')
    assert re.search(pattern, main), name
    assert "DECLARE_EXPERIMENT(" + prefix + ")" in main
    assert "EXPERIMENT_BACKEND(" + prefix + ")" in main
assert "selected->reset(workload)" in main
assert "selected->run(workload,reps)" in main
assert "selected->digest(workload)" in main
assert "bytes[workload]" in main and "ops[workload]" in main
assert "suite == 2" not in main and "i == 2" not in main
assert "backend_count" in main
assert "experiments=(r h s g k c d p q e n w)" in builder
assert "experiments=(r g c d q e w)" in builder
assert "-DEE_MMI_POLY1305_SCALAR_ABSORB" in builder
assert "-DEE_MMI_AES_TOWER_SBOX" in builder
assert "-UEE_MMI_GHASH_WINDOW_BITS" in builder
assert "--redefine-syms" in builder
assert builder.index("finish_compiles") < builder.index('ld" -r')
assert "source test/ps2/build-experiments.sh" in read("test/ps2/build.sh")
print("PASS: fifteen additional rows, twelve private namespaces, unchanged scalar controls")

assert "result_row = FIRST_TEST_ROW + (int)suite_count" in main
assert "scr_setXY(0,result_row+1)" in main
assert "EE_MMI_BN_REDC_SHIFT" in builder
assert "experiment_tests=(aes_gcm)" in builder
assert "experiment_tests=(bn_mont rsa)" in builder
assert "#define FIRST_TEST_ROW 4" in main
assert 1 + 10 + len(expected_rows) + 1 < 28, "screen footer would overflow"
assert "q_ps2_test_bn_mont(1,bn_argv)" in main
assert "-DEE_MMI_BN_ACTIVE_SCRATCH" in builder
assert "-DEE_MMI_RSA_SWAP_POWERS" in builder

assert "#define FIRST_TEST_ROW 1" in main
assert "n_ps2_test_bn_mont(1,bn_argv)" in main
assert "-DEE_MMI_BN_PUBLIC_SQUARE" in builder
assert "-DEE_MMI_POLY1305_FUSED_REDUCE" in builder

selected = main.split("#ifdef PS2_SELECTED\n",1)[1].split("#else",1)[0]
assert len(re.findall(r'\{"',selected)) == 19
assert "f_ps2_test_poly1305" not in selected
assert "scalar_validation[suites[i].workload]" in main
assert "backends[i].prepare == NULL" in main
for slot,prefix in ((3,"r"),(6,"g"),(8,"c"),(9,"d"),(11,"q"),(12,"e"),(14,"w")):
    assert f"[{slot}] = EXPERIMENT_BACKEND({prefix})" in main
build = read("test/ps2/build.sh")
assert "ps2_profile=selected" in build
assert '"$ps2_profile" != selected' in build
assert "-DPS2_SELECTED" in build
for name,prefix,suite,reps,workload,slot in (
    ("AES fixedSR","j","aes",5,3,15),
    ("GCM full","l","aes_gcm",2,9,16),
    ("P256 redc7","t","p256_ecdh",1,8,17)):
    assert re.search(r'\{"'+name+r'",\s*\{'+prefix+r'_ps2_test_'+suite+
                     r',b_ps2_test_'+suite+r',NULL\},\s*'+f'{reps}, {workload}, {slot}'+r'\}',selected)
    assert f"[{slot}] = EXPERIMENT_BACKEND({prefix})" in main
assert "experiments+=(j l t u v x y z o)" in builder
assert "t_ps2_test_bn_mont(1,bn_argv)" in main
assert "-DPS2_NEW_IDEAS" in build
assert 4+19+1 < 28
print("PASS: selected profile has ten winners + nine optional candidates, stable backend slots")
