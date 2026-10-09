#!/usr/bin/env python3
"""Static checks of the EE MMI ChaCha20 vector register layout.

This is NOT a substitute for an R5900 assembler or console test.
The goal is to catch accidental register remapping or round-order edits
even in host-only CI where MMI instructions cannot be assembled.
"""
from pathlib import Path
from asm_layout import read_asm
import re
import sys

ROOT = Path(__file__).resolve().parents[2]
asm = read_asm((ROOT / "crypto/chacha/chacha-ee-mmi.S"))
build = (ROOT / "crypto/chacha/build.info").read_text()
dispatcher = (ROOT / "crypto/chacha/chacha-ee-mmi.c").read_text()
config = (ROOT / "Configurations/50-ee-mmi.conf").read_text()

def check(condition, message):
    if not condition:
        print("FAIL:", message, file=sys.stderr)
        sys.exit(1)

registers = (
    "v0", "v1", "a1", "a2", "a3", "t0", "t1", "t2", "t3",
    "t4", "t5", "t6", "t7", "t8", "t9", "s0"
)
mapping = {reg: index for index, reg in enumerate(registers)}

load = re.findall(r"^\s*lq\s+\$(\w+),\s*(\d+)\(\$a0\)",
                  asm, re.MULTILINE)
store = re.findall(r"^\s*sq\s+\$(\w+),\s*(\d+)\(\$a0\)",
                   asm, re.MULTILINE)
expected = [(reg, str(i * 16)) for i, reg in enumerate(registers)]
check(load == expected, "16 vector loads / 16-byte positions")
check(store == expected, "16 vector stores / 16-byte positions")
check(all(re.search(r"^\s*sq\s+\$" + reg + r",\s*" + str(i * 16)
                    + r"\(\$sp\)", asm, re.MULTILINE)
          for i, reg in enumerate(("s0", "s1", "s2", "s3"))),
      "callee-saved 128-bit stores")
check(all(re.search(r"^\s*lq\s+\$" + reg + r",\s*" + str(i * 16)
                    + r"\(\$sp\)", asm, re.MULTILINE)
          for i, reg in enumerate(("s0", "s1", "s2", "s3"))),
      "callee-saved 128-bit reloads")
check("addiu   $sp, $sp, -64" in asm
      and "addiu   $sp, $sp, 64" in asm,
      "16-byte stack frame alignment")

rounds = re.findall(
    r"^\s*EE_QR\s+\$(\w+),\s*\$(\w+),\s*\$(\w+),\s*\$(\w+)",
    asm, re.MULTILINE)
check(len(rounds) == 8, "exactly eight quarter-round calls")
try:
    actual = [[mapping[reg] for reg in one] for one in rounds]
except KeyError as exc:
    check(False, "unregistered ChaCha vector register: " + str(exc))
expected_rounds = [
    [0, 4, 8, 12], [1, 5, 9, 13], [2, 6, 10, 14],
    [3, 7, 11, 15], [0, 5, 10, 15], [1, 6, 11, 12],
    [2, 7, 8, 13], [3, 4, 9, 14],
]
check(actual == expected_rounds, "RFC 8439 round ordering")

for register, shift, complement in (
    ("d", 16, 16), ("b", 12, 20),
    ("d", 8, 24), ("b", 7, 25),
):
    check(("EE_ROTL \\" + register + ", " +
           str(shift) + ", " + str(complement)) in asm,
          "rotation " + str(shift))
check(re.search(r"^\s*addiu\s+\$s3,\s*\$zero,\s*10$",
                asm, re.MULTILINE), "10 double rounds")
check(".set noreorder" in asm, "manual scheduling mode")
check("psllw" in asm and "psrlw" in asm and "por" in asm,
      "MMI rotate operations")
check("$CHACHAASM_ee_mmi=chacha_enc.c chacha-ee-mmi.c chacha-ee-mmi.S"
      in build, "MMI backend source selection")
check("$CHACHADEF_ee_mmi=INCLUDE_C_CHACHA20"
      in build, "C scalar remainder included")
check("asm_arch       => \"ee_mmi\"" in config, "PS2 target arch selection")
check("while (len >= 256)" in dispatcher, "four-block batches")
check("ChaCha20_ctr32_c(out, in, len, key, next_counter)" in dispatcher,
      "scalar tail handling")

print("PASS: EE MMI static layout, rounds, ABI preservation and integration")

# SHA-256 four-lane compressor invariants.
sha = read_asm((ROOT / "crypto/sha/sha256-ee-mmi.S"))
sha_build = (ROOT / "crypto/sha/build.info").read_text()
sha_c = (ROOT / "crypto/sha/sha256-ee-mmi.c").read_text()
sha_regs = ["v0", "v1", "a3", "t0", "t1", "t2", "t3", "t4"]
sha_load = re.findall(r"^\s*lq\s+\$(\w+),\s*(\d+)\(\$a0\)",
                      sha.split(".Lee_sha256_round:")[0], re.MULTILINE)
sha_store = re.findall(r"^\s*sq\s+\$(\w+),\s*(\d+)\(\$a0\)",
                       sha, re.MULTILINE)
check(sha_load == [(r, str(i * 16)) for i, r in enumerate(sha_regs)],
      "SHA256 state register loads")
check(sha_store == [(r, str(i * 16)) for i, r in enumerate(sha_regs)],
      "SHA256 state register stores")
check(sha.count("EE_ROTR32 ") == 7,
      "SHA256 six Sigma rotations and macro definition")
check("addiu   $s1, $zero, 64" in sha, "SHA256 64 rounds")
check("paddw" in sha and "pand" in sha and "pxor" in sha,
      "SHA256 MMI arithmetic")
check(all(re.search(r"^\s*sq\s+\$" + reg + r",\s*" + str(i * 16)
                    + r"\(\$sp\)", sha, re.MULTILINE)
          for i, reg in enumerate(("s0", "s1"))),
      "SHA256 callee-saved 128-bit stores")
check(all(re.search(r"^\s*lq\s+\$" + reg + r",\s*" + str(i * 16)
                    + r"\(\$sp\)", sha, re.MULTILINE)
          for i, reg in enumerate(("s0", "s1"))),
      "SHA256 callee-saved 128-bit restores")
check("$target{asm_arch} eq \"ee_mmi\"" in sha_build,
      "SHA256 source only built on EE")
check("sha256-ee-mmi.c sha256-ee-mmi.S" in sha_build,
      "SHA256 MMI C/assembly paired")
check("sha256_prepare4" in sha_c
      and "ossl_ee_sha256_compress4" in sha_c,
      "SHA256 schedule calls compressor")
check("tail_bytes = remaining <= 55 ? 64 : 128;" in sha_c,
      "SHA256 1/2-block padding")

print("PASS: EE SHA256 static layout, 64 rounds, ABI preservation and build")



# Poly1305 four-lane add (does not multiply or normalize limbs).
poly_asm = read_asm((ROOT / "crypto/poly1305/poly1305-ee-mmi.S"))
poly_src = (ROOT / "crypto/poly1305/poly1305-ee-mmi.c").read_text()
poly_build = (ROOT / "crypto/poly1305/build.info").read_text()
poly_lq_acc = re.findall(r"^\s*lq\s+\$t0,\s*(\d+)\(\$a0\)",
                        poly_asm, re.MULTILINE)
poly_lq_msg = re.findall(r"^\s*lq\s+\$t1,\s*(\d+)\(\$a1\)",
                        poly_asm, re.MULTILINE)
poly_sq_acc = re.findall(r"^\s*sq\s+\$t0,\s*(\d+)\(\$a0\)",
                        poly_asm, re.MULTILINE)
check(poly_lq_acc == [str(16*i) for i in range(5)],
      "Poly1305 five aligned accumulator loads")
check(poly_lq_msg == [str(16*i) for i in range(5)],
      "Poly1305 five aligned message loads")
check(poly_sq_acc == [str(16*i) for i in range(5)],
      "Poly1305 five aligned accumulator stores")
check(len(re.findall(r"^\s*paddw\s+\$t0,\s*\$t0,\s*\$t1",
                     poly_asm, re.MULTILINE)) == 5,
      "Poly1305 exactly five 4-lane additions")
check("ossl_ee_poly1305_add4(h, m);" in poly_src,
      "Poly1305 MMI absorber actually called")
check("multiply_reduce(h, r);" in poly_src,
      "Poly1305 integer multiplication and carry")
check("size == 16" in poly_src and "last[size] = 1;" in poly_src,
      "Poly1305 full/partial block padding")
check('asm_arch} eq "ee_mmi"' in poly_build
      and "poly1305-ee-mmi.c poly1305-ee-mmi.S" in poly_build,
      "Poly1305 MMI build gating")
check("$POLY1305DEF_ee_mmi=" not in poly_build,
      "Do not intercept OpenSSL Poly1305_*")
print("PASS: EE Poly1305 MMI 4-way absorption and independent API gating")


# PMULTUW: two 32x32->64 products per instruction, 25 convolution
# terms per stream. PEXTLW/PEXTUW MUST pair streams 0,1 and 2,3
# with zero upper words; feeding raw packed PADDW vectors to PMULTUW
# would violate EE's NotWordValue requirement.
pmul = read_asm((ROOT / "crypto/poly1305/poly1305-ee-pmultuw.S"))
header = (ROOT / "include/crypto/ee_mmi.h").read_text()
mmiregex = r"^\s*EE_POLY_MUL2\s+(\d+),\s*(\d+),\s*(\d+),\s*(\d+)"
instructions = [tuple(map(int, item)) for item
                in re.findall(mmiregex, pmul, re.MULTILINE)]
expected_products = []
for k in range(5):
    for i in range(5):
        j = (k - i + 5) % 5 + (5 if i > k else 0)
        out = (k*5 + i) * 32
        expected_products.append((i*16, j*16, out, out + 16))
check(instructions == expected_products,
      "Poly1305 PMULTUW 25-convolution product and offset mapping")
check(all(offset % 16 == 0 for item in instructions for offset in item),
      "PMULTUW LQ/SQ addresses must be 16-byte aligned")
check(pmul.count("pmultuw $t4,") == 2,
      "PMULTUW twice per product macro (4 unsigned products)")
check("pextlw  $t2, $zero, $t0" in pmul
      and "pextlw  $t3, $zero, $t1" in pmul
      and "pextuw  $t5, $zero, $t0" in pmul
      and "pextuw  $t6, $zero, $t1" in pmul,
      "PMULTUW operands zero-extended before multiplication")
check("sq      $t4, \\out0($a0)" in pmul
      and "sq      $t4, \\out1($a0)" in pmul,
      "PMULTUW 64-bit product pairs stored in correct lane order")
check("ossl_ee_poly1305_products4(products, h, scale_r);" in poly_src,
      "MMI product helper used in default Poly1305 path")
check("EE_MMI_POLY1305_SCALAR_MULTIPLY" in poly_src
      and "fold_reduce(h, lane," in poly_src,
      "identical radix-2^26 carry reduction shared by both modes")
check("poly1305-ee-pmultuw.S" in poly_build,
      "EE PMULTUW source wired into crypto/poly1305/build.info")
check("ossl_ee_poly1305_products4(" in header,
      "MMI product layout declared in internal header")
print("PASS: EE Poly1305 PMULTUW pairs, exact convolution and scalar fallback")


# Fused PMULTUW/PMADDUW: five exact terms, not five rounded or
# word-truncated 32-bit additions. Each PMULTUW must reinitialize
# the EE HI/LO accumulator before four dependent PMADDUW operations.
fused = read_asm((ROOT / "crypto/poly1305/poly1305-ee-pmadduw.S"))
acc = re.findall(
    r"^\s*EE_POLY_ACC\s+(pmultuw|pmadduw),\s*"
    r"(pextlw|pextuw),\s*(\d+),\s*(\d+)",
    fused, re.MULTILINE)
expected_acc = []
expected_sq = []
for k in range(5):
    for pair, extractor in enumerate(("pextlw", "pextuw")):
        for i in range(5):
            j = (k - i + 5) % 5 + (5 if i > k else 0)
            expected_acc.append((
                "pmultuw" if i == 0 else "pmadduw",
                extractor, str(i * 16), str(j * 16)
            ))
        expected_sq.append(str(k * 32 + pair * 16))
check(acc == expected_acc, "fused PMADDUW 50 instructions, group order")
fused_sqs = re.findall(r"^\s*sq\s+\$t4,\s*(\d+)\(\$a0\)",
                       fused, re.MULTILINE)
check(fused_sqs == expected_sq,
      "fused PMADDUW 160-byte output layout and 10 stores")
check("\\operation $t4, $t2, $t3" in fused
      and "\\extract $t2, $zero, $t0" in fused
      and "\\extract $t3, $zero, $t1" in fused,
      "fused PMADDUW zero-extended operand packing")
check("ossl_ee_poly1305_sums4(sums, h, scale_r);" in poly_src,
      "fused PMADDUW kernel wired to C reduction")
check("EE_MMI_POLY1305_FUSED_MADD" in poly_src
      and "poly1305-ee-pmadduw.S" in poly_build,
      "EE fused PMADDUW opt-in flag and build wiring")
print("PASS: EE PMADDUW 5x4 lane sums, 160-byte layout, HI/LO chains")


# Key-derived r and 5*r are block-invariant. Rebuild them once, before
# the per-16-byte message loop; otherwise the fused and unfused MMI
# variants waste 160 bytes of per-block key setup traffic.
setup_marker = "scale_r[word + 5][lane] = 5U * r[lane][word];"
loop_marker = "while (offset < len) {"
check(poly_src.count(setup_marker) == 1
      and poly_src.index(setup_marker) < poly_src.index(loop_marker),
      "Poly1305 MMI operands are prepared once per key, not per block")
check("multiply_reduce(h, scale_r);" in poly_src
      and "poly_wipe(scale_r, sizeof(scale_r));" in poly_src,
      "Poly1305 reused key operands are wiped when finished")
print("PASS: EE Poly1305 one-time key-derived MMI packing")
