#!/usr/bin/env python3
"""Independent SP 800-38D GHASH BigInt oracle and AES-GCM integration lint.

This validates the GCM algebra using Python big integers, not target
R5900 instructions. The portable and PS2 C tests additionally execute
the complete AES/GHASH implementation and known-answer tests.
"""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
core = (ROOT / "crypto/modes/aes-gcm-ee-mmi.c").read_text()
head = (ROOT / "include/crypto/ee_aes_gcm.h").read_text()
tests = (ROOT / "test/ee_mmi/aes_gcm_test.c").read_text()
build = (ROOT / "crypto/modes/build.info").read_text()
harness = (ROOT / "test/ps2/bench.c").read_text()

R = 0xe1000000000000000000000000000000
MASK = (1 << 128)-1


def multiply(x, h):
    z, v = 0, h
    for i in range(128):
        z ^= v if ((x >> (127-i)) & 1) else 0
        v = (v >> 1) ^ (R if v & 1 else 0)
    return z & MASK


def ghash(h, aad, ciphertext):
    y = 0
    for data in (aad, ciphertext):
        for i in range(0, len(data), 16):
            block = data[i:i+16]
            y = multiply(y ^ int.from_bytes(block.ljust(16,b"\0"),"big"), h)
    length = ((len(aad)*8) << 64) | (len(ciphertext)*8)
    return multiply(y ^ length, h)


# Official AES-128-GCM zero-key/zero-IV published known answers.
h = int("66e94bd4ef8a2c3b884cfa59ca342b2e",16)
mask = int("58e2fccefa7e3061367f1d57a4e7455a",16)
ct = bytes.fromhex("0388dace60b6a392f328c2b971b2fe78")
assert ghash(h,b"",b"") == 0
assert ghash(h,b"",ct) == int("f38cbb1ad69223dcc3457ae5b6b0f885",16)
assert ghash(h,b"",ct) ^ mask == int(
    "ab6e47d42cec13bdf53a67b21257bddf",16)
# Different-length AAD and ciphertext including final padding.
assert ghash(h, b"\x00",ct) != ghash(h,b"",ct)
assert ghash(h, b"",ct+b"\x00") != ghash(h,b"",ct)

assert "ossl_ee_aes_encrypt4" in core
assert "ossl_ee_ghash_mul4" in core
assert "gcm_auth_block(state, ctx->h, auth GCM_WIN_ARG);" in core
assert "ossl_ee_ghash_update4(" not in core
assert "gcm_auth_bytes(state, ctx->h, aad, aad_len GCM_WIN_ROOT);" in core
assert "gcm_auth_bytes(state, ctx->h, in, len GCM_WIN_ROOT);" in core
# Cached-window parameters are optional; GCM u8 compiles the ordinary
# ossl_ee_ghash_mul4 call and links the eight-step bit-serial assembler.
assert "# define GCM_WIN_ARG\n" in core
assert "# define GCM_WIN_ROOT\n" in core
assert "put_be64(length_block[lane], (uint64_t)aad_len * 8);" in core
assert "put_be64(length_block[lane] + 8, (uint64_t)len * 8);" in core
assert "if (diff != 0)" in core
assert core.index("if (diff != 0)") < core.index(
    "ok = gcm_ctr4(ctx, out, in, len, iv, state, 0 GCM_WIN_ROOT)")
assert "blocks > (uint64_t)UINT32_MAX - 1U" in core
assert "gcm_wipe(expected, sizeof(expected));" in core
assert "ossl_ee_aes_gcm4_open" in head
assert "aes-gcm-ee-mmi.c" in build
assert "EE_GCM_SCALAR" in (
    ROOT / "test/ee_mmi/run-aes-gcm-host.sh").read_text()
for v in ("nist_examples", "multi_key_kat",
          "random_regression", "invalid_args"):
    assert v in tests
assert "ossl_ee_aes_gcm4_seal" in harness
assert "sizeof(gcm_tags)" in harness

print("PASS: GCM BigInt NIST GHASH, padding and 128-bit length block")
print("PASS: 4-stream CTR/GHASH integration, verify-before-release, and build wiring")
