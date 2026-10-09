"""Normalize physical temporary GPRs to the original o32 layout labels.

These labels describe the algorithm's register allocation, not the n32
assembler aliases (where t0..t3 mean different physical registers).
"""
import re


def read_asm(path):
    return re.sub(r"\$(8|9|1[0-5])\b",
                  lambda match: "$t" + str(int(match[1]) - 8),
                  path.read_text())
