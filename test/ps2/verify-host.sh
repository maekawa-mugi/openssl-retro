#!/usr/bin/env bash
# Portable regression checks only; no R5900 instructions execute here.
set -euo pipefail
cd "$(dirname "$0")/../.."
# The PS2 benchmark is syntax-checked on native GCC/Clang using mock SDK headers.
bash test/ps2/verify-bench-host.sh
for check in test/ee_mmi/check-*.py; do
    python3 "$check"
done
python3 test/ee_mmi/poly1305-oracle.py
for suite in chacha20 sha256 poly1305 aes ghash bn-mont x25519 rsa p256 aes-gcm; do
    if [[ $suite == chacha20 ]]; then
        script=test/ee_mmi/run-host.sh
    else
        script="test/ee_mmi/run-$suite-host.sh"
    fi
    # Windows Git checkouts may use CRLF; retain the original $0 so each
    # existing script still resolves its source directory correctly.
    bash -c "$(tr -d '\r' < "$script")" "$script"
done
