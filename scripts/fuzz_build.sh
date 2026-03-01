#!/usr/bin/env bash
set -euo pipefail

if ! command -v cargo-fuzz >/dev/null 2>&1; then
  if [ "${ALLOW_NO_CARGO_FUZZ:-0}" = "1" ]; then
    echo "SKIP: cargo-fuzz missing"
    exit 0
  else
    echo "FAIL: cargo-fuzz missing"
    exit 1
  fi
fi

cargo fuzz build fuzz_decode_recordframe
