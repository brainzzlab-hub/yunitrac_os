#!/usr/bin/env bash
set -euo pipefail

WORKDIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$WORKDIR"

# Gate A1: secure_runner must not read from stdin (code-level; comments allowed).
if rg -q "std::io::stdin|Stdin|stdin\s*\(" crates/secure_runner/src; then
  echo "FAIL: secure_runner references stdin" >&2
  exit 1
fi

# Gate A2: prove_enterprise must not introduce reverse channels (no pipe into secure_runner).
if rg -q "secure_runner[^\n]*<" scripts/prove_enterprise.sh; then
  echo "FAIL: secure_runner reads from stdin in prove_enterprise" >&2
  exit 1
fi
if rg -q "\|[^\n]*secure_runner" scripts/prove_enterprise.sh; then
  echo "FAIL: secure_runner appears in pipe RHS (potential backchannel)" >&2
  exit 1
fi

# Gate A3: ensure ro_out_receiver is only sink side (no pipe from it back to secure_runner).
if rg -q "ro_out_receiver[^\n]*>.*secure_runner" scripts/prove_enterprise.sh; then
  echo "FAIL: reverse path involving ro_out_receiver detected" >&2
  exit 1
fi

echo "PASS: gate_no_ack"
