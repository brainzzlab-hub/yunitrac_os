#!/usr/bin/env bash
set -euo pipefail

WORKDIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$WORKDIR"

DENY_REGEX='(rand|getrandom|chrono|\btime\b|tokio|async-std|reqwest|hyper|ureq|mio|tracing|log|env_logger|fern|flexi_logger)'
# Boundary crates explicitly enumerated (enterprise boundary only)
BOUNDARY_CRATES=(secure_runner dio_core)

rg_nc() { RG_CONFIG_PATH=/dev/null rg --no-config "$@"; }

FAIL() {
  local code="$1"
  echo "FAIL: boundary_guard $code" >&2
  exit 1
}

check_tree() {
  local crate="$1"
  if ! CARGO_NET_OFFLINE=true cargo tree -p "$crate" -e normal --prefix none >/tmp/tree.out 2>/tmp/tree.err; then
    FAIL SEC_BOUNDARY_TREE_FAIL
  fi
  if rg_nc -i -e "$DENY_REGEX" /tmp/tree.out; then
    FAIL SEC_BOUNDARY_DEP_FORBIDDEN
  fi
}

check_sources() {
  local crate="$1"
  local dir="crates/$crate"
  if rg_nc -q "std::(fs|net|time|thread)" "$dir"; then
    FAIL SEC_BOUNDARY_STD_FORBIDDEN
  fi
  if rg_nc -q "(tokio::|async_std::)" "$dir"; then
    FAIL SEC_BOUNDARY_ASYNC_FORBIDDEN
  fi
  if rg_nc -q "(println!|eprintln!)" "$dir"; then
    FAIL SEC_BOUNDARY_LOG_FORBIDDEN
  fi
  if rg_nc -q "(log::|tracing::)" "$dir"; then
    FAIL SEC_BOUNDARY_TRACING_FORBIDDEN
  fi
}

for c in "${BOUNDARY_CRATES[@]}"; do
  check_tree "$c"
  check_sources "$c"
done

echo "PASS: gate_boundary_deps"
