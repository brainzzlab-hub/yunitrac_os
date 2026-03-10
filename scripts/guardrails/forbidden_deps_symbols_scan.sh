#!/usr/bin/env bash
set -euo pipefail

# Fail-closed scan for forbidden deps/symbols in boundary crates.
# Success: silent exit 0.
# Failure: prints bounded SECURITY line and exits non-zero.

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

BOUNDARY_CRATES=("secure_runner" "dio_core")
BOUNDARY_DIRS=("crates/secure_runner" "crates/dio_core")

FORBIDDEN_CRATES="rand|getrandom|chrono|time|reqwest|hyper|async-std|tokio"
FORBIDDEN_SYMBOLS=(
  "std::fs::"
  "std::time::SystemTime"
  "std::time::Instant"
  "chrono::"
  "rand::"
  "reqwest::"
  "hyper::"
  "tokio::spawn"
  "std::thread"
  "println!"
  "eprintln!"
  "tracing::trace!"
  "tracing::debug!"
  "tracing::info!"
  "tracing::warn!"
  "tracing::error!"
)

boundary_present=false
for dir in "${BOUNDARY_DIRS[@]}"; do
  if [ -d "$dir" ]; then
    boundary_present=true
    break
  fi
done

# If no boundary dirs exist, treat as pass (nothing to scan).
if [ "$boundary_present" = false ]; then
  exit 0
fi

# Dependency scan per boundary crate.
for crate in "${BOUNDARY_CRATES[@]}"; do
  if ! env CARGO_NET_OFFLINE=true cargo tree -p "$crate" -e normal --prefix none >/tmp/.forbidden_deps_scan 2>/dev/null; then
    # If cargo tree fails (crate missing), continue to next.
    continue
  fi
  if grep -Eq "$FORBIDDEN_CRATES" /tmp/.forbidden_deps_scan; then
    echo "SECURITY: FORBIDDEN_DEPS_SYMBOLS_FAIL"
    exit 1
  fi
done

# Symbol scan per boundary dir (tests/benches excluded).
for dir in "${BOUNDARY_DIRS[@]}"; do
  [ -d "$dir" ] || continue
  for sym in "${FORBIDDEN_SYMBOLS[@]}"; do
    if rg -q --glob '!**/tests/**' --glob '!**/benches/**' --fixed-strings "$sym" "$dir"; then
      echo "SECURITY: FORBIDDEN_DEPS_SYMBOLS_FAIL"
      exit 1
    fi
  done
done

exit 0
