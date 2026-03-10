#!/usr/bin/env bash
set -euo pipefail

# Fail-closed guardrail to ensure boundary crate set stays frozen and secure_ingress
# remains outside the boundary list. Output: single line PASS/FAIL + SecCode.

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

SEC_FAIL="FAIL: BOUNDARY_SCOPE_SEC"
EXPECTED=("secure_runner" "dio_core")

expect_sorted() {
  printf "%s\n" "${EXPECTED[@]}" | LC_ALL=C sort | paste -sd',' -
}

extract_sorted() {
  local file="$1"
  local line
  line=$(grep -E 'BOUNDARY_CRATES=' "$file" | head -n 1 | sed -e 's/.*(//' -e 's/).*//')
  if [ -z "$line" ]; then
    echo ""
    return
  fi
  line=${line//\"/}
  line=${line//\'/}
  # shellcheck disable=SC2086  # intentional word splitting over array items
  printf "%s\n" $line | LC_ALL=C sort | paste -sd',' -
}

expect_val="$(expect_sorted)"
gate_val="$(extract_sorted "scripts/gate_boundary_deps.sh")"
guard_val="$(extract_sorted "scripts/guardrails/forbidden_deps_symbols_scan.sh")"

if [ -z "$gate_val" ] || [ -z "$guard_val" ]; then
  echo "$SEC_FAIL"
  exit 1
fi

# Quick check to ensure secure_ingress is not in the extracted lists.
if echo "$gate_val" | grep -q "secure_ingress"; then
  echo "$SEC_FAIL"
  exit 1
fi
if echo "$guard_val" | grep -q "secure_ingress"; then
  echo "$SEC_FAIL"
  exit 1
fi

if [ "$gate_val" != "$expect_val" ] || [ "$guard_val" != "$expect_val" ]; then
  echo "$SEC_FAIL"
  exit 1
fi

echo "PASS: boundary_scope_enforce"
