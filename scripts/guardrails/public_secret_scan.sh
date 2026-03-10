#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

# Exclude generated/vendor paths
EXCLUDES=(
  "--glob" "!artifacts/**"
  "--glob" "!target/**"
  "--glob" "!fuzz/target/**"
  "--glob" "!node_modules/**"
  "--glob" "!artifacts/sbom/**"
  "--glob" "!Cargo.lock*"
)

PATS=(
  "BEGIN (RSA|EC|OPENSSH|PRIVATE) KEY"
  "AKIA[0-9A-Z]{16}"
  "ASIA[0-9A-Z]{16}"
  "ghp_[A-Za-z0-9]{36}"
  "github_pat_[A-Za-z0-9_]{82,}"
  "sk-[A-Za-z0-9]{20,}"
  "xox[baprs]-[A-Za-z0-9-]{10,}"
  "[A-Za-z0-9_-]{20,}\\.[A-Za-z0-9_-]{20,}\\.[A-Za-z0-9_-]{20,}"
)

hits=0
for pat in "${PATS[@]}"; do
  out=$(rg --pcre2 -n "$pat" "${EXCLUDES[@]}" "$ROOT" | head -n 50 || true)
  if [ -n "$out" ]; then
    echo "$out"
    hits=1
  fi
done

if [ "$hits" -ne 0 ]; then
  echo "FAIL: public_secret_scan SEC_SECRET_HIT"
  exit 1
fi

echo "PASS: public_secret_scan SEC_OK"
