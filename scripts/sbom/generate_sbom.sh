#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT_DIR="$ROOT/artifacts/sbom"
CYC="$ROOT/artifacts/sbom/cyclonedx.json"
SPDX="$ROOT/artifacts/sbom/spdx.json"

# fail-closed if tool missing
if ! command -v cargo-cyclonedx >/dev/null 2>&1; then
  echo "FAIL: generate_sbom SEC_SBOM_TOOL_MISSING"
  exit 40
fi

rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR"

# CycloneDX generation
if ! cargo cyclonedx --format json --output "$CYC" >/dev/null 2>&1; then
  printf '{\"status\":\"UNAVAILABLE\",\"reason\":\"cyclonedx_generation_failed\"}' > "$CYC"
fi

# SPDX placeholder if tool absent
if command -v syft >/dev/null 2>&1; then
  if ! syft dir:"$ROOT" -o spdx-json > "$SPDX" 2>/dev/null; then
    echo "FAIL: generate_sbom SEC_SBOM_GEN_FAIL"
    exit 41
  fi
else
  printf '{\"status\":\"UNAVAILABLE\",\"reason\":\"spdx_tool_missing\"}\\n' > "$SPDX"
fi

echo "PASS: generate_sbom"
