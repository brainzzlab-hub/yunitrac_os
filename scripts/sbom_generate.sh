#!/usr/bin/env bash
set -euo pipefail

if ! command -v cargo-cyclonedx >/dev/null 2>&1; then
  if [ "${ALLOW_NO_SBOM:-0}" = "1" ]; then
    echo "SKIP: cargo-cyclonedx missing"; exit 0; fi
  cargo install cargo-cyclonedx --locked
fi
rm -rf artifacts/sbom
mkdir -p artifacts/sbom
cargo cyclonedx --format json
find . -maxdepth 4 -name 'cyclonedx*.json' | while read -r file; do
  pkg=$(basename "$(dirname "$file")")
  cp "$file" "artifacts/sbom/${pkg}.cyclonedx.json"
done
