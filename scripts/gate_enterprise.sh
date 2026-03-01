#!/usr/bin/env bash
set -euo pipefail

WORKDIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$WORKDIR"

./scripts/gate_no_ack.sh
./scripts/gate_boundary_deps.sh

echo "PASS: gate_enterprise"
