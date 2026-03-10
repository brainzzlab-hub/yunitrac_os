#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

OUT_DIR="$ROOT/artifacts/incident"
SBOM_DIR="$ROOT/artifacts/sbom"
AUDIT_DIR="$ROOT/artifacts/audit"
SECURITY_DIR="$ROOT/artifacts/security"

REQUIRED_FILES=(
  "$SBOM_DIR/cyclonedx.json"
  "$SBOM_DIR/license_policy_report.json"
  "$AUDIT_DIR/index_manifest.json"
  "$AUDIT_DIR/evidence.zip"
)

fail() {
  echo "FAIL: export_incident_bundle $1"
  exit "$2"
}

# Check prerequisites
for f in "${REQUIRED_FILES[@]}"; do
  if [ ! -f "$f" ]; then
    fail "AUDIT_MISSING" 50
  fi
done

python3 - <<'PY'
import hashlib
import json
import os
import zipfile
from pathlib import Path

ROOT = Path(os.environ.get("ROOT_OVERRIDE", ".")).resolve()
OUT_DIR = ROOT / "artifacts/incident"
SBOM_DIR = ROOT / "artifacts/sbom"
AUDIT_DIR = ROOT / "artifacts/audit"
SECURITY_DIR = ROOT / "artifacts/security"

required = [
    SBOM_DIR / "cyclonedx.json",
    SBOM_DIR / "license_policy_report.json",
    AUDIT_DIR / "index_manifest.json",
    AUDIT_DIR / "evidence.zip",
]
optional = [
    SBOM_DIR / "spdx.json",
    SECURITY_DIR / "gdpr_findings.json",
    ROOT / "artifacts/incident/hitl_signature_failure.json",
    ROOT / "artifacts/incident/control_plane_ledger_failure.json",
    ROOT / "artifacts/proof_report_enterprise.json",
    ROOT / "artifacts/proof_report_lite.json",
]

OUT_DIR.mkdir(parents=True, exist_ok=True)
manifest_path = OUT_DIR / "index_manifest.json"
zip_path = OUT_DIR / "incident_bundle.zip"

files = []
for p in required + optional:
    if p.exists() and p.is_file():
        files.append(p)

# Deterministic order
files = sorted(files, key=lambda p: str(p))

entries = []
for path in files:
    data = path.read_bytes()
    h = hashlib.sha256(data).hexdigest()
    entries.append({"path": str(path.relative_to(ROOT)), "sha256": h, "size": len(data)})

manifest = {
    "version": "1.0",
    "generated_utc": "1970-01-01T00:00:00Z",
    "entries": entries,
}

manifest_path.write_text(json.dumps(manifest, sort_keys=True, separators=(",", ":")))

# Build deterministic zip
with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
    fixed_dt = (1980, 1, 1, 0, 0, 0)
    for entry in entries:
        rel = entry["path"]
        src = ROOT / rel
        info = zipfile.ZipInfo(rel)
        info.date_time = fixed_dt
        info.external_attr = 0o600 << 16
        with src.open("rb") as fh:
            zf.writestr(info, fh.read())
    info = zipfile.ZipInfo(str(manifest_path.relative_to(ROOT)))
    info.date_time = fixed_dt
    info.external_attr = 0o600 << 16
    zf.writestr(info, manifest_path.read_bytes())
PY

echo "PASS: export_incident_bundle"
exit 0
