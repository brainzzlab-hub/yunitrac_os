#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
ART_ROOT="$ROOT/artifacts"
OUT_DIR="$ART_ROOT/audit"
ZIP_PATH="$OUT_DIR/evidence.zip"
MANIFEST="$OUT_DIR/index_manifest.json"
export ROOT ART_ROOT OUT_DIR ZIP_PATH MANIFEST

REQUIRED=(
  "$ART_ROOT/sbom/cyclonedx.json"
  "$ART_ROOT/sbom/spdx.json"
  "$ART_ROOT/sbom/license_policy_report.json"
)

for f in "${REQUIRED[@]}"; do
  if [ ! -f "$f" ]; then
    echo "FAIL: export_audit_packet SEC_AUDIT_MISSING"
    exit 50
  fi
done

python3 - <<'PY'
import json, pathlib, hashlib, zipfile, os
from datetime import datetime, timezone

root = pathlib.Path(os.environ["ROOT"])
art_root = pathlib.Path(os.environ["ART_ROOT"])
out_dir = pathlib.Path(os.environ["OUT_DIR"])
zip_path = pathlib.Path(os.environ["ZIP_PATH"])
manifest_path = pathlib.Path(os.environ["MANIFEST"])

required = [art_root / "sbom/cyclonedx.json", art_root / "sbom/spdx.json", art_root / "sbom/license_policy_report.json"]
optional = [
    art_root / "security/gdpr_findings.json",
    art_root / "proof_report_enterprise.json",
    art_root / "proof_report_lite.json",
]

files = []
for p in required + optional:
    if p.exists():
        files.append(p)

if not files:
    print("FAIL: export_audit_packet SEC_AUDIT_MISSING")
    raise SystemExit(50)

files = sorted(files, key=lambda x: str(x.relative_to(root)))

out_dir.mkdir(parents=True, exist_ok=True)

fixed_date = (1980, 1, 1, 0, 0, 0)
with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
    for p in files:
        rel = p.relative_to(root)
        data = p.read_bytes()
        info = zipfile.ZipInfo(rel.as_posix(), fixed_date)
        info.external_attr = 0o600 << 16
        zf.writestr(info, data)

entries = []
for p in files:
    rel = p.relative_to(root).as_posix()
    data = p.read_bytes()
    sha = hashlib.sha256(data).hexdigest()
    entries.append({"path": rel, "sha256": sha, "size": len(data)})

manifest = {
    "version": "1.0",
    "generated_utc": "1970-01-01T00:00:00Z",
    "entries": entries
}
manifest_path.write_text(json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n")
print("PASS: export_audit_packet")
PY
