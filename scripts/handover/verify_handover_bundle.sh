#!/usr/bin/env bash
set -euo pipefail

WORKDIR="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$WORKDIR"

OUT_DIR="$WORKDIR/artifacts/handover"
ZIP_PATH="$OUT_DIR/handover_bundle.zip"
INDEX_PATH="$OUT_DIR/handover_bundle_index.json"
mkdir -p "$OUT_DIR"

fail() { echo "FAIL: verify_handover_bundle $1" >&2; exit "$2"; }

to_include=()
while IFS= read -r p; do to_include+=("$p"); done <<'EOF'
docs/handover/RELEASE_CHECKLIST.md
docs/handover/ARTIFACT_MAP.md
docs/handover/PROCUREMENT_PACKET.md
artifacts/audit/evidence_pack_index.json
artifacts/audit/index_manifest.json
artifacts/incident/index_manifest.json
artifacts/sbom/license_policy_report.json
EOF

# Generate zip deterministically
python3 - <<'PY' "$WORKDIR" "$ZIP_PATH" "${to_include[@]}"
import sys, os, hashlib, json, zipfile
from pathlib import Path
root = Path(sys.argv[1])
zip_path = Path(sys.argv[2])
files = [Path(p) for p in sys.argv[3:]]
existing = [p for p in files if (root / p).is_file()]
missing_required = [p for p in files[:3] if not (root/p).is_file()]  # handover docs required
if missing_required:
    print("FAIL: verify_handover_bundle EVIDPACK_MISSING", file=sys.stderr)
    sys.exit(90)

def fixed_info(path: Path, arcname: str) -> zipfile.ZipInfo:
    zi = zipfile.ZipInfo(arcname, (1980,1,1,0,0,0))
    zi.external_attr = (0o644 & 0xFFFF) << 16
    zi.compress_type = zipfile.ZIP_STORED
    return zi

with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_STORED, allowZip64=False) as zf:
    for p in sorted(existing, key=lambda x: x.as_posix()):
        data = (root / p).read_bytes()
        zf.writestr(fixed_info(p, p.as_posix()), data)

# Build index
entries = []
for p in sorted(existing, key=lambda x: x.as_posix()):
    full = root / p
    data = full.read_bytes()
    entries.append({
        "path": p.as_posix(),
        "sha256": hashlib.sha256(data).hexdigest(),
        "size": len(data),
    })
from datetime import datetime, timezone
index = {
    "version": "1.0",
    "generated_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "entries": entries,
    "zip_path": Path(zip_path).relative_to(root).as_posix(),
}
(root / Path(sys.argv[2]).parent / "handover_bundle_index.json").write_text(
    json.dumps(index, sort_keys=True, separators=(",",":")) + "\n",
    encoding="utf-8"
)
PY

# Verify index and zip structure
python3 - <<'PY' "$WORKDIR" "$ZIP_PATH" "$INDEX_PATH" || exit $?
import sys, json, hashlib, zipfile, fnmatch, os
root, zip_path, index_path = map(Path := __import__('pathlib').Path, sys.argv[1:4])
def fail(code, exitcode): print(f"FAIL: verify_handover_bundle {code}", file=sys.stderr); sys.exit(exitcode)
if not zip_path.is_file() or not index_path.is_file(): fail("EVIDBUNDLE_MISSING", 96)
try:
    idx = json.loads(index_path.read_text(encoding="utf-8"))
except Exception:
    fail("EVIDBUNDLE_INDEX_BAD", 97)

def sha(path):
    h=hashlib.sha256()
    with open(path,'rb') as f:
        for chunk in iter(lambda:f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

entries = idx.get("entries") or []
for e in entries:
    p = root / e.get("path","")
    if not p.is_file(): fail("EVIDBUNDLE_MISSING", 96)
    if sha(p) != e.get("sha256"): fail("EVIDBUNDLE_MISMATCH", 98)
    if p.stat().st_size != e.get("size"): fail("EVIDBUNDLE_MISMATCH", 98)

forbidden_patterns = ["*.pem","*.key","*id_rsa*","*ed25519*","*secret*","__MACOSX/*","*.DS_Store","*.dylib","*.so","*.exe"]
try:
    with zipfile.ZipFile(zip_path, "r") as zf:
        infos = zf.infolist()
        for zi in infos:
            fn = zi.filename
            for pat in forbidden_patterns:
                if fnmatch.fnmatch(fn, pat):
                    fail("EVIDBUNDLE_ZIP_FORBIDDEN", 95)
except zipfile.BadZipFile:
    fail("EVIDBUNDLE_ZIP_BAD", 94)

print("PASS: verify_handover_bundle")
PY
