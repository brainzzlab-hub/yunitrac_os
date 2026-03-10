#!/usr/bin/env bash
set -euo pipefail

WORKDIR="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$WORKDIR"

INDEX="$WORKDIR/artifacts/audit/evidence_pack_index.json"

fail() { echo "FAIL: verify_evidence_pack $1" >&2; exit "$2"; }

[ -f "$INDEX" ] || fail "EVIDPACK_MISSING" 90

python3 - <<'PY' "$INDEX" "$WORKDIR"  || exit $?
import sys, json, hashlib, os, zipfile
idx_path, root = sys.argv[1], sys.argv[2]
try:
    with open(idx_path, "r", encoding="utf-8") as f:
        data = json.load(f)
except Exception:
    print("FAIL: verify_evidence_pack EVIDPACK_BAD", file=sys.stderr)
    sys.exit(92)

required = set(data.get("overall_required") or [])
entries = data.get("entries") or []
entry_map = {e.get("name"): e for e in entries if "name" in e}

# Check required presence
for r in required:
    if r not in entry_map:
        print("FAIL: verify_evidence_pack EVIDPACK_MISSING", file=sys.stderr)
        sys.exit(90)

def sha256_path(path):
    h=hashlib.sha256()
    with open(path,"rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

forbidden_patterns = ["*.pem","*.key","*id_rsa*","*ed25519*","*secret*","*.dylib","*.so","*.exe","__MACOSX/*","*.DS_Store"]

for e in entries:
    name=e.get("name")
    path=e.get("path")
    sha=e.get("sha256")
    size=e.get("size")
    if not name or not path or sha is None or size is None:
        print("FAIL: verify_evidence_pack EVIDPACK_BAD", file=sys.stderr)
        sys.exit(92)
    full=os.path.join(root, path)
    if not os.path.isfile(full):
        print("FAIL: verify_evidence_pack EVIDPACK_MISSING", file=sys.stderr)
        sys.exit(90)
    st=os.stat(full)
    if st.st_size!=int(size):
        print("FAIL: verify_evidence_pack EVIDPACK_MISMATCH", file=sys.stderr)
        sys.exit(91)
    if sha256_path(full)!=sha:
        print("FAIL: verify_evidence_pack EVIDPACK_MISMATCH", file=sys.stderr)
        sys.exit(91)
    if full.endswith(".zip"):
        try:
            with zipfile.ZipFile(full, "r") as zf:
                infos = zf.infolist()
                for zi in infos:
                    fn = zi.filename
                    # forbid patterns
                    for pat in forbidden_patterns:
                        if zipfile.fnmatch.fnmatch(fn, pat):
                            print("FAIL: verify_evidence_pack EVIDPACK_ZIP_FORBIDDEN", file=sys.stderr)
                            sys.exit(95)
        except Exception:
            print("FAIL: verify_evidence_pack EVIDPACK_ZIP_BAD", file=sys.stderr)
            sys.exit(94)

print("PASS: verify_evidence_pack")
PY
