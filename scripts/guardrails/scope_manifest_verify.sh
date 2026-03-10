#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
export ROOT
SCOPE="$ROOT/artifacts/lite/scope_manifest.json"
MANIFEST="$ROOT/artifacts/lite/evidence_bundle/manifest.json"

fail() { echo "SECURITY: SCOPE_MANIFEST_INVALID"; exit 1; }

[ -f "$SCOPE" ] || fail
[ -f "$MANIFEST" ] || fail

python3 - <<'PY' || exit 1
import json, os, pathlib, sys
root = pathlib.Path(os.environ.get("ROOT", ".")).resolve()
scope_path = root / "artifacts/lite/scope_manifest.json"
manifest_path = root / "artifacts/lite/evidence_bundle/manifest.json"

def fail():
    sys.exit(1)

try:
    scope = json.loads(scope_path.read_text())
    manifest = json.loads(manifest_path.read_text())
except Exception:
    fail()

req = scope.get("REQUIRED_EQUALITY_SET")
exc = scope.get("EXCLUDED_SET")
if not isinstance(req, list) or not req:
    fail()
if req != sorted(req):
    fail()
if not isinstance(exc, list):
    fail()
# Check reasons/notes present
for entry in exc:
    if not isinstance(entry, dict):
        fail()
    if "pattern" not in entry or ("reason" not in entry and "note" not in entry):
        fail()
# No direct overlap (string equality) between required and excluded patterns
excluded_patterns = {e["pattern"] for e in exc if isinstance(e, dict) and "pattern" in e}
if any(path in excluded_patterns for path in req):
    fail()

# Manifest file list
files = manifest.get("files")
if not isinstance(files, list):
    fail()
files_set = set(files)

# Required files must exist on disk and if under evidence_bundle, must be listed in manifest
for path_str in req:
    p = root / path_str
    if not p.exists():
        fail()
    # If within evidence_bundle, enforce manifest presence
    try:
        eb = root / "artifacts/lite/evidence_bundle"
        if eb in p.parents and p.relative_to(eb).as_posix() not in files_set:
            fail()
    except ValueError:
        pass

sys.exit(0)
PY
