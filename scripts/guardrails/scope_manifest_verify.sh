#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SCOPE="$ROOT/artifacts/lite/scope_manifest.json"
BUNDLE="$ROOT/artifacts/lite/evidence_bundle"
MANIFEST="$BUNDLE/manifest.json"

fail() {
  echo "FAIL: scope_manifest_verify $1"
  exit 1
}

[ -f "$SCOPE" ] || fail "SCOPE_MISSING"
[ -f "$MANIFEST" ] || fail "EVIDENCE_MANIFEST_MISSING"

python3 - <<'PY'
import json
from pathlib import Path
import sys

root = Path(".").resolve()
scope = Path("artifacts/lite/scope_manifest.json")
manifest_path = Path("artifacts/lite/evidence_bundle/manifest.json")
bundle_root = Path("artifacts/lite/evidence_bundle")

fail = lambda msg: (print(f"FAIL: scope_manifest_verify {msg}"), sys.exit(1))

def load_json(path: Path):
    try:
        return json.loads(path.read_text())
    except Exception as exc:
        fail(f"INVALID_JSON {path}: {exc}")

scope_json = load_json(scope)
man_json = load_json(manifest_path)

req = scope_json.get("REQUIRED_EQUALITY_SET")
exc = scope_json.get("EXCLUDED_SET")
if not isinstance(req, list) or len(req) == 0:
    fail("REQUIRED_EQUALITY_SET_INVALID")
if sorted(req) != req:
    fail("REQUIRED_EQUALITY_SET_NOT_SORTED")
if not isinstance(exc, list):
    fail("EXCLUDED_SET_INVALID")
exc_patterns = []
allowed_notes = {"build outputs", "scratch", "ordering variance"}
for item in exc:
    if not isinstance(item, dict):
        fail("EXCLUDED_SET_ENTRY_NOT_OBJECT")
    pat = item.get("pattern")
    note = item.get("note")
    if not isinstance(pat, str) or not pat:
        fail("EXCLUDED_SET_PATTERN_INVALID")
    if not isinstance(note, str) or note not in allowed_notes:
        fail("EXCLUDED_SET_NOTE_INVALID")
    exc_patterns.append(pat)
if sorted(exc, key=lambda x: x.get("pattern")) != exc:
    fail("EXCLUDED_SET_NOT_SORTED")

# Overlap check
if any(p in exc_patterns for p in req):
    fail("REQUIRED_EXCLUDED_OVERLAP")

man_files = []
if not isinstance(man_json, dict) or set(man_json.keys()) != {"files"}:
    fail("MANIFEST_KEYS_INVALID")
files = man_json.get("files")
if not isinstance(files, list):
    fail("MANIFEST_FILES_INVALID")
if sorted(files) != files:
    fail("MANIFEST_FILES_NOT_SORTED")
# determinism: file content equals normalized form
normalized = json.dumps({"files": files}, sort_keys=True, separators=(",", ":"))
if manifest_path.read_text().strip() != normalized:
    fail("MANIFEST_NOT_NORMALIZED")

manifest_set = set(files)
for entry in req:
    p = Path(entry)
    if p.is_absolute():
        fail("REQUIRED_ABSOLUTE_PATH")
    full = Path(entry)
    if full.exists():
        continue
    try:
        rel = p.relative_to(bundle_root)
    except ValueError:
        rel = p
    if rel.as_posix() not in manifest_set:
        fail("REQUIRED_MISSING:" + entry)

print("PASS: scope_manifest_verify SEC_OK")
PY
