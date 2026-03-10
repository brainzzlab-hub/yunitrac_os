#!/usr/bin/env bash
set -euo pipefail

WORKDIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$WORKDIR"

python3 - <<'PY' "$WORKDIR"
import json
from pathlib import Path
root = Path(__import__("sys").argv[1])

def load_json(p: Path):
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return None

sections = []

def add(name, status, detail=""):
    sections.append((name, status, detail))

# Proof status
runbook = load_json(root / "artifacts/control_plane/runbook_report.json")
if runbook:
    add("Proof status", runbook.get("overall","UNKNOWN"), f"steps={len(runbook.get('steps',[]))}")
else:
    add("Proof status", "MISSING", "")

# Evidence pack
evid = load_json(root / "artifacts/audit/evidence_pack_index.json")
if evid:
    add("Evidence pack index", "PRESENT", f"entries={len(evid.get('entries',[]))}")
else:
    add("Evidence pack index", "MISSING", "")

# SBOM / license
lic = load_json(root / "artifacts/sbom/license_policy_report.json")
if lic:
    add("License policy", "PRESENT", f"violations={lic.get('violations_total','?')}")
else:
    add("License policy", "MISSING", "")

# Audit packet
audit_manifest = load_json(root / "artifacts/audit/index_manifest.json")
if audit_manifest:
    add("Audit packet", "PRESENT", f"files={len(audit_manifest.get('entries',[]))}")
else:
    add("Audit packet", "MISSING", "")

# Incident bundle
incident_manifest = load_json(root / "artifacts/incident/index_manifest.json")
if incident_manifest:
    add("Incident bundle", "PRESENT", f"files={len(incident_manifest.get('entries',[]))}")
else:
    add("Incident bundle", "MISSING", "")

# HITL
hitl_signed = root / "artifacts/control_plane/hitl_markers_signed.json"
hitl_staged = root / "artifacts/control_plane/hitl_markers_staged.json"
if hitl_signed.is_file():
    add("HITL markers", "SIGNED", "")
elif hitl_staged.is_file():
    add("HITL markers", "STAGED", "")
else:
    add("HITL markers", "MISSING", "")

# Control-plane ledger
ledger_signed = root / "artifacts/control_plane/action_ledger_signed.json"
ledger_raw = root / "artifacts/control_plane/action_ledger.jsonl"
if ledger_signed.is_file():
    add("Control-plane ledger", "SIGNED", "")
elif ledger_raw.is_file():
    add("Control-plane ledger", "UNSIGNED", "")
else:
    add("Control-plane ledger", "MISSING", "")

# UX files
ux_files = []
for p in ["artifacts/ux/dashboard_1.txt","artifacts/ux/dashboard_preview.html"]:
    if (root/p).is_file():
        ux_files.append(p)
add("UX artifacts", "PRESENT" if ux_files else "MISSING", f"count={len(ux_files)}")

print("Yunitrack Operator Dashboard")
print("="*32)
for name, status, detail in sections:
    line = f"{name}: {status}"
    if detail:
        line += f" | {detail}"
    print(line)
PY
