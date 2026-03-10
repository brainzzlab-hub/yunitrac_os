#!/usr/bin/env bash
set -euo pipefail

WORKDIR="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$WORKDIR"

OUT_DIR="$WORKDIR/artifacts/audit"
OUT_FILE="$OUT_DIR/evidence_pack_index.json"
mkdir -p "$OUT_DIR"

required_names=(runbook_report audit_packet_manifest sbom_cyclonedx license_policy_report)
optional_names=(incident_bundle_manifest gdpr_findings action_ledger_signed)

name_list=(
  runbook_report
  audit_packet_manifest
  sbom_cyclonedx
  license_policy_report
  incident_bundle_manifest
  gdpr_findings
  action_ledger_signed
)
path_list=(
  "artifacts/control_plane/runbook_report.json"
  "artifacts/audit/index_manifest.json"
  "artifacts/sbom/cyclonedx.json"
  "artifacts/sbom/license_policy_report.json"
  "artifacts/incident/index_manifest.json"
  "artifacts/security/gdpr_findings.json"
  "artifacts/control_plane/action_ledger_signed.json"
)

is_required() {
  local n="$1"
  for r in "${required_names[@]}"; do
    [ "$r" = "$n" ] && return 0
  done
  return 1
}

fail() { echo "FAIL: generate_evidence_index SEC_EVIDENCE_INDEX_MISSING" >&2; exit 1; }

entries=()
for idx in "${!name_list[@]}"; do
  name="${name_list[$idx]}"
  rel="${path_list[$idx]}"
  if [ ! -f "$WORKDIR/$rel" ]; then
    is_required "$name" && fail || continue
  fi
  read -r sha size <<<"$(python3 - <<'PY' "$WORKDIR/$rel"
import hashlib, os, sys
path=sys.argv[1]
with open(path,'rb') as f: data=f.read()
print(hashlib.sha256(data).hexdigest(), len(data))
PY
)"
  entries+=("${name}|${rel}|${sha}|${size}")
done

IFS=$'\n' entries_sorted=($(printf '%s\n' "${entries[@]}" | LC_ALL=C sort))

python3 - <<'PY' "${entries_sorted[@]}" >"$OUT_FILE"
import sys, json, datetime
items=[]
for arg in sys.argv[1:]:
    name,path,sha,size=arg.split("|")
    items.append({"name":name,"path":path,"sha256":sha,"size":int(size)})
items.sort(key=lambda x:x["name"])
out={
    "version":"1.0",
    "generated_utc": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
    "entries": items,
    "overall_required": ["runbook_report","audit_packet_manifest","sbom_cyclonedx","license_policy_report"],
    "optional": ["incident_bundle_manifest","gdpr_findings","action_ledger_signed"],
    "total_entries": len(items),
}
json.dump(out, sys.stdout, sort_keys=True, separators=(",",":"))
sys.stdout.write("\n")
PY

echo "PASS: generate_evidence_index"
