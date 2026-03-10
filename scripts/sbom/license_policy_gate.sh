#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SBOM_DIR="$ROOT/artifacts/sbom"
CYC="$SBOM_DIR/cyclonedx.json"
SPDX="$SBOM_DIR/spdx.json"
POLICY="$ROOT/docs/policies/license_policy.json"
OUT="$SBOM_DIR/license_policy_report.json"
export CYC SPDX POLICY OUT

EXIT_VIOL=30
EXIT_MISS=31
EXIT_BAD=32

if [ ! -f "$CYC" ]; then
  echo "FAIL: license_policy_gate SEC_LIC_POLICY_MISSING"
  exit $EXIT_MISS
fi
if [ ! -f "$POLICY" ]; then
  echo "FAIL: license_policy_gate SEC_LIC_POLICY_MISSING"
  exit $EXIT_MISS
fi

python3 - <<'PY'
import json, sys, pathlib, os
from datetime import datetime, timezone

sbom_path = pathlib.Path(os.environ["CYC"])
spdx_path = pathlib.Path(os.environ["SPDX"])
policy_path = pathlib.Path(os.environ["POLICY"])
out_path = pathlib.Path(os.environ["OUT"])

EXIT_VIOL=30
EXIT_MISS=31
EXIT_BAD=32

def main():
    try:
        policy = json.loads(policy_path.read_text())
        allow = set(policy.get("allow_licenses", []))
        deny = set(policy.get("deny_licenses", []))
        unknown_behavior = policy.get("unknown_license_behavior", "fail")
    except Exception:
        print("FAIL: license_policy_gate SEC_LIC_POLICY_BAD")
        return EXIT_BAD

    try:
        sbom = json.loads(sbom_path.read_text())
    except Exception:
        print("FAIL: license_policy_gate SEC_LIC_POLICY_BAD")
        return EXIT_BAD

    components = sbom.get("components", []) if isinstance(sbom, dict) else []
    counts = {}
    violations = 0

    for comp in components:
        licenses = comp.get("licenses", [])
        ids = []
        for lic in licenses:
            if isinstance(lic, dict):
                idv = lic.get("license", {}).get("id")
                if idv:
                    ids.append(idv)
        if not ids:
            ids = ["UNKNOWN"]
        for lid in ids:
            counts[lid] = counts.get(lid, 0) + 1
            if lid in deny:
                violations += 1
            elif lid == "UNKNOWN" and unknown_behavior == "fail":
                violations += 1

    report = {
        "version": "1.0",
        "generated_utc": "1970-01-01T00:00:00Z",
        "total_components": len(components),
        "counts": [{"label": k, "count": v} for k, v in sorted(counts.items(), key=lambda x: x[0])],
        "violations_total": violations
    }

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, sort_keys=True, separators=(",", ":")) + "\n")

    if violations > 0:
        print("FAIL: license_policy_gate SEC_LIC_POLICY_VIOLATION")
        return EXIT_VIOL
    print("PASS: license_policy_gate")
    return 0

rc = main()
sys.exit(rc)
PY
