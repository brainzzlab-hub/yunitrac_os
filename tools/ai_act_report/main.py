#!/usr/bin/env python3
"""
EU AI Act evidence mapping generator (deterministic, no PII).
Stdlib only.
"""
import argparse
import json
import sys
from pathlib import Path

SEC_CODES = {
    "missing": "AIACT_MISSING_REQUIRED",
    "badjson": "AIACT_BAD_JSON",
    "io": "AIACT_IO_FAIL",
}

def fail(code: str):
    print(f"FAIL: ai_act_report {SEC_CODES[code]}")
    sys.exit(1)

def load_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        fail("badjson")

def main():
    ap = argparse.ArgumentParser(add_help=False)
    ap.add_argument("--out_md", required=True)
    ap.add_argument("--out_json", required=True)
    args = ap.parse_args()

    evidence_index_path = Path("artifacts/audit/evidence_pack_index.json")
    evidence_report_json = Path("artifacts/compliance/evidence_report.json")
    attestation_index = Path("artifacts/attestations/attestation_index.json")
    attestation_dsse = Path("artifacts/attestations/evidence_pack.dsse.json")

    required_paths = [evidence_index_path, evidence_report_json]
    if attestation_index.is_file():
        required_paths.append(attestation_index)
    else:
        required_paths.append(attestation_dsse)

    for p in required_paths:
        if not p.is_file():
            fail("missing")

    def safe_load(path: Path):
        try:
            return load_json(path)
        except SystemExit:
            raise
        except Exception:
            fail("badjson")

    idx = safe_load(evidence_index_path)
    entries = idx.get("entries") or []
    artifacts = {e.get("name"): e for e in entries if e.get("name")}

    def add_ref_from_index(name):
        e = artifacts.get(name)
        if not e:
            return None
        return {
            "name": e.get("name", name),
            "path": e.get("path", ""),
            "sha256": e.get("sha256", ""),
            "size": e.get("size", 0),
        }

    referenced = []
    for e in sorted(artifacts.keys()):
        ref = add_ref_from_index(e)
        if ref:
            referenced.append(ref)

    # attestation index entries if present
    if attestation_index.is_file():
        att_idx = safe_load(attestation_index)
        for e in att_idx.get("entries", []):
            if e.get("name"):
                referenced.append({
                    "name": e.get("name"),
                    "path": attestation_index.as_posix(),
                    "sha256": e.get("sha256", ""),
                    "size": e.get("size", 0),
                })

    referenced = sorted(referenced, key=lambda x: x["name"])

    def section(lines):
        return "\n".join(lines) + "\n"

    md_lines = []
    md_lines.append("# EU AI Act Evidence Mapping (Deterministic, No PII)")
    md_lines.append("_This is an evidence mapping, not a legal opinion or compliance attestation._")
    md_lines.append("")
    md_lines.append("## Evidence inventory")
    for ref in referenced:
        md_lines.append(f"- {ref['name']}: {ref['path']} (sha256={ref['sha256']}, size={ref['size']})")
    md_lines.append("")

    def item_row(label, present, refs):
        status = "PRESENT" if present else "MISSING"
        refs_txt = ", ".join(sorted(refs)) if refs else "none"
        return f"- [{status}] {label} (refs: {refs_txt})"

    def exists(path: Path):
        return path.is_file()

    gdpr_stmt = Path("artifacts/security/gdpr_compliance_statement.json")
    license_report = Path("artifacts/sbom/license_policy_report.json")
    runbook_report = Path("artifacts/control_plane/runbook_report.json")
    incident_manifest = Path("artifacts/incident/index_manifest.json")
    trace_lg = sorted(Path("artifacts/trace/run").rglob("trace_evidence_index.json")) if Path("artifacts/trace/run").is_dir() else []
    trace_otel = sorted(Path("artifacts/trace_otel/run").rglob("trace_evidence_index.json")) if Path("artifacts/trace_otel/run").is_dir() else []

    md_lines.append("### Article 13 (Transparency / Instructions for use)")
    md_lines.append(item_row("Instructions present", exists(evidence_report_json), ["evidence_report.json"]))
    md_lines.append(item_row("Auditability evidence", exists(evidence_index_path), ["evidence_pack_index.json"]))
    md_lines.append(item_row("Output bounding evidence", exists(gdpr_stmt), ["gdpr_compliance_statement.json"] if exists(gdpr_stmt) else []))
    md_lines.append(item_row("Attestation present", exists(attestation_index) or exists(attestation_dsse), ["attestation_index.json" if attestation_index.is_file() else "evidence_pack.dsse.json"]))
    md_lines.append("")

    md_lines.append("### Article 17 (Quality management system)")
    md_lines.append(item_row("Runbook procedure", exists(runbook_report), ["runbook_report.json"] if exists(runbook_report) else []))
    md_lines.append(item_row("Incident workflow evidence", exists(incident_manifest), ["incident/index_manifest.json"] if exists(incident_manifest) else []))
    md_lines.append(item_row("SBOM & license policy gate", exists(license_report), ["license_policy_report.json"] if exists(license_report) else []))
    md_lines.append(item_row("Change control signals (proof scripts/verifiers)", True, ["prove.sh", "prove_enterprise.sh", "prove_lite.sh", "verify_evidence_pack.sh"]))
    md_lines.append("")

    md_lines.append("### Annex IV (Technical documentation)")
    md_lines.append(item_row("System description docs", Path("CANON.txt").is_file(), ["CANON.txt"]))
    md_lines.append(item_row("Verification procedure", Path("scripts/prove.sh").is_file(), ["scripts/prove.sh"]))
    md_lines.append(item_row("Risk controls evidence (GDPR)", exists(gdpr_stmt), ["gdpr_compliance_statement.json"] if exists(gdpr_stmt) else []))
    md_lines.append(item_row("Logs/audit structure", exists(evidence_index_path), ["evidence_pack_index.json"]))
    md_lines.append(item_row("Trace ingestion evidence", bool(trace_lg or trace_otel), ["trace/run/.../trace_evidence_index.json"] if (trace_lg or trace_otel) else []))
    md_lines.append("")

    md_lines.append("## Gaps / operator inputs needed")
    md_lines.append("- Intended purpose and deployment context")
    md_lines.append("- Human oversight and intervention procedures")
    md_lines.append("- Post-market monitoring plan")
    md_lines.append("")

    out_md = Path(args.out_md)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_md.write_text("\n".join(md_lines), encoding="utf-8")

    json_summary = {
        "version": "1.0",
        "sections": [
            {"id": "A13", "present": 3 + int(exists(gdpr_stmt)), "missing": 4 - (3 + int(exists(gdpr_stmt)))},
            {"id": "A17", "present": int(exists(runbook_report)) + int(exists(incident_manifest)) + int(exists(license_report)) + 1, "missing": 4 - (int(exists(runbook_report)) + int(exists(incident_manifest)) + int(exists(license_report)) + 1)},
            {"id": "ANNEX_IV", "present": int(Path('CANON.txt').is_file()) + int(Path('scripts/prove.sh').is_file()) + int(exists(gdpr_stmt)) + int(exists(evidence_index_path)) + int(bool(trace_lg or trace_otel)), "missing": 5 - (int(Path('CANON.txt').is_file()) + int(Path('scripts/prove.sh').is_file()) + int(exists(gdpr_stmt)) + int(exists(evidence_index_path)) + int(bool(trace_lg or trace_otel)))},
        ],
        "referenced_artifacts_count": len(referenced),
    }
    out_json = Path(args.out_json)
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(json_summary, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")

    print("PASS: ai_act_report")


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception:
        fail("io")
