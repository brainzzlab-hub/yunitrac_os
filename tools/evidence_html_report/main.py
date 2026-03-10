#!/usr/bin/env python3
"""
Deterministic, PII-free HTML evidence report.
Stdlib only. Bounded stdout.
"""
import argparse
import json
import sys
from pathlib import Path

SEC_CODES = {
    "missing": "EHTML_MISSING_REQUIRED",
    "badjson": "EHTML_BAD_JSON",
    "io": "EHTML_IO_FAIL",
}


def fail(code: str):
    print(f"FAIL: evidence_html_report {SEC_CODES[code]}")
    sys.exit(1)


def load_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        fail("badjson")


def main():
    ap = argparse.ArgumentParser(add_help=False)
    ap.add_argument("--evidence_index", required=True)
    ap.add_argument("--out_html", required=True)
    ap.add_argument("--out_json", required=True)
    args = ap.parse_args()

    idx_path = Path(args.evidence_index)
    if not idx_path.is_file():
        fail("missing")
    idx = load_json(idx_path)
    entries = idx.get("entries") or []
    artifacts = {e.get("name"): e for e in entries if e.get("name")}
    inv = sorted(
        [
            {
                "name": name,
                "path": str(e.get("path", "")),
                "sha256": e.get("sha256", ""),
                "size": e.get("size", 0),
            }
            for name, e in artifacts.items()
        ],
        key=lambda x: x["name"],
    )

    # Optional inputs
    def read_opt(rel):
        p = Path(rel)
        return load_json(p) if p.is_file() else None

    runbook = read_opt("artifacts/control_plane/runbook_report.json")
    gdpr = read_opt("artifacts/security/gdpr_findings.json")
    gdpr_stmt = read_opt("artifacts/security/gdpr_compliance_statement.json")
    license_r = read_opt("artifacts/sbom/license_policy_report.json")
    audit_manifest = Path("artifacts/audit/index_manifest.json").is_file()
    incident_manifest = Path("artifacts/incident/index_manifest.json").is_file()

    def latest_trace(base: Path):
        run_dir = base / "run"
        if not run_dir.is_dir():
            return None
        candidates = sorted([p for p in run_dir.iterdir() if p.is_dir()], key=lambda x: x.name)
        if not candidates:
            return None
        latest = candidates[-1] / "trace_evidence_index.json"
        return load_json(latest) if latest.is_file() else None

    lg_trace = latest_trace(Path("artifacts/trace"))
    otel_trace = latest_trace(Path("artifacts/trace_otel"))
    lc_trace = latest_trace(Path("artifacts/trace_langchain"))

    overall = "UNKNOWN"
    if runbook and isinstance(runbook, dict):
        overall = runbook.get("overall", "UNKNOWN")

    gdpr_summary = []
    if gdpr and isinstance(gdpr, dict):
        for item in gdpr.get("counts", []):
            if isinstance(item, dict) and "label" in item and "count" in item:
                gdpr_summary.append(f"{item['label']}={item['count']}")
    gdpr_stmt_summary = []
    if gdpr_stmt and isinstance(gdpr_stmt, dict):
        verdict = gdpr_stmt.get("verdict", "UNKNOWN")
        statement = gdpr_stmt.get("statement", "UNKNOWN")
        rules_version = gdpr_stmt.get("rules_version", "UNKNOWN")
        cats = gdpr_stmt.get("categories_scanned", [])
        buckets = {
            "audit": gdpr_stmt.get("findings_in_audit_bucket", 0),
            "metrics": gdpr_stmt.get("findings_in_metrics_bucket", 0),
            "security": gdpr_stmt.get("findings_in_security_bucket", 0),
        }
        gdpr_stmt_summary.append(f"verdict={verdict}")
        gdpr_stmt_summary.append(f"statement={statement}")
        gdpr_stmt_summary.append(f"rules_version={rules_version}")
        gdpr_stmt_summary.append(f"categories_scanned_count={len(cats) if isinstance(cats, list) else 0}")
        gdpr_stmt_summary.append(
            "bucket_counts=" + ",".join(f"{k}={buckets[k]}" for k in sorted(buckets.keys()))
        )

    license_summary = []
    if license_r and isinstance(license_r, dict):
        for k, v in sorted(license_r.items()):
            if isinstance(v, (int, float, str)):
                license_summary.append(f"{k}={v}")

    def trace_summary(label: str, data: dict):
        if not data or not isinstance(data, dict):
            return [f"{label}: MISSING"]
        ev_counts = data.get("event_type_counts", {}) if isinstance(data.get("event_type_counts"), dict) else {}
        ev_summary = ",".join(f"{k}={ev_counts[k]}" for k in sorted(ev_counts))
        pii_counts = data.get("pii_category_counts", {}) if isinstance(data.get("pii_category_counts"), dict) else {}
        pii_nonzero = sum(1 for v in pii_counts.values() if v)
        return [
            f"{label}: run_id={data.get('run_id','')}",
            f"{label}: input_sha={str(data.get('input_trace_sha256',''))[:12]}",
            f"{label}: events_total={data.get('events_total',0)} redacted={data.get('events_redacted',0)}",
            f"{label}: event_types={ev_summary}",
            f"{label}: pii_nonzero_categories={pii_nonzero}",
            f"{label}: canon_sha={str(data.get('canon_events_sha256',''))[:12]}",
        ]

    trace_lines = []
    trace_lines.extend(trace_summary("LangGraph trace", lg_trace))
    trace_lines.extend(trace_summary("OTEL trace", otel_trace))
    trace_lines.extend(trace_summary("LangChain trace", lc_trace))

    # Build HTML
    def esc(s: str) -> str:
        return (
            s.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
        )

    lines = []
    lines.append("<!doctype html>")
    lines.append("<html><head><meta charset='utf-8'>")
    lines.append("<title>YuniTrack Evidence Report</title>")
    lines.append(
        "<style>body{font-family:system-ui;margin:24px;}table{border-collapse:collapse;width:100%;}"
        "th,td{border:1px solid #ccc;padding:6px;text-align:left;}pre{white-space:pre-wrap;}"
        ".muted{color:#666;}</style></head><body>"
    )
    lines.append("<h1>YuniTrack Evidence Report</h1>")
    lines.append("<p class='muted'>Evidence summary, not legal advice.</p>")
    lines.append("<h2>Overall status</h2>")
    lines.append(f"<p><strong>{esc(str(overall))}</strong></p>")

    lines.append("<h2>Evidence inventory</h2>")
    lines.append("<table><tr><th>Name</th><th>Path</th><th>SHA256</th><th>Size</th></tr>")
    for item in inv:
        lines.append(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>".format(
                esc(item["name"]), esc(item["path"]), esc(item["sha256"]), item["size"]
            )
        )
    lines.append("</table>")

    lines.append("<h2>Trace Evidence</h2>")
    lines.append("<ul>")
    for s in trace_lines:
        lines.append(f"<li>{esc(s)}</li>")
    lines.append("</ul>")

    lines.append("<h2>GDPR summary</h2>")
    if gdpr_summary or gdpr_stmt_summary:
        lines.append("<ul>")
        for s in gdpr_summary:
            lines.append(f"<li>{esc(s)}</li>")
        for s in gdpr_stmt_summary:
            lines.append(f"<li>{esc(s)}</li>")
        lines.append("</ul>")
    else:
        lines.append("<p>MISSING</p>")

    lines.append("<h2>SBOM / license summary</h2>")
    if license_summary:
        lines.append("<ul>")
        for s in license_summary:
            lines.append(f"<li>{esc(s)}</li>")
        lines.append("</ul>")
    else:
        lines.append("<p>MISSING</p>")

    lines.append("<h2>Manifests</h2>")
    lines.append(f"<p>Audit manifest: {'YES' if audit_manifest else 'NO'}</p>")
    lines.append(f"<p>Incident manifest: {'YES' if incident_manifest else 'NO'}</p>")

    lines.append("<hr>")
    lines.append("<p class='muted'>Generated by yunitrack_os | Stateless | No data retained</p>")
    lines.append("</body></html>")

    out_html = Path(args.out_html)
    try:
        out_html.parent.mkdir(parents=True, exist_ok=True)
        out_html.write_text("\n".join(lines), encoding="utf-8")
    except Exception:
        fail("io")

    json_summary = {
        "version": "1.0",
        "inputs_required_present": True,
        "referenced_artifacts_count": len(inv),
        "sections": [
            {"id": "overall", "items": 1},
            {"id": "inventory", "items": len(inv)},
            {"id": "gdpr", "items": len(gdpr_summary) + len(gdpr_stmt_summary)},
            {"id": "sbom", "items": len(license_summary)},
            {"id": "trace", "items": len(trace_lines)},
            {"id": "manifests", "items": 2},
        ],
    }
    out_json = Path(args.out_json)
    try:
        out_json.parent.mkdir(parents=True, exist_ok=True)
        out_json.write_text(
            json.dumps(json_summary, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8"
        )
    except Exception:
        fail("io")

    print("PASS: evidence_html_report")


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception:
        fail("io")
