#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
DEFAULT_RULES="$ROOT/docs/specs/gdpr_default_scrub_rules.json"
CUSTOM_RULES="${GDPR_SCRUB_CUSTOM_RULES_JSON:-}"
HITL="${GDPR_SCRUB_HITL:-0}"
QUICKNAMES="${GDPR_SCRUB_QUICKNAMES:-0}"
OUT_DIR="$ROOT/artifacts/security"
OUT_FILE="$OUT_DIR/gdpr_findings.json"
OUT_STATEMENT="$OUT_DIR/gdpr_compliance_statement.json"

python3 - <<PY
import json, os, re, sys, pathlib, time
from typing import List, Dict

root = pathlib.Path("$ROOT")
default_rules_path = pathlib.Path("$DEFAULT_RULES")
custom_rules_env = "$CUSTOM_RULES"
hitl_enabled = "$HITL" == "1"
quicknames_enabled = "$QUICKNAMES" == "1"
out_dir = pathlib.Path("$OUT_DIR")
out_file = pathlib.Path("$OUT_FILE")
out_statement = pathlib.Path("$OUT_STATEMENT")

EXIT_HIT = 20
EXIT_MISSING = 21
EXIT_RULES_BAD = 22
EXIT_INTERNAL = 23

MAX_FILES = 50_000
MAX_BYTES = 2_000_000

def write_statement(*, categories, audit_hits, metrics_hits, security_hits, verdict, seccode, statement):
    out_dir.mkdir(parents=True, exist_ok=True)
    payload = {
        "version": "1.0",
        "statement": statement,
        "scope": "Configured regex patterns; scans audit/metrics/security buckets; content not retained; not legal advice",
        "rules_version": "1.0",
        "categories_scanned": categories,
        "findings_in_audit_bucket": audit_hits,
        "findings_in_metrics_bucket": metrics_hits,
        "findings_in_security_bucket": security_hits,
        "verdict": verdict,
        "seccode": seccode,
    }
    out_statement.write_text(json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")

try:
    if not default_rules_path.exists():
        write_statement(categories=[], audit_hits=0, metrics_hits=0, security_hits=0,
                        verdict="FAIL", seccode="GDPR_SCAN_MISSING_INPUTS", statement="PII_PATTERN_SCAN_FAIL")
        print("FAIL: gdpr_scrub_scan GDPR_SCAN_MISSING_INPUTS")
        sys.exit(EXIT_MISSING)

    def load_rules(path: pathlib.Path):
        try:
            data = json.loads(path.read_text())
            return data
        except Exception:
            write_statement(categories=[], audit_hits=0, metrics_hits=0, security_hits=0,
                            verdict="FAIL", seccode="GDPR_SCAN_BAD_RULES", statement="PII_PATTERN_SCAN_FAIL")
            print("FAIL: gdpr_scrub_scan GDPR_SCAN_BAD_RULES")
            sys.exit(EXIT_RULES_BAD)

    default_rules = load_rules(default_rules_path)
    custom_rules = None
    if custom_rules_env:
        p = pathlib.Path(custom_rules_env)
        if p.exists():
            custom_rules = load_rules(p)
        else:
            write_statement(categories=[], audit_hits=0, metrics_hits=0, security_hits=0,
                            verdict="FAIL", seccode="GDPR_SCAN_MISSING_INPUTS", statement="PII_PATTERN_SCAN_FAIL")
            print("FAIL: gdpr_scrub_scan GDPR_SCAN_MISSING_INPUTS")
            sys.exit(EXIT_MISSING)

    def extract_categories(rules_obj):
        cats = []
        for c in rules_obj.get("categories", []) if isinstance(rules_obj, dict) else []:
            cid = c.get("id")
            if cid:
                cats.append(cid)
        return sorted(set(cats))

    categories_scanned = extract_categories(default_rules)

    def collect_active(rules_obj, key: str):
        if not rules_obj or "modes" not in rules_obj:
            return []
        mode = rules_obj["modes"].get(key, {})
        if isinstance(mode, dict):
            return mode.get("rules", [])
        return []

    active_rules: List[Dict] = []
    active_rules += collect_active(default_rules, "DEFAULT")
    if custom_rules:
        active_rules += collect_active(custom_rules, "DEFAULT")
    if hitl_enabled:
        active_rules += collect_active(default_rules, "HITL")
        if custom_rules:
            active_rules += collect_active(custom_rules, "HITL")

    quicknames_block = default_rules.get("quicknames", {}) if isinstance(default_rules, dict) else {}
    if quicknames_enabled and quicknames_block.get("patterns"):
        active_rules.append({
            "id": "QUICKNAMES",
            "label": "quicknames_heuristic",
            "enabled": True,
            "severity": "low",
            "pattern": "|".join(quicknames_block.get("patterns", [])),
            "flags": "i",
            "apply_to": "contents",
            "allow_extensions": [],
            "deny_extensions": []
        })

    # drop disabled
    active_rules = [r for r in active_rules if r.get("enabled", False)]

    def compile_rule(r):
        pattern = r.get("pattern", "")
        flags = 0
        flist = r.get("flags", [])
        if isinstance(flist, str):
            flist = [flist]
        for f in flist:
            if f in ("i", "IGNORECASE"):
                flags |= re.IGNORECASE
            if f in ("m", "MULTILINE"):
                flags |= re.MULTILINE
        return re.compile(pattern, flags), r

    compiled = []
    try:
        for r in active_rules:
            compiled.append(compile_rule(r))
    except re.error:
        write_statement(categories=categories_scanned, audit_hits=0, metrics_hits=0, security_hits=0,
                        verdict="FAIL", seccode="GDPR_SCAN_BAD_RULES", statement="PII_PATTERN_SCAN_FAIL")
        print("FAIL: gdpr_scrub_scan GDPR_SCAN_BAD_RULES")
        sys.exit(EXIT_RULES_BAD)

    roots = [root / "artifacts"]
    excludes = {".git", "target", "node_modules", "dist"}

    files: List[pathlib.Path] = []
    for base in roots:
        if not base.exists():
            continue
        for p in base.rglob("*"):
            if p.is_dir():
                if p.name in excludes:
                    # skip subtree
                    parts = p.parts
                continue
            # skip excluded ancestors
            if any(seg in excludes for seg in p.parts):
                continue
            if not p.is_file():
                continue
            files.append(p)

    files = sorted(files, key=lambda x: str(x))
    if len(files) > MAX_FILES:
        write_statement(categories=categories_scanned, audit_hits=0, metrics_hits=0, security_hits=0,
                        verdict="FAIL", seccode="GDPR_SCAN_INTERNAL", statement="PII_PATTERN_SCAN_FAIL")
        print("FAIL: gdpr_scrub_scan GDPR_SCAN_INTERNAL")
        sys.exit(EXIT_INTERNAL)

    counts = {}
    total_hits = 0
    audit_hits = 0
    metrics_hits = 0
    security_hits = 0
    default_allow_exts = {"txt", "log", "md"}
    for path in files:
        ext = path.suffix.lower().lstrip('.')
        try:
            size = path.stat().st_size
        except FileNotFoundError:
            continue
        if size > MAX_BYTES:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        for regex, rule in compiled:
            allow = rule.get("allow_extensions") or []
            deny = rule.get("deny_extensions") or []
            if not allow:
                if ext and ext not in default_allow_exts:
                    continue
            if allow and ext and ext not in [a.lower() for a in allow]:
                continue
            if deny and ext and ext in [d.lower() for d in deny]:
                continue
            hits = len(regex.findall(text))
            if hits > 0:
                lbl = rule.get("label", "unknown")
                counts[lbl] = counts.get(lbl, 0) + hits
                total_hits += hits
                try:
                    rel_parts = path.relative_to(root).parts
                    bucket = rel_parts[1] if len(rel_parts) > 1 else ""
                except ValueError:
                    bucket = ""
                if bucket == "audit":
                    audit_hits += hits
                elif bucket == "metrics":
                    metrics_hits += hits
                elif bucket == "security":
                    security_hits += hits

    counts_items = sorted(counts.items(), key=lambda x: x[0])
    findings = {
        "version": "1.0",
        "generated_utc": "1970-01-01T00:00:00Z",
        "mode": "DEFAULT" + ("+CUSTOM" if custom_rules else "") + ("+HITL" if hitl_enabled else ""),
        "counts": [{"label": k, "count": v} for k, v in counts_items],
        "total": total_hits,
    }

    out_dir.mkdir(parents=True, exist_ok=True)
    out_file.write_text(json.dumps(findings, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")

    if total_hits > 0:
        write_statement(categories=categories_scanned, audit_hits=audit_hits, metrics_hits=metrics_hits, security_hits=security_hits,
                        verdict="FAIL", seccode="GDPR_SCAN_HIT", statement="PII_PATTERN_SCAN_FAIL")
        print("FAIL: gdpr_scrub_scan GDPR_SCAN_HIT")
        sys.exit(EXIT_HIT)

    write_statement(categories=categories_scanned, audit_hits=audit_hits, metrics_hits=metrics_hits, security_hits=security_hits,
                    verdict="PASS", seccode="GDPR_SCAN_PASS", statement="PII_PATTERN_SCAN_PASS")
    print("PASS: gdpr_scrub_scan")
    sys.exit(0)

except SystemExit:
    raise
except Exception:
    write_statement(categories=[], audit_hits=0, metrics_hits=0, security_hits=0,
                    verdict="FAIL", seccode="GDPR_SCAN_INTERNAL", statement="PII_PATTERN_SCAN_FAIL")
    print("FAIL: gdpr_scrub_scan GDPR_SCAN_INTERNAL")
    sys.exit(EXIT_INTERNAL)
PY
