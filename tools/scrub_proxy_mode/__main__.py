#!/usr/bin/env python3
import argparse
import json
import re
import sys
from pathlib import Path

def load_rules(path: Path):
    data = json.loads(path.read_text())
    return data.get("modes", {}).get("DEFAULT", {}).get("rules", []), data.get("quicknames", {})

def compile_rules(rules, quicknames_enabled, quicknames_block):
    active = [r for r in rules if r.get("enabled", False)]
    if quicknames_enabled and quicknames_block.get("patterns"):
        pat = "|".join(quicknames_block.get("patterns", []))
        active.append({"id":"QUICKNAMES","label":"quicknames_heuristic","enabled":True,"severity":"low","pattern":pat,"flags":["i"],"apply_to":"contents","allow_extensions":[],"deny_extensions":[]})
    compiled = []
    for r in active:
        flags = 0
        flist = r.get("flags", [])
        if isinstance(flist, str):
            flist = [flist]
        for f in flist:
            if f in ("i","IGNORECASE"):
                flags |= re.IGNORECASE
            if f in ("m","MULTILINE"):
                flags |= re.MULTILINE
        compiled.append((re.compile(r.get("pattern",""), flags), r))
    return compiled

def scan_text(text: str, compiled):
    counts = {}
    for rx, rule in compiled:
        hits = len(rx.findall(text))
        if hits:
            lbl = rule.get("label","rule")
            counts[lbl] = counts.get(lbl,0) + hits
    return counts

def main():
    ap = argparse.ArgumentParser(description="Scrub Proxy Mode (dry-run by default)")
    ap.add_argument("--rules", default=str(Path("docs/specs/gdpr_default_scrub_rules.json")), help="Rules JSON path")
    ap.add_argument("--custom", help="Custom rules JSON (optional)")
    ap.add_argument("--hitl", action="store_true", help="Enable HITL rules")
    ap.add_argument("--quicknames", action="store_true", help="Enable quicknames heuristic")
    ap.add_argument("--input", dest="input_path", help="Input file (default stdin)")
    ap.add_argument("--enable-forward", action="store_true", help="Allow writing scrubbed output")
    ap.add_argument("--forward-to", dest="forward_to", help="Destination file when forwarding enabled")
    args = ap.parse_args()

    rules_path = Path(args.rules)
    default_rules, qblock = load_rules(rules_path)
    custom_rules = []
    if args.custom:
        cp = Path(args.custom)
        if cp.exists():
            custom_rules, _ = load_rules(cp)
    rules = default_rules + custom_rules
    compiled = compile_rules(rules, args.quicknames, qblock)

    if args.input_path:
        text = Path(args.input_path).read_text(encoding="utf-8", errors="replace")
    else:
        text = sys.stdin.read()

    counts = scan_text(text, compiled)
    total = sum(counts.values())
    summary = {
        "total": total,
        "counts": [{"label": k, "count": v} for k,v in sorted(counts.items())]
    }
    print(json.dumps(summary, sort_keys=True))

    if args.enable_forward:
        if not args.forward_to:
            print("forward_to required when --enable-forward", file=sys.stderr)
            sys.exit(1)
        Path(args.forward_to).write_text(text, encoding="utf-8")

if __name__ == "__main__":
    main()
