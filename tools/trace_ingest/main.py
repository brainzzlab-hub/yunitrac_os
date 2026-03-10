#!/usr/bin/env python3
"""
Deterministic trace ingestion for LangGraph-style JSONL into Trace Contract v1.
Stdlib only. No payload text stored. Bounded stdout handled by caller.
"""
import argparse
import json
import sys
import hashlib
import struct
from pathlib import Path

SEC = {
    "bad_args": "TRACE_BAD_ARGS",
    "io": "TRACE_IO_FAIL",
    "bad_json": "TRACE_BAD_JSON",
    "unsup": "TRACE_UNSUPPORTED_EVENT",
    "nonascii": "TRACE_NONASCII_FIELD",
    "policy": "TRACE_POLICY_MISSING",
    "internal": "TRACE_INTERNAL",
}

EVENT_CODES = {
    "LLM_CALL": 1,
    "TOOL_CALL": 2,
    "TOOL_RESULT": 3,
    "HITL_REQUEST": 4,
    "HITL_DECISION": 5,
    "STATE": 6,
    "ERROR": 7,
    "FINAL": 8,
}

STATUS_CODES = {
    "OK": 0,
    "FAIL": 1,
    "REDACTED": 2,
}


def fail(code: str):
    print(f"FAIL: trace_ingest {SEC[code]}")
    sys.exit(1)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        fail("bad_json")


def normalize_payload(obj):
    if obj is None:
        return b""
    if isinstance(obj, str):
        return obj.replace("\r\n", "\n").rstrip().encode("utf-8")
    if isinstance(obj, (dict, list)):
        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
    # numbers / bools -> stringify
    return str(obj).encode("utf-8")


def ascii_only(s: str) -> bool:
    try:
        s.encode("ascii")
        return True
    except UnicodeEncodeError:
        return False


def compile_pii_rules(rules_path: Path):
    if not rules_path.is_file():
        fail("policy")
    try:
        data = json.loads(rules_path.read_text(encoding="utf-8"))
    except Exception:
        fail("bad_json")
    categories = []
    for cat in data.get("categories", []):
        if not cat.get("enabled_by_default", False):
            continue
        cid = cat.get("id")
        regex = cat.get("regex")
        if not cid or not regex:
            continue
        categories.append(cat)
    import re

    compiled = []
    for cat in categories:
        try:
            compiled.append((cat["id"], re.compile(cat["regex"])))
        except re.error:
            fail("bad_json")
    return compiled, data.get("version", "1.0")


def main():
    ap = argparse.ArgumentParser(add_help=False)
    ap.add_argument("--in", dest="inp", required=True)
    ap.add_argument("--out_dir", required=True)
    ap.add_argument("--rules", default="docs/specs/gdpr_default_scrub_rules.json")
    args = ap.parse_args()

    in_path = Path(args.inp)
    out_dir = Path(args.out_dir)
    rules_path = Path(args.rules)

    if not in_path.is_file():
        fail("io")
    resolved_out = out_dir.resolve()
    parts = list(resolved_out.parts)
    if "artifacts" not in parts:
        fail("bad_args")
    idx = parts.index("artifacts")
    if idx + 1 >= len(parts) or parts[idx + 1] != "trace":
        fail("bad_args")

    try:
        raw_bytes = in_path.read_bytes()
    except Exception:
        fail("io")

    input_sha = sha256_bytes(raw_bytes)
    compiled_rules, rules_version = compile_pii_rules(rules_path)

    run_id_src = f"{input_sha}:{rules_version}".encode("utf-8")
    run_id = sha256_bytes(run_id_src)[:16]
    final_out = out_dir / run_id
    final_out.mkdir(parents=True, exist_ok=True)

    events = []
    pii_counts = {}
    event_type_counts = {}
    events_redacted = 0

    lines = in_path.read_text(encoding="utf-8", errors="replace").splitlines()
    for idx, line in enumerate(lines):
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
        except Exception:
            fail("bad_json")
        if not isinstance(obj, dict):
            fail("bad_json")
        etype = obj.get("event_type")
        if etype not in EVENT_CODES:
            fail("unsup")
        step = obj.get("step")
        if not isinstance(step, int) or step < 0:
            fail("bad_args")
        agent_id = obj.get("agent_id", "agent0")
        span = obj.get("span", "")
        status = obj.get("status", "OK")
        if status not in STATUS_CODES:
            fail("bad_args")
        if not (isinstance(agent_id, str) and isinstance(span, str)):
            fail("bad_args")
        if not ascii_only(agent_id) or not ascii_only(span):
            fail("nonascii")

        payload_bytes = normalize_payload(obj.get("payload"))
        redacted = False
        text_for_scan = payload_bytes.decode("utf-8", errors="ignore")
        for cid, rx in compiled_rules:
            hits = len(rx.findall(text_for_scan))
            if hits > 0:
                pii_counts[cid] = pii_counts.get(cid, 0) + hits
                redacted = True
        if redacted:
            payload_bytes = b""
            status = "REDACTED"
            events_redacted += 1

        payload_sha = sha256_bytes(payload_bytes)
        payload_len = len(payload_bytes)

        event_type_counts[etype] = event_type_counts.get(etype, 0) + 1

        events.append(
            {
                "event_type": etype,
                "status": status,
                "step": step,
                "agent_id": agent_id,
                "span": span,
                "payload_sha256": payload_sha,
                "payload_len": payload_len,
            }
        )

    # Sort canonical order
    events.sort(
        key=lambda e: (
            e["agent_id"],
            e["step"],
            e["event_type"],
            e["span"],
            e["payload_sha256"],
        )
    )

    # Binary encoding
    buf = []
    buf.append(struct.pack("<I", len(events)))
    for e in events:
        buf.append(struct.pack("<B", EVENT_CODES[e["event_type"]]))
        buf.append(struct.pack("<B", STATUS_CODES[e["status"]]))
        buf.append(struct.pack("<I", e["step"]))
        agent_b = e["agent_id"].encode("ascii")
        span_b = e["span"].encode("ascii")
        if len(agent_b) > 255 or len(span_b) > 255:
            fail("bad_args")
        buf.append(struct.pack("<B", len(agent_b)) + agent_b)
        buf.append(struct.pack("<B", len(span_b)) + span_b)
        buf.append(bytes.fromhex(e["payload_sha256"]))
        buf.append(struct.pack("<I", e["payload_len"]))
    canonical_bytes = b"".join(buf)
    canon_sha = sha256_bytes(canonical_bytes)

    # Evidence index
    idx = {
        "version": "1.0",
        "run_id": run_id,
        "input_trace_sha256": input_sha,
        "input_trace_bytes": len(raw_bytes),
        "rules_version": rules_version if isinstance(rules_version, str) else str(rules_version),
        "events_total": len(events),
        "events_redacted": events_redacted,
        "event_type_counts": {k: event_type_counts[k] for k in sorted(event_type_counts)},
        "pii_category_counts": {k: pii_counts[k] for k in sorted(pii_counts)},
        "canon_events_sha256": canon_sha,
        "canon_events_bytes": len(canonical_bytes),
    }

    # Write artifacts
    (final_out / "canonical_events.bin").write_bytes(canonical_bytes)
    (final_out / "trace_evidence_index.json").write_text(
        json.dumps(idx, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8"
    )
    (final_out / "ingest_status.json").write_text(
        json.dumps({"status": "PASS", "seccode": "TRACE_OK"}, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )

    print("PASS: trace_ingest")


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception:
        fail("internal")
