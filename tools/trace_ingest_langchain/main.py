#!/usr/bin/env python3
"""
Ingest LangChain hash-only ledger JSONL -> Trace Contract v1.
Stdlib only. No payload text stored.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path

SEC = {
    "bad_args": "LCH_BAD_ARGS",
    "io": "LCH_IO_FAIL",
    "bad_json": "LCH_BAD_JSON",
    "nonascii": "LCH_NONASCII_FIELD",
    "internal": "LCH_INTERNAL",
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

STATUS_CODES = {"OK": 0, "FAIL": 1, "REDACTED": 2}


def fail(code: str):
    print(f"FAIL: langchain_trace_ingest {SEC[code]}")
    raise SystemExit(1)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest(), path.stat().st_size


def load_json(line: str):
    try:
        return json.loads(line)
    except Exception:
        fail("bad_json")


def is_ascii(s: str) -> bool:
    try:
        s.encode("ascii")
        return True
    except UnicodeEncodeError:
        return False


def encode_events(events):
    buf = [struct.pack("<I", len(events))]
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
    return b"".join(buf)


def main():
    ap = argparse.ArgumentParser(add_help=False)
    ap.add_argument("--in", dest="inp", required=True)
    args = ap.parse_args()

    ledger_path = Path(args.inp)
    if not ledger_path.is_file():
        fail("io")

    ledger_sha, ledger_bytes = sha256_file(ledger_path)
    run_id = sha256_bytes(f"{ledger_sha}:langchain_ledger_v1".encode("utf-8"))[:16]
    out_base = Path("artifacts/trace_langchain/run") / run_id
    out_base.mkdir(parents=True, exist_ok=True)

    events = []
    event_type_counts = {}
    with ledger_path.open("r", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            obj = load_json(line)
            if obj.get("v") != 1:
                fail("bad_json")
            seq = obj.get("seq")
            if not isinstance(seq, int) or seq < 0:
                fail("bad_json")
            event = obj.get("event")
            if event not in {"tool_start", "tool_end", "agent_action", "final", "error"}:
                fail("bad_json")
            agent_id = obj.get("agent_id", "agent0")
            tool = obj.get("tool") or ""
            status = obj.get("status", "OK")
            if not (isinstance(agent_id, str) and is_ascii(agent_id)) or not is_ascii(tool):
                fail("nonascii")
            etype = {
                "tool_start": "TOOL_CALL",
                "agent_action": "TOOL_CALL",
                "tool_end": "TOOL_RESULT",
                "final": "FINAL",
                "error": "ERROR",
            }[event]
            event_type_counts[etype] = event_type_counts.get(etype, 0) + 1
            events.append(
                {
                    "event_type": etype,
                    "status": "OK" if status == "OK" else "FAIL",
                    "step": seq,
                    "agent_id": agent_id,
                    "span": tool,
                    "payload_sha256": sha256_bytes(b""),
                    "payload_len": 0,
                }
            )

    events.sort(key=lambda e: (e["agent_id"], e["step"], e["event_type"], e["span"], e["payload_sha256"]))
    canonical = encode_events(events)
    canon_sha = sha256_bytes(canonical)

    idx = {
        "version": "1.0",
        "adapter_id": "langchain_ledger_v1",
        "run_id": run_id,
        "ledger_sha256": ledger_sha,
        "ledger_bytes": ledger_bytes,
        "events_total": len(events),
        "events_redacted": 0,
        "event_type_counts": {k: event_type_counts[k] for k in sorted(event_type_counts)},
        "pii_category_counts": {},
        "canon_events_sha256": canon_sha,
        "canon_events_bytes": len(canonical),
    }

    (out_base / "canonical_events.bin").write_bytes(canonical)
    (out_base / "trace_evidence_index.json").write_text(
        json.dumps(idx, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8"
    )
    (out_base / "ingest_status.json").write_text(
        json.dumps({"status": "PASS", "seccode": "LCH_OK"}, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )

    print("PASS: langchain_trace_ingest")


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception:
        fail("internal")
