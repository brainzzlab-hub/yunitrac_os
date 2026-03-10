#!/usr/bin/env python3
"""
Offline demo: simulate LangChain events and emit hash-only ledger.
No external calls, deterministic output.
"""
import json
from pathlib import Path
from hashlib import sha256

LEDGER = Path("artifacts/control_plane/action_ledger.jsonl")
LEDGER.parent.mkdir(parents=True, exist_ok=True)


def h(s: str) -> str:
    return sha256(s.encode("utf-8")).hexdigest()


events = [
    {"v": 1, "seq": 0, "event": "tool_start", "agent_id": "agent0", "tool": "search", "input_sha256": h("query"), "input_len": 5, "output_sha256": None, "output_len": None, "status": "OK"},
    {"v": 1, "seq": 1, "event": "tool_end", "agent_id": "agent0", "tool": "search", "input_sha256": None, "input_len": None, "output_sha256": h("result"), "output_len": 6, "status": "OK"},
    {"v": 1, "seq": 2, "event": "agent_action", "agent_id": "agent0", "tool": "summarize", "input_sha256": h("result"), "input_len": 6, "output_sha256": None, "output_len": None, "status": "OK"},
    {"v": 1, "seq": 3, "event": "tool_end", "agent_id": "agent0", "tool": "summarize", "input_sha256": None, "input_len": None, "output_sha256": h("summary"), "output_len": 7, "status": "OK"},
    {"v": 1, "seq": 4, "event": "final", "agent_id": "agent0", "tool": None, "input_sha256": None, "input_len": None, "output_sha256": h("done"), "output_len": 4, "status": "OK"},
]

with LEDGER.open("w", encoding="utf-8") as f:
    for e in events:
        f.write(json.dumps(e, sort_keys=True, separators=(",", ":")) + "\n")

print("PASS: demo_agent")  # bounded single line
