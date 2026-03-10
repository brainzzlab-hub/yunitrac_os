#!/usr/bin/env python3
"""
LangChain-compatible hash-only callback (deterministic, no PII, no timestamps).
"""
import hashlib
import json
from pathlib import Path


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def safe_bytes(obj) -> bytes:
    if obj is None:
        return b""
    if isinstance(obj, str):
        return obj.encode("utf-8")
    try:
        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
    except Exception:
        return str(obj).encode("utf-8")


def is_ascii(s: str) -> bool:
    try:
        s.encode("ascii")
        return True
    except UnicodeEncodeError:
        return False


class YuniTrackCallbackHashOnly:
    def __init__(self, ledger_path="artifacts/control_plane/action_ledger.jsonl", agent_id="agent0"):
        self.ledger_path = Path(ledger_path)
        self.agent_id = agent_id
        self.seq = 0
        self.ledger_path.parent.mkdir(parents=True, exist_ok=True)

    # LangChain BaseCallbackHandler-compatible attributes
    @property
    def ignore_llm(self):
        return False

    def _append(self, entry):
        try:
            line = json.dumps(entry, sort_keys=True, separators=(",", ":")) + "\n"
            with self.ledger_path.open("a", encoding="utf-8") as f:
                f.write(line)
        except Exception:
            # bounded: silent fail; ingest will fail if ledger missing
            pass
        self.seq += 1

    def _mk_entry(self, event, tool=None, input_obj=None, output_obj=None, status="OK"):
        aid = self.agent_id or "agent0"
        if not is_ascii(aid) or (tool and not is_ascii(tool)):
            return
        inp_b = safe_bytes(input_obj)
        out_b = safe_bytes(output_obj)
        entry = {
            "v": 1,
            "seq": self.seq,
            "event": event,
            "agent_id": aid,
            "tool": tool if tool else None,
            "input_sha256": sha256_bytes(inp_b) if input_obj is not None else None,
            "input_len": len(inp_b) if input_obj is not None else None,
            "output_sha256": sha256_bytes(out_b) if output_obj is not None else None,
            "output_len": len(out_b) if output_obj is not None else None,
            "status": status,
        }
        self._append(entry)

    # Callback hooks (subset)
    def on_tool_start(self, serialized, input_str, **kwargs):
        tool_name = (serialized or {}).get("name") if isinstance(serialized, dict) else None
        if isinstance(input_str, dict) and "name" in input_str:
            tool_name = tool_name or input_str.get("name")
        self._mk_entry("tool_start", tool=tool_name, input_obj=input_str, status="OK")

    def on_tool_end(self, output, **kwargs):
        self._mk_entry("tool_end", output_obj=output, status="OK")

    def on_agent_action(self, action, **kwargs):
        tool_name = getattr(action, "tool", None) if action is not None else None
        tool_input = getattr(action, "tool_input", None) if action is not None else None
        self._mk_entry("agent_action", tool=tool_name, input_obj=tool_input, status="OK")

    def on_chain_end(self, outputs, **kwargs):
        self._mk_entry("final", output_obj=outputs, status="OK")

    def on_agent_finish(self, finish, **kwargs):
        self._mk_entry("final", output_obj=finish, status="OK")

    def on_chain_error(self, error, **kwargs):
        self._mk_entry("error", output_obj=str(error) if error else None, status="FAIL")
