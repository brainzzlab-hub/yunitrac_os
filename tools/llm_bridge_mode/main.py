#!/usr/bin/env python3
"""
LLM Bridge Mode (offline by default, deterministic artifacts).
Python stdlib only.
"""
import argparse
import hashlib
import json
import sys
from pathlib import Path

SEC_CODES = {
    "args": "BRIDGE_BAD_ARGS",
    "hex": "BRIDGE_BAD_HEX",
    "sliders": "BRIDGE_BAD_SLIDERS",
    "io": "BRIDGE_IO_FAIL",
    "tool": "BRIDGE_TOOL_MISSING",
    "disabled": "BRIDGE_PROVIDER_DISABLED",
    "provider": "BRIDGE_PROVIDER_FAIL",
}

MODES = ["ANALYZE", "GENERATE", "COMMUNICATE", "MOVEMENT"]
MODE_BYTE = {m: i for i, m in enumerate(MODES)}


def fail(code: str, msg: str):
    sys.stdout.write(f"FAIL: llm_bridge_mode {SEC_CODES[code]}\n")
    sys.exit(1)


def parse_args():
    p = argparse.ArgumentParser(add_help=False)
    p.add_argument("--mode", required=True, choices=MODES)
    p.add_argument("--canon_hash_hex", required=True)
    p.add_argument("--tick_hash_hex", required=True)
    p.add_argument("--tick", required=True, type=int)
    p.add_argument("--sliders", required=True)
    p.add_argument("--task_file")
    p.add_argument("--out_dir", required=True)
    p.add_argument("--provider", default="none", choices=["none", "openai", "anthropic", "local"])
    p.add_argument("--forward", default=0, type=int, choices=[0, 1])
    p.add_argument("--max_bytes", default=4096, type=int)
    return p.parse_args()


def validate_hex(h: str):
    if len(h) != 64:
        fail("hex", "bad hex length")
    try:
        return bytes.fromhex(h)
    except ValueError:
        fail("hex", "non-hex")


def validate_sliders(s: str):
    try:
        parts = [int(x) for x in s.split(",")]
    except Exception:
        fail("sliders", "parse")
    if len(parts) != 4:
        fail("sliders", "count")
    for v in parts:
        if not (0 <= v <= 100) or v % 2 != 0:
            fail("sliders", "range")
    return parts


def normalize_payload_bytes(provider: str, forward: int, task_file: str | None, max_bytes: int):
    # Offline by default
    if provider == "none" or forward == 0:
        return b"", "DRY_RUN" if provider == "none" else "DISABLED"
    # Forwarding requested but no provider implementation available
    fail("tool", "provider tooling not available")


def main():
    args = parse_args()
    if args.max_bytes <= 0:
        fail("args", "max_bytes")

    canon_hash = validate_hex(args.canon_hash_hex)
    tick_hash = validate_hex(args.tick_hash_hex)
    sliders = validate_sliders(args.sliders)
    out_dir = Path(args.out_dir)
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
    except Exception:
        fail("io", "outdir")

    # Read task file only to ensure accessibility (content not stored)
    if args.task_file:
        tf = Path(args.task_file)
        if not tf.is_file():
            fail("io", "task_file_missing")
        try:
            _ = tf.read_bytes()
        except Exception:
            fail("io", "task_read")

    payload_bytes, status = normalize_payload_bytes(args.provider, args.forward, args.task_file, args.max_bytes)
    payload_sha = hashlib.sha256(payload_bytes).hexdigest()
    payload_len = len(payload_bytes)

    mode_byte = MODE_BYTE.get(args.mode)
    tick_le = int(args.tick).to_bytes(8, "little", signed=False)
    sliders_bytes = bytes(sliders)

    proposal = bytes([mode_byte]) + tick_le + sliders_bytes + canon_hash + tick_hash + bytes.fromhex(payload_sha)
    proposal_sha = hashlib.sha256(proposal).hexdigest()

    # Write artifacts
    try:
        (out_dir / "proposal.bin").write_bytes(proposal)
        manifest = {
            "version": "1.0",
            "mode": args.mode,
            "tick": int(args.tick),
            "sliders": sliders,
            "canon_hash_hex": args.canon_hash_hex,
            "tick_hash_hex": args.tick_hash_hex,
            "payload_sha256": payload_sha,
            "payload_len": payload_len,
            "proposal_sha256": proposal_sha,
            "proposal_size": len(proposal),
        }
        (out_dir / "proposal_manifest.json").write_text(
            json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8"
        )
        provider_status = {
            "provider": args.provider,
            "forward": int(args.forward),
            "status": status,
        }
        (out_dir / "provider_status.json").write_text(
            json.dumps(provider_status, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8"
        )
        audit_stub = {
            "version": "1.0",
            "mode": args.mode,
            "tick": int(args.tick),
            "canon_hash": args.canon_hash_hex,
            "tick_hash": args.tick_hash_hex,
            "payload_sha256": payload_sha,
            "proposal_sha256": proposal_sha,
            "sec_code": "PASS",
        }
        (out_dir / "audit_stub.json").write_text(
            json.dumps(audit_stub, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8"
        )
    except Exception:
        fail("io", "write")

    sys.stdout.write("PASS: llm_bridge_mode\n")


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception:
        fail("io", "unhandled")
