#!/usr/bin/env python3
"""
Deterministic task hash helper (no content output).
"""
import argparse
import hashlib
import json
import sys
from pathlib import Path


def sha256_file(path: Path) -> tuple[str, int]:
    h = hashlib.sha256()
    total = 0
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
            total += len(chunk)
    return h.hexdigest(), total


def main():
    p = argparse.ArgumentParser(add_help=False)
    p.add_argument("--task_file", required=True)
    p.add_argument("--out", required=True)
    args = p.parse_args()

    task_path = Path(args.task_file)
    out_path = Path(args.out)
    if not task_path.is_file():
        print("FAIL: demo_task_hash TASK_FILE_MISSING")
        sys.exit(1)

    sha, length = sha256_file(task_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    data = {"task_sha256": sha, "task_len": length}
    out_path.write_text(json.dumps(data, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
    print("PASS: demo_task_hash")


if __name__ == "__main__":
    main()
