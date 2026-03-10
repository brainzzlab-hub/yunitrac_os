# Scrub Proxy Mode (offline, deterministic)

Purpose: apply GDPR scrub rules to text streams/files in a controlled, offline manner. Default is dry-run (counts only). Forwarding is disabled unless explicitly enabled.

Run (dry-run, stdin):
```
python3 -m scrub_proxy_mode < input.txt
```

Run with input file and summary only:
```
python3 -m scrub_proxy_mode --input path/to/file.txt
```

Enable forward (explicit opt-in) to write scrubbed output:
```
python3 -m scrub_proxy_mode --input in.txt --enable-forward --forward-to out.txt
```

Flags
- --rules PATH       : default uses docs/specs/gdpr_default_scrub_rules.json
- --custom PATH      : optional custom rules JSON
- --hitl             : enable HITL rules
- --quicknames       : enable quicknames heuristic
- --input PATH       : file to read (default stdin)
- --enable-forward   : allow writing scrubbed output
- --forward-to PATH  : destination when forward enabled (required if enable-forward)

Determinism & Safety
- Offline only; no network calls.
- Stable ordering and JSON outputs (summary on stdout).
- Scrubbed output is written only when --enable-forward is set; otherwise summary only.
- No payloads in summary; counts per label only.
