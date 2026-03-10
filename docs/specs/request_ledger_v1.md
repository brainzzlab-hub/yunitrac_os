# Request Ledger v1 (NDJSON)

Purpose: read-only operational ledger for Operator Dashboard. No wallclock, no reasons, no payloads. One JSON object per line (NDJSON).

Required fields (per entry)
- `request_id` : string, 1..128 chars, opaque, bounded
- `profile`    : "enterprise" | "lite"
- `decision`   : "ACCEPTED" | "REJECTED"
- `seccode`    : string (bounded enum, see docs/specs/seccode_lite.md)
- `created_seq`: integer (monotonic sequence, no timestamps)
- `anti_replay`: "PASS" | "FAIL" | "UNKNOWN"

Optional
- `approvals_ref` : string, 0..128 chars, opaque (no key material)

Forbidden (must not appear)
- Wallclock time, timestamps, durations
- Reasons, validator details, payload content, schema dumps
- Keys, signatures, hashes other than existing opaque refs
- File paths or hostnames

Encoding
- NDJSON (one JSON object per line), UTF-8
- Blank lines and lines starting with `#` are ignored
- No extra top-level arrays or objects

Determinism
- Consumers sort by `created_seq` ascending, then `request_id` lexicographically.
- No timestamps; `created_seq` is the only ordering hint.

Location
- Preferred: `artifacts/ops/request_ledger.ndjson`
- Fixture fallback: `tools/operator_dashboard/fixtures/request_ledger.ndjson` (clearly marked “FIXTURE MODE”)

Security / Privacy
- No PII, no payload content.
- No feedback beyond bounded decision + seccode + anti_replay status.
