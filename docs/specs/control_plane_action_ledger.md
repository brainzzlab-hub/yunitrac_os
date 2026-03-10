<meta charset="utf-8">

# Control Plane Action Ledger (deterministic, bounded)

Purpose: deterministic, signed trail of operator-triggered actions without leaking payloads.

State machine
- IDLE -> RUNNING -> DONE|FAILED per action record (record stores final result only).
- Actions: run_proof_enterprise, run_proof_lite, export_audit_packet, export_incident_bundle, sign_hitl_markers, sign_hitl_markers_ed25519.

Ledger files
- State: `artifacts/control_plane/ledger_state.json` {version, generated_utc, seq}
- Ledger: `artifacts/control_plane/action_ledger.jsonl` (one canonical JSON line per action)
- Signed: `artifacts/control_plane/action_ledger_signed.json` envelope

Record fields (canonical, sort_keys=True, separators=(',',':'))
{version, seq, generated_utc, action, result, seccode}
- result in {"PASS","FAIL"}
- seq monotonic starting at 1
- hard caps: max 10_000 lines; max len action/seccode 64 chars

Signing
- HMAC-SHA256 over raw ledger jsonl bytes
- key supplied via env `CONTROL_PLANE_SIGNING_KEY_PATH` (external; never stored in repo)
- key_id = basename of key file

Failure / incident
- If verify fails, bounded stub written to `artifacts/incident/control_plane_ledger_failure.json` {version, generated_utc, seccode}

Determinism
- No wallclock reliance beyond fixed generated_utc="1970-01-01T00:00:00Z".
- File ordering deterministic; signing deterministic.

Lite boundary
- No payloads, no reasons; only bounded codes. Lite UI shows counts only.
