# Anti-Replay Profiles (yunitrack_os)

Enterprise (Profile E)
- Cross-run anti-replay is mandatory.
- A persisted ledger must exist after proof runs; absence is fail-closed.
- Allowed behavior when ledger missing: proof gate must fail (no fallback).

Lite (Profile L)
- Cross-run anti-replay is optional/best-effort.
- If no persisted ledger is present, proof reports this fact deterministically.

Common
- Within-run duplicate nonces must be rejected.
- Nonce zero rejected.
- No payloads, signatures, or reasons are emitted in actor-visible outputs.
