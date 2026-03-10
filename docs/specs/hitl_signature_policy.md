# HITL Signature Policy (Ed25519 + HMAC)

Scope: staged HITL markers -> signed bundle -> proof verification.

## Algorithms
- Default: HMAC-SHA256 (existing path).
- Optional: Ed25519 (openssl) when `HITL_SIGNATURE_MODE=ed25519`.

## Key handling
- Private keys: operator-provided, never committed; passed via env:
  - HMAC: `HITL_SIGNING_KEY_PATH`
  - Ed25519: `HITL_ED25519_PRIVKEY_PATH`
- Public keys: stored under `docs/keys/` or env override (`HITL_APPROVALS_PUBKEY_PATH`, `HITL_ED25519_PUBKEY_PATH`).
- key_id: SHA256(pubkey PEM bytes) hex.

## Rotation / expiry
- Each signed bundle must include `policy.expires_utc` (ISO-like string).
- Verification fails if `expires_utc` missing or not far-future. (Clockless policy: accept only values starting with `9999` or explicitly configured future epochs.)
- Rotate keys before expiry; publish new pubkey under `docs/keys/`.

## Anti-replay scope
- Signed bundles must include `policy.anti_replay_scope` (string).
- Enterprise verification requires scope match to current expected scope (env `HITL_ANTI_REPLAY_SCOPE`, default `enterprise`).
- Lite may set `HITL_ANTI_REPLAY_SCOPE=lite` when opting in.

## Bounds
- Max 100 markers; id<=64; label<=128; expires_utc<=64; signature<=256; total payload<=1MB.
- Deterministic canonicalization: `json.dumps(..., sort_keys=True, separators=(',', ':'))`, items sorted by `id`.

## Failure behavior
- Missing tooling or keys: fail-closed with bounded SecCode.
- Signature mismatch, expiry, or scope mismatch: fail-closed.
- No reasons or payloads are surfaced beyond SecCode and counts.

