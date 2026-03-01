# SECURITY MODEL

- Canon discipline: CANON.txt governs; /schemas untouched.
- Secure boundary crates (shared, skeleton, cm, ac, va_gate, ro_in) are Rust-only, `#![forbid(unsafe_code)]`, no IO/time/network/rng, deterministic tick loop.
- Single connector Port (P0/P1); no globals/side channels.
- Tick hash chain (T1/T2): SHA256(prev || tick_le || canon_hash), stored in records/hashes.json.
- Slider rules: step==2, even 0..=100; drift only s1 ±2 in MOVEMENT; enforced in skeleton/cm.
- Exit allowlist (I4/I5): audit/metrics/security/logs only. Audit records carry ids/hashes/status; metrics numeric-only; security codes only.
- Diode (I6): DioWriter inside boundary (write-only); DioReader outside; boundary never reads after writing.
- Audit chain (C1): HMAC-SHA256 keyed at runtime; head stored in hashes.json; verifier recomputes.
- Determinism (I2): no randomness/wallclock/nondeterministic concurrency; outputs derived from tick/canon/run_id.
- Approvals/PKCS#11 (C2/C3): not implemented yet in v0.1-proof scaffolding; to be added per Canon.
