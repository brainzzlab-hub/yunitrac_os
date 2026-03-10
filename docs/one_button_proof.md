# One-Button-Proof (Enterprise)

**Command (one line)**  
`just prove-enterprise`

**What happens on PASS**
- Deterministic evidence is produced under `artifacts/enterprise/...` and summarized in `artifacts/proof_report_enterprise.json`.
- Equality checks (B == C) across outputs/audit/metrics/security/hashes succeed.
- Guardrails stay quiet (no extra output beyond bounded PASS lines).

**What happens on FAIL**
- Execution stops immediately; only bounded SECURITY lines are emitted (e.g., `SECURITY: ...`), no detailed reasons, no payload leakage.
- Existing artifacts remain for inspection; reports are not marked PASS.

**Offline expectation**
- Proof runs fully offline; cargo commands already use `CARGO_NET_OFFLINE=true` where applicable.
- No network calls are made by the proof scripts or boundary binaries.

**No-git note**
- The proof does not require git; repository state is taken as-is. No commits/pushes are performed.
