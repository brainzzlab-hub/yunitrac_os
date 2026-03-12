# yunitrac_os proof commands

Baseline (v0.1 reference):
```bash
./scripts/prove.sh
```
Outputs: `artifacts/` with `proof_report.json`.

Enterprise (diode-first split):
```bash
./scripts/prove_enterprise.sh
```
Outputs under `artifacts/enterprise/...`, evidence bundle in `artifacts/enterprise/evidence_bundle/`, summary at `artifacts/proof_report_enterprise.json`.

See PROOF.md for checks, SECURITY_MODEL.md for boundaries, and CANON.txt for the governing Canon.

### Fuzzing (dio_core decode)
- Install: `cargo install cargo-fuzz --locked`
- Build check: `./scripts/fuzz_build.sh`
- Allow skip (dev without cargo-fuzz): `ALLOW_NO_CARGO_FUZZ=1 ./scripts/fuzz_build.sh`
- Run (short): `cargo fuzz run fuzz_decode_recordframe -- -max_total_time=30`

## Proof / Evidence
- Verified green gates summary (PDF): `docs/evidence/YuniTrack_Verified_Green_Checklist.pdf`
- Technical scope and findings (PDF): `docs/evidence/YuniTrack_Technisch_Rapport.pdf`

## Origin (honest)
- I started building this after ~108 days of hands-on learning in software/IT.
- I did not come in as a career developer; I learned by shipping small, verified steps with strict gates.
- The repo is proof-driven: run the scripts and inspect reports rather than trusting claims.
# yunitrac_os proof commands

## What this repo is
- Deterministic, diode-first agent governance proof harness (enterprise-grade topology).
- One-command proofs:
  - `./scripts/prove.sh`
  - `./scripts/prove_enterprise.sh`
  - `./scripts/prove_lite.sh`

## Evidence
- `docs/evidence/YuniTrack_Verified_Green_Checklist.pdf`
- `docs/evidence/YuniTrack_Technisch_Rapport.pdf`

## Notes
- CI runs fmt/clippy/test/build/proofs as hard gates.
- Security advisory tools (cargo-audit / cargo-deny) are warn-only due to upstream CVSS4 advisory DB format drift.

# yunitrac_os proof commands
# yunitrac_os

**What it is:** deterministic, diode-first governance skeleton for running “agents/actors” under strict boundaries, with proof scripts and evidence.

**Quick test (local):**
- `./scripts/prove.sh`
- `./scripts/prove_enterprise.sh`
- `./scripts/prove_lite.sh`

**Evidence (PDFs):**
- `docs/evidence/YuniTrack_Verified_Green_Checklist.pdf`
- `docs/evidence/YuniTrack_Technisch_Rapport.pdf`

**If this repo is useful:** click ⭐ **Star** on GitHub. It helps others find it.

---
