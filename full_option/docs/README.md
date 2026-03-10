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
