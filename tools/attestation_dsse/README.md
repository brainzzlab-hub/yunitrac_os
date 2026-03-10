# Supply-Chain Attestation (DSSE / in-toto, offline)

Purpose: deterministically attest the evidence pack, handover bundle, and evidence report using ed25519 (offline) and verify offline.

## Modes
- `attest`: build statement, wrap in DSSE envelope, sign with ed25519 private key.
- `verify`: verify DSSE signature and subject digests against current files.

## Inputs
- Evidence pack index: `artifacts/audit/evidence_pack_index.json`
- Handover bundle zip (+ index if present)
- Evidence report HTML
- Registry: `docs/keys/hitl_key_registry.json` (key id + pubkey metadata)
- Private key: `--key <ed25519_priv.pem>` (attest mode)
- Public key: `--pubkey <ed25519_pub.pem>` or registry (verify mode)

## Outputs (all in `artifacts/attestations/`)
- `evidence_pack.dsse.json` (DSSE envelope)
- `evidence_pack.dsse.sig`  (base64url signature)
- `attestation_index.json`   (name/sha256/size only)

## Stdout contract
- PASS: `PASS: attest_dsse` or `PASS: verify_dsse`
- FAIL: `FAIL: <name> <SecCode>`

## SecCodes
- Attest: `ATTEST_MISSING_INPUTS`, `ATTEST_BAD_INDEX`, `ATTEST_KEY_MISSING`, `ATTEST_SIGN_FAIL`, `ATTEST_IO_FAIL`, `ATTEST_INTERNAL`
- Verify: `VERIFY_BAD_DSSE`, `VERIFY_SIG_FAIL`, `VERIFY_SUBJECT_MISMATCH`, `VERIFY_MISSING_SUBJECT`, `VERIFY_INTERNAL`

## Example
```bash
./scripts/attest/attest_evidence_pack.sh --key artifacts/tmp/attest_priv.pem
./scripts/attest/verify_attestation.sh --pubkey artifacts/tmp/attest_pub.pem
```
