# Supply-Chain Attestation (DSSE / in-toto, offline)

Purpose: produce a deterministic, PII-free attestation over the delivered evidence artifacts (audit packet, handover bundle, evidence report) with offline ed25519 signatures and an offline verifier.

Scope: tools/scripts/docs only; no runtime/boundary changes; offline (no network). Deterministic (no timestamps), bounded stdout.

## Inputs (required)
- `artifacts/audit/evidence_pack_index.json`
- `artifacts/handover/handover_bundle.zip` (and `handover_bundle_index.json` if present)
- `artifacts/compliance/evidence_report.html`
- `docs/keys/hitl_key_registry.json` (for key id/pubkey metadata)
- ed25519 private key path supplied at runtime (`--key`), never stored in repo.

## Statement (in-toto style)
Payload JSON (canonical, sorted keys, no timestamps):
```
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [ { "name": "...", "digest":{"sha256":"..."},"size":N }, ... ],
  "predicateType": "https://slsa.dev/provenance/v1",
  "predicate": {
    "buildType": "yunitrack_runbook_operator_v1",
    "invocation": { "parameters": { "proofs":["prove.sh","prove_enterprise.sh","prove_lite.sh"], "verifiers":["verify_evidence_pack.sh"] } },
    "metadata": { "reproducible": true },
    "materials": [
      {"uri":"file:Cargo.lock","digest":{"sha256":"..."}},
      {"uri":"file:CANON.txt","digest":{"sha256":"..."}}
    ]
  }
}
```
Subject list is sorted by `name` and contains at minimum:
- `artifacts/audit/evidence.zip`
- `artifacts/audit/evidence_pack_index.json`
- `artifacts/handover/handover_bundle.zip`
- `artifacts/compliance/evidence_report.html`

## DSSE envelope (deterministic)
```
{
  "dsseVersion":"0.1",
  "payloadType":"application/vnd.in-toto+json",
  "payload":"<base64url payload bytes>",
  "signatures":[{"keyid":"<registry key id>","sig":"<base64url signature>"}]
}
```
Signature input: `b"DSSEv1\n" + payloadType + b"\n" + payload_b64url`.
Base64url is unpadded. JSON is compact (separators=(',',':')) and newline-terminated.

## Signature scheme
- ed25519 via `openssl pkeyutl -sign` (offline).
- key id comes from `docs/keys/hitl_key_registry.json` (active_key_id).
- Public key for verification comes from registry or `--pubkey` override.

## Outputs
Under `artifacts/attestations/`:
- `evidence_pack.dsse.json` (envelope)
- `evidence_pack.dsse.sig`  (base64url signature only)
- `attestation_index.json`  (label+count only: names, sha256, sizes)

## Verifier
Offline checker that:
- validates DSSE structure,
- verifies signature with provided pubkey,
- re-computes subject sha256/size and fails if mismatch/missing.

## Determinism and safety
- No timestamps or environment data.
- No payload contents, prompts, or PII recorded.
- Bounded stdout: single PASS/FAIL line with SecCode.

SecCodes:
- Attest: `ATTEST_MISSING_INPUTS`, `ATTEST_BAD_INDEX`, `ATTEST_KEY_MISSING`, `ATTEST_SIGN_FAIL`, `ATTEST_IO_FAIL`
- Verify: `VERIFY_BAD_DSSE`, `VERIFY_SIG_FAIL`, `VERIFY_SUBJECT_MISMATCH`, `VERIFY_MISSING_SUBJECT`
- Common internal: `ATTEST_INTERNAL`, `VERIFY_INTERNAL`.
