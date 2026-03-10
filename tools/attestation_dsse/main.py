#!/usr/bin/env python3
"""
Deterministic DSSE/in-toto attestation + verifier (ed25519 via openssl).
Stdlib only. Bounded stdout handled in scripts.
"""
import argparse
import base64
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

SEC_ATTEST = {
    "missing": "ATTEST_MISSING_INPUTS",
    "bad_index": "ATTEST_BAD_INDEX",
    "key": "ATTEST_KEY_MISSING",
    "sign": "ATTEST_SIGN_FAIL",
    "io": "ATTEST_IO_FAIL",
    "internal": "ATTEST_INTERNAL",
}

SEC_VERIFY = {
    "bad_dsse": "VERIFY_BAD_DSSE",
    "sig": "VERIFY_SIG_FAIL",
    "mismatch": "VERIFY_SUBJECT_MISMATCH",
    "missing": "VERIFY_MISSING_SUBJECT",
    "internal": "VERIFY_INTERNAL",
}


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64url_decode(s: str) -> bytes:
    pad = "=" * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode(s + pad)


def sha256_file(path: Path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest(), path.stat().st_size


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def load_registry(registry_path: Path):
    if not registry_path.is_file():
        return None
    try:
        data = load_json(registry_path)
    except Exception:
        return None
    return data


def get_registry_key(registry_path: Path):
    reg = load_registry(registry_path)
    if not reg or "active_key_id" not in reg:
        return None, None
    active = reg.get("active_key_id")
    for k in reg.get("keys", []):
        if k.get("key_id") == active:
            return active, k.get("pubkey_path")
    return active, None


def fail_attest(code: str):
    print(f"FAIL: attest_dsse {SEC_ATTEST[code]}")
    sys.exit(1)


def fail_verify(code: str):
    print(f"FAIL: verify_dsse {SEC_VERIFY[code]}")
    sys.exit(1)


def openssl_sign(privkey: Path, message: bytes):
    try:
        with tempfile.NamedTemporaryFile(delete=False) as msg, tempfile.NamedTemporaryFile(delete=False) as sig:
            msg.write(message)
            msg.flush()
            cmd = [
                "openssl",
                "pkeyutl",
                "-sign",
                "-inkey",
                str(privkey),
                "-in",
                msg.name,
                "-out",
                sig.name,
            ]
            res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if res.returncode != 0:
                return None
            return Path(sig.name).read_bytes()
    except Exception:
        return None


def openssl_verify(pubkey: Path, message: bytes, signature: bytes):
    try:
        with tempfile.NamedTemporaryFile(delete=False) as tmp_sig, tempfile.NamedTemporaryFile(delete=False) as tmp_msg:
            tmp_sig.write(signature)
            tmp_sig.flush()
            tmp_msg.write(message)
            tmp_msg.flush()
            cmd = [
                "openssl",
                "pkeyutl",
                "-verify",
                "-pubin",
                "-inkey",
                str(pubkey),
                "-sigfile",
                tmp_sig.name,
                "-in",
                tmp_msg.name,
            ]
            res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            return res.returncode == 0
    except Exception:
        return False


def gather_subjects():
    subjects = []
    idx_path = Path("artifacts/audit/evidence_pack_index.json")
    if not idx_path.is_file():
        fail_attest("missing")
    try:
        idx = load_json(idx_path)
    except Exception:
        fail_attest("bad_index")
    entries = {e.get("name"): e for e in idx.get("entries", []) if e.get("name")}

    def from_entry(name, fallback_path):
        if name in entries:
            e = entries[name]
            sha = e.get("sha256")
            size = e.get("size")
            if sha and size is not None:
                return {"name": name, "digest": {"sha256": sha}, "size": size}
        p = Path(fallback_path)
        if not p.is_file():
            fail_attest("missing")
        sha, sz = sha256_file(p)
        return {"name": name, "digest": {"sha256": sha}, "size": sz}

    subjects.append(from_entry("artifacts/audit/evidence.zip", "artifacts/audit/evidence.zip"))
    subjects.append(from_entry("artifacts/audit/evidence_pack_index.json", "artifacts/audit/evidence_pack_index.json"))

    handover_zip = Path("artifacts/handover/handover_bundle.zip")
    if not handover_zip.is_file():
        fail_attest("missing")
    sha_h, sz_h = sha256_file(handover_zip)
    subjects.append({"name": "artifacts/handover/handover_bundle.zip", "digest": {"sha256": sha_h}, "size": sz_h})

    evidence_html = Path("artifacts/compliance/evidence_report.html")
    if not evidence_html.is_file():
        fail_attest("missing")
    sha_e, sz_e = sha256_file(evidence_html)
    subjects.append({"name": "artifacts/compliance/evidence_report.html", "digest": {"sha256": sha_e}, "size": sz_e})

    subjects.sort(key=lambda x: x["name"])
    return subjects


def build_statement(subjects):
    cargo = Path("Cargo.lock")
    canon = Path("CANON.txt")
    if not (cargo.is_file() and canon.is_file()):
        fail_attest("missing")
    cargo_sha, _ = sha256_file(cargo)
    canon_sha, _ = sha256_file(canon)
    stmt = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": subjects,
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildType": "yunitrack_runbook_operator_v1",
            "invocation": {"parameters": {"proofs": ["prove.sh", "prove_enterprise.sh", "prove_lite.sh"], "verifiers": ["verify_evidence_pack.sh"]}},
            "metadata": {"reproducible": True},
            "materials": [
                {"uri": "file:Cargo.lock", "digest": {"sha256": cargo_sha}},
                {"uri": "file:CANON.txt", "digest": {"sha256": canon_sha}},
            ],
        },
    }
    return stmt


def write_json(path: Path, obj):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")


def attest(args):
    key_path = Path(args.key)
    if not key_path.is_file():
        fail_attest("key")
    registry_path = Path(args.registry)
    key_id, reg_pub = get_registry_key(registry_path)
    if not key_id:
        fail_attest("key")

    subjects = gather_subjects()
    stmt = build_statement(subjects)
    payload_bytes = json.dumps(stmt, sort_keys=True, separators=(",", ":")).encode("utf-8")
    payload_b64 = b64url(payload_bytes)

    payload_type = "application/vnd.in-toto+json"
    msg = b"DSSEv1\n" + payload_type.encode("utf-8") + b"\n" + payload_b64.encode("ascii")

    sig_raw = openssl_sign(key_path, msg)
    if not sig_raw:
        fail_attest("sign")
    sig_b64 = b64url(sig_raw)

    envelope = {
        "dsseVersion": "0.1",
        "payloadType": payload_type,
        "payload": payload_b64,
        "signatures": [{"keyid": key_id, "sig": sig_b64}],
    }

    out_dir = Path("artifacts/attestations")
    dsse_path = out_dir / "evidence_pack.dsse.json"
    sig_path = out_dir / "evidence_pack.dsse.sig"
    write_json(dsse_path, envelope)
    sig_path.write_text(sig_b64 + "\n", encoding="utf-8")

    idx = {
        "version": "1.0",
        "entries": [],
    }
    for name, path in [
        ("evidence_pack.dsse.json", dsse_path),
        ("evidence_pack.dsse.sig", sig_path),
    ]:
        sha, sz = sha256_file(path)
        idx["entries"].append({"name": name, "sha256": sha, "size": sz})
    idx["entries"].sort(key=lambda x: x["name"])
    write_json(out_dir / "attestation_index.json", idx)

    print("PASS: attest_dsse")


def verify(args):
    registry_path = Path(args.registry)
    dsse_path = Path(args.dsse)
    if not dsse_path.is_file():
        fail_verify("bad_dsse")
    try:
        envelope = load_json(dsse_path)
    except Exception:
        fail_verify("bad_dsse")

    payload_b64 = envelope.get("payload")
    payload_type = envelope.get("payloadType")
    sigs = envelope.get("signatures", [])
    if not payload_b64 or not payload_type or not sigs:
        fail_verify("bad_dsse")
    sig_entry = sigs[0]
    sig_b64 = sig_entry.get("sig")
    if not sig_b64:
        fail_verify("bad_dsse")

    payload_bytes = b64url_decode(payload_b64)
    try:
        stmt = json.loads(payload_bytes.decode("utf-8"))
    except Exception:
        fail_verify("bad_dsse")

    msg = b"DSSEv1\n" + payload_type.encode("utf-8") + b"\n" + payload_b64.encode("ascii")
    sig_raw = b64url_decode(sig_b64)

    pubkey_path = Path(args.pubkey) if args.pubkey else None
    if not pubkey_path:
        key_id, reg_pub = get_registry_key(registry_path)
        if not reg_pub:
            fail_verify("bad_dsse")
        pubkey_path = Path(reg_pub)
    if not pubkey_path.is_file():
        fail_verify("bad_dsse")
    if not openssl_verify(pubkey_path, msg, sig_raw):
        fail_verify("sig")

    subjects = stmt.get("subject", [])
    if not isinstance(subjects, list):
        fail_verify("bad_dsse")
    for subj in subjects:
        name = subj.get("name")
        dig = subj.get("digest", {}).get("sha256")
        size = subj.get("size")
        if not name or not dig or size is None:
            fail_verify("bad_dsse")
        p = Path(name)
        if not p.is_file():
            fail_verify("missing")
        sha, sz = sha256_file(p)
        if sha != dig or sz != size:
            fail_verify("mismatch")

    print("PASS: verify_dsse")


def parse_args():
    ap = argparse.ArgumentParser(add_help=False)
    ap.add_argument("--mode", choices=["attest", "verify"], required=True)
    ap.add_argument("--key")
    ap.add_argument("--pubkey")
    ap.add_argument("--registry", default="docs/keys/hitl_key_registry.json")
    ap.add_argument("--dsse", default="artifacts/attestations/evidence_pack.dsse.json")
    return ap.parse_args()


if __name__ == "__main__":
    try:
        args = parse_args()
        if args.mode == "attest":
            attest(args)
        else:
            verify(args)
    except SystemExit:
        raise
    except Exception:
        if 'args' in locals() and args.mode == "attest":
            fail_attest("internal")
        else:
            fail_verify("internal")
