#!/usr/bin/env python3
import argparse
import base64
import hashlib
import hmac
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ZERO_TIME = "1970-01-01T00:00:00Z"
MAX_ITEMS = 100
MAX_TOTAL_BYTES = 1_000_000


def load_json(path: Path):
    try:
        data = json.loads(path.read_text())
    except Exception:
        return None
    return data


def validate_markers(obj):
    if not isinstance(obj, dict):
        raise ValueError("payload not object")
    items = obj.get("items", [])
    version = obj.get("version", "1.0")
    generated = obj.get("generated_utc", ZERO_TIME)
    if not isinstance(version, str) or len(version) > 32:
        raise ValueError("version invalid")
    if not isinstance(generated, str) or len(generated) > 64:
        raise ValueError("generated_utc invalid")
    if not isinstance(items, list):
        raise ValueError("items invalid")
    if len(items) > MAX_ITEMS:
        raise ValueError("too many items")
    norm_items = []
    for it in items:
        if not isinstance(it, dict):
            raise ValueError("item not object")
        mid = it.get("id")
        label = it.get("label")
        expires = it.get("expires_utc")
        sig = it.get("signature")
        if not (isinstance(mid, str) and 1 <= len(mid) <= 64):
            raise ValueError("id invalid")
        if not (isinstance(label, str) and 1 <= len(label) <= 128):
            raise ValueError("label invalid")
        if not (isinstance(expires, str) and 1 <= len(expires) <= 64):
            raise ValueError("expires invalid")
        if sig is not None and not (isinstance(sig, str) and 1 <= len(sig) <= 256):
            raise ValueError("signature invalid")
        entry = {"id": mid, "label": label, "expires_utc": expires}
        if sig is not None:
            entry["signature"] = sig
        norm_items.append(entry)
    norm_items.sort(key=lambda i: i["id"])
    payload = {
        "version": version,
        "generated_utc": generated,
        "items": norm_items,
    }
    data = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    if len(data) > MAX_TOTAL_BYTES:
        raise ValueError("payload too large")
    return payload, data


def sign(key_path: Path, inp: Path, out: Path):
    key = key_path.read_bytes()
    if len(key) == 0:
        raise ValueError("empty key")
    staged = load_json(inp)
    if staged is None:
        raise ValueError("malformed staged file")
    payload, data = validate_markers(staged)
    key_id = hashlib.sha256(key).hexdigest()
    sig_bytes = hmac.new(key, data, hashlib.sha256).digest()
    sig_b64 = base64.b64encode(sig_bytes).decode()
    signed = {
        "version": "1.0",
        "generated_utc": ZERO_TIME,
        "payload": payload,
        "signature": {"alg": "HMAC-SHA256", "key_id": key_id, "sig_b64": sig_b64},
    }
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(signed, sort_keys=True, separators=(",", ":")))


def verify(key_path: Path, signed_path: Path):
    key = key_path.read_bytes()
    if len(key) == 0:
        raise ValueError("empty key")
    signed = load_json(signed_path)
    if not isinstance(signed, dict):
        raise ValueError("signed not object")
    sig_block = signed.get("signature")
    payload = signed.get("payload")
    if not isinstance(sig_block, dict) or not isinstance(payload, dict):
        raise ValueError("signature block missing")
    key_id = sig_block.get("key_id")
    sig_b64 = sig_block.get("sig_b64")
    alg = sig_block.get("alg")
    if alg != "HMAC-SHA256":
        raise ValueError("alg mismatch")
    if not (isinstance(key_id, str) and isinstance(sig_b64, str)):
        raise ValueError("signature fields invalid")
    expected_key_id = hashlib.sha256(key).hexdigest()
    if key_id != expected_key_id:
        raise ValueError("key_id mismatch")
    # canonicalize payload
    payload_obj, data = validate_markers(payload)
    try:
        sig_bytes = base64.b64decode(sig_b64, validate=True)
    except Exception:
        raise ValueError("sig decode fail")
    calc = hmac.new(key, data, hashlib.sha256).digest()
    if not hmac.compare_digest(sig_bytes, calc):
        raise ValueError("sig mismatch")
    return payload_obj


def openssl_supports_ed25519() -> bool:
    try:
        out = subprocess.run(["openssl", "list", "-public-key-algorithms"], capture_output=True, text=True, check=False)
        return out.returncode == 0 and ("ED25519" in out.stdout or "Ed25519" in out.stdout)
    except FileNotFoundError:
        return False


def run_openssl_sign(priv: Path, data: bytes) -> bytes:
    with tempfile.NamedTemporaryFile(delete=True) as tmp:
        tmp.write(data)
        tmp.flush()
        proc = subprocess.run([
            "openssl", "pkeyutl", "-sign", "-inkey", str(priv), "-in", tmp.name
        ], capture_output=True)
        if proc.returncode != 0:
            raise ValueError("openssl sign failed")
        return proc.stdout


def run_openssl_verify(pub: Path, data: bytes, sig: bytes) -> None:
    with tempfile.NamedTemporaryFile(delete=True) as data_f, tempfile.NamedTemporaryFile(delete=True) as sig_f:
        data_f.write(data)
        data_f.flush()
        sig_f.write(sig)
        sig_f.flush()
        proc = subprocess.run([
            "openssl", "pkeyutl", "-verify", "-pubin", "-inkey", str(pub), "-in", data_f.name, "-sigfile", sig_f.name
        ], capture_output=True)
        if proc.returncode != 0:
            raise ValueError("openssl verify failed")


def load_registry(path: Path):
    if not path.exists():
        raise ValueError("registry missing")
    data = load_json(path)
    if not isinstance(data, dict):
        raise ValueError("registry malformed")
    keys = data.get("keys", [])
    if not isinstance(keys, list):
        raise ValueError("registry keys invalid")
    reg = {k.get("key_id"): k for k in keys if isinstance(k, dict) and k.get("key_id")}
    active = data.get("active_key_id")
    return data, reg, active


def sign_ed25519(priv: Path, inp: Path, out: Path, expires: str, scope: str, registry: Path):
    if not openssl_supports_ed25519():
        raise ValueError("ed25519 unsupported")
    staged = load_json(inp)
    if staged is None:
        raise ValueError("malformed staged file")
    payload, data = validate_markers(staged)
    if not (isinstance(expires, str) and expires):
        raise ValueError("expires missing")
    if not (isinstance(scope, str) and scope):
        raise ValueError("scope missing")
    key_id_override = None
    if registry:
        _, reg_keys, active = load_registry(registry)
        key_id_override = active

    sig_bytes = run_openssl_sign(priv, data)
    sig_b64 = base64.b64encode(sig_bytes).decode()
    pub_proc = subprocess.run(["openssl", "pkey", "-in", str(priv), "-pubout"], capture_output=True)
    if pub_proc.returncode != 0:
        raise ValueError("pub extract fail")
    key_id = hashlib.sha256(pub_proc.stdout).hexdigest()
    if key_id_override and key_id_override != key_id:
        raise ValueError("registry active key mismatch")
    signed = {
        "version": "1.0",
        "generated_utc": ZERO_TIME,
        "payload": payload,
        "signature": {"alg": "Ed25519", "key_id": key_id, "sig_b64": sig_b64},
        "policy": {"expires_utc": expires, "anti_replay_scope": scope},
    }
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(signed, sort_keys=True, separators=(",", ":")))


def verify_ed25519(pub: Path, signed_path: Path, scope_required: str, registry: Path):
    if not openssl_supports_ed25519():
        raise ValueError("ed25519 unsupported")
    signed = load_json(signed_path)
    if not isinstance(signed, dict):
        raise ValueError("signed not object")
    sig_block = signed.get("signature")
    payload = signed.get("payload")
    policy = signed.get("policy") or {}
    if not isinstance(sig_block, dict) or not isinstance(payload, dict):
        raise ValueError("signature block missing")
    if policy.get("anti_replay_scope") != scope_required:
        raise ValueError("scope mismatch")
    expires = policy.get("expires_utc")
    if not isinstance(expires, str) or not expires:
        raise ValueError("expires missing")
    if registry:
        reg, reg_keys, active = load_registry(registry)
    else:
        reg_keys = {}
        active = None
    if not expires.startswith("9999") and expires <= ZERO_TIME:
        raise ValueError("expires in past")
    payload_obj, data = validate_markers(payload)
    sig_b64 = sig_block.get("sig_b64")
    alg = sig_block.get("alg")
    key_id = sig_block.get("key_id")
    if alg != "Ed25519" or not isinstance(sig_b64, str) or not isinstance(key_id, str):
        raise ValueError("sig fields invalid")
    try:
        sig_bytes = base64.b64decode(sig_b64, validate=True)
    except Exception:
        raise ValueError("sig decode fail")
    if reg_keys:
        entry = reg_keys.get(key_id)
        if not entry or entry.get("status") != "active":
            raise ValueError("key not active")
        nb = entry.get("not_before_utc")
        na = entry.get("not_after_utc")
        if nb and nb > expires:
            raise ValueError("window not_before")
        if na and na < expires:
            raise ValueError("window not_after")
        pub_path = entry.get("pubkey_path")
        if not pub_path:
            raise ValueError("pub path missing")
        pub = Path(pub_path)
    pub_bytes = pub.read_bytes()
    expected_key_id = hashlib.sha256(pub_bytes).hexdigest()
    if key_id != expected_key_id:
        raise ValueError("key_id mismatch")
    run_openssl_verify(pub, data, sig_bytes)
    return payload_obj


def keygen_ed25519(out_dir: Path):
    if not openssl_supports_ed25519():
        raise ValueError("ed25519 unsupported")
    out_dir.mkdir(parents=True, exist_ok=True)
    priv = out_dir / "hitl_ed25519_priv.pem"
    pub = out_dir / "hitl_ed25519_pub.pem"
    proc = subprocess.run(["openssl", "genpkey", "-algorithm", "Ed25519", "-out", str(priv)], capture_output=True)
    if proc.returncode != 0:
        raise ValueError("keygen failed")
    proc = subprocess.run(["openssl", "pkey", "-in", str(priv), "-pubout", "-out", str(pub)], capture_output=True)
    if proc.returncode != 0:
        raise ValueError("pubout failed")
    return priv, pub


def main(argv=None):
    parser = argparse.ArgumentParser(description="HITL approvals signer/verifier (deterministic)")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_sign = sub.add_parser("sign")
    p_sign.add_argument("--key", required=True, dest="key")
    p_sign.add_argument("--in", required=True, dest="inp")
    p_sign.add_argument("--out", required=True, dest="out")

    p_verify = sub.add_parser("verify")
    p_verify.add_argument("--pubkey", required=True, dest="key")
    p_verify.add_argument("--in", required=True, dest="inp")

    p_sign_ed = sub.add_parser("sign-ed25519")
    p_sign_ed.add_argument("--privkey", required=True, dest="key")
    p_sign_ed.add_argument("--in", required=True, dest="inp")
    p_sign_ed.add_argument("--out", required=True, dest="out")
    p_sign_ed.add_argument("--expires-utc", required=True, dest="expires")
    p_sign_ed.add_argument("--anti-replay-scope", required=True, dest="scope")
    p_sign_ed.add_argument("--registry", default="docs/keys/hitl_key_registry.json", dest="registry")

    p_verify_ed = sub.add_parser("verify-ed25519")
    p_verify_ed.add_argument("--pubkey", required=False, dest="key")
    p_verify_ed.add_argument("--in", required=True, dest="inp")
    p_verify_ed.add_argument("--anti-replay-scope", required=True, dest="scope")
    p_verify_ed.add_argument("--registry", default="docs/keys/hitl_key_registry.json", dest="registry")

    p_keygen = sub.add_parser("keygen-ed25519")
    p_keygen.add_argument("--out-dir", required=True, dest="out_dir")

    args = parser.parse_args(argv)

    try:
        if args.cmd == "sign":
            sign(Path(args.key), Path(args.inp), Path(args.out))
            print("PASS: hitl_sign")
            return 0
        if args.cmd == "verify":
            verify(Path(args.key), Path(args.inp))
            print("PASS: hitl_verify")
            return 0
        if args.cmd == "sign-ed25519":
            sign_ed25519(Path(args.key), Path(args.inp), Path(args.out), args.expires, args.scope, Path(args.registry))
            print("PASS: hitl_sign_ed25519")
            return 0
        if args.cmd == "verify-ed25519":
            pub = Path(args.key) if args.key else None
            reg = Path(args.registry) if args.registry else None
            if pub is None and reg is None:
                raise ValueError("pubkey or registry required")
            if pub is None and reg is not None:
                # registry will supply pub path; leave pub as placeholder
                pub = Path(".")
            verify_ed25519(pub, Path(args.inp), args.scope, reg)
            print("PASS: hitl_verify_ed25519")
            return 0
        if args.cmd == "keygen-ed25519":
            keygen_ed25519(Path(args.out_dir))
            print("PASS: hitl_keygen_ed25519")
            return 0
    except Exception:
        if args.cmd == "sign":
            print("FAIL: hitl_sign SEC_HITL_SIGN_FAIL")
        elif args.cmd == "verify":
            print("FAIL: hitl_verify SEC_HITL_VERIFY_FAIL")
        elif args.cmd == "sign-ed25519":
            print("FAIL: hitl_sign_ed25519 SEC_HITL_SIGN_ED25519_FAIL")
        elif args.cmd == "verify-ed25519":
            print("FAIL: hitl_verify_ed25519 SEC_HITL_VERIFY_ED25519_FAIL")
        else:
            print("FAIL: hitl_keygen_ed25519 SEC_HITL_KEYGEN_FAIL")
        return 1
    return 1


if __name__ == "__main__":
    sys.exit(main())
