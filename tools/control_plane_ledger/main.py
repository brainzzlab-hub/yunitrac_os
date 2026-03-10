#!/usr/bin/env python3
import argparse
import base64
import hashlib
import hmac
import json
import subprocess
import sys
from pathlib import Path

ZERO_TIME = "1970-01-01T00:00:00Z"
MAX_LINES = 10000
MAX_LEN = 64


def write_json(path: Path, obj):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, sort_keys=True, separators=(",", ":")))


def load_state(path: Path):
    if not path.exists():
        raise ValueError("state missing")
    try:
        data = json.loads(path.read_text())
    except Exception:
        raise ValueError("state malformed")
    if not isinstance(data, dict) or "seq" not in data:
        raise ValueError("state invalid")
    return data


def cmd_init(args):
    state = {"version": "1.0", "generated_utc": ZERO_TIME, "seq": 0}
    write_json(Path(args.state), state)
    print("init PASS")


def cmd_record(args):
    state_path = Path(args.state)
    ledger_path = Path(args.ledger)
    state = load_state(state_path)
    seq = int(state.get("seq", 0)) + 1
    if seq > MAX_LINES:
        print("record FAIL CP_LEDGER_CAP")
        sys.exit(62)
    action = args.action
    seccode = args.seccode
    result = args.result
    for val in (action, seccode, result):
        if not isinstance(val, str) or len(val) == 0 or len(val) > MAX_LEN:
            print("record FAIL CP_LEDGER_BAD")
            sys.exit(61)
    entry = {
        "version": "1.0",
        "seq": seq,
        "generated_utc": ZERO_TIME,
        "action": action,
        "result": result,
        "seccode": seccode,
    }
    line = json.dumps(entry, sort_keys=True, separators=(",", ":"))
    ledger_path.parent.mkdir(parents=True, exist_ok=True)
    with ledger_path.open("a", encoding="utf-8") as f:
        f.write(line + "\n")
    state["seq"] = seq
    write_json(state_path, state)
    print("record PASS")


def cmd_sign(args):
    ledger_path = Path(args.infile)
    if not ledger_path.exists():
        print("sign FAIL CP_LEDGER_MISSING")
        sys.exit(60)
    key_path = Path(args.key)
    if not key_path.exists():
        print("sign FAIL CP_LEDGER_MISSING")
        sys.exit(60)
    data = ledger_path.read_bytes()
    key = key_path.read_bytes()
    sig = hmac.new(key, data, hashlib.sha256).digest()
    env = {
        "version": "1.0",
        "generated_utc": ZERO_TIME,
        "alg": "HMAC-SHA256",
        "key_id": key_path.name,
        "sig_b64": base64.b64encode(sig).decode(),
        "ledger_path": str(ledger_path),
        "ledger_sha256": hashlib.sha256(data).hexdigest(),
    }
    write_json(Path(args.out), env)
    print("sign PASS")


def cmd_verify(args):
    env_path = Path(args.infile)
    ledger_path = Path(args.ledger)
    key_path = Path(args.key)
    if not env_path.exists() or not ledger_path.exists() or not key_path.exists():
        print("verify FAIL CP_LEDGER_MISSING")
        sys.exit(60)
    try:
        env = json.loads(env_path.read_text())
    except Exception:
        print("verify FAIL CP_LEDGER_BAD")
        sys.exit(61)
    data = ledger_path.read_bytes()
    key = key_path.read_bytes()
    sig = base64.b64decode(env.get("sig_b64", ""))
    calc = hmac.new(key, data, hashlib.sha256).digest()
    if not hmac.compare_digest(sig, calc):
        print("verify FAIL CP_LEDGER_SIG_BAD")
        sys.exit(63)
    if env.get("ledger_sha256") != hashlib.sha256(data).hexdigest():
        print("verify FAIL CP_LEDGER_SIG_BAD")
        sys.exit(63)
    print("verify PASS")


def openssl_supports_ed25519() -> bool:
    try:
        out = subprocess.run(["openssl", "list", "-public-key-algorithms"], capture_output=True, text=True, check=False)
        return out.returncode == 0 and ("ED25519" in out.stdout or "Ed25519" in out.stdout)
    except FileNotFoundError:
        return False


def load_registry(path: Path):
    if not path.exists():
        raise ValueError("registry missing")
    data = json.loads(path.read_text())
    if not isinstance(data, dict):
        raise ValueError("registry malformed")
    keys = data.get("keys", [])
    if not isinstance(keys, list):
        raise ValueError("registry keys invalid")
    reg = {k.get("key_id"): k for k in keys if isinstance(k, dict) and k.get("key_id")}
    active = data.get("active_key_id")
    return reg, active


def select_pub_from_registry(registry: Path, key_id: str) -> Path:
    reg, active = load_registry(registry)
    entry = reg.get(key_id if key_id else active)
    if not entry:
        raise ValueError("registry key missing")
    if entry.get("alg") != "Ed25519":
        raise ValueError("alg mismatch")
    pub = entry.get("pubkey_path")
    if not isinstance(pub, str) or not pub:
        raise ValueError("pub path missing")
    nb = entry.get("not_before_utc")
    na = entry.get("not_after_utc")
    if nb and na and nb > na:
        raise ValueError("window invalid")
    return Path(pub)


def sign_ed25519(priv: Path, ledger: Path, out: Path, registry: Path, scope: str):
    if not openssl_supports_ed25519():
        print("sign-ed25519 FAIL CP_LEDGER_ED_TOOL_MISSING")
        sys.exit(70)
    if not ledger.exists():
        print("sign-ed25519 FAIL CP_LEDGER_MISSING")
        sys.exit(60)
    if not registry.exists():
        print("sign-ed25519 FAIL CP_LEDGER_ED_REG_BAD")
        sys.exit(71)
    if not scope:
        print("sign-ed25519 FAIL CP_LEDGER_SCOPE_MISSING")
        sys.exit(72)
    data = ledger.read_bytes()
    ledger_sha = hashlib.sha256(data).hexdigest()
    reg, active = load_registry(registry)
    if not active:
        print("sign-ed25519 FAIL CP_LEDGER_ED_REG_BAD")
        sys.exit(71)
    # message = scope + "\\n" + ledger_sha + "\\n"
    message = (scope + "\\n" + ledger_sha + "\\n").encode()
    import tempfile
    with tempfile.NamedTemporaryFile(delete=True) as msg_f:
        msg_f.write(message)
        msg_f.flush()
        proc = subprocess.run(["openssl", "pkeyutl", "-sign", "-inkey", str(priv), "-in", msg_f.name],
                              capture_output=True)
        if proc.returncode != 0:
            print("sign-ed25519 FAIL CP_LEDGER_ED_TOOL_MISSING")
            sys.exit(70)
        sig = proc.stdout
    env = {
        "version": "1.0",
        "generated_utc": ZERO_TIME,
        "alg": "Ed25519",
        "key_id": active,
        "ledger_sha256": ledger_sha,
        "anti_replay_scope": scope,
        "sig_b64": base64.b64encode(sig).decode(),
    }
    write_json(out, env)
    print("sign-ed25519 PASS")


def verify_ed25519(signed: Path, ledger: Path, registry: Path):
    if not openssl_supports_ed25519():
        print("verify-ed25519 FAIL CP_LEDGER_ED_TOOL_MISSING")
        sys.exit(70)
    if not (signed.exists() and ledger.exists() and registry.exists()):
        print("verify-ed25519 FAIL CP_LEDGER_MISSING")
        sys.exit(60)
    try:
        env = json.loads(signed.read_text())
    except Exception:
        print("verify-ed25519 FAIL CP_LEDGER_BAD")
        sys.exit(61)
    scope = env.get("anti_replay_scope")
    if not isinstance(scope, str) or not scope:
        print("verify-ed25519 FAIL CP_LEDGER_SCOPE_MISSING")
        sys.exit(72)
    ledger_sha = env.get("ledger_sha256")
    if ledger_sha != hashlib.sha256(ledger.read_bytes()).hexdigest():
        print("verify-ed25519 FAIL CP_LEDGER_ED_SIG_BAD")
        sys.exit(73)
    key_id = env.get("key_id")
    pub = select_pub_from_registry(registry, key_id)
    sig_b64 = env.get("sig_b64", "")
    try:
        sig = base64.b64decode(sig_b64, validate=True)
    except Exception:
        print("verify-ed25519 FAIL CP_LEDGER_ED_SIG_BAD")
        sys.exit(73)
    message = (scope + "\\n" + ledger_sha + "\\n").encode()
    import tempfile
    with tempfile.NamedTemporaryFile(delete=True) as msg_f, tempfile.NamedTemporaryFile(delete=True) as sig_f:
        msg_f.write(message)
        msg_f.flush()
        sig_f.write(sig)
        sig_f.flush()
        proc = subprocess.run(["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", str(pub),
                              "-in", msg_f.name, "-sigfile", sig_f.name],
                              capture_output=True)
        if proc.returncode != 0:
            print("verify-ed25519 FAIL CP_LEDGER_ED_SIG_BAD")
            sys.exit(73)
    print("verify-ed25519 PASS")


def main(argv=None):
    parser = argparse.ArgumentParser(description="Control-plane action ledger")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_init = sub.add_parser("init")
    p_init.add_argument("--state", required=True)

    p_record = sub.add_parser("record")
    p_record.add_argument("--state", required=True)
    p_record.add_argument("--ledger", required=True)
    p_record.add_argument("--action", required=True)
    p_record.add_argument("--result", required=True)
    p_record.add_argument("--seccode", required=True)

    p_sign = sub.add_parser("sign")
    p_sign.add_argument("--key", required=True)
    p_sign.add_argument("--infile", required=True)
    p_sign.add_argument("--out", required=True)

    p_verify = sub.add_parser("verify")
    p_verify.add_argument("--key", required=True)
    p_verify.add_argument("--infile", required=True)
    p_verify.add_argument("--ledger", required=True)

    p_sign_ed = sub.add_parser("sign-ed25519")
    p_sign_ed.add_argument("--privkey", required=True)
    p_sign_ed.add_argument("--ledger", required=True)
    p_sign_ed.add_argument("--out", required=True)
    p_sign_ed.add_argument("--registry", required=True)
    p_sign_ed.add_argument("--anti-replay-scope", required=True)

    p_verify_ed = sub.add_parser("verify-ed25519")
    p_verify_ed.add_argument("--signed", required=True)
    p_verify_ed.add_argument("--ledger", required=True)
    p_verify_ed.add_argument("--registry", required=True)

    args = parser.parse_args(argv)
    try:
        if args.cmd == "init":
            cmd_init(args)
        elif args.cmd == "record":
            cmd_record(args)
        elif args.cmd == "sign":
            cmd_sign(args)
        elif args.cmd == "verify":
            cmd_verify(args)
        elif args.cmd == "sign-ed25519":
            sign_ed25519(Path(args.privkey), Path(args.ledger), Path(args.out), Path(args.registry), args.anti_replay_scope)
        elif args.cmd == "verify-ed25519":
            verify_ed25519(Path(args.signed), Path(args.ledger), Path(args.registry))
        else:
            raise ValueError("unknown")
    except SystemExit:
        raise
    except Exception as e:
        code = 61 if isinstance(e, ValueError) else 63
        print(f"{args.cmd} FAIL CP_LEDGER_BAD")
        sys.exit(code)

if __name__ == "__main__":
    main()
