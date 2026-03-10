#!/usr/bin/env python3
import json
import os
import pathlib
import subprocess
from typing import Dict, Any, List, Tuple, Optional

BASE = pathlib.Path(__file__).resolve().parent.parent  # tools/operator_dashboard
WORKDIR = BASE.parent.parent
TEMPLATE_PATH = BASE / "src" / "templates" / "index.html"
DIST_PATH = BASE / "dist" / "index.html"
FIXTURE_ROOT = BASE / "fixtures"
LEDGER_PRIMARY = WORKDIR / "artifacts/ops/request_ledger.ndjson"
LEDGER_FIXTURE = FIXTURE_ROOT / "request_ledger.ndjson"
ACTION_STATUS_PATH = WORKDIR / "artifacts/control_plane/action_status.json"
HITL_STAGED_PATH = WORKDIR / "artifacts/control_plane/hitl_markers_staged.json"
LEDGER_PATH = WORKDIR / "artifacts/control_plane/action_ledger.jsonl"
LEDGER_SIGNED_PATH = WORKDIR / "artifacts/control_plane/action_ledger_signed.json"

ZERO_TIME = "1970-01-01T00:00:00Z"

# Controlled actions (ordered)
ACTIONS = (
    ("run_proof_enterprise", ["./scripts/prove_enterprise.sh"], "SEC_ACTION_FAIL"),
    ("run_proof_lite", ["./scripts/prove_lite.sh"], "SEC_ACTION_FAIL"),
    ("export_audit_packet", ["./scripts/audit/export_audit_packet.sh"], "SEC_ACTION_FAIL"),
    ("export_incident_bundle", ["./scripts/incident/export_incident_bundle.sh"], "SEC_ACTION_FAIL"),
    ("manage_hitl_markers", None, "SEC_HITL_INVALID"),
    ("sign_hitl_markers", ["./scripts/hitl/sign_hitl_markers.sh"], "SEC_HITL_SIGN_FAIL"),
    ("sign_hitl_markers_ed25519", ["./scripts/hitl/sign_hitl_markers_ed25519.sh"], "SEC_HITL_SIGN_ED25519_FAIL"),
    ("verify_ledger_signature", ["./scripts/control_plane/ledger_verify_ed25519.sh"], "CP_LEDGER_ED_SIG_BAD"),
)

# Inputs (primary -> fixture fallback)
SOURCES = {
    "enterprise_report": (
        WORKDIR / "artifacts/proof_report_enterprise.json",
        FIXTURE_ROOT / "artifacts/proof_report_enterprise.json",
    ),
    "lite_report": (
        WORKDIR / "artifacts/proof_report_lite.json",
        FIXTURE_ROOT / "artifacts/proof_report_lite.json",
    ),
    "lite_scope": (
        WORKDIR / "artifacts/lite/scope_manifest.json",
        FIXTURE_ROOT / "artifacts/lite/scope_manifest.json",
    ),
    "lite_required_hashes": (
        WORKDIR / "artifacts/lite/evidence_bundle/required_hashes.json",
        FIXTURE_ROOT / "artifacts/lite/evidence_bundle/required_hashes.json",
    ),
    "lite_policy": (
        WORKDIR / "artifacts/lite/evidence_bundle/policy_checks.json",
        FIXTURE_ROOT / "artifacts/lite/evidence_bundle/policy_checks.json",
    ),
    "lite_commands": (
        WORKDIR / "artifacts/lite/evidence_bundle/commands.txt",
        FIXTURE_ROOT / "artifacts/lite/evidence_bundle/commands.txt",
    ),
    "enterprise_chain": (
        WORKDIR / "artifacts/enterprise/evidence_bundle/chain_verification.json",
        FIXTURE_ROOT / "artifacts/enterprise/evidence_bundle/chain_verification.json",
    ),
}


def load_json(primary: pathlib.Path, fallback: pathlib.Path) -> Tuple[Any, bool]:
    if primary.exists():
        return json.loads(primary.read_text()), False
    if fallback.exists():
        return json.loads(fallback.read_text()), True
    return None, False


def load_text(primary: pathlib.Path, fallback: pathlib.Path) -> Tuple[str, bool]:
    if primary.exists():
        return primary.read_text(), False
    if fallback.exists():
        return fallback.read_text(), True
    return "", False


def guardrail_status(commands_text: str) -> Dict[str, str]:
    status = {}
    for line in commands_text.splitlines():
        line = line.strip()
        if not line:
            continue
        if ":" not in line:
            continue
        key, val = line.split(":", 1)
        key = key.strip()
        val = val.strip()
        # Expected formats: "guardrails: name=PASS" or "checks: foo=PASS"
        if "=" in val:
            name, result = val.split("=", 1)
            status[name.strip()] = result.strip()
        else:
            status[key] = val
    return status


def status_label(pass_bool: Any) -> str:
    if pass_bool is True:
        return "PASS"
    if pass_bool is False:
        return "FAIL"
    return "UNKNOWN"


def render_list(items: List[str]) -> str:
    if not items:
        return "<div class=\"card\">(none)</div>"
    lis = "".join(f"<li>{json.dumps(it)}</li>" for it in items)
    return f"<div class=\"card\"><ul>{lis}</ul></div>"


def load_ledger() -> Tuple[List[Dict[str, Any]], bool, bool]:
    def parse_line(line: str) -> Dict[str, Any]:
        obj = json.loads(line)
        if not isinstance(obj, dict):
            raise ValueError("not object")
        req_id = obj.get("request_id")
        profile = obj.get("profile")
        decision = obj.get("decision")
        seccode = obj.get("seccode")
        created_seq = obj.get("created_seq")
        anti_replay = obj.get("anti_replay")
        approvals_ref = obj.get("approvals_ref", None)
        if not (isinstance(req_id, str) and 1 <= len(req_id) <= 128):
            raise ValueError("request_id invalid")
        if profile not in ("enterprise", "lite"):
            raise ValueError("profile invalid")
        if decision not in ("ACCEPTED", "REJECTED"):
            raise ValueError("decision invalid")
        if not (isinstance(seccode, str) and 1 <= len(seccode) <= 128):
            raise ValueError("seccode invalid")
        if not (isinstance(created_seq, int) and created_seq >= 0):
            raise ValueError("created_seq invalid")
        if anti_replay not in ("PASS", "FAIL", "UNKNOWN"):
            raise ValueError("anti_replay invalid")
        if approvals_ref is not None:
            if not (isinstance(approvals_ref, str) and 0 < len(approvals_ref) <= 128):
                raise ValueError("approvals_ref invalid")
        return {
            "request_id": req_id,
            "profile": profile,
            "decision": decision,
            "seccode": seccode,
            "created_seq": created_seq,
            "anti_replay": anti_replay,
            "approvals_ref": approvals_ref,
        }

    path_used = None
    for path in (LEDGER_PRIMARY, LEDGER_FIXTURE):
        if path.exists():
            path_used = path
            break
    if path_used is None:
        return [], False, False
    entries: List[Dict[str, Any]] = []
    try:
        for raw in path_used.read_text().splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            entries.append(parse_line(line))
    except Exception:
        return [], path_used == LEDGER_FIXTURE, True
    entries.sort(key=lambda e: (e["created_seq"], e["request_id"]))
    return entries, path_used == LEDGER_FIXTURE, False


def load_action_status() -> Dict[str, Any]:
    if not ACTION_STATUS_PATH.exists():
        return {}
    try:
        data = json.loads(ACTION_STATUS_PATH.read_text())
        if isinstance(data, dict) and isinstance(data.get("actions"), dict):
            return data
    except Exception:
        pass
    return {}


def write_action_status(actions: Dict[str, Dict[str, Any]]) -> None:
    ACTION_STATUS_PATH.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "version": "1.0",
        "generated_utc": ZERO_TIME,
        "actions": {k: actions[k] for k in sorted(actions.keys())},
    }
    ACTION_STATUS_PATH.write_text(json.dumps(payload, sort_keys=True, separators=(",", ":")))


def run_subprocess_action(cmd: List[str]) -> Tuple[int, str]:
    try:
        result = subprocess.run(cmd, cwd=WORKDIR, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        exit_code = int(result.returncode)
        seccode = "OK" if exit_code == 0 else "SEC_ACTION_FAIL"
        return exit_code, seccode
    except FileNotFoundError:
        return 127, "SEC_ACTION_NOT_FOUND"


def manage_hitl_markers() -> Tuple[int, str, int]:
    markers_path = os.environ.get("YUNITRACK_HITL_MARKERS_PATH")
    items: List[Dict[str, Any]] = []
    version = "1.0"
    if markers_path:
        try:
            obj = json.loads(pathlib.Path(markers_path).read_text())
            if not isinstance(obj, dict):
                raise ValueError("not object")
            version = obj.get("version", version)
            raw_items = obj.get("items", [])
            if not isinstance(raw_items, list):
                raise ValueError("items invalid")
            if len(raw_items) > 100:
                raise ValueError("too many items")
            for it in raw_items:
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
                    raise ValueError("sig invalid")
                items.append({"id": mid, "label": label, "expires_utc": expires, **({"signature": sig} if sig is not None else {})})
        except Exception:
            return 1, "SEC_HITL_INVALID", 0

    items.sort(key=lambda i: i["id"])
    HITL_STAGED_PATH.parent.mkdir(parents=True, exist_ok=True)
    staged = {
        "version": version,
        "generated_utc": ZERO_TIME,
        "items": items,
    }
    HITL_STAGED_PATH.write_text(json.dumps(staged, sort_keys=True, separators=(",", ":")))
    if not markers_path and not items:
        return 0, "STAGED_EMPTY_NO_INPUT", 0
    return 0, "STAGED_OK", len(items)


def load_hitl_summary() -> str:
    if not HITL_STAGED_PATH.exists():
        return "none"
    try:
        data = json.loads(HITL_STAGED_PATH.read_text())
        if isinstance(data, dict) and isinstance(data.get("items"), list):
            return f"{len(data['items'])} staged"
    except Exception:
        return "MALFORMED"
    return "unknown"


def load_registry_summary() -> str:
    reg_path = WORKDIR / "docs/keys/hitl_key_registry.json"
    if not reg_path.exists():
        return "missing"
    try:
        data = json.loads(reg_path.read_text())
        keys = data.get("keys", [])
        if isinstance(keys, list):
            active = [k for k in keys if isinstance(k, dict) and k.get("status") == "active"]
            retired = [k for k in keys if isinstance(k, dict) and k.get("status") == "retired"]
            active_id = data.get("active_key_id", "?")
            return f"active_id={active_id[:8]}.. active={len(active)} retired={len(retired)}"
    except Exception:
        return "malformed"
    return "unknown"


def ledger_summary() -> str:
    if not LEDGER_PATH.exists():
        return "ledger missing"
    try:
        lines = LEDGER_PATH.read_text().splitlines()
        total = len(lines)
        counts: Dict[str, int] = {}
        last_seq = 0
        for ln in lines:
            obj = json.loads(ln)
            if not isinstance(obj, dict):
                continue
            act = obj.get("action", "?")
            counts[act] = counts.get(act, 0) + 1
            last_seq = obj.get("seq", last_seq)
        parts = [f"total={total}", f"last_seq={last_seq}"]
        if counts:
            parts.append("counts=" + ",".join(f"{k}:{counts[k]}" for k in sorted(counts.keys())))
        signed = "yes" if LEDGER_SIGNED_PATH.exists() else "no"
        parts.append(f"signed={signed}")
        return " ".join(parts)
    except Exception:
        return "ledger malformed"


def main() -> None:
    data_used_fixtures = []

    ent_report, used = load_json(*SOURCES["enterprise_report"])
    if used:
        data_used_fixtures.append("enterprise_report")
    lite_report, used = load_json(*SOURCES["lite_report"])
    if used:
        data_used_fixtures.append("lite_report")
    lite_scope, used = load_json(*SOURCES["lite_scope"])
    if used:
        data_used_fixtures.append("lite_scope")
    lite_required, used = load_json(*SOURCES["lite_required_hashes"])
    if used:
        data_used_fixtures.append("lite_required_hashes")
    lite_policy, used = load_json(*SOURCES["lite_policy"])
    if used:
        data_used_fixtures.append("lite_policy")
    lite_commands_text, used = load_text(*SOURCES["lite_commands"])
    if used:
        data_used_fixtures.append("lite_commands")
    enterprise_chain, used = load_json(*SOURCES["enterprise_chain"])
    if used:
        data_used_fixtures.append("enterprise_chain")
    ledger_entries, ledger_used_fixture, ledger_malformed = load_ledger()
    if ledger_used_fixture:
        data_used_fixtures.append("request_ledger")

    guards = guardrail_status(lite_commands_text)

    overview_cards = []
    overview_cards.append(f"<div class=\"card\"><strong>Enterprise proof:</strong> <span class=\"status-{status_label(ent_report.get('pass') if ent_report else None).lower()}\">{status_label(ent_report.get('pass') if ent_report else None)}</span></div>")
    overview_cards.append(f"<div class=\"card\"><strong>Lite proof:</strong> <span class=\"status-{status_label(lite_report.get('pass') if lite_report else None).lower()}\">{status_label(lite_report.get('pass') if lite_report else None)}</span></div>")

    guard_items = []
    for key in sorted(guards.keys()):
        guard_items.append(f"<tr><td>{key}</td><td>{guards[key]}</td></tr>")
    guard_table = "<div class=\"card\"><table><tr><th>Guardrail</th><th>Status</th></tr>" + "".join(guard_items) + "</table></div>" if guard_items else "<div class=\"card\">No guardrail records</div>"

    policy_section = "<div class=\"card\">" + json.dumps(lite_policy or {}, sort_keys=True, indent=2) + "</div>"

    anti_replay_status = guards.get("anti_replay_cross_run", "UNKNOWN")
    anti_replay_section = f"<div class=\"card\"><strong>Anti-replay:</strong> {anti_replay_status}</div>"

    audit_chain_status = "UNKNOWN"
    if isinstance(enterprise_chain, dict):
        if enterprise_chain.get("pass") is True:
            audit_chain_status = "PASS"
        elif enterprise_chain.get("pass") is False:
            audit_chain_status = "FAIL"
    audit_section = f"<div class=\"card\"><strong>Audit chain:</strong> {audit_chain_status}</div>"

    req_set = lite_scope.get("REQUIRED_EQUALITY_SET", []) if isinstance(lite_scope, dict) else []
    req_hashes = lite_required or {}
    determinism_html = "<div class=\"card\"><strong>Required equality set:</strong> " + json.dumps(req_set) + "<br><strong>Required hashes:</strong><pre>" + json.dumps(req_hashes, sort_keys=True, indent=2) + "</pre></div>"

    fixture_banner = ""
    if data_used_fixtures:
        fixture_banner = "<div class=\"card\" style=\"background:#fef9c3;\"><strong>FIXTURE MODE:</strong> using fixtures for: " + ", ".join(sorted(data_used_fixtures)) + "</div>"

    if ledger_malformed:
        requests_section = "<div class=\"card\"><strong>Requests:</strong> LEDGER_MALFORMED</div>"
    elif ledger_entries:
        rows = []
        for e in ledger_entries:
            rows.append(
                f"<tr><td>{e['created_seq']}</td><td>{e['request_id']}</td><td>{e['profile']}</td><td>{e['decision']}</td><td>{e['seccode']}</td><td>{e['anti_replay']}</td><td>{e['approvals_ref'] or ''}</td></tr>"
            )
        requests_section = (
            "<div class=\"card\"><table><tr><th>created_seq</th><th>request_id</th><th>profile</th><th>decision</th><th>seccode</th><th>anti_replay</th><th>approvals_ref</th></tr>"
            + "".join(rows)
            + "</table></div>"
        )
    else:
        requests_section = "<div class=\"card\">No request ledger present (read-only)</div>"

    actions_enabled = os.environ.get("YUNITRACK_DASH_ENABLE_ACTIONS") == "1"
    existing_actions = load_action_status().get("actions", {})
    action_records: Dict[str, Dict[str, Any]] = {} if actions_enabled else existing_actions

    if actions_enabled:
        run_results: Dict[str, Dict[str, Any]] = {}
        for name, cmd, default_sec in ACTIONS:
            if name == "manage_hitl_markers":
                ec, sc, count = manage_hitl_markers()
                record = {"exit_code": ec, "seccode": sc, "last_run_utc": ZERO_TIME, "count": count}
            elif name == "sign_hitl_markers":
                if os.environ.get("HITL_SIGNING_KEY_PATH"):
                    ec, sc = run_subprocess_action(cmd)
                    record = {"exit_code": ec, "seccode": sc if sc else default_sec, "last_run_utc": ZERO_TIME}
                else:
                    record = {"exit_code": 0, "seccode": "SKIP_NO_KEY", "last_run_utc": ZERO_TIME}
            elif name == "sign_hitl_markers_ed25519":
                if os.environ.get("HITL_SIGNATURE_MODE") == "ed25519" and os.environ.get("HITL_ED25519_PRIVKEY_PATH"):
                    ec, sc = run_subprocess_action(cmd)
                    record = {"exit_code": ec, "seccode": sc if sc else default_sec, "last_run_utc": ZERO_TIME}
                else:
                    record = {"exit_code": 0, "seccode": "SKIP_NO_KEY_OR_MODE", "last_run_utc": ZERO_TIME}
            elif name == "verify_ledger_signature":
                if os.environ.get("CONTROL_PLANE_LEDGER_SIGNATURE_MODE") == "ed25519":
                    ec, sc = run_subprocess_action(cmd)
                    record = {"exit_code": ec, "seccode": sc if sc else default_sec, "last_run_utc": ZERO_TIME}
                else:
                    record = {"exit_code": 0, "seccode": "SKIP_NO_LEDGER_ED25519", "last_run_utc": ZERO_TIME}
            else:
                ec, sc = run_subprocess_action(cmd)
                record = {"exit_code": ec, "seccode": sc if sc else default_sec, "last_run_utc": ZERO_TIME}
            run_results[name] = record
        write_action_status(run_results)
        action_records = run_results

    actions_rows = []
    for name, _, _ in ACTIONS:
        record = action_records.get(name, {})
        exit_code = record.get("exit_code")
        seccode = record.get("seccode") or ("DISABLED" if not actions_enabled else "UNKNOWN")
        label = "DISABLED" if not actions_enabled else ("PASS" if exit_code == 0 else ("FAIL" if exit_code is not None else "UNKNOWN"))
        actions_rows.append(
            f"<tr><td>{name}</td><td>{label}</td><td>{seccode}</td><td>{'' if exit_code is None else exit_code}</td></tr>"
        )

    actions_table = (
        "<div class=\"card\"><table><tr><th>Action</th><th>Status</th><th>SecCode</th><th>Exit</th></tr>"
        + "".join(actions_rows)
        + "</table></div>"
    )

    hitl_summary = load_hitl_summary()
    registry_summary = load_registry_summary()
    ledger_info = ledger_summary()
    actions_state = "ENABLED" if actions_enabled else "DISABLED"
    controlled_actions_section = f"""
    <h2>Controlled actions</h2>
    <div class=\"card\"><strong>Actions state:</strong> {actions_state} (set YUNITRACK_DASH_ENABLE_ACTIONS=1 to enable)</div>
    <div class=\"card\"><strong>HITL markers:</strong> {hitl_summary}</div>
    <div class=\"card\"><strong>HITL key registry:</strong> {registry_summary}</div>
    <div class=\"card\"><strong>Action ledger:</strong> {ledger_info}</div>
    {actions_table}
    """

    content = f"""
    {fixture_banner}
    <h2>Overview</h2>
    <div class=\"grid\">{''.join(overview_cards)}</div>

    <h2>Guardrails (Lite)</h2>
    {guard_table}

    <h2>Approvals / Policy Checks (Lite)</h2>
    {policy_section}

    <h2>Anti-replay</h2>
    {anti_replay_section}

    <h2>Audit Chain (Enterprise)</h2>
    {audit_section}

    <h2>Determinism (Lite)</h2>
    {determinism_html}

    <h2>Requests</h2>
    {requests_section}

    {controlled_actions_section}
    """

    template = TEMPLATE_PATH.read_text()
    html = template.replace("{{CONTENT}}", content)

    DIST_PATH.parent.mkdir(parents=True, exist_ok=True)
    DIST_PATH.write_text(html)


if __name__ == "__main__":
    main()
