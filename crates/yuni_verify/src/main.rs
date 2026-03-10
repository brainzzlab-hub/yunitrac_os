#![forbid(unsafe_code)]

use anyhow::{anyhow, Result};
use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, ObjectClass};
use cryptoki::session::{Session, UserType};
use cryptoki::types::AuthPin;
use p256::ecdsa::Signature as P256Signature;
use serde::Serialize;
use shared::{compute_event_hash, sha256_bytes, ApprovalPayload, Vector, TICK_HASH_ZERO};
use std::env;

const PASS_LINE: &str = "PASS";
const FAIL_USAGE: &str = "FAIL: VERIFY_USAGE";
const FAIL_IO: &str = "FAIL: VERIFY_IO";
const FAIL_PARSE: &str = "FAIL: VERIFY_PARSE";
const FAIL_PKCS11: &str = "FAIL: VERIFY_PKCS11";
const FAIL_REPORT: &str = "FAIL: VERIFY_REPORT";
const FAIL_CHECK: &str = "FAIL: VERIFY_CHECK_FAIL";

fn main() {
    match run() {
        Ok(Outcome::Pass) => {
            println!("{PASS_LINE}");
        }
        Ok(Outcome::CheckFail) => {
            println!("{FAIL_CHECK}");
            std::process::exit(1);
        }
        Err(code) => {
            println!("{code}");
            std::process::exit(1);
        }
    }
}

#[derive(Clone, Copy)]
enum Outcome {
    Pass,
    CheckFail,
}

fn run() -> Result<Outcome, &'static str> {
    let mut args = env::args().skip(1);
    let Some(first) = args.next() else {
        return Err(FAIL_USAGE);
    };

    if first == "--sign" {
        let mut vector: Option<String> = None;
        let mut run_id: Option<String> = None;
        let mut out: Option<String> = None;

        while let Some(a) = args.next() {
            match a.as_str() {
                "--vector" => vector = args.next(),
                "--run-id" => run_id = args.next(),
                "--out" => out = args.next(),
                _ => return Err(FAIL_USAGE),
            }
        }

        let (Some(vector), Some(run_id), Some(out)) = (vector, run_id, out) else {
            return Err(FAIL_USAGE);
        };

        sign_from_vector(&vector, &run_id, &out).map_err(map_sign_err)?;
        return Ok(Outcome::Pass);
    }

    // VERIFY mode (new form with leading "verify" or legacy form starting with --a/--b/etc)
    let mut verify_args: Vec<String> = Vec::new();
    if first == "verify" {
        verify_args.extend(args);
    } else if first.starts_with("--") {
        verify_args.push(first);
        verify_args.extend(args);
    } else {
        return Err(FAIL_USAGE);
    }

    let mut a_dir: Option<String> = None;
    let mut b_dir: Option<String> = None;
    let mut c_dir: Option<String> = None;
    let mut report: Option<String> = None;
    let mut audit_key: Option<String> = None;

    let mut it = verify_args.into_iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--a" => a_dir = it.next(),
            "--b" => b_dir = it.next(),
            "--c" => c_dir = it.next(),
            "--report" => report = it.next(),
            "--audit-key" => audit_key = it.next(),
            _ => return Err(FAIL_USAGE),
        }
    }

    let (Some(a_dir), Some(b_dir), Some(report), Some(audit_key)) =
        (a_dir, b_dir, report, audit_key)
    else {
        return Err(FAIL_USAGE);
    };
    let c_dir = c_dir.unwrap_or_else(|| b_dir.clone());

    let pass = verify_runs(&a_dir, &b_dir, &c_dir, &audit_key, &report)?;
    if pass {
        Ok(Outcome::Pass)
    } else {
        Ok(Outcome::CheckFail)
    }
}

fn verify_runs(
    a_dir: &str,
    b_dir: &str,
    c_dir: &str,
    audit_key_path: &str,
    report_path: &str,
) -> Result<bool, &'static str> {
    let audit_key = std::fs::read(audit_key_path).map_err(|_| FAIL_IO)?;

    let a = Artifacts::load(a_dir)?;
    let b = Artifacts::load(b_dir)?;
    let c = Artifacts::load(c_dir)?;

    let report = vec![
        check_eq("outputs_equal_ab", &a.outputs, &b.outputs),
        check_eq("outputs_equal_ac", &a.outputs, &c.outputs),
        check_eq("metrics_equal_ab", &a.metrics, &b.metrics),
        check_eq("metrics_equal_ac", &a.metrics, &c.metrics),
        check_eq("audit_equal_ab", &a.audit, &b.audit),
        check_eq("audit_equal_ac", &a.audit, &c.audit),
        check_eq("security_equal_ab", &a.security, &b.security),
        check_eq("security_equal_ac", &a.security, &c.security),
        check_audit_chain("audit_chain_a", &a.audit, &audit_key),
        check_audit_chain("audit_chain_b", &b.audit, &audit_key),
        check_audit_chain("audit_chain_c", &c.audit, &audit_key),
        check_gdpr_numeric("metrics_numeric_a", &a.metrics),
        check_gdpr_numeric("metrics_numeric_b", &b.metrics),
        check_gdpr_numeric("metrics_numeric_c", &c.metrics),
    ];

    let overall_pass = report.iter().all(|c| c.pass);
    let summary = serde_json::json!({
        "pass": overall_pass,
        "checks": report,
    });
    let bytes = serde_json::to_vec_pretty(&summary).map_err(|_| FAIL_REPORT)?;
    std::fs::write(report_path, bytes).map_err(|_| FAIL_REPORT)?;
    Ok(overall_pass)
}

#[derive(Debug, Serialize)]
struct Check {
    name: String,
    pass: bool,
    detail: Option<String>,
}

fn check_eq(name: &str, a: &[u8], b: &[u8]) -> Check {
    let pass = a == b;
    let detail = if pass {
        None
    } else {
        Some(format!(
            "mismatch: a_hash={} b_hash={}",
            hex::encode(sha256_bytes(a)),
            hex::encode(sha256_bytes(b))
        ))
    };
    Check {
        name: name.to_string(),
        pass,
        detail,
    }
}

fn check_audit_chain(name: &str, audit_stream: &[u8], key: &[u8]) -> Check {
    let records: Vec<&[u8]> = audit_stream.split(|b| *b == b'\n').collect();
    let mut prev = TICK_HASH_ZERO;
    for rec in &records {
        let h = compute_event_hash(&prev, rec, key);
        prev = h;
    }
    let pass = !records.is_empty();
    let detail = Some(format!("head={}", hex::encode(prev)));
    Check {
        name: name.to_string(),
        pass,
        detail,
    }
}

fn check_gdpr_numeric(name: &str, metrics: &[u8]) -> Check {
    let pass = metrics.iter().all(|b| {
        matches!(
            b,
            b'0'..=b'9'
                | b','
                | b':'
                | b'{'
                | b'}'
                | b'['
                | b']'
                | b'"'
                | b' '
                | b'\n'
                | b'\r'
                | b'\t'
        )
    });
    Check {
        name: name.to_string(),
        pass,
        detail: None,
    }
}

struct Artifacts {
    outputs: Vec<u8>,
    metrics: Vec<u8>,
    audit: Vec<u8>,
    security: Vec<u8>,
}

impl Artifacts {
    fn load(dir: &str) -> Result<Self, &'static str> {
        Ok(Self {
            outputs: read_bin(dir, "outputs.bin")?,
            metrics: read_bin(dir, "metrics_records.bin")?,
            audit: read_bin(dir, "audit_records.bin")?,
            security: read_bin(dir, "security_records.bin")?,
        })
    }
}

fn read_bin(dir: &str, file: &str) -> Result<Vec<u8>, &'static str> {
    let path = format!("{}/{}", dir, file);
    std::fs::read(path).map_err(|_| FAIL_IO)
}

fn sign_from_vector(vector_path: &str, run_id_hex: &str, out: &str) -> Result<(), SignError> {
    let vector_bytes = std::fs::read(vector_path).map_err(|_| SignError::Io)?;
    let (vector, canon_code, canon_header) =
        Vector::parse(&vector_bytes).map_err(|_| SignError::Parse)?;
    let canon_hash = shared::compute_canon_hash(&canon_header, &canon_code);
    let mut run_id = [0u8; 32];
    let run_bytes = hex::decode(run_id_hex).map_err(|_| SignError::Usage)?;
    if run_bytes.len() != 32 {
        return Err(SignError::Usage);
    }
    run_id.copy_from_slice(&run_bytes);

    let approvals = vector.approvals.actions.first().ok_or(SignError::Parse)?;
    let payload = ApprovalPayload {
        canon_hash,
        run_id,
        retry_epoch: vector.retry_epoch,
        nonce: vector.approvals.nonce.clone(),
        action: approvals.action.clone(),
        proposal_id: vector.approvals.proposal_id.clone(),
    };
    const DOMAIN_PREFIX: &[u8] = b"YUNITRACK_APPROVAL_V1\0";
    let mut msg = Vec::with_capacity(DOMAIN_PREFIX.len() + payload.to_bytes().len());
    msg.extend_from_slice(DOMAIN_PREFIX);
    msg.extend_from_slice(&payload.to_bytes());
    let payload_hash = sha256_bytes(&msg);

    let module = env::var("YUNI_PKCS11_MODULE").map_err(|_| SignError::Usage)?;
    let pin = env::var("YUNI_PKCS11_PIN").map_err(|_| SignError::Usage)?;
    let key_label = env::var("YUNI_PKCS11_KEY_LABEL").map_err(|_| SignError::Usage)?;
    let slot_index: usize = env::var("YUNI_PKCS11_SLOT")
        .unwrap_or_else(|_| "0".into())
        .parse()
        .map_err(|_| SignError::Usage)?;

    let pkcs11 = Pkcs11::new(&module).map_err(|_| SignError::Pkcs11)?;
    initialize_pkcs11(&pkcs11).map_err(|_| SignError::Pkcs11)?;
    let slots = pkcs11.get_all_slots().map_err(|_| SignError::Pkcs11)?;
    let slot = *slots.get(slot_index).ok_or(SignError::Usage)?;
    let session = pkcs11
        .open_rw_session(slot)
        .map_err(|_| SignError::Pkcs11)?;
    let auth_pin = AuthPin::from(pin);
    session
        .login(UserType::User, Some(&auth_pin))
        .map_err(|_| SignError::Pkcs11)?;

    let key_handle = find_private_key(&session, &key_label).map_err(|_| SignError::Pkcs11)?;
    let sig_raw = session
        .sign(&Mechanism::Ecdsa, key_handle, &payload_hash)
        .map_err(|_| SignError::Pkcs11)?;

    if sig_raw.len() != 64 {
        return Err(SignError::Pkcs11);
    }
    let sig = P256Signature::from_slice(&sig_raw).map_err(|_| SignError::Pkcs11)?;
    let der = sig.to_der().as_bytes().to_vec();
    std::fs::write(out, der).map_err(|_| SignError::Io)?;
    Ok(())
}

#[derive(Debug, Clone, Copy)]
enum SignError {
    Usage,
    Io,
    Parse,
    Pkcs11,
}

fn map_sign_err(e: SignError) -> &'static str {
    match e {
        SignError::Usage => FAIL_USAGE,
        SignError::Io => FAIL_IO,
        SignError::Parse => FAIL_PARSE,
        SignError::Pkcs11 => FAIL_PKCS11,
    }
}

fn initialize_pkcs11(pkcs11: &Pkcs11) -> Result<()> {
    pkcs11
        .initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
        .or_else(|e| {
            if format!("{e}").contains("CKR_CRYPTOKI_ALREADY_INITIALIZED") {
                Ok(())
            } else {
                Err(e)
            }
        })
        .map_err(anyhow::Error::from)
}

fn find_private_key(session: &Session, label: &str) -> Result<cryptoki::object::ObjectHandle> {
    session
        .find_objects(&[
            Attribute::Class(ObjectClass::PRIVATE_KEY),
            Attribute::Label(label.into()),
        ])?
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("key not found"))
}
