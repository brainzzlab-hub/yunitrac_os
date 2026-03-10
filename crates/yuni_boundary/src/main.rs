#![forbid(unsafe_code)]

use ac::run as ac_run;
use clap::Parser;
use cm::run as cm_run;
use ro_in::run as ro_in_run;
use shared::{compute_canon_hash, compute_tick_hash, derive_run_id, Port, Vector, TICK_HASH_ZERO};
use skeleton::run as skeleton_run;
use va_gate::run as va_gate_run;

const PASS_LINE: &str = "PASS";
const FAIL_PARSE: &str = "FAIL: BOUNDARY_PARSE";
const FAIL_IO: &str = "FAIL: BOUNDARY_IO";
const FAIL_RUN_ID: &str = "FAIL: BOUNDARY_RUN_ID";
const FAIL_UNKNOWN: &str = "FAIL: BOUNDARY_UNKNOWN";

#[derive(Debug, Parser)]
struct Args {
    #[arg(long)]
    vector: String,
    #[arg(long)]
    audit_key: String,
    #[arg(long)]
    out: String,
    #[arg(long)]
    run_id: Option<String>,
}

fn main() {
    let args = Args::parse();
    match run(args) {
        Ok(()) => println!("{PASS_LINE}"),
        Err(BoundaryError::Parse) => {
            println!("{FAIL_PARSE}");
            std::process::exit(1);
        }
        Err(BoundaryError::Io) => {
            println!("{FAIL_IO}");
            std::process::exit(1);
        }
        Err(BoundaryError::RunId) => {
            println!("{FAIL_RUN_ID}");
            std::process::exit(1);
        }
        Err(BoundaryError::Unknown) => {
            println!("{FAIL_UNKNOWN}");
            std::process::exit(1);
        }
    };
}

#[derive(Debug, Error)]
enum BoundaryError {
    #[error("parse")]
    Parse,
    #[error("io")]
    Io,
    #[error("run_id")]
    RunId,
    #[error("unknown")]
    Unknown,
}

fn run(args: Args) -> Result<(), BoundaryError> {
    let vector_bytes = std::fs::read(&args.vector).map_err(|_| BoundaryError::Io)?;
    let (vector, canon_code_bytes, canon_header_bytes) =
        Vector::parse(&vector_bytes).map_err(|_| BoundaryError::Parse)?;

    let canon_hash = compute_canon_hash(&canon_header_bytes, &canon_code_bytes);
    let run_id = if let Some(run_str) = args.run_id.as_ref() {
        let bytes = hex::decode(run_str).map_err(|_| BoundaryError::RunId)?;
        if bytes.len() != 32 {
            return Err(BoundaryError::RunId);
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        arr
    } else {
        derive_run_id(&vector, &canon_hash)
    };
    let audit_key = std::fs::read(&args.audit_key).map_err(|_| BoundaryError::Io)?;

    // Baseline sliders captured once at tick 0 (S2).
    let baseline_sliders = vector.sliders;
    let mut tick_hash_prev = TICK_HASH_ZERO;
    let mut port = Port {
        canon_hash,
        run_id,
        audit_key: Some(audit_key.clone()),
        ..Port::default()
    };

    // Single tick for now; tick loop deterministic (T2).
    let tick = port.meta.tick;
    let tick_hash = compute_tick_hash(&tick_hash_prev, tick, &canon_hash);
    port.tick_hash = tick_hash;

    // Skeleton stage enforces tick budget and mode.
    port = skeleton_run(port, &vector, &baseline_sliders);
    // Constraint manager enforces drift (no drift yet; use baseline).
    port = cm_run(port, &baseline_sliders, &baseline_sliders);
    // Actor: provide sanitized view (no approval/signature/pubkey/security/meta flags).
    let mut ac_view = port.clone();
    ac_view.approval = None;
    ac_view.signature_der = None;
    ac_view.security = None;
    ac_view.hl_pubkey_pem = None;
    ac_view.meta.flags = 0;
    ac_view.outputs = {
        let mut v = Vec::with_capacity(32 + 32 + 8);
        v.extend_from_slice(&port.canon_hash);
        v.extend_from_slice(&port.tick_hash);
        v.extend_from_slice(&port.meta.tick.to_le_bytes());
        v
    };
    let mut ac_out = ac_run(ac_view);
    // Restore sensitive fields from secure port after ac.
    ac_out.approval = port.approval;
    ac_out.signature_der = port.signature_der;
    ac_out.security = port.security;
    ac_out.hl_pubkey_pem = port.hl_pubkey_pem;
    ac_out.canon_hash = port.canon_hash;
    ac_out.run_id = port.run_id;
    ac_out.audit_key = port.audit_key.clone();
    ac_out.tick_hash = port.tick_hash;
    ac_out.outputs.clear(); // reset to avoid leaking ac payload
    port = ac_out;
    // Validator placeholder.
    port = va_gate_run(port);
    // Router placeholder.
    port = ro_in_run(port);

    // Update meta tick hash head for potential next iterations.
    tick_hash_prev = tick_hash;

    // Persist artifacts deterministically.
    std::fs::create_dir_all(&args.out).map_err(|_| BoundaryError::Io)?;
    std::fs::write(format!("{}/outputs.bin", &args.out), &port.outputs)
        .map_err(|_| BoundaryError::Io)?;
    std::fs::write(
        format!("{}/metrics_records.bin", &args.out),
        join_records(&port.metrics_records),
    )
    .map_err(|_| BoundaryError::Io)?;
    std::fs::write(
        format!("{}/audit_records.bin", &args.out),
        join_records(&port.audit_records),
    )
    .map_err(|_| BoundaryError::Io)?;
    std::fs::write(
        format!("{}/security_records.bin", &args.out),
        join_records(&port.security_records),
    )
    .map_err(|_| BoundaryError::Io)?;

    let outputs_hash = shared::sha256_bytes(&port.outputs);
    let metrics_hash = shared::sha256_bytes(&join_records(&port.metrics_records));
    let audit_chain_head = shared::compute_event_hash(
        &shared::TICK_HASH_ZERO,
        &join_records(&port.audit_records),
        &audit_key,
    );
    let tick_hash_head = tick_hash_prev;

    let hashes = serde_json::json!({
        "canon_hash": shared::hex_lower(&canon_hash),
        "tick_hash_head": shared::hex_lower(&tick_hash_head),
        "audit_chain_head": shared::hex_lower(&audit_chain_head),
        "outputs_hash": shared::hex_lower(&outputs_hash),
        "metrics_hash": shared::hex_lower(&metrics_hash),
    });
    let hashes_bytes = serde_json::to_vec_pretty(&hashes).map_err(|_| BoundaryError::Unknown)?;
    std::fs::write(format!("{}/hashes.json", &args.out), hashes_bytes)
        .map_err(|_| BoundaryError::Io)?;
    Ok(())
}
fn join_records(records: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    for (i, rec) in records.iter().enumerate() {
        out.extend_from_slice(rec);
        if i + 1 != records.len() {
            out.push(b'\n');
        }
    }
    out
}
use thiserror::Error;
