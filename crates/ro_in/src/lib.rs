#![forbid(unsafe_code)]

use shared::{
    compute_event_hash, sha256_bytes, AuditRecord, MetricsRecord, Port, SecurityRecord,
    TICK_HASH_ZERO,
};
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RoInError {
    #[error("outputs already set")]
    OutputsSet,
    #[error("missing audit key")]
    AuditKeyMissing,
}

/// Read-out ingress/egress router; computes hashes and records deterministically into Port.
pub fn run(mut port: Port) -> Port {
    if !port.outputs.is_empty() {
        port.security = Some(shared::SecCode::SecInvalidSig);
        return port;
    }
    let audit_key = match &port.audit_key {
        Some(k) => k.clone(),
        None => {
            port.security = Some(shared::SecCode::SecInvalidSig);
            return port;
        }
    };

    // Deterministic outputs: concat tick_hash, canon_hash, run_id.
    let mut outputs = Vec::with_capacity(96);
    outputs.extend_from_slice(&port.tick_hash);
    outputs.extend_from_slice(&port.canon_hash);
    outputs.extend_from_slice(&port.run_id);
    port.outputs = outputs;

    let metrics = MetricsRecord {
        tick: port.meta.tick,
        s1: port.sliders.s1,
        s2: port.sliders.s2,
        s3: port.sliders.s3,
        s4: port.sliders.s4,
    };
    port.metrics_records.push(metrics.to_bytes());

    let metrics_concat: Vec<u8> = port
        .metrics_records
        .iter()
        .flat_map(|r| r.clone())
        .collect();
    let metrics_hash = sha256_bytes(&metrics_concat);
    let outputs_hash = sha256_bytes(&port.outputs);

    let audit = AuditRecord {
        tick: port.meta.tick,
        status: 0,
        canon_hash: port.canon_hash,
        tick_hash: port.tick_hash,
        outputs_hash,
        metrics_hash,
    };
    port.audit_records.push(audit.to_bytes());

    let audit_payload_concat: Vec<u8> = port.audit_records.iter().flat_map(|r| r.clone()).collect();
    let audit_head = compute_event_hash(&TICK_HASH_ZERO, &audit_payload_concat, &audit_key);
    let security = SecurityRecord {
        tick: port.meta.tick,
        code: u16::from_le_bytes([audit_head[0], audit_head[1]]),
    };
    port.security_records.push(security.to_bytes());

    port
}
