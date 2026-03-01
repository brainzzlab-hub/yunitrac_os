#![forbid(unsafe_code)]

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Mode values are fixed by Canon (M0).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Mode {
    #[default]
    Analyze,
    Generate,
    Communicate,
    Movement,
}

/// Slider set constrained by Canon (S0/S1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sliders {
    pub step: u8,
    pub s1: u8,
    pub s2: u8,
    pub s3: u8,
    pub s4: u8,
}

impl Default for Sliders {
    fn default() -> Self {
        Self {
            step: 2,
            s1: 0,
            s2: 0,
            s3: 0,
            s4: 0,
        }
    }
}

/// Metadata carried across the tick loop; flags reserved for derived params (S2).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Meta {
    pub tick: u64,
    pub flags: u32,
}

/// Port is the single connector (P0) passed through all plugins.
#[derive(Clone, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Port {
    pub meta: Meta,
    pub sliders: Sliders,
    pub mode: Mode,
    pub approval: Option<ApprovalPayload>,
    pub signature_der: Option<Vec<u8>>,
    pub security: Option<SecCode>,
    pub hl_pubkey_pem: Option<String>,
    pub canon_hash: [u8; 32],
    pub tick_hash: [u8; 32],
    pub run_id: [u8; 32],
    pub audit_key: Option<Vec<u8>>,
    pub outputs: Vec<u8>,
    pub audit_records: Vec<Vec<u8>>,
    pub metrics_records: Vec<Vec<u8>>,
    pub security_records: Vec<Vec<u8>>,
}

/// Exit categories (I4 allowlist).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ExitId {
    Audit,
    Metrics,
    Security,
    Logs,
}

/// Security codes for approvals/validation failures (C2/C3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u16)]
pub enum SecCode {
    SecUnsignedRejected = 1,
    SecInvalidSig = 2,
    SecReplayNonce = 3,
}

/// Approval payload bound to canon/run_id/retry_epoch/nonce/action/proposal_id (C3).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalPayload {
    pub canon_hash: [u8; 32],
    pub run_id: [u8; 32],
    pub retry_epoch: u64,
    pub nonce: String,
    pub action: String,
    pub proposal_id: String,
}

impl ApprovalPayload {
    /// Deterministic encoding: concat fixed fields and length-prefixed strings.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.canon_hash);
        out.extend_from_slice(&self.run_id);
        out.extend_from_slice(&self.retry_epoch.to_le_bytes());
        encode_len_bytes(&mut out, self.nonce.as_bytes());
        encode_len_bytes(&mut out, self.action.as_bytes());
        encode_len_bytes(&mut out, self.proposal_id.as_bytes());
        out
    }
}

/// Audit record payload (I5 audit bucket: ids/counters/status only).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditRecord {
    pub tick: u64,
    pub status: u16,
    pub canon_hash: [u8; 32],
    pub tick_hash: [u8; 32],
    pub outputs_hash: [u8; 32],
    pub metrics_hash: [u8; 32],
}

impl AuditRecord {
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        // serde_json preserves field order for structs; deterministic.
        serde_json::to_vec(self).expect("audit serialize")
    }
}

/// Metrics record (I5 metrics bucket: numeric-only telemetry).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetricsRecord {
    pub tick: u64,
    pub s1: u8,
    pub s2: u8,
    pub s3: u8,
    pub s4: u8,
}

impl MetricsRecord {
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        // metrics bucket must be numeric-only: encode as compact array
        serde_json::to_vec(&[
            self.tick,
            self.s1 as u64,
            self.s2 as u64,
            self.s3 as u64,
            self.s4 as u64,
        ])
        .expect("metrics serialize")
    }
}

/// Security record (I4 security exit).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityRecord {
    pub tick: u64,
    pub code: u16,
}

impl SecurityRecord {
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("security serialize")
    }
}

/// Budget limits from vector.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Budgets {
    pub max_attempts: u32,
    pub max_tokens: u32,
}

/// Approval action input from vector.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalActionInput {
    pub action: String, // "APPROVE" | "REJECT"
    #[serde(default)]
    pub signature_b64: Option<String>, // None for unsigned case
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalsInput {
    pub nonce: String,
    pub proposal_id: String,
    pub actions: Vec<ApprovalActionInput>,
}

/// Canon vector as supplied to boundary binary.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Vector {
    pub canon_header_json: String, // base64 encoded bytes
    pub canon_code_bytes: String,  // base64 encoded
    pub mode: Mode,
    pub sliders: Sliders,
    pub budgets: Budgets,
    pub approvals: ApprovalsInput,
    pub retry_epoch: u64,
}

/// Canon hash per C0.
#[must_use]
pub fn compute_canon_hash(canon_header_json: &[u8], canon_code_bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(canon_header_json);
    hasher.update(canon_code_bytes);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Deterministic run_id derived from canon and sliders/mode content.
#[must_use]
pub fn derive_run_id(vector: &Vector, canon_hash: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(canon_hash);
    hasher.update([vector.mode as u8]);
    hasher.update([
        vector.sliders.step,
        vector.sliders.s1,
        vector.sliders.s2,
        vector.sliders.s3,
        vector.sliders.s4,
    ]);
    hasher.update(vector.retry_epoch.to_le_bytes());
    hasher.update(vector.budgets.max_attempts.to_le_bytes());
    hasher.update(vector.budgets.max_tokens.to_le_bytes());
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum VectorError {
    #[error("decode canon_code_bytes: {0}")]
    CanonCodeDecode(String),
    #[error("decode canon_header_json: {0}")]
    CanonHeaderDecode(String),
    #[error("slider invalid: {0:?}")]
    SliderInvalid(SliderError),
}

impl Vector {
    /// Load from JSON bytes, decode canon_code_bytes, validate sliders.
    pub fn parse(json_bytes: &[u8]) -> Result<(Self, Vec<u8>, Vec<u8>), VectorError> {
        let v: Vector = serde_json::from_slice(json_bytes)
            .map_err(|e| VectorError::CanonCodeDecode(e.to_string()))?;
        let decoded = B64
            .decode(v.canon_code_bytes.as_bytes())
            .map_err(|e| VectorError::CanonCodeDecode(e.to_string()))?;
        let header = B64
            .decode(v.canon_header_json.as_bytes())
            .map_err(|e| VectorError::CanonHeaderDecode(e.to_string()))?;
        validate_sliders(&v.sliders).map_err(VectorError::SliderInvalid)?;
        Ok((v.clone(), decoded, header))
    }
}

/// Canon tick hash zero value (T1).
pub const TICK_HASH_ZERO: [u8; 32] = [0u8; 32];

/// Compute tick_hash_i = SHA256(prev || tick_le || canon_hash) (T1).
#[must_use]
pub fn compute_tick_hash(prev: &[u8; 32], tick: u64, canon_hash: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(prev);
    hasher.update(tick.to_le_bytes());
    hasher.update(canon_hash);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Slider validation per Canon S0 (step==2, values even within 0..=100).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SliderError {
    StepInvalid(u8),
    OutOfRange { slider: &'static str, value: u8 },
    NotEven { slider: &'static str, value: u8 },
}

pub fn validate_sliders(sliders: &Sliders) -> Result<(), SliderError> {
    if sliders.step != 2 {
        return Err(SliderError::StepInvalid(sliders.step));
    }
    for (label, value) in [
        ("s1", sliders.s1),
        ("s2", sliders.s2),
        ("s3", sliders.s3),
        ("s4", sliders.s4),
    ] {
        if value > 100 {
            return Err(SliderError::OutOfRange {
                slider: label,
                value,
            });
        }
        if value % 2 != 0 {
            return Err(SliderError::NotEven {
                slider: label,
                value,
            });
        }
    }
    Ok(())
}

/// Drift enforcement per Canon S1.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DriftError {
    DriftNotAllowed {
        slider: &'static str,
        from: u8,
        to: u8,
    },
    DriftTooLarge {
        slider: &'static str,
        from: u8,
        to: u8,
    },
}

pub fn validate_drift(current: &Sliders, baseline: &Sliders, mode: Mode) -> Result<(), DriftError> {
    // s2..s4 never drift.
    for (label, cur, base) in [
        ("s2", current.s2, baseline.s2),
        ("s3", current.s3, baseline.s3),
        ("s4", current.s4, baseline.s4),
    ] {
        if cur != base {
            return Err(DriftError::DriftNotAllowed {
                slider: label,
                from: base,
                to: cur,
            });
        }
    }

    // s1 drift only in Movement and by ±2.
    match mode {
        Mode::Movement => {
            let from = baseline.s1;
            let to = current.s1;
            let diff = to.abs_diff(from);
            if diff > 2 {
                return Err(DriftError::DriftTooLarge {
                    slider: "s1",
                    from,
                    to,
                });
            }
        }
        _ => {
            if current.s1 != baseline.s1 {
                return Err(DriftError::DriftNotAllowed {
                    slider: "s1",
                    from: baseline.s1,
                    to: current.s1,
                });
            }
        }
    }

    Ok(())
}

/// SHA-256 of arbitrary bytes.
#[must_use]
pub fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Lowercase hex encoding for stable hash output.
#[must_use]
pub fn hex_lower(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

fn encode_len_bytes(out: &mut Vec<u8>, data: &[u8]) {
    let len = data.len() as u32;
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(data);
}

/// HMAC-SHA256 audit chain step (C1).
#[must_use]
pub fn compute_event_hash(prev: &[u8; 32], payload: &[u8], key: &[u8]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("hmac key");
    mac.update(prev);
    mac.update(payload);
    let digest = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tick_hash_matches_reference() {
        let prev = TICK_HASH_ZERO;
        let canon_hash = [1u8; 32];
        let h = compute_tick_hash(&prev, 0, &canon_hash);
        // Stable expected digest for determinism.
        assert_eq!(
            h,
            [
                0xa9, 0x8c, 0x79, 0x06, 0xf6, 0xf9, 0x58, 0xb7, 0xce, 0xd7, 0x7c, 0xae, 0xad, 0xfb,
                0xc6, 0xb7, 0xe6, 0xfc, 0x86, 0x4b, 0xa3, 0x78, 0x61, 0x64, 0x61, 0x03, 0x86, 0xe9,
                0x2e, 0x67, 0x50, 0xbf
            ]
        );
    }

    #[test]
    fn sliders_valid() {
        let s = Sliders {
            step: 2,
            s1: 4,
            s2: 6,
            s3: 8,
            s4: 10,
        };
        assert!(validate_sliders(&s).is_ok());
    }

    #[test]
    fn sliders_invalid_step() {
        let s = Sliders {
            step: 1,
            ..Default::default()
        };
        assert!(matches!(
            validate_sliders(&s),
            Err(SliderError::StepInvalid(1))
        ));
    }

    #[test]
    fn drift_only_in_movement_small_delta() {
        let base = Sliders {
            s1: 10,
            s2: 0,
            s3: 0,
            s4: 0,
            step: 2,
        };
        let cur = Sliders {
            s1: 12,
            s2: 0,
            s3: 0,
            s4: 0,
            step: 2,
        };
        assert!(validate_drift(&cur, &base, Mode::Movement).is_ok());
    }

    #[test]
    fn drift_rejected_in_analyze() {
        let base = Sliders {
            s1: 10,
            ..Default::default()
        };
        let cur = Sliders {
            s1: 12,
            ..Default::default()
        };
        assert!(matches!(
            validate_drift(&cur, &base, Mode::Analyze),
            Err(DriftError::DriftNotAllowed { .. })
        ));
    }

    #[test]
    fn drift_too_large() {
        let base = Sliders {
            s1: 10,
            ..Default::default()
        };
        let cur = Sliders {
            s1: 14,
            ..Default::default()
        };
        assert!(matches!(
            validate_drift(&cur, &base, Mode::Movement),
            Err(DriftError::DriftTooLarge { .. })
        ));
    }

    #[test]
    fn sha256_bytes_matches_reference() {
        let h = sha256_bytes(b"abc");
        assert_eq!(
            h,
            [
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
                0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
                0xf2, 0x00, 0x15, 0xad
            ]
        );
    }

    #[test]
    fn event_hash_matches_reference() {
        let prev = [0u8; 32];
        let payload = b"payload";
        let key = b"key123";
        let h = compute_event_hash(&prev, payload, key);
        assert_eq!(
            h,
            [
                0x5c, 0x3c, 0xf0, 0x87, 0xe1, 0x93, 0x47, 0xb2, 0xd2, 0x2a, 0xbf, 0x28, 0x5e, 0x23,
                0x63, 0x20, 0x8c, 0x13, 0x0c, 0xfa, 0xfd, 0x1a, 0x02, 0x56, 0x22, 0x37, 0x54, 0x73,
                0x56, 0xe0, 0x4c, 0x1c
            ]
        );
    }

    #[test]
    fn approval_payload_deterministic_bytes() {
        let payload = ApprovalPayload {
            canon_hash: [1u8; 32],
            run_id: [2u8; 32],
            retry_epoch: 3,
            nonce: "n".to_string(),
            action: "APPROVE".to_string(),
            proposal_id: "p".to_string(),
        };
        let b = payload.to_bytes();
        let expected_hex = "010101010101010101010101010101010101010101010101010101010101010102020202020202020202020202020202020202020202020202020202020202020300000000000000010000006e07000000415050524f56450100000070";
        assert_eq!(hex::encode(b), expected_hex);
    }
}
