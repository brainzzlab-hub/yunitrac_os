#![forbid(unsafe_code)]

use shared::{validate_drift, Port, Sliders};
use thiserror::Error;

/// Constraint manager stage; pure pass-through for now.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CmError {
    #[error("drift invalid: {0:?}")]
    DriftInvalid(shared::DriftError),
}

pub fn run(mut port: Port, drifted_sliders: &Sliders, baseline_sliders: &Sliders) -> Port {
    // Enforce drift rules (S1).
    if validate_drift(drifted_sliders, baseline_sliders, port.mode).is_err() {
        port.security = Some(shared::SecCode::SecInvalidSig);
        return port;
    }
    port.sliders = *drifted_sliders;
    port
}
