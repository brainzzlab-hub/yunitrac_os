#![forbid(unsafe_code)]

use shared::Port;
use shared::{Sliders, Vector};
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SkeletonError {
    #[error("tick exceeded max_attempts")]
    MaxAttempts,
    #[error("retry_epoch exhausted")]
    RetryEpochExhausted,
}

/// Deterministic skeleton stage; no side effects.
pub fn run(mut port: Port, vector: &Vector, baseline_sliders: &Sliders) -> Port {
    // Enforce max_attempts: tick counts attempts (T0).
    if port.meta.tick >= vector.budgets.max_attempts as u64 {
        port.security = Some(shared::SecCode::SecInvalidSig);
        return port;
    }
    // retry_epoch gate: simple guard; future retry logic may check equality.
    if vector.retry_epoch == u64::MAX {
        port.security = Some(shared::SecCode::SecInvalidSig);
        return port;
    }
    // Enforce mode lock.
    port.mode = vector.mode;
    // Enforce sliders from vector baseline (no drift yet).
    port.sliders = *baseline_sliders;
    port
}
