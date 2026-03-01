#![forbid(unsafe_code)]

use shared::Port;
use thiserror::Error;

/// Actor/attempt component; no feedback or side effects yet.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum AcError {
    #[error("actor not implemented")]
    NotImplemented,
}

pub fn run(port: Port) -> Port {
    // Placeholder: in proof scope actor produces no output but pipeline continues.
    port
}
