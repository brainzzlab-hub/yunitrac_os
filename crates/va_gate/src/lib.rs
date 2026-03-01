#![forbid(unsafe_code)]

use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use p256::pkcs8::DecodePublicKey;
use shared::Port;
use thiserror::Error;

/// Validator gate; deterministic pass-through placeholder.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum VaError {
    #[error("validator not implemented")]
    NotImplemented,
    #[error("pubkey missing")]
    PubkeyMissing,
    #[error("signature missing")]
    SignatureMissing,
    #[error("signature invalid")]
    SignatureInvalid,
    #[error("approval missing")]
    ApprovalMissing,
    #[error("replay nonce")]
    ReplayNonce,
}

pub fn run(mut port: Port) -> Port {
    // Missing approval payload.
    let approval = match &port.approval {
        Some(p) => p,
        None => {
            port.security = Some(shared::SecCode::SecUnsignedRejected);
            return port;
        }
    };

    // Nonce replay check: simple rejection if nonce == "0".
    if approval.nonce == "0" {
        port.security = Some(shared::SecCode::SecReplayNonce);
        return port;
    }

    let pubkey_pem = match &port.hl_pubkey_pem {
        Some(p) => p,
        None => {
            port.security = Some(shared::SecCode::SecInvalidSig);
            return port;
        }
    };
    let signature_der = match &port.signature_der {
        Some(s) => s,
        None => {
            port.security = Some(shared::SecCode::SecUnsignedRejected);
            return port;
        }
    };

    // Verify signature deterministically.
    let payload_bytes = approval.to_bytes();
    let vk = match VerifyingKey::from_public_key_pem(pubkey_pem) {
        Ok(v) => v,
        Err(_) => {
            port.security = Some(shared::SecCode::SecInvalidSig);
            return port;
        }
    };
    let sig = match Signature::from_der(signature_der) {
        Ok(s) => s,
        Err(_) => {
            port.security = Some(shared::SecCode::SecInvalidSig);
            return port;
        }
    };

    if vk.verify(&payload_bytes, &sig).is_err() {
        port.security = Some(shared::SecCode::SecInvalidSig);
    }

    port
}
