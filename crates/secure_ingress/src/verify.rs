use hex::FromHex;
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use p256::pkcs8::{DecodePublicKey, EncodePublicKey};
use sha2::{Digest, Sha256};
use std::fmt;

use crate::types::SignedEnvelope;

const DOMAIN_PREFIX: &[u8] = b"YUNITRACK_APPROVAL_V1\0";

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct VerifyInput {
    pub canon_hash: String,
    pub run_id: String,
    pub retry_epoch: u64,
    pub nonce: u64,
    pub action: String,
    pub proposal_id: String,
    pub hl_key_id: String,
}

#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("nonce_zero")]
    NonceZero,
    #[error("sig_length")]
    SigLength,
    #[error("sig_decode")]
    SigDecode,
    #[error("pubkey_decode")]
    PubkeyDecode,
    #[error("payload_object_not_allowed")]
    PayloadObject,
    #[error("signature_invalid")]
    InvalidSignature,
    #[error("hex_decode")]
    HexDecode,
}

fn canonical_payload_bytes<T: serde::Serialize + fmt::Debug>(
    payload: &T,
) -> Result<Vec<u8>, VerifyError> {
    let value = serde_json::to_value(payload).map_err(|_| VerifyError::PayloadObject)?;
    if value.is_object() {
        return Err(VerifyError::PayloadObject);
    }
    serde_json::to_vec(&value).map_err(|_| VerifyError::PayloadObject)
}

fn domain_separated_bytes<T: serde::Serialize + fmt::Debug>(
    env: &SignedEnvelope<T>,
) -> Result<Vec<u8>, VerifyError> {
    let payload_bytes = canonical_payload_bytes(&env.payload)?;
    let mut out = Vec::with_capacity(
        DOMAIN_PREFIX.len()
            + 32
            + env.run_id.len()
            + 8
            + 8
            + env.action.len()
            + env.proposal_id.len()
            + payload_bytes.len(),
    );
    out.extend_from_slice(DOMAIN_PREFIX);
    let canon_hash_bytes = Vec::from_hex(&env.canon_hash).map_err(|_| VerifyError::HexDecode)?;
    out.extend_from_slice(&canon_hash_bytes);
    out.extend_from_slice(env.run_id.as_bytes());
    out.extend_from_slice(&env.retry_epoch.to_le_bytes());
    out.extend_from_slice(&env.nonce.to_le_bytes());
    out.extend_from_slice(env.action.as_bytes());
    out.extend_from_slice(env.proposal_id.as_bytes());
    out.extend_from_slice(&payload_bytes);
    Ok(out)
}

pub fn verify_envelope<T: serde::Serialize + fmt::Debug>(
    env: &SignedEnvelope<T>,
    hl_pubkey_pem: &str,
) -> Result<VerifyInput, VerifyError> {
    if env.nonce == 0 {
        return Err(VerifyError::NonceZero);
    }

    let sig_bytes = Vec::from_hex(&env.sig_raw64).map_err(|_| VerifyError::SigDecode)?;
    if sig_bytes.len() != 64 {
        return Err(VerifyError::SigLength);
    }
    let sig = Signature::from_slice(&sig_bytes).map_err(|_| VerifyError::SigDecode)?;

    let message = domain_separated_bytes(env)?;
    let digest = Sha256::digest(&message);

    let pubkey =
        VerifyingKey::from_public_key_pem(hl_pubkey_pem).map_err(|_| VerifyError::PubkeyDecode)?;
    pubkey
        .verify(digest.as_ref(), &sig)
        .map_err(|_| VerifyError::InvalidSignature)?;

    Ok(VerifyInput {
        canon_hash: env.canon_hash.clone(),
        run_id: env.run_id.clone(),
        retry_epoch: env.retry_epoch,
        nonce: env.nonce,
        action: env.action.clone(),
        proposal_id: env.proposal_id.clone(),
        hl_key_id: hex::encode(
            pubkey
                .to_public_key_der()
                .map_err(|_| VerifyError::PubkeyDecode)?,
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::{
        ecdsa::{signature::Signer, SigningKey, VerifyingKey},
        SecretKey,
    };
    use serde_json::json;

    fn make_env(sig: &str, nonce: u64) -> SignedEnvelope<serde_json::Value> {
        SignedEnvelope {
            payload: json!(1),
            nonce,
            run_id: "run1".into(),
            retry_epoch: 0,
            canon_hash: "4cb8e65ae62a598cefb3efefde323ebadb78a84b36324496e9783f7ade0746ea".into(),
            proposal_id: "p1".into(),
            action: "approve".into(),
            sig_raw64: sig.into(),
        }
    }

    #[test]
    fn rejects_zero_nonce() {
        let env = make_env("00", 0);
        assert!(matches!(
            verify_envelope(&env, "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtQ==\n-----END PUBLIC KEY-----"),
            Err(VerifyError::NonceZero)
        ));
    }

    #[test]
    fn rejects_short_sig() {
        let env = make_env("00", 1);
        assert!(matches!(
            verify_envelope(&env, "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtQ==\n-----END PUBLIC KEY-----"),
            Err(VerifyError::SigLength) | Err(VerifyError::SigDecode)
        ));
    }

    fn deterministic_signing_key() -> SigningKey {
        SigningKey::from(SecretKey::from_bytes(&[7u8; 32].into()).unwrap())
    }

    #[test]
    fn accepts_valid_signature() {
        let signing_key = deterministic_signing_key();
        let verifying: VerifyingKey = *signing_key.verifying_key();
        let pem = verifying.to_public_key_pem(Default::default()).unwrap();

        let mut env = make_env("", 1);
        let digest = Sha256::digest(&domain_separated_bytes(&env).unwrap());
        let sig: Signature = signing_key.sign(digest.as_slice());
        env.sig_raw64 = hex::encode(sig.to_bytes());

        assert!(verify_envelope(&env, &pem).is_ok());
    }

    #[test]
    fn rejects_object_payload() {
        let mut env = make_env("", 1);
        env.payload = serde_json::json!({ "a": 1 });
        let signing_key = deterministic_signing_key();
        // build a syntactically valid signature (value won't be verified because payload is rejected earlier)
        let dummy_sig: Signature = signing_key.sign(b"fixed");
        env.sig_raw64 = hex::encode(dummy_sig.to_bytes());
        let pem = signing_key
            .verifying_key()
            .to_public_key_pem(Default::default())
            .unwrap();
        assert!(matches!(
            verify_envelope(&env, &pem),
            Err(VerifyError::PayloadObject)
        ));
    }

    #[test]
    fn rejects_unsigned_envelope() {
        let env = make_env("", 1);
        let pem = deterministic_signing_key()
            .verifying_key()
            .to_public_key_pem(Default::default())
            .unwrap();
        assert!(matches!(
            verify_envelope(&env, &pem),
            Err(VerifyError::SigDecode) | Err(VerifyError::SigLength)
        ));
    }

    #[test]
    fn rejects_signature_over_wrong_message() {
        let signing_key = deterministic_signing_key();
        let pem = signing_key
            .verifying_key()
            .to_public_key_pem(Default::default())
            .unwrap();
        let mut env = make_env("", 1);
        // Sign a different digest (wrong message)
        let wrong_digest = Sha256::digest(b"wrong");
        let sig: Signature = signing_key.sign(wrong_digest.as_slice());
        env.sig_raw64 = hex::encode(sig.to_bytes());
        assert!(matches!(
            verify_envelope(&env, &pem),
            Err(VerifyError::InvalidSignature)
        ));
    }

    #[test]
    fn rejects_signature_with_wrong_public_key() {
        let signing_key = deterministic_signing_key();
        let mut env = make_env("", 1);
        // Build correct digest then sign it
        let digest = Sha256::digest(&domain_separated_bytes(&env).unwrap());
        let sig: Signature = signing_key.sign(digest.as_slice());
        env.sig_raw64 = hex::encode(sig.to_bytes());

        // Use a different verifying key
        let other_key = SigningKey::from(SecretKey::from_bytes(&[9u8; 32].into()).unwrap());
        let other_pem = other_key
            .verifying_key()
            .to_public_key_pem(Default::default())
            .unwrap();
        assert!(matches!(
            verify_envelope(&env, &other_pem),
            Err(VerifyError::InvalidSignature)
        ));
    }

    #[test]
    fn rejects_mutated_payload_after_signing() {
        let signing_key = deterministic_signing_key();
        let pem = signing_key
            .verifying_key()
            .to_public_key_pem(Default::default())
            .unwrap();
        let mut env = make_env("", 1);
        // Sign correct digest
        let digest = Sha256::digest(&domain_separated_bytes(&env).unwrap());
        let sig: Signature = signing_key.sign(digest.as_slice());
        env.sig_raw64 = hex::encode(sig.to_bytes());

        // Mutate payload after signing
        env.payload = json!(2);
        assert!(matches!(
            verify_envelope(&env, &pem),
            Err(VerifyError::InvalidSignature)
        ));
    }

    #[test]
    fn rejects_empty_approval_blob() {
        let pem = deterministic_signing_key()
            .verifying_key()
            .to_public_key_pem(Default::default())
            .unwrap();
        let env = make_env("", 1);
        assert!(matches!(
            verify_envelope(&env, &pem),
            Err(VerifyError::SigDecode) | Err(VerifyError::SigLength)
        ));
    }

    #[test]
    fn rejects_malformed_truncated_sig_bytes() {
        let pem = deterministic_signing_key()
            .verifying_key()
            .to_public_key_pem(Default::default())
            .unwrap();
        // not valid hex length
        let env = make_env("aa", 1);
        assert!(matches!(
            verify_envelope(&env, &pem),
            Err(VerifyError::SigDecode) | Err(VerifyError::SigLength)
        ));
    }

    #[test]
    fn rejects_signature_without_domain_prefix() {
        let signing_key = deterministic_signing_key();
        let pem = signing_key
            .verifying_key()
            .to_public_key_pem(Default::default())
            .unwrap();
        let mut env = make_env("", 1);
        let payload_bytes = canonical_payload_bytes(&env.payload).unwrap();
        let mut hasher = Sha256::new();
        let canon_hash_bytes = Vec::from_hex(&env.canon_hash).unwrap();
        hasher.update(&canon_hash_bytes);
        hasher.update(env.run_id.as_bytes());
        hasher.update(env.retry_epoch.to_le_bytes());
        hasher.update(env.nonce.to_le_bytes());
        hasher.update(env.action.as_bytes());
        hasher.update(env.proposal_id.as_bytes());
        hasher.update(&payload_bytes);
        let digest = hasher.finalize();
        let sig: Signature = signing_key.sign(digest.as_slice());
        env.sig_raw64 = hex::encode(sig.to_bytes());

        assert!(matches!(
            verify_envelope(&env, &pem),
            Err(VerifyError::InvalidSignature)
        ));
    }
}
