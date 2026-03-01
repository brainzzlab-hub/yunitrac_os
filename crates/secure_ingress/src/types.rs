use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct SignedEnvelope<T> {
    pub payload: T,
    pub nonce: u64,
    pub run_id: String,
    pub retry_epoch: u64,
    pub canon_hash: String,
    pub proposal_id: String,
    pub action: String,
    pub sig_raw64: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct RunRequest {
    pub mode: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ApprovalRequest {
    pub approval: Value,
}
