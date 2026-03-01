//! Secure ingress skeleton: mTLS server verifying HL signatures and enforcing nonce checks.

use secure_ingress::server::serve;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    serve(secure_ingress::server::AppState {
        hl_pubkey_pem: std::sync::Arc::new(String::new()), // overwritten in serve via env
        ledger: secure_ingress::nonce::InMemoryNonceLedger::default(),
    })
    .await
}
