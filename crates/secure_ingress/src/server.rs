use std::net::SocketAddr;
use std::sync::Arc;

use axum::{extract::State, routing::post, Json, Router};
use axum_server::tls_rustls::RustlsConfig;
use rustls::server::WebPkiClientVerifier;
use rustls::{pki_types::CertificateDer, RootCertStore};
use rustls_pemfile::{certs, pkcs8_private_keys};

use crate::nonce::{InMemoryNonceLedger, NonceLedger};
use crate::types::{ApprovalRequest, RunRequest, SignedEnvelope};
use crate::verify::verify_envelope;

#[derive(Clone)]
pub struct AppState {
    pub hl_pubkey_pem: Arc<String>,
    pub ledger: InMemoryNonceLedger,
}

pub async fn router(state: AppState) -> Router {
    Router::new()
        .route("/run", post(handle_run))
        .route("/approval", post(handle_approval))
        .with_state(state)
}

async fn handle_run(
    State(state): State<AppState>,
    Json(env): Json<SignedEnvelope<RunRequest>>,
) -> (axum::http::StatusCode, &'static str) {
    handle_common(env, &state)
}

async fn handle_approval(
    State(state): State<AppState>,
    Json(env): Json<SignedEnvelope<ApprovalRequest>>,
) -> (axum::http::StatusCode, &'static str) {
    handle_common(env, &state)
}

fn handle_common<T: serde::Serialize + std::fmt::Debug>(
    env: SignedEnvelope<T>,
    state: &AppState,
) -> (axum::http::StatusCode, &'static str) {
    let verdict = verify_envelope(&env, &state.hl_pubkey_pem);
    let verify_input = match verdict {
        Ok(v) => v,
        Err(_) => return (axum::http::StatusCode::BAD_REQUEST, "REJECTED"),
    };
    if verify_input.hl_key_id.is_empty() {
        return (axum::http::StatusCode::BAD_REQUEST, "REJECTED");
    }
    let decision = state
        .ledger
        .check_and_record(verify_input, current_unix_ts());
    if !matches!(decision, crate::nonce::Decision::Accept) {
        return (axum::http::StatusCode::BAD_REQUEST, "REJECTED");
    }
    (axum::http::StatusCode::OK, "ACCEPTED")
}

fn current_unix_ts() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub async fn serve(_state: AppState) -> anyhow::Result<()> {
    let bind: SocketAddr = std::env::var("INGRESS_BIND")
        .unwrap_or_else(|_| "127.0.0.1:8443".into())
        .parse()?;

    let server_cert = std::env::var("INGRESS_SERVER_CERT")?;
    let server_key = std::env::var("INGRESS_SERVER_KEY")?;
    let client_ca = std::env::var("INGRESS_CLIENT_CA")?;
    let hl_pubkey = std::env::var("INGRESS_HL_PUBKEY_PEM")?;

    let config = tls_config(&server_cert, &server_key, &client_ca)?;
    let app = router(AppState {
        hl_pubkey_pem: Arc::new(hl_pubkey),
        ledger: InMemoryNonceLedger::default(),
    })
    .await;
    axum_server::bind_rustls(bind, config)
        .serve(app.into_make_service())
        .await?;
    Ok(())
}

fn tls_config(
    cert_path: &str,
    key_path: &str,
    client_ca_path: &str,
) -> anyhow::Result<RustlsConfig> {
    let mut cert_reader = std::io::BufReader::new(std::fs::File::open(cert_path)?);
    let cert_chain: Vec<CertificateDer> = certs(&mut cert_reader).collect::<Result<Vec<_>, _>>()?;

    let mut key_reader = std::io::BufReader::new(std::fs::File::open(key_path)?);
    let key = pkcs8_private_keys(&mut key_reader)
        .next()
        .ok_or_else(|| anyhow::anyhow!("no private key"))??;
    let key = rustls::pki_types::PrivateKeyDer::from(key);

    let mut roots = RootCertStore::empty();
    let mut ca_reader = std::io::BufReader::new(std::fs::File::open(client_ca_path)?);
    for cert in certs(&mut ca_reader) {
        let cert = cert?;
        roots
            .add(cert)
            .map_err(|_| anyhow::anyhow!("invalid client CA cert"))?;
    }

    let client_auth = WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .map_err(|_| anyhow::anyhow!("client verifier build"))?;

    let config = rustls::ServerConfig::builder()
        .with_client_cert_verifier(client_auth)
        .with_single_cert(cert_chain, key)?;
    Ok(RustlsConfig::from_config(config.into()))
}
