# Docker (dev) packaging: secure_ingress + ro_out_receiver

## Images
- `docker/Dockerfile.secure_ingress`: builds secure_ingress with Rust 1.85, non-root runtime, minimal Debian, read-only rootfs expected.
- `docker/Dockerfile.ro_out_receiver`: builds ro_out_receiver similarly.
- secure_runner stays host-side with bubblewrap wrapper (not containerized here).

## Compose (developer convenience)
File: `docker/docker-compose.dev.yml`
- Hardening defaults per service:
  - `cap_drop: [ALL]`
  - `security_opt: ["no-new-privileges:true"]`
  - `read_only: true`
  - `tmpfs: ["/tmp"]`
- secure_ingress:
  - Port: 8443
  - Mount certs/keys (read-only):
    - `./secrets/server.crt -> /certs/server.crt`
    - `./secrets/server.key -> /certs/server.key`
    - `./secrets/client_ca.crt -> /certs/client_ca.crt`
    - `./secrets/hl_pubkey.pem -> /certs/hl_pubkey.pem`
  - Nonce ledger (rw): `./artifacts/nonce_ledger -> /data/nonce_ledger`
  - Env defaults: `INGRESS_BIND=0.0.0.0:8443`, `NONCE_LEDGER_PATH=/data/nonce_ledger/ledger.log`
- ro_out_receiver:
  - No inbound ports.
  - Artifacts volume (rw): `./artifacts/enterprise -> /artifacts`
  - Env: `RO_OUT_DIR=/artifacts`

## Build & run (dev)
```bash
cd docker
docker compose -f docker-compose.dev.yml build
docker compose -f docker-compose.dev.yml up
```

## Notes
- Containers run as non-root user `app` created in Dockerfiles.
- Root filesystem is read-only; all writes must go to mounted volumes (`/data/nonce_ledger`, `/artifacts`, `/tmp` tmpfs).
- Proof scripts (`prove.sh`, `prove_enterprise.sh`) remain host-driven; Docker is optional and not part of the proof gate.
