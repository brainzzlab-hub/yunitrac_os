# Docker (dev) packaging: secure_ingress + ro_out_receiver (DEV-ONLY)

## Images
- `docker/Dockerfile.secure_ingress`: builds secure_ingress with Rust 1.85, non-root runtime, minimal Debian, read-only rootfs expected.
- `docker/Dockerfile.ro_out_receiver`: builds ro_out_receiver similarly.
- secure_runner stays host-side with bubblewrap wrapper (not containerized here).

## Compose layout (offline by default)
- `docker/docker-compose.dev.yml` (default, safe/offline): only `ro_out_receiver`, no published ports, no secrets mounted, read-only rootfs + tmpfs `/tmp`.
- `docker/docker-compose.dev.online.yml` (opt-in): adds `secure_ingress` with port 8443 and cert mounts; **requires** `YUNITRACK_DOCKER_ENABLE_SECRETS=1` or the container exits `SEC_DENY`.
- Secrets are operator-supplied (not shipped). Do **not** use these compose files in production.

### Default offline run (no secrets, no ports)
```bash
cd /Users/brainzzlab/Dev/yunitrack_workdir
docker compose -f docker/docker-compose.dev.yml build
docker compose -f docker/docker-compose.dev.yml up ro_out_receiver
```

### Opt-in online run (explicit secrets + port)
```bash
cd /Users/brainzzlab/Dev/yunitrack_workdir
YUNITRACK_DOCKER_ENABLE_SECRETS=1 \\
  docker compose -f docker/docker-compose.dev.yml -f docker/docker-compose.dev.online.yml \\
  up secure_ingress ro_out_receiver
```
- Mounts in online mode (read-only certs): `./secrets/server.crt|server.key|client_ca.crt|hl_pubkey.pem -> /certs/*`
- Nonce ledger (rw): `./artifacts/nonce_ledger -> /data/nonce_ledger`
- Port: `8443:8443`

## Notes
- Containers run as non-root user `app` created in Dockerfiles.
- Root filesystem is read-only; all writes must go to mounted volumes (`/data/nonce_ledger`, `/artifacts`, `/tmp` tmpfs).
- Proof scripts (`prove.sh`, `prove_enterprise.sh`) remain host-driven; Docker is optional and not part of the proof gate.
