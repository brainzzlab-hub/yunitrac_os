# Reproducible Build Notes

- Toolchain pinned via `rust-toolchain.toml` (Rust 1.85.0 + rustfmt + clippy).
- Build steps (deterministic):
  - `cargo fetch --locked`
  - `CARGO_NET_OFFLINE=true cargo build --release`
- Locked inputs: `Cargo.lock` committed; `deny.toml` enforces dependency policy; `cargo-audit` and `cargo-deny` in CI.
- SBOM: `./scripts/sbom_generate.sh` -> per-crate CycloneDX files under `artifacts/sbom/*.cyclonedx.json`.
- Signing (out of repo): generate release binaries, then sign with org-managed keys (cosign or gpg); do not store keys in repo.
- Repro tips: ensure same toolchain and `CARGO_NET_OFFLINE=true` to avoid network variance.
