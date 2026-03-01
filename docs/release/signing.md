# Release Signing Process (outline)

- Build artifacts with pinned toolchain (see reproducible_builds.md).
- Artifact set: release binaries from `target/release/`, SBOM from `artifacts/sbom/cyclonedx.json`, proof reports.
- Sign using organization-managed keys (cosign or GPG). Keys are kept outside this repo.
- Recommended:
  - `cosign sign-blob --key <KMS_OR_HSM> <artifact>` and store signatures alongside artifacts.
  - Publish checksums (sha256) and sign checksum file.
- Verification: `cosign verify-blob` or `gpg --verify` against published signatures.
- No private keys are stored or referenced in this repository.
