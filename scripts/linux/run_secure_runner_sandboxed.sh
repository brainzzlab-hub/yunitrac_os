#!/usr/bin/env bash
set -euo pipefail

# Linux-only sandbox wrapper for secure_runner.
# Default: require bubblewrap. Fail closed if missing.

if ! command -v bwrap >/dev/null 2>&1; then
  echo "FAIL: bubblewrap (bwrap) not found; cannot sandbox secure_runner" >&2
  exit 1
fi

SEC_BIN="${SEC_BIN:-$(dirname "$0")/../../target/release/secure_runner}"
SEC_BIN="$(cd "$(dirname "$SEC_BIN")" && pwd)/$(basename "$SEC_BIN")"

if [ ! -x "$SEC_BIN" ]; then
  echo "FAIL: secure_runner binary not found at $SEC_BIN" >&2
  exit 1
fi

# Optional seccomp profile; if not present, still run with bwrap's defaults.
SECCOMP_ARGS=()
if [ -n "${SECCOMP_PROFILE:-}" ]; then
  if [ -r "$SECCOMP_PROFILE" ]; then
    SECCOMP_ARGS=(--seccomp "$SECCOMP_PROFILE")
  else
    echo "FAIL: SECCOMP_PROFILE set but unreadable" >&2
    exit 1
  fi
fi

# Build bwrap command: isolate namespace, drop network, no new privs, tmpfs root, limited binds.
bwrap \
  --unshare-all \
  --new-session \
  --die-with-parent \
  --unshare-net \
  --ro-bind /usr /usr \
  --ro-bind /lib /lib \
  --ro-bind /lib64 /lib64 2>/dev/null || true \
  --ro-bind /bin /bin \
  --proc /proc \
  --dev /dev \
  --tmpfs /tmp \
  --chdir / \
  -- \
  "${SECCOMP_ARGS[@]}" \
  "$SEC_BIN" "$@"
