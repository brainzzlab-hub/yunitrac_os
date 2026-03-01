# Secure Runner Linux Sandbox Runbook

Purpose: run `secure_runner` with hardened Linux isolation (no_new_privs, caps drop, net deny, fs minimal, optional seccomp).

Prereqs
- Linux host with `bubblewrap` (`bwrap`) available.
- `secure_runner` built: `cargo build --release -p secure_runner`.
- Optional seccomp profile JSON: set `SECCOMP_PROFILE=/path/profile.json`.

How to run
```bash
# from repo root (adjust SEC_BIN if needed)
scripts/linux/run_secure_runner_sandboxed.sh --bucket audit --tick 0
```

What the wrapper enforces
- `bwrap --unshare-all --unshare-net --die-with-parent --new-session`
- Read-only binds: /usr, /lib, /bin (and /lib64 if present)
- tmpfs /tmp, isolated /proc, minimal /dev
- Network namespace with no interfaces (no outbound/inbound)
- no_new_privs inherent in bwrap setup
- Optional seccomp: `SECCOMP_PROFILE` if provided; absent => still isolated, fail closed if profile path unreadable.

Notes
- Wrapper fails closed if `bwrap` missing.
- No filesystem writes from secure_runner; diode output must be via inherited fds or stdout as designed.
- For systemd services, invoke the wrapper; do not call secure_runner directly.
