# Forbidden Dependencies & Symbols (Boundary Crates)

Boundary crates (initial set):
- crates/secure_runner/**
- crates/dio_core/**

Extend this list as boundary inventory evolves; keep it explicit and small.

Forbidden dependencies (denylist):
- rand, getrandom
- chrono, time
- reqwest, hyper, async-std, tokio (all network/async stacks)

Forbidden symbols/macros inside boundary source:
- std::fs::
- std::time::SystemTime, std::time::Instant
- chrono::
- rand::
- reqwest::, hyper::
- tokio::spawn, std::thread
- println!, eprintln!
- tracing::{trace,debug,info,warn,error}!

Rationale:
- Enforce no wallclock, no randomness, no filesystem IO, no networking, no nondeterministic concurrency, no stdout/stderr/logging inside boundary.

Enforcement:
- scripts/guardrails/forbidden_deps_symbols_scan.sh
  - cargo tree per boundary crate to catch forbidden dependencies
  - ripgrep source scan (tests/benches excluded) for forbidden symbols/macros
  - fail-closed with bounded SECURITY message
