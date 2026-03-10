# Pad C Entrypoint (Placeholder, Out of Scope for v0.3)

## Purpose
Pad C is a future component intended to handle post-diode processing/aggregation. It is **explicitly out of scope** for v0.3 dual-profile. This document marks the planned entrypoint and boundaries without introducing code or commitments.

## Current status
- No implementation.
- No APIs, binaries, or integration hooks are present.
- Not part of prove_enterprise or prove_lite.

## Constraints (when implemented later)
- Must adhere to the same canon: no feedback to ac, bounded outputs, deterministic within declared scope.
- Must not weaken diode-first assumptions; any ingress from Pad C toward secure_runner is forbidden.
- GDPR buckets must remain content-free (AUDIT/SECURITY) and numeric-bounded (METRICS).

## Next steps (future work only)
- Define Pad C responsibilities and evidence outputs.
- Add schema (if needed) under HL-only governance when approved.
- Integrate into proof harness only after design review and HL approval.
