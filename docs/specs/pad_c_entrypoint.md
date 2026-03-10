# Pad C Entry-Point (Spec-Only, v1)

Pad C is the "ShotBible Consistency Vault" for gating shot requests against curated bibles and variance policy. This microtask ships **specs only**: JSON Schemas plus small samples. No runtime wiring, no connectors, and no promises beyond the schemas provided here.

## What is in scope now
- New schemas under `schemas_pad_c/v1/`: ShotBible, ShotRequest, GenerationPlan.
- Examples under `examples/pad_c/v1/` showing a minimal bible, a passing request, a failing request, and a sample generated plan.
- No code changes, no enforcement, and no pipelines are added in this microtask.

## Intended future integration (outline only)
1. An agent proposes a `ShotRequest` (future Z3 policy may assist selection).
2. A secure-side validator plugin compares the request against the `ShotBible` and variance policy.
3. The validator emits a `GenerationPlan` **or** a list of `SecCodes` (content-free reasons) without leaking details to the actor, preserving I3 (no feedback) by using SecCode-only surface.
4. Evidence bundles would record PASS/FAIL outcomes only; no pixel determinism or model determinism is claimed in this spec.

## Explicit non-claims (v1 spec microtask)
- No pixel determinism and no model-level determinism are asserted here.
- No transport/connectors, UI hooks, or runtime enforcement are provided.
- Proof scripts are unchanged; this is documentation + schema-only.

## References
- Schemas: `schemas_pad_c/v1/*.schema.json`
- Samples: `examples/pad_c/v1/*.json`
- Evidence (future work): plug-in validator will produce `GenerationPlan` or SecCodes.

## Required design tokens (for guardrails)
- ShotBible, ShotRequest, GenerationPlan
- Determinism scope noted in `determinism_scope_note`
- GDPR separation and No-feedback handling via SecCodes-only exposure
- Anti-replay and Approvals are deferred to future Pad C execution plugins
