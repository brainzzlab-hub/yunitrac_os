# Pad C Entry-Point Specification (Docs-Only)

**Scope**: Defines the Pad C ingestion/compile contract for three documents: `ShotBible` (static catalog), `ShotRequest` (runtime request), and `GenerationPlan` (deterministic compiler output). This is a documentation-only spec; no runtime changes or `/schemas/**` artifacts are introduced.

## Canon-Aligned Invariants
- **Determinism**: Identical `ShotBible` + `ShotRequest` → identical `GenerationPlan` bytes. Ordering rules are explicit and canonicalized (sorted keys; stable array order where specified).
- **GDPR-minimal**: No PII fields permitted. Only pseudonymous identifiers with bounded formats are allowed.
- **No-feedback (Lite)**: Actor-facing outputs remain `{ACCEPTED|REJECTED} + SecCode` (see `docs/specs/seccode_lite.md`). No reasons, hints, payload echoes, or schema details.
- **Anti-replay**: Requests carry a bounded `nonce` and `request_id`; replays must be rejected or fail-closed per profile policies.
- **Approvals**: References to approvals are opaque identifiers only (e.g., `approvals_ref` as `sha256_hex`). No public/private key material in payloads.
- **Size bounds**: All strings and arrays are length-bounded; unbounded maps are forbidden.

## Common Scalar Types (human-readable, schema-like)
- `uuid_v4`: string, regex `^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$` (lowercase hex).
- `ulid`: string, regex `^[0-9A-HJKMNP-TV-Z]{26}$`.
- `sha256_hex`: string, 64 lowercase hex chars.
- `seccode`: string, one of the enumerated SecCode values defined in `docs/specs/seccode_lite.md`.
- `nonce`: uint64, **must be > 0**, bounded TTL/policy external to payload.
- `revision`: uint32, monotonically increasing; replaces any wallclock fields.

## ShotBible (static catalog)
Top-level:
- `revision` (uint32, required) — monotonic; **no timestamps** (created_at/updated_at are forbidden).
- `shots` (array, 1..256) — order is canonical as provided; no duplicates by `shot_id`.

Each `shot` entry:
- `shot_id` (ulid, required)
- `name` (string, ASCII, 1..80)
- `template_ref` (`sha256_hex`, required) — content hash of the immutable template.
- `required_inputs` (array, 0..32, ordered):
  - `input_id` (string slug `[a-z0-9_]{1,32}`)
  - `type` (enum: `text` | `bool` | `int`)
  - `max_len` (uint16, applies to `text` only, <= 4096)
  - `range` (optional, for `int`: `{min:int, max:int}` with |min|max <= 1_000_000)
- `allowed_outputs` (array, 0..16, each slug `[A-Z0-9_]{1,32}`)
- `constraints` (object):
  - `max_frames` (uint16, <= 1000)
  - `max_seconds` (uint16, <= 3600)

Forbidden in ShotBible: wallclock fields, free-form maps, unbounded arrays, nested maps beyond the above.

## ShotRequest (runtime)
- `request_id` (ulid, required)
- `nonce` (uint64 > 0, required) — single-use per `(requester, request_epoch)`; TTL handled by ingress/ledger.
- `shot_id` (ulid, must match an entry in ShotBible)
- `inputs` (array, 0..32, ordered by `input_id` lexicographically):
  - `input_id` (string slug, matches ShotBible)
  - `value`:
    - `text`: UTF-8, 0..4096 bytes
    - `bool`: `true|false`
    - `int`: bounded by ShotBible `range`
- `output_profile` (enum: `enterprise` | `lite`)
- `approvals_ref` (optional `sha256_hex`) — opaque reference to approval envelope; no key material.

Constraints:
- No additional properties.
- Keys must be lower_snake_case.
- Ordering: `inputs` sorted by `input_id`; overall object keys serialized in canonical (sorted) order.

## GenerationPlan (compiler output)
- `plan_id` (`sha256_hex`, required) — defined as SHA256 of canonical serialization of `{shot_request_ref_sha256, shot_bible_revision}`.
- `shot_id` (ulid) and `request_id` (ulid) echoed for traceability (content-free).
- `steps` (array, 1..128, **ordered**):
  - `step_id` (uint16, 1-based, strictly increasing)
  - `op` (enum: `load_template` | `bind_inputs` | `render` | `package`)
  - `params` (object, deterministic key order; values are bounded strings/ints; no blobs)
- `artifacts_expected` (array, 0..64, strings, each 1..120 chars, ASCII; represent logical names, not filesystem paths)
- `required_equality_set` (array, 1..32, lexicographically sorted strings) — paths (relative to artifacts root) that must be byte-identical across runs B and C.

Determinism rules:
- `steps` order is fixed and derived purely from ShotBible + ShotRequest; no randomness, no time, no IO.
- `plan_id` reproducible given identical inputs.

Anti-replay and approvals hooks:
- `nonce` and `request_id` travel with the plan for verification.
- `approvals_ref` is opaque; verification happens outside the plan; the plan must not embed signatures or keys.

GDPR / No-feedback:
- No PII fields permitted.
- No free-form diagnostic text.
- Lite actor-facing outputs must remain `{ACCEPTED|REJECTED}+SecCode` only; plan content is not emitted to actors directly.

Size and encoding:
- All strings UTF-8, ASCII preferred; length bounds as stated.
- No unbounded maps; arrays capped as listed.
- Canonical JSON serialization: sorted keys, separators `(",", ":")`, no whitespace.
