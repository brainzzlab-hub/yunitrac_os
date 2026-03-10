# Lite SecCode Specification (bounded, no-feedback)

## Purpose
Define the allowed SecCode values and response shape for Lite profile runs, ensuring bounded, content-free outputs with no reasons or near-pass hints.

## Allowed SecCode enum (Lite)
- `SEC_UNSIGNED_REJECTED`
- `SEC_SIGNED_ACCEPTED`
- `SEC_SIG_LEN_INVALID`
- `SEC_REPLAY_REJECTED`
- `SEC_POLICY_VIOLATION`

No other values are permitted. Payload is the UTF-8 uppercase code only; no additional text.

## Response shape
```json
{
  "result": "SEC_*"
}
```
- `result` must be one of the allowed codes above.
- No extra fields; no reasons; no stack traces; no timestamps.

## Bounded behavior
- On reject paths, emit only the SecCode; do not leak validation detail (I3L).
- Rate/ordering: single response per run; no retries unless scoped by tick/retry rules in canon.

## Test guidance (existing harnesses)
- Ensure any Lite output producer (bins or scripts) writes only the SecCode string or the JSON shape above.
- Equality checks in `prove_lite.sh` already bound to declared REQUIRED_EQUALITY_SET; ensure future Lite artifacts that carry SecCode stay within allowed set.
