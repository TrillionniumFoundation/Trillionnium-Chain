# TRNM Bridge Settlement Audit Note (2026-04-02)

Scope: operator-facing clarification for the current `trnm-bridge-poc` settlement boundary.
This note does **not** expand bridge scope; it freezes the evidence operators should quote during replay and incident review.

## Settlement confirmation boundary

For the current X2 settlement path, finalization remains fail-closed and bounded by the heartbeat sample embedded in the attempt:

- required lower bound: `target < confirm` in normal ranges
- required upper bound: `confirm <= source + 1`
- stricter catch-up rule: once `target == source`, the only acceptable confirmation height is `source + 1`
- saturated edge case: when `source == target == u64::MAX`, arithmetic saturates, so `confirm == u64::MAX` remains the only acceptable terminal value even though `target < confirm` can no longer be expressed literally

Operationally, this means a stale target-height confirm must never be accepted as enough evidence once the target heartbeat has already caught up to the source head.

## Retry / degraded boundary

Before finalization is considered:

- `degraded == true` must terminate the attempt as compensation/revert
- `should_retry == true` must block finalization unless the terminal confirmation is already an explicit failed settlement outcome
- malformed embedded heartbeat bounds must fail closed rather than be reinterpreted as success evidence

## Frozen settlement audit evidence

Replay and incident review should quote the structured settlement event fields below as the canonical evidence surface:

- `phase`
- `heartbeat_source_height`
- `heartbeat_target_height`
- `heartbeat_latency_ms`
- `confirm_height`
- `confirm_reason`

Interpretation guidance:

- `phase = settlement_confirmed` implies `confirm_height` is present and `confirm_reason` is absent
- `phase = settlement_confirm_failed` implies `confirm_reason` is present and `confirm_height` is absent
- `phase = relay_heartbeat_degraded` implies the relay heartbeat gate failed before finalization, `confirm_height` remains absent, and the event carries the degraded reason in `confirm_reason`
- `should_retry == true` without an explicit terminal confirm failure is **not** a terminal settlement event: the attempt must stop before finalization and be retried, so operators should treat the absence of a new settlement event as expected rather than infer a silent success
- `should_retry == true` does **not** override an explicit terminal confirm failure: when the settlement confirmation itself is already a declared failure, the canonical audit tuple must still be emitted as `phase = settlement_confirm_failed` with the normalized failure reason, rather than being downgraded to a retry-only hint
- when an embedded heartbeat sample is malformed, the attempt must still fail closed; only explicitly declared invalid-heartbeat reason families (for example `invalid heartbeat height...` / `invalid heartbeat progression...`) are allowed to flow into the compensated audit trail instead of being reinterpreted as successful settlement evidence
- those explicit invalid-heartbeat degradations preserve the normalized reason in `confirm_reason`, but the canonical `heartbeat_source_height`, `heartbeat_target_height`, and `heartbeat_latency_ms` fields remain absent so replay reviews do not accidentally quote malformed embedded bounds as trusted metrics
- `confirm_reason` is a normalized audit string, not a raw upstream blob: invisible/control separators are collapsed to plain spaces, empty-or-fully-sanitized inputs fall back to a stable unknown-reason contract string, and the final stored reason is capped to a replay-stable bounded length (currently 160 chars, with a single terminal ellipsis when truncation occurs)

## Audit quoting rule

When operators summarize a bridge incident, prefer the structured event tuple first and log phrasing second. A compact quote template is:

`phase=<phase> hb=(<source>,<target>,<latency_ms>) confirm_height=<confirm_height> confirm_reason=<confirm_reason>`

This avoids replay drift caused by ad-hoc prose or differently sanitized log lines.
