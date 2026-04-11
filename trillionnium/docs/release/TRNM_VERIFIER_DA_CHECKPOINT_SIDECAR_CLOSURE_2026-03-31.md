# TRNM Verifier / DA / Checkpoint Sidecar Closure Notes — 2026-03-31

## Purpose

This note narrows **P1.3 Verifier / proof sidecar productization** into a deployable closure checklist that operators and release reviewers can evaluate without over-claiming current readiness.

It does **not** upgrade the repository's overall release verdict. `RELEASE_READINESS.md` remains the truth source for mainnet go/no-go.

## Scope

This document covers only the verifier-sidecar lane questions:

- deployable verifier boundary
- DA/checkpoint evidence linkage
- sidecar trust / retry / failure semantics
- replayable operator evidence for verifier mismatches or outages

## Current hard floor

Before claiming any verifier-sidecar readiness, the following must already be true:

1. checkpoint/WAL evidence surfaces stay canonical and fail closed;
2. a verifier consumer can bind its audit view to the exact checkpoint state root and WAL content hash;
3. operator-visible failure modes are explicit enough to distinguish:
   - verifier unavailable
   - verifier returned malformed evidence
   - verifier returned evidence for the wrong checkpoint tuple
   - verifier/DA linkage is canonical but policy-incompatible
4. the recovery path preserves enough evidence to replay or audit the mismatch later.

## Minimum deployable boundary

A production-facing verifier sidecar should not be described as "ready" unless its public contract is stable enough to answer all of these:

- **Input identity**: which exact checkpoint tuple is being verified?
  - required anchor set: `checkpoint.height`, `checkpoint.state_root_hex`, `checkpoint.wal_entry_hash_hex`
- **DA binding**: what DA/light-verifier summary or equivalent evidence binds to that checkpoint?
  - minimum audit linkage: checkpoint commitment + WAL content hash + state commitment
- **Policy surface**: which verifier policy/schema version produced the verdict?
- **Failure surface**: can callers tell timeout / unavailable / malformed / mismatch / policy-reject apart?
- **Replay surface**: can an operator reproduce the exact verification attempt from persisted evidence?

If any of the above is missing or hand-wavy, the sidecar remains product-incomplete.

## Required evidence linkage

For launch-grade operator confidence, verifier evidence should preserve these relationships end-to-end:

1. `checkpoint.height` binds to the exact WAL height.
2. checkpoint/WAL recovery prefixes remain contiguous from genesis or an already-proven lower-height anchor; a height gap (for example `1 -> 3`) is a terminal evidence break, not a retryable omission.
3. `checkpoint.state_root_hex` binds to the exact committed WAL state root.
4. `checkpoint.wal_entry_hash_hex` binds to the exact WAL content hash.
5. non-genesis checkpoints preserve predecessor linkage through canonical `prev_hash_hex` handling.
6. any exported DA/light-verifier summary preserves canonical lower-hex digest surfaces and rejects trim/control/case drift.
7. non-genesis `checkpoint_prev_hash_hex` / WAL `prev_hash_hex` surfaces also reject invisible layout drift (for example zero-width characters), not just obvious whitespace or case changes.

In short: a verifier receipt that cannot be traced back to a single canonical checkpoint/WAL tuple is not sufficient release evidence.

## Concrete minimum sidecar contract

To keep release review falsifiable, the sidecar should publish at least one concrete request/response tuple instead of only prose.

### Minimum request tuple

A launch-reviewable verifier submission should carry, at minimum:

- `checkpoint_height`
- `checkpoint_state_root_hex`
- `checkpoint_wal_entry_hash_hex`
- `checkpoint_prev_hash_hex` (required for non-genesis checkpoints; omitted only for canonical genesis)
- `checkpoint_commitment_hex`
- `da_light_verifier_summary`
- `verifier_policy_version`
- `verifier_schema_version`
- `request_id` or equivalent replay handle

### Request-derived invariants (fail-closed)

The request tuple above intentionally carries both the raw checkpoint anchors and a derived checkpoint commitment. That derived field must not become an independent truth source.

Release-review invariants for request ingestion:

- `checkpoint_commitment_hex` must be recomputed from `checkpoint_height + checkpoint_state_root_hex + checkpoint_wal_entry_hash_hex` using the declared schema, not trusted as an opaque caller-supplied digest;
- if the derived commitment and the caller-supplied `checkpoint_commitment_hex` disagree, the sidecar must fail closed with a terminal mismatch outcome instead of "repairing" the tuple by picking one field opportunistically;
- `checkpoint_prev_hash_hex` remains part of the replay/audit anchor for non-genesis checkpoints even though it is not part of the checkpoint commitment tuple; a sidecar must therefore preserve it alongside the commitment rather than assuming the commitment alone is enough to audit predecessor linkage;
- `da_light_verifier_summary` should resolve to a canonical digest or replayable raw-evidence handle; if the implementation emits both a summary object and a digest, the digest must be derived from the exact emitted summary instead of copied from unrelated cache state.

In short: commitment/digest convenience fields may help operators replay a verdict, but they must never outrank the underlying checkpoint/WAL identity tuple they summarize.

### Minimum response tuple

A verifier response should preserve enough structure for operators to distinguish policy failure from transport failure:

- `request_id`
- `attempt_id` (fresh per bounded retry attempt; never reused across retries)
- `verdict` = `verified | rejected | unavailable`
- `failure_code` = stable machine-readable code when `verdict != verified`
- `failure_code_class` = stable retry-class prefix derived from `failure_code` (`retryable-bounded | terminal-no-retry`); if compound codes are emitted, preserve both the prefix-class and the specific suffix instead of collapsing everything into one opaque string
- `checkpoint_commitment_hex`
- `observed_checkpoint_height`
- `observed_checkpoint_prev_hash_hex` (required for non-genesis checkpoints; omitted only for canonical genesis)
- `observed_wal_entry_hash_hex`
- `observed_state_root_hex`
- `observed_da_summary_hash` or equivalent digest
- `verifier_policy_version`
- `verifier_schema_version`
- `evidence_ref` (path, object key, or digest for replay/audit)

### Minimum replay/audit evidence bundle

`evidence_ref` should resolve to a durable bundle that lets an operator replay the exact trust decision later instead of reinterpreting logs by hand.

Minimum fields:

- `request_id`
- `attempt_id` (unique per bounded retry attempt; never reused across retries)
- `verdict`
- `failure_code`
- `failure_code_class` (stable retry-class prefix such as `retryable-bounded` or `terminal-no-retry`)
- `requested_checkpoint_height`
- `requested_checkpoint_state_root_hex`
- `requested_checkpoint_wal_entry_hash_hex`
- `requested_checkpoint_prev_hash_hex` (required for non-genesis checkpoints)
- `requested_checkpoint_commitment_hex`
- `requested_da_summary_hash` or equivalent canonical digest
- `observed_checkpoint_height`
- `observed_checkpoint_prev_hash_hex` (required for non-genesis checkpoints; omitted only for canonical genesis)
- `observed_state_root_hex`
- `observed_wal_entry_hash_hex`
- `observed_da_summary_hash` or equivalent canonical digest
- `verifier_policy_version`
- `verifier_schema_version`
- `attempt_started_at`
- `attempt_finished_at`
- `transport_outcome` (for example `http_200`, `timeout`, `process_unavailable`)
- `raw_evidence_ref` (raw proof, receipt, or response body handle)

Release-review invariants for this bundle:

- a terminal mismatch must preserve both the requested tuple and the observed tuple in the same bundle;
- a bounded retry must mint a fresh `attempt_id` and append a new bundle rather than overwrite the prior one;
- the same `request_id` must stay bound to one canonical requested checkpoint tuple plus DA summary identity for its entire lifetime; if any of `requested_checkpoint_height`, `requested_checkpoint_state_root_hex`, `requested_checkpoint_wal_entry_hash_hex`, `requested_checkpoint_prev_hash_hex`, or `requested_da_summary_hash` changes, the caller must mint a new `request_id` instead of reusing the old audit handle;
- a later successful retry may supersede the operational state, but it must not erase prior failed trust evidence for the same `request_id`.

### Example replay/audit evidence bundle

A concrete bundle example keeps release review anchored in a single checkpoint/WAL tuple instead of vague "verifier said no" logs.

```json
{
  "request_id": "verify-ckpt-0001842",
  "attempt_id": "verify-ckpt-0001842-attempt-02",
  "verdict": "rejected",
  "failure_code": "checkpoint_tuple_mismatch",
  "failure_code_class": "terminal-no-retry",
  "requested_checkpoint_height": 1842,
  "requested_checkpoint_state_root_hex": "4f3c2a1b9e8d7c6b5a4938271605f4e3d2c1b0a9988776655443322110ffeedd",
  "requested_checkpoint_wal_entry_hash_hex": "0a1b2c3d4e5f60718273645566778899aabbccddeeff00112233445566778899",
  "requested_checkpoint_prev_hash_hex": "11223344556677889900aabbccddeeff00112233445566778899aabbccddeeff",
  "requested_checkpoint_commitment_hex": "9d4c3b2a1908f7e6d5c4b3a291807f6e5d4c3b2a1908f7e6d5c4b3a291807f6e",
  "requested_da_summary_hash": "6a5b4c3d2e1f00112233445566778899aabbccddeeff00112233445566778899",
  "observed_checkpoint_height": 1842,
  "observed_checkpoint_prev_hash_hex": "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100",
  "observed_state_root_hex": "4f3c2a1b9e8d7c6b5a4938271605f4e3d2c1b0a9988776655443322110ffeedd",
  "observed_wal_entry_hash_hex": "deadbeef4e5f60718273645566778899aabbccddeeff00112233445566778899",
  "observed_da_summary_hash": "7b6c5d4e3f2a00112233445566778899aabbccddeeff00112233445566778899",
  "verifier_policy_version": "policy-2026-03-31",
  "verifier_schema_version": "checkpoint-wal-v1",
  "attempt_started_at": "2026-03-31T15:04:11Z",
  "attempt_finished_at": "2026-03-31T15:04:14Z",
  "transport_outcome": "http_200",
  "raw_evidence_ref": "s3://trnm-verifier-audit/2026/03/31/verify-ckpt-0001842-attempt-02.json"
}
```

What this example makes explicit:

- the sidecar kept the **requested** checkpoint tuple intact;
- the verifier answered successfully at the transport layer (`http_200`), so this is **not** an outage-class retry;
- `failure_code_class=terminal-no-retry` preserves, inside the replay bundle itself, that this was a trust failure rather than a bounded-retry transport incident;
- the observed predecessor/WAL anchor diverged from the requested checkpoint binding, so the correct outcome is a terminal trust failure (`checkpoint_tuple_mismatch`);
- a later retry may succeed for the same `request_id`, but it must append a new `attempt_id` rather than rewrite this rejected evidence.

### Minimum failure code taxonomy

At minimum, operators should be able to tell these cases apart without reading raw logs:

- `timeout`
- `unavailable`
- `malformed_evidence`
- `checkpoint_tuple_mismatch`
- `da_summary_mismatch`
- `policy_version_reject`
- `schema_version_reject`
- `non_canonical_checkpoint_surface`
- `uncommitted_wal_reject`

If the implementation cannot yet emit a stable set at least this rich, verifier-sidecar scope is still product-incomplete.

## Required failure semantics

The sidecar path should remain **fail-closed** under at least these operator-visible cases:

- timeout while waiting for verifier output
- transport or process unavailability
- malformed proof / malformed digest surface
- checkpoint tuple mismatch
- DA summary mismatch
- schema/policy version drift
- replay attempted against non-canonical or uncommitted WAL evidence

Expected operator rule:

> On verifier ambiguity, do not silently downgrade to a "best-effort success" path. Preserve evidence, mark the surface non-audit-ready, and require explicit operator action.

### Minimum retry / operator-action matrix

To keep retry behavior from masking trust failures, the sidecar should treat each stable `failure_code` as one of two classes:

| failure_code | retry class | expected operator meaning | required sidecar behavior |
| --- | --- | --- | --- |
| `timeout` | retryable-bounded | verifier may be healthy but did not answer before the caller deadline | retry only up to the configured bounded attempt budget; persist the final timeout as audit evidence |
| `unavailable` | retryable-bounded | transport/process outage or dependency unavailable | retry only up to the configured bounded attempt budget; do not rewrite the outcome as `verified` without a fresh successful response |
| `malformed_evidence` | terminal-no-retry | verifier answered, but the proof/digest surface is unusable | stop immediately, preserve raw evidence/ref, and mark the attempt non-audit-ready |
| `checkpoint_tuple_mismatch` | terminal-no-retry | verifier evidence does not bind to the requested checkpoint tuple | stop immediately; treat as a trust failure, not a transient outage |
| `da_summary_mismatch` | terminal-no-retry | DA/light-verifier linkage disagrees with the requested checkpoint evidence | stop immediately; preserve both observed and requested summary handles for replay |
| `policy_version_reject` | terminal-no-retry | request is semantically outside the active verifier policy | stop immediately and surface the rejecting policy version to the operator |
| `schema_version_reject` | terminal-no-retry | request/response schema drifted across a declared boundary | stop immediately and require an explicit compatibility decision before reattempt |
| `non_canonical_checkpoint_surface` | terminal-no-retry | caller supplied trim/control/case drift or other non-canonical checkpoint identity surface | reject before any success downgrade or retry path; require canonical checkpoint/WAL evidence |
| `uncommitted_wal_reject` | terminal-no-retry | caller attempted to verify speculative rather than committed checkpoint evidence | reject before transport retry; the issue is evidence class, not verifier availability |

Retry invariants for release review:

- only `timeout` and `unavailable` may enter bounded retry paths;
- all mismatch/canonicalization/policy/schema failures are **terminal** for that request id;
- every terminal failure must preserve enough evidence to replay the exact rejected tuple later;
- a later success must be tied to a **new** attempt/result pair, not silently overwrite the prior failed trust decision.

Implementation note for current review surfaces:

- compound/operator-facing diagnostics such as `unavailable:no_matching_wal_entry` should preserve the stable retry-class prefix (`unavailable`) **and** the more specific suffix (`no_matching_wal_entry`);
- the prefix determines whether bounded retry is even eligible, while the suffix stays in the persisted evidence/log surface so operators can distinguish transport outage from concrete evidence lookup failure;
- no compound code may be rewritten into `verified` without a fresh successful attempt carrying a new attempt/result identity.

Fail-closed interpretation rule for compound codes:

- `unavailable:<suffix>` may use the `unavailable` retry class only for a bounded retry budget, but the persisted evidence bundle must still preserve the exact suffix so release review can tell dependency outage from missing local evidence;
- suffixes such as `no_matching_wal_entry`, `checkpoint_store_unreachable`, or `evidence_bundle_unreadable` must never be collapsed into a generic transport-only incident in operator-facing artifacts;
- if a later retry succeeds, the prior `unavailable:<suffix>` evidence remains part of the audit trail and must not be deleted or rewritten as if the failed attempt had only been a transient log line.

## Release-review checklist

Use this when deciding whether verifier-sidecar scope is still trailing work or has crossed into launch-blocking territory.

### Ready to say "productized" only if all are true

- a stable verifier request/response boundary is documented
- canonical checkpoint/DA linkage is explicitly documented
- retry semantics are bounded and do not hide ambiguity
- failure taxonomy is operator-visible and fail-closed
- replay/audit evidence path is documented and exercised
- packaging/runtime ownership is assigned
- on-call / rollback expectations are documented

### Still not productized if any are true

- verifier output is treated as opaque success/failure without checkpoint identity anchors
- DA linkage exists only implicitly in code/tests, not in operator-facing contract language
- retry behavior can mask mismatch vs outage
- outage handling lacks replayable evidence capture
- operator handoff cannot show which schema/policy version produced a verdict

## Current repository mapping (implemented today)

The current repository does not yet expose a full standalone verifier sidecar service boundary, but it already contains one concrete **checkpoint/DA evidence surface** that release review can point at without over-claiming product readiness:

- `trnm-state::checkpoint_evidence_surface_is_canonical(...)`
- `trnm-state::checkpoint_da_light_verifier_summary(...)`

These helpers are not the whole sidecar, but they already establish a fail-closed floor for the checkpoint/WAL tuple that any future sidecar contract must preserve.

### Current regression anchors for release review

Reviewers should not treat the helper names above as prose-only claims. The current repository already carries concrete regression anchors that exercise the fail-closed surface from both the helper layer and the checkpoint-recovery path:

- `trillionnium/crates/trnm-state/src/lib.rs`
  - `checkpoint_da_light_verifier_summary_is_canonical_and_includes_wal_linkage`
  - `checkpoint_da_light_verifier_summary_fails_closed_on_uncommitted_wal`
  - `checkpoint_da_light_verifier_summary_fails_closed_on_non_ascii_proposal_hash`
- `trillionnium/crates/trnm-state/tests/state_root_regression.rs`
  - `checkpoint_evidence_surface_requires_canonical_state_root_and_hash_hex`
  - `checkpoint_da_light_verifier_summary_fails_closed_on_non_ascii_wal_proposal_hash_surface`
  - `checkpoint_da_light_verifier_summary_fails_closed_on_missing_non_genesis_wal_prev_hash_surface`
  - `checkpoint_da_light_verifier_summary_fails_closed_on_uncommitted_wal_surface`
  - `node_recovery_checkpoint_rejects_non_genesis_prev_hash_with_carriage_return_control_drift`
- `trillionnium/crates/trnm-state/tests/state_root_regression/regression/canonicalization.rs`
  - `checkpoint_audit_summary_rejects_noncanonical_prev_hash_surface`
- `trillionnium/crates/trnm-node/src/tests.rs`
  - `metadata_only_recovery_error_surfaces_da_unavailability_reason_when_checkpoint_wal_linkage_is_missing`

Together these anchors give release review one concrete trail for verifying that:

1. canonical checkpoint/WAL tuples emit a stable DA/light-verifier summary;
2. speculative or malformed WAL evidence is rejected before it can be presented as audit-ready;
3. proposal-hash surface drift is treated as a fail-closed trust problem before retry logic can blur malformed evidence into a generic outage story;
4. predecessor-link drift — including a missing non-genesis `prev_hash_hex`, not just malformed casing/control-byte drift — is treated as a fail-closed trust problem rather than a transport/retry problem; and
5. when checkpoint/WAL linkage cannot be reconstructed locally, the operator-facing recovery surface preserves the concrete `unavailable:no_matching_wal_entry` reason instead of collapsing it into a generic success/failure blur.

### Minimal targeted replay commands

When reviewers want a smallest-possible replay set instead of broad crate sweeps, start with these targeted commands from the **repo root** so the replay remains stable even when the operator shell is not already inside `trillionnium/`:

- `cargo test --manifest-path trillionnium/Cargo.toml -p trnm-state checkpoint_da_light_verifier_summary_is_canonical_and_includes_wal_linkage -q`
- `cargo test --manifest-path trillionnium/Cargo.toml -p trnm-state checkpoint_da_light_verifier_summary_fails_closed_on_non_ascii_wal_proposal_hash_surface -q`
- `cargo test --manifest-path trillionnium/Cargo.toml -p trnm-state checkpoint_da_light_verifier_summary_fails_closed_on_missing_non_genesis_wal_prev_hash_surface -q`
- `cargo test --manifest-path trillionnium/Cargo.toml -p trnm-state checkpoint_audit_summary_rejects_noncanonical_prev_hash_surface -q`
- `cargo test --manifest-path trillionnium/Cargo.toml -p trnm-state checkpoint_da_light_verifier_summary_fails_closed_on_uncommitted_wal_surface -q`
- `cargo test --manifest-path trillionnium/Cargo.toml -p trnm-node metadata_only_recovery_error_surfaces_da_unavailability_reason_when_checkpoint_wal_linkage_is_missing -q`

If a reviewer prefers working from `trillionnium/`, the same commands may omit `--manifest-path trillionnium/Cargo.toml`, but the repo-root form is the safer release-review default because it removes cwd ambiguity from the evidence replay path.

This replay set is intentionally narrow: one happy-path linkage proof, four fail-closed canonicalization regressions spanning WAL proposal-hash surfaces, non-genesis predecessor-link presence, non-canonical predecessor-link encoding, and uncommitted WAL rejection, plus one operator-facing DA-unavailability triage check.

### What the current helper surface already proves

For canonical checkpoint/WAL evidence, `checkpoint_da_light_verifier_summary(...)` currently emits operator-reviewable fields covering at least:

- checkpoint identity anchors:
  - `checkpoint_height`
  - `checkpoint_state_root`
  - `checkpoint_wal_entry_hash`
  - derived `checkpoint_commitment`
- WAL linkage anchors:
  - `wal_height`
  - `wal_round`
  - `wal_proposal_hash`
  - `wal_committed`
  - `wal_state_root`
  - `wal_prev_hash`
  - derived `wal_content_hash`
- canonicalization metadata:
  - `*_kind=canonical-hex-32b` and `*_bytes=32` for digest surfaces
  - height/round encoding metadata
  - `wal_proposal_hash_surface_policy=ascii-trimmed-no-ws-control-max256`
  - `wal_prev_hash_surface_policy=canonical-hex-32b-or-none`
- binding/invariant metadata:
  - `checkpoint_height_matches_wal=true`
  - `checkpoint_state_root_matches_wal=true`
  - `checkpoint_wal_entry_hash_matches_wal=true`
  - `wal_content_hash_matches_checkpoint=true`
  - `checkpoint_surface_canonical=true`

This means the repository already has one concrete, replayable checkpoint/DA summary surface that:

1. binds a checkpoint to a single WAL tuple;
2. preserves canonical lower-hex digest semantics for checkpoint/state/WAL hashes;
3. distinguishes genesis vs non-genesis predecessor linkage through explicit `wal_prev_hash_*` metadata; and
4. fails closed by returning no summary when canonicalization or linkage invariants do not hold.

### Release-review interpretation boundary

This helper surface should be cited as **implemented evidence linkage**, not as proof that the full verifier sidecar is productized.

Accurate wording today:

> the repository already exposes a fail-closed checkpoint/WAL audit summary suitable for DA/light-verifier evidence linkage review, but it does not yet by itself close the higher-level sidecar service contract, retry policy ownership, or deployable runtime boundary.

## Scope-freeze interpretation

When Day-1 launch scope is frozen, reviewers should classify verifier-sidecar work using the same fail-closed standard as the rest of the mainnet blocker board:

- if public launch claims stop at core chain execution and do **not** promise trusted verification as an operator-facing product, this area may remain P1 trailing work;
- if launch language promises verifier-backed trust, DA attestation, or checkpoint-proof service semantics to validators/integrators, this checklist should be treated as launch-blocking until the contract/retry/replay surfaces below are concretely closed.

Fail-closed interpretation rule:

> generic statements like "the verifier exists" or "proof checks are wired in" are not enough for scope freeze. Reviewers should require one stable tuple contract, one bounded retry matrix, and one replayable evidence bundle shape that preserves both requested and observed checkpoint/WAL anchors.

## Suggested next closure slice

The next low-risk engineering slice should prefer one of:

1. tighten a canonicalization or fail-closed regression test around checkpoint/DA linkage;
2. document a concrete verifier request/response tuple with failure codes;
3. add a replay/audit evidence example tied to checkpoint/WAL identity.

Choose only one per iteration.
