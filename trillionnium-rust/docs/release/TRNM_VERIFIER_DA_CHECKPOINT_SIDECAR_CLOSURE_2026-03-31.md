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
2. `checkpoint.state_root_hex` binds to the exact committed WAL state root.
3. `checkpoint.wal_entry_hash_hex` binds to the exact WAL content hash.
4. non-genesis checkpoints preserve predecessor linkage through canonical `prev_hash_hex` handling.
5. any exported DA/light-verifier summary preserves canonical lower-hex digest surfaces and rejects trim/control/case drift.

In short: a verifier receipt that cannot be traced back to a single canonical checkpoint/WAL tuple is not sufficient release evidence.

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

## Suggested next closure slice

The next low-risk engineering slice should prefer one of:

1. tighten a canonicalization or fail-closed regression test around checkpoint/DA linkage;
2. document a concrete verifier request/response tuple with failure codes;
3. add a replay/audit evidence example tied to checkpoint/WAL identity.

Choose only one per iteration.
