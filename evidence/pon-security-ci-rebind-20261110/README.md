# PQ source-lock / branch-count CI repair — restricted qualification

Tested parent: `e4abb172147e941b62483652b0ceabaae4317624` (PR #876). This is a CI-integrity repair, not a protocol or production admission change.

## Reproduced failures

- [Original PQ witness run 42830743380](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42830743380), job 129879770644: `pq_chain_claim_guard.py` refused with `invalid lifetime budget: source lock hash mismatch: trillionnium/crates/trnm-pon-node/src/consensus.rs` before native steps.
- [Original branch encoding run 42830743317](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42830743317), job 129879770405: Rust `consensus::tests::` reported 11 passed, 0 failed, but the CI predicate expected 10.
- On operator host ai395, a distinct sparse checkout at exact parent reproduced the source-lock failure with exit 2. Its actual `consensus.rs` SHA-256 is `dbbd44790428ae0aff32d7305e062a6fc09ca0add0e3c4c077deefd8bfec760d`; previous declared hash was `a5600aeb8287cce30ae3075b675082df4e6e5569a80f23e9a2e381f8202a8f62`.

## Scoped patch and observed checks

- Rebind only `consensus.rs` in the existing research source lock to the actual file hash. Keep the original source-revision identity, assumptions and all unknown bounds unchanged.
- Require 11 successful tests in the pinned branch encoding workflow and explicitly rerun `native_arithmetic_matches_versioned_python_domain_vectors` with `--exact`, in addition to the previous individually selected tests.
- Re-pin the exact Git blob IDs of the two changed files in `pq-cross-branch-corpus-v1.json`.
- On ai395, `pq_lifetime_budget.py` changed from the matching source-lock refusal to a successful declared-path inspection with `source_revision_bound=true`, `source_binding_scope=declared-event-paths-only`, and `actual_lifetime_failure_bound=null`.
- The unchanged relevant Python suites passed on that sparse checkout: lifetime budget 58/58; PQ claim guard 55/55; research integration tests 59/59. `git diff --check` passed. These are not a native Rust execution or a complete checkout CI pass.

## Release / safety boundary

**HOLD_NO_GO; no chain PQ qualification.** No original 3x30-second native campaign re-run, no new proof of independent rollback freshness/physical custody, no complete publicly admitted malicious-request resource test, no M15 / FinalUse / payment authority test, no source-qualified eight-domain lifetime proof, and no production deployment. The full hosted head and prospective-merge workflows must re-execute at this exact new commit; initial job failures cannot be reclassified as passes. `whole_chain_pq_qualified=false`, `production_activation=false`.
