---
status: canonical-production-candidate
owner: Trillionnium Chain maintainers
last_verified: 2026-09-04
applies_to: main@b2d485e5641614ea0ca34ebf80a5f7843ff1e6d9
---

# `trnm-consensus-app`

> **Maturity:** `canonical-production-candidate`  
> **Repository release status:** follow [`RELEASE_READINESS.md`](../../../RELEASE_READINESS.md). A green crate test is not repository or mainnet readiness.

CometBFT ABCI++ application adapter and durable canonical-state boundary.

## Responsibilities

- Own ABCI++ request handling and translation between signed canonical envelopes and the pure `trnm-runtime` state transition.
- Persist canonical objects, authenticated-tree nodes, block metadata, validator lifecycle, snapshots, and recovery journals.
- Produce the committed AppHash and expose membership/non-membership proof queries and transaction simulation.

## Non-responsibilities and production boundary

- Must not duplicate business-state transition logic that belongs in `trnm-runtime`.
- Must not accept unknown production payloads as opaque state.
- Local loopback, scale, or crash fixtures are development evidence, not public-mainnet evidence.

The binding production-candidate architecture is documented in
[`TRNM_CANONICAL_RUNTIME_FREEZE_2026-07-28.md`](../../../docs/architecture/TRNM_CANONICAL_RUNTIME_FREEZE_2026-07-28.md).
Where this README and an older report disagree, the runtime freeze and current
release-readiness document take precedence.

## Source layout

- `src/lib.rs`: ABCI application, request lifecycle, snapshot/state-sync coordination, tests.
- `src/store.rs`: SQLite/WAL durable store and canonical schema handling.
- `src/auth_tree.rs`: versioned authenticated tree and ICS23 proof surface.
- `src/validator_lifecycle.rs`: validator update validation and persistence.
- `src/scale.rs` and `src/persistent_scale.rs`: bounded scale evidence runners.
- `src/bin/trnm-cometbft-app.rs`: application process entrypoint.
- `src/bin/trnm-v3-export-new-genesis.rs`: review-only v3-to-v4 export path.

## Required invariants

- Every accepted transaction is decoded as a supported typed payload and executed by `trnm-runtime`.
- Finalize/commit replay must converge to the same objects, validator updates, height, and AppHash.
- Durable state is committed transactionally before success is exposed; restart recovery must not invent or skip a height.
- Snapshot installation is fail-closed on schema, chain, signer-policy, reachability, and authenticated-root mismatch.
- Simulation reads the latest committed state and must not mutate persistent or pending state.

A change that can affect consensus, signing bytes, object identity, balances,
authorization, replay handling, persistence, or finality must add a regression
test that fails before the change and passes after it. Tests from a legacy or
research path may not be cited as evidence for the canonical path.

## Build and test

Run from `trillionnium/`:

```bash
cargo check -p trnm-consensus-app --locked
cargo test -p trnm-consensus-app --locked
```

Additional evidence:

- `cargo test -p trnm-consensus-app --locked`
- `trillionnium/scripts/consensus/spike_cometbft_four_validator.sh`
- `trillionnium/scripts/consensus/spike_cometbft_validator_lifecycle.sh`
- Scale binaries require explicit release-profile evidence and do not replace multi-host SLO tests.

## Failure, recovery, and observability

- Reject malformed, unknown, ambiguous, stale, replayed, unauthorized, or
  resource-exhausting inputs before changing durable or consensus-visible state.
- Errors consumed by another process must expose a stable machine-readable code;
  display text remains diagnostic.
- Recovery must be idempotent and preserve chain, height, version, hash, signer,
  and domain bindings.
- Logs and evidence must not contain private keys, seed material, bearer tokens,
  or unredacted confidential payloads.
- Operational claims must identify the exact commit, configuration, platform,
  command, result, and artifact digest.

## Change rules

1. Keep responsibilities and non-responsibilities current in the same pull request.
2. Version every externally consumed schema or signing representation.
3. Add positive, negative, boundary, replay, and failure-immutability tests.
4. Update [`MODULE_CATALOG.md`](../../../docs/MODULE_CATALOG.md) when maturity or
   ownership changes.
5. Do not mark an item implemented until it passes through the owning canonical
   path and produces reproducible evidence.

## Known gaps / activation conditions

- Authenticated multi-host transport, cross-host recovery, long soak, HSM/KMS integration, and threshold governance remain release blockers.
- Production storage/auth-tree code is still partly coupled to `trnm-node` library modules and must be extracted before legacy removal.
- Durable indexer/event replay is not yet a complete public historical read service.

These gaps are intentionally visible. They may be closed only by implementation
and reproducible evidence; wording changes alone cannot close them.

## References

- [Workspace guide](../../README.md)
- [Crate catalog](../README.md)
- [Documentation standard](../../../docs/DOCUMENTATION_STANDARD.md)
- [Architecture index](../../../docs/architecture/README.md)
- [Protocol index](../../../docs/protocol/README.md)
- [Release truth source](../../../RELEASE_READINESS.md)
