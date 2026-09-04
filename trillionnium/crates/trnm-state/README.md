---
status: legacy-compatibility
owner: Trillionnium Chain maintainers
last_verified: 2026-09-04
applies_to: main@b2d485e5641614ea0ca34ebf80a5f7843ff1e6d9
---

# `trnm-state`

> **Maturity:** `legacy-compatibility`  
> **Repository release status:** follow [`RELEASE_READINESS.md`](../../../RELEASE_READINESS.md). A green crate test is not repository or mainnet readiness.

Versioned legacy state store, governance, consumption, balance, root, WAL, and restore implementation.

## Responsibilities

- Maintain object/state helpers used by legacy and compatibility paths.
- Implement balance, governance, consumption, pending-resolution, state-root, WAL, and restore operations.
- Provide deterministic state-root and recovery helpers where explicitly consumed.

## Non-responsibilities and production boundary

- Is not the canonical AppHash v4 store by directory name alone; canonical evidence is owned by `trnm-consensus-app`.
- Must not be cited as production support for a feature unless the same transition executes through `trnm-runtime` under CometBFT.
- Does not own network consensus or external API semantics.

The binding production-candidate architecture is documented in
[`TRNM_CANONICAL_RUNTIME_FREEZE_2026-07-28.md`](../../../docs/architecture/TRNM_CANONICAL_RUNTIME_FREEZE_2026-07-28.md).
Where this README and an older report disagree, the runtime freeze and current
release-readiness document take precedence.

## Source layout

- `src/store.rs` and `src/store_ops*`: object and domain store operations.
- `src/state_root.rs` and `src/state_root_ops/`: root calculation and WAL helpers.
- `src/governance*.rs`, `src/consumption.rs`, `src/balances.rs`: domain state machines.
- `src/restore.rs` and `src/resolve_approval.rs`: restoration and approval flows.
- `src/tests*`: extensive legacy/compatibility regression coverage.

## Required invariants

- Object versions advance monotonically and failed operations do not partially alter state.
- Balance and escrow operations preserve value subject to explicit mint/burn policy.
- Root calculation is deterministic over a canonical object ordering and encoding.
- WAL recovery validates continuity and rejects corrupted or incompatible metadata.
- Governance and resolution operations enforce authorization, timelock/version, and replay constraints.

A change that can affect consensus, signing bytes, object identity, balances,
authorization, replay handling, persistence, or finality must add a regression
test that fails before the change and passes after it. Tests from a legacy or
research path may not be cited as evidence for the canonical path.

## Build and test

Run from `trillionnium/`:

```bash
cargo check -p trnm-state --locked
cargo test -p trnm-state --locked
```

Additional evidence:

- `cargo test -p trnm-state --locked`
- State-root and WAL changes require replay, corruption, partial-write, restore, and deterministic-order tests.

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

- Document and enforce exact compatibility boundaries with the canonical SQLite/JMT store.
- Reduce the oversized `lib.rs`, separate schema from domain operations, and publish migration/version tables.

These gaps are intentionally visible. They may be closed only by implementation
and reproducible evidence; wording changes alone cannot close them.

## References

- [Workspace guide](../../README.md)
- [Crate catalog](../README.md)
- [Documentation standard](../../../docs/DOCUMENTATION_STANDARD.md)
- [Architecture index](../../../docs/architecture/README.md)
- [Protocol index](../../../docs/protocol/README.md)
- [Release truth source](../../../RELEASE_READINESS.md)
