---
status: canonical-consensus-critical
owner: Trillionnium Chain maintainers
last_verified: 2026-09-04
applies_to: main@b2d485e5641614ea0ca34ebf80a5f7843ff1e6d9
---

# `trnm-runtime`

> **Maturity:** `canonical-consensus-critical`  
> **Repository release status:** follow [`RELEASE_READINESS.md`](../../../RELEASE_READINESS.md). A green crate test is not repository or mainnet readiness.

Pure deterministic state-transition engine for the canonical transaction protocol.

## Responsibilities

- Validate transaction context and execute account, fee, task escrow, assignment, commit/reveal, consumption, challenge, resolution, settlement, and expiry commands.
- Return version-checked object mutations, deterministic events, gas usage, and charged fees without performing I/O.
- Provide a shared resource estimator used by simulation and finalized execution.

## Non-responsibilities and production boundary

- Must not access networking, filesystem, database, wall clock, randomness, environment variables, or CometBFT.
- Does not authorize an envelope signature; the application boundary supplies verified signer identity and role.
- Does not persist mutations or calculate the final AppHash.

The binding production-candidate architecture is documented in
[`TRNM_CANONICAL_RUNTIME_FREEZE_2026-07-28.md`](../../../docs/architecture/TRNM_CANONICAL_RUNTIME_FREEZE_2026-07-28.md).
Where this README and an older report disagree, the runtime freeze and current
release-readiness document take precedence.

## Source layout

- `src/lib.rs`: runtime errors, state view, mutation/receipt model, resource estimation, command execution.
- `tests/state_machine_model.rs`: bounded model tests for conservation, replay, failure immutability, and deterministic outcomes.

## Required invariants

- Identical `(state, transaction, execution context)` produces byte-identical mutations, events, gas, and fee.
- Failed execution returns no committed mutation and cannot consume a nonce or fee partially.
- Account nonces are sequential; replay and gaps fail closed.
- All value movement is funded by an account, escrow, stake, bond, or explicit fee collector; no receipt mints value.
- Mutation `expected_version` and `next_version` prevent silent lost updates and version overflow.

A change that can affect consensus, signing bytes, object identity, balances,
authorization, replay handling, persistence, or finality must add a regression
test that fails before the change and passes after it. Tests from a legacy or
research path may not be cited as evidence for the canonical path.

## Build and test

Run from `trillionnium/`:

```bash
cargo check -p trnm-runtime --locked
cargo test -p trnm-runtime --locked
```

Additional evidence:

- `cargo test -p trnm-runtime --locked`
- `cargo test -p trnm-runtime --test state_machine_model --locked`
- Canonical acceptance additionally requires execution through the four-validator CometBFT vertical slice.

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

- Any new command requires protocol type, gas schedule, error code, invariant tests, application routing, and multi-validator AppHash evidence in the same change.
- Stable error-code compatibility must be versioned before public SDK guarantees are made.

These gaps are intentionally visible. They may be closed only by implementation
and reproducible evidence; wording changes alone cannot close them.

## References

- [Workspace guide](../../README.md)
- [Crate catalog](../README.md)
- [Documentation standard](../../../docs/DOCUMENTATION_STANDARD.md)
- [Architecture index](../../../docs/architecture/README.md)
- [Protocol index](../../../docs/protocol/README.md)
- [Release truth source](../../../RELEASE_READINESS.md)
