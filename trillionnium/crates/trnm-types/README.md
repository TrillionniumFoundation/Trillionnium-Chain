---
status: legacy-shared-types
owner: Trillionnium Chain maintainers
last_verified: 2026-09-04
applies_to: main@b2d485e5641614ea0ca34ebf80a5f7843ff1e6d9
---

# `trnm-types`

> **Maturity:** `legacy-shared-types`  
> **Repository release status:** follow [`RELEASE_READINESS.md`](../../../RELEASE_READINESS.md). A green crate test is not repository or mainnet readiness.

Shared legacy/interop types, identity registry, capability, settlement, hashing, and normalization models.

## Responsibilities

- Provide types reused by legacy state, executor, RPC, worker, and compatibility modules.
- Implement DID/capability identity lifecycle, normalization, audit, and settlement-adjacent structures.
- Centralize common hashes, object references, task metadata, and compatibility models.

## Non-responsibilities and production boundary

- Does not define the canonical v1 transaction protocol; that belongs to `trnm-protocol`.
- Type reuse does not make a field consensus-stable.
- Identity registry helpers do not replace dynamic canonical account-key onboarding.

The binding production-candidate architecture is documented in
[`TRNM_CANONICAL_RUNTIME_FREEZE_2026-07-28.md`](../../../docs/architecture/TRNM_CANONICAL_RUNTIME_FREEZE_2026-07-28.md).
Where this README and an older report disagree, the runtime freeze and current
release-readiness document take precedence.

## Source layout

- `src/interop_identity.rs` and `src/interop_identity/`: DID, capability, hashing, settlement, normalization, and error model.
- `src/interop_identity/tests/`: lifecycle, sanitation, authorization, replay, and failure-path coverage.
- `src/lib.rs`: remaining shared models and re-exports.

## Required invariants

- Identifiers are canonicalized once; whitespace, case, and malformed DID ambiguity fail closed.
- Capability issue/renew/revoke/verify transitions are authorized, time-bounded, and auditable.
- Hashing is domain separated and stable for each declared version.
- Consensus-critical consumers must convert explicitly into `trnm-protocol` types.

A change that can affect consensus, signing bytes, object identity, balances,
authorization, replay handling, persistence, or finality must add a regression
test that fails before the change and passes after it. Tests from a legacy or
research path may not be cited as evidence for the canonical path.

## Build and test

Run from `trillionnium/`:

```bash
cargo check -p trnm-types --locked
cargo test -p trnm-types --locked
```

Additional evidence:

- `cargo test -p trnm-types --locked`
- Changes require downstream workspace tests because this crate has a broad dependency fan-out.

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

- Split identity/capability and generic legacy models into narrower crates.
- Publish conversion and deprecation rules between `trnm-types` and canonical protocol objects.

These gaps are intentionally visible. They may be closed only by implementation
and reproducible evidence; wording changes alone cannot close them.

## References

- [Workspace guide](../../README.md)
- [Crate catalog](../README.md)
- [Documentation standard](../../../docs/DOCUMENTATION_STANDARD.md)
- [Architecture index](../../../docs/architecture/README.md)
- [Protocol index](../../../docs/protocol/README.md)
- [Release truth source](../../../RELEASE_READINESS.md)
