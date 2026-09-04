---
status: supported-consumer-boundary
owner: Trillionnium Chain maintainers
last_verified: 2026-09-04
applies_to: main@b2d485e5641614ea0ca34ebf80a5f7843ff1e6d9
---

# `trnm-finality-verifier`

> **Maturity:** `supported-consumer-boundary`  
> **Repository release status:** follow [`RELEASE_READINESS.md`](../../../RELEASE_READINESS.md). A green crate test is not repository or mainnet readiness.

Minimal independent verifier for finality receipts and validator-set evidence.

## Responsibilities

- Verify finality material using `trnm-finality-types` without depending on the full node.
- Return deterministic, machine-classifiable rejection results for malformed, unauthorized, or under-threshold evidence.
- Serve as the library boundary for sidecars, bridges, indexers, and external services.

## Non-responsibilities and production boundary

- Does not discover trusted validator sets, checkpoints, chain IDs, or fork-choice anchors.
- Does not operate a network service or secure a key.
- Passing unit tests is not proof of a deployed independent sidecar.

The binding production-candidate architecture is documented in
[`TRNM_CANONICAL_RUNTIME_FREEZE_2026-07-28.md`](../../../docs/architecture/TRNM_CANONICAL_RUNTIME_FREEZE_2026-07-28.md).
Where this README and an older report disagree, the runtime freeze and current
release-readiness document take precedence.

## Source layout

- `src/lib.rs`: verification API and focused tests.

## Required invariants

- Verification binds the expected chain, height/root, certificate version, validator set, and threshold.
- No untrusted receipt field may select its own trust anchor.
- Invalid signatures, duplicate signers, unknown validators, and threshold shortfall fail closed.
- Verification performs no I/O and has bounded work proportional to supplied evidence.

A change that can affect consensus, signing bytes, object identity, balances,
authorization, replay handling, persistence, or finality must add a regression
test that fails before the change and passes after it. Tests from a legacy or
research path may not be cited as evidence for the canonical path.

## Build and test

Run from `trillionnium/`:

```bash
cargo check -p trnm-finality-verifier --locked
cargo test -p trnm-finality-verifier --locked
```

Additional evidence:

- `cargo test -p trnm-finality-verifier --locked`
- Release evidence must include an independently packaged verifier replaying canonical and adversarial fixtures.

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

- Ship a standalone CLI/package, public fixture bundle, cross-language implementation, and deployed sidecar evidence.
- Define validator-set rotation/checkpoint acquisition and retention semantics.

These gaps are intentionally visible. They may be closed only by implementation
and reproducible evidence; wording changes alone cannot close them.

## References

- [Workspace guide](../../README.md)
- [Crate catalog](../README.md)
- [Documentation standard](../../../docs/DOCUMENTATION_STANDARD.md)
- [Architecture index](../../../docs/architecture/README.md)
- [Protocol index](../../../docs/protocol/README.md)
- [Release truth source](../../../RELEASE_READINESS.md)
