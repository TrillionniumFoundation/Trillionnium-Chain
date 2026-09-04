---
status: legacy-experimental
owner: Trillionnium Chain maintainers
last_verified: 2026-09-04
applies_to: main@b2d485e5641614ea0ca34ebf80a5f7843ff1e6d9
---

# `trnm-mempool`

> **Maturity:** `legacy-experimental`  
> **Repository release status:** follow [`RELEASE_READINESS.md`](../../../RELEASE_READINESS.md). A green crate test is not repository or mainnet readiness.

Legacy admission, lane fairness, quota, retry, spillover, and recovery queue.

## Responsibilities

- Implement bounded admission and per-lane quota/fairness behavior for legacy and experimental ingress paths.
- Track retry/deferral state, poison handling, duplicate recovery, and ready-pop semantics.
- Provide hard-stop and self-heal behavior under configured pressure.

## Non-responsibilities and production boundary

- Does not replace the CometBFT mempool in the canonical network path.
- Admission success does not imply protocol validity or finalized execution.
- Lane policy may not become consensus-visible ordering without an explicit deterministic protocol decision.

The binding production-candidate architecture is documented in
[`TRNM_CANONICAL_RUNTIME_FREEZE_2026-07-28.md`](../../../docs/architecture/TRNM_CANONICAL_RUNTIME_FREEZE_2026-07-28.md).
Where this README and an older report disagree, the runtime freeze and current
release-readiness document take precedence.

## Source layout

- `src/admission_gate.rs` and `src/gate/`: admission, fairness, retry bookkeeping.
- `src/lane_*.rs` and `src/lane_recovery/`: quotas, spillover, readiness, and duplicate recovery.
- `src/main.rs`: diagnostic/demo binary.
- `src/tests/`: limits, fairness, hard-stop, recovery, and quota regressions.

## Required invariants

- Memory, queue, retry, and per-source/lane limits are bounded.
- Duplicate and poisoned entries cannot consume unbounded retry capacity.
- Fairness reservations do not bypass hard global capacity or security checks.
- Failure and recovery preserve deterministic bookkeeping for the same input sequence.

A change that can affect consensus, signing bytes, object identity, balances,
authorization, replay handling, persistence, or finality must add a regression
test that fails before the change and passes after it. Tests from a legacy or
research path may not be cited as evidence for the canonical path.

## Build and test

Run from `trillionnium/`:

```bash
cargo check -p trnm-mempool --locked
cargo test -p trnm-mempool --locked
```

Additional evidence:

- `cargo test -p trnm-mempool --locked`
- Load tests must include spam, starvation, retry storms, duplicate recovery, and bounded-memory assertions.

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

- Define the exact boundary with CometBFT CheckTx/RecheckTx and remove unsupported duplicate admission logic.
- Publish operator metrics, SLOs, and anti-DoS parameter rationale.

These gaps are intentionally visible. They may be closed only by implementation
and reproducible evidence; wording changes alone cannot close them.

## References

- [Workspace guide](../../README.md)
- [Crate catalog](../README.md)
- [Documentation standard](../../../docs/DOCUMENTATION_STANDARD.md)
- [Architecture index](../../../docs/architecture/README.md)
- [Protocol index](../../../docs/protocol/README.md)
- [Release truth source](../../../RELEASE_READINESS.md)
