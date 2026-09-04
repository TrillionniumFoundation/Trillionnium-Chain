---
status: legacy-experimental
owner: Trillionnium Chain maintainers
last_verified: 2026-09-04
applies_to: main@b2d485e5641614ea0ca34ebf80a5f7843ff1e6d9
---

# `trnm-executor`

> **Maturity:** `legacy-experimental`  
> **Repository release status:** follow [`RELEASE_READINESS.md`](../../../RELEASE_READINESS.md). A green crate test is not repository or mainnet readiness.

Conflict analysis and adaptive parallel grouping strategies for legacy/benchmark execution.

## Responsibilities

- Derive conflict relationships and deterministic parallel groups from transaction access information.
- Provide original, aggressive, reordering, and adaptive strategy experiments.
- Expose bounded environment configuration and profiling signals for benchmark comparison.

## Non-responsibilities and production boundary

- Does not execute canonical `trnm-runtime` mutations or commit state.
- Benchmark speedups do not establish consensus safety or canonical production throughput.
- Environment-driven adaptation must not influence consensus-visible ordering unless fully deterministic and frozen.

The binding production-candidate architecture is documented in
[`TRNM_CANONICAL_RUNTIME_FREEZE_2026-07-28.md`](../../../docs/architecture/TRNM_CANONICAL_RUNTIME_FREEZE_2026-07-28.md).
Where this README and an older report disagree, the runtime freeze and current
release-readiness document take precedence.

## Source layout

- `src/conflict.rs`: conflict detection.
- `src/reorder.rs`: transaction/group reordering.
- `src/adaptive.rs` and `src/aggressive_profile.rs`: strategy selection and profiling.
- `src/env_config.rs`: bounded configuration parsing.
- `src/tests/`: conflict, grouping, hotspot, and fail-closed configuration tests.

## Required invariants

- Given identical input and frozen configuration, grouping and ordering are deterministic.
- Conflicting transactions never execute concurrently in the same group.
- Invalid, non-finite, out-of-range, or ambiguous tuning inputs fail closed.
- Fallback to the conservative strategy is explicit and observable.

A change that can affect consensus, signing bytes, object identity, balances,
authorization, replay handling, persistence, or finality must add a regression
test that fails before the change and passes after it. Tests from a legacy or
research path may not be cited as evidence for the canonical path.

## Build and test

Run from `trillionnium/`:

```bash
cargo check -p trnm-executor --locked
cargo test -p trnm-executor --locked
```

Additional evidence:

- `cargo test -p trnm-executor --locked`
- Performance claims require fixed hardware/workload/seed/warm-up and raw evidence, not a single local ratio.

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

- Either integrate a deterministic scheduler into the canonical runtime with AppHash evidence or keep this crate explicitly non-canonical.
- Split the oversized `lib.rs` and freeze a machine-readable benchmark methodology.

These gaps are intentionally visible. They may be closed only by implementation
and reproducible evidence; wording changes alone cannot close them.

## References

- [Workspace guide](../../README.md)
- [Crate catalog](../README.md)
- [Documentation standard](../../../docs/DOCUMENTATION_STANDARD.md)
- [Architecture index](../../../docs/architecture/README.md)
- [Protocol index](../../../docs/protocol/README.md)
- [Release truth source](../../../RELEASE_READINESS.md)
