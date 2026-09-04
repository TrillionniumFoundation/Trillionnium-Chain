---
status: test-only
owner: Trillionnium Chain maintainers
last_verified: 2026-09-04
applies_to: main@b2d485e5641614ea0ca34ebf80a5f7843ff1e6d9
---

# `trnm-bench`

> **Maturity:** `test-only`  
> **Repository release status:** follow [`RELEASE_READINESS.md`](../../../RELEASE_READINESS.md). A green crate test is not repository or mainnet readiness.

Benchmark and evidence generator for execution, state, and workload experiments.

## Responsibilities

- Run bounded benchmark scenarios and emit machine-readable/raw evidence.
- Compare execution strategies and workload mixes under explicit parameters.
- Support regression thresholds without changing consensus behavior.

## Non-responsibilities and production boundary

- Benchmark output is not release readiness or multi-host production evidence.
- Results from legacy paths cannot be attributed to the canonical runtime.
- Threshold tuning must not silently alter protocol or production defaults.

The binding production-candidate architecture is documented in
[`TRNM_CANONICAL_RUNTIME_FREEZE_2026-07-28.md`](../../../docs/architecture/TRNM_CANONICAL_RUNTIME_FREEZE_2026-07-28.md).
Where this README and an older report disagree, the runtime freeze and current
release-readiness document take precedence.

## Source layout

- `src/main.rs`: benchmark CLI, workload generation, measurement, and output.

## Required invariants

- Every result records commit, binary/profile, hardware/OS, workload, seed, warm-up, sample count, and units.
- Raw observations are preserved; summaries never replace source evidence.
- Failures, skipped samples, and variance are explicit.
- Comparisons use identical correctness checks and input sets.

A change that can affect consensus, signing bytes, object identity, balances,
authorization, replay handling, persistence, or finality must add a regression
test that fails before the change and passes after it. Tests from a legacy or
research path may not be cited as evidence for the canonical path.

## Build and test

Run from `trillionnium/`:

```bash
cargo check -p trnm-bench --locked
cargo test -p trnm-bench --locked
```

Additional evidence:

- `cargo test -p trnm-bench --locked`
- `cargo run -p trnm-bench --release -- <explicit arguments>`
- Release claims additionally require canonical multi-host and persistent-store workloads.

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

- Split workload definitions from reporting, add schema-versioned outputs, and enforce benchmark provenance in CI.

These gaps are intentionally visible. They may be closed only by implementation
and reproducible evidence; wording changes alone cannot close them.

## References

- [Workspace guide](../../README.md)
- [Crate catalog](../README.md)
- [Documentation standard](../../../docs/DOCUMENTATION_STANDARD.md)
- [Architecture index](../../../docs/architecture/README.md)
- [Protocol index](../../../docs/protocol/README.md)
- [Release truth source](../../../RELEASE_READINESS.md)
