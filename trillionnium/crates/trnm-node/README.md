---
status: legacy-frozen
owner: Trillionnium Chain maintainers
last_verified: 2026-09-04
applies_to: main@b2d485e5641614ea0ca34ebf80a5f7843ff1e6d9
---

# `trnm-node`

> **Maturity:** `legacy-frozen`  
> **Repository release status:** follow [`RELEASE_READINESS.md`](../../../RELEASE_READINESS.md). A green crate test is not repository or mainnet readiness.

Legacy harness package retained for compatibility, local simulation, and temporarily shared library code.

## Responsibilities

- Provide legacy `trnm-chain-node`, `trnm-chain-validator`, `trnm-chain-cli`, and simulation binaries behind the `legacy-harness` feature.
- Retain historical BFT, recovery, configuration, event, ordering, and local test utilities while canonical code is extracted.
- Supply temporarily reused storage/Merkle/signer-policy library pieces where explicitly imported by the canonical application.

## Non-responsibilities and production boundary

- This package is not the production-candidate state-transition path.
- Legacy simulator, bespoke BFT, throughput, or fault tests cannot prove a feature exists in the CometBFT canonical runtime.
- No new protocol capability may be added solely to a legacy binary or path.

The binding production-candidate architecture is documented in
[`TRNM_CANONICAL_RUNTIME_FREEZE_2026-07-28.md`](../../../docs/architecture/TRNM_CANONICAL_RUNTIME_FREEZE_2026-07-28.md).
Where this README and an older report disagree, the runtime freeze and current
release-readiness document take precedence.

## Source layout

- `src/bin/`: frozen legacy entrypoints.
- `src/bft/` and `src/live/`: bespoke simulation/network paths.
- `src/recovery.rs`, `src/config.rs`, `src/events.rs`, `src/ordering.rs`: legacy/support libraries.
- `src/main.rs`: large legacy simulation executable; changes require heightened review.

## Required invariants

- Legacy entrypoints and manifest remain checksum-frozen by CI.
- Production code may not silently route transactions through the legacy state machine.
- Every remaining canonical import from this crate must be listed and removed through an extraction plan.
- Builds without `legacy-harness` must not expose legacy executables as production defaults.

A change that can affect consensus, signing bytes, object identity, balances,
authorization, replay handling, persistence, or finality must add a regression
test that fails before the change and passes after it. Tests from a legacy or
research path may not be cited as evidence for the canonical path.

## Build and test

Run from `trillionnium/`:

```bash
cargo check -p trnm-node --locked
cargo test -p trnm-node --locked
```

Additional evidence:

- `cargo test -p trnm-node --locked`
- `bash scripts/ci/check_legacy_harness_freeze.sh`
- Legacy tests are regression evidence only; canonical acceptance comes from `trnm-consensus-app`.

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

- Extract shared production libraries into dedicated crates, remove reverse dependencies, then delete obsolete binaries and simulation state-transition code.
- Until extraction completes, changes to shared modules require both legacy and canonical test coverage.

These gaps are intentionally visible. They may be closed only by implementation
and reproducible evidence; wording changes alone cannot close them.

## References

- [Workspace guide](../../README.md)
- [Crate catalog](../README.md)
- [Documentation standard](../../../docs/DOCUMENTATION_STANDARD.md)
- [Architecture index](../../../docs/architecture/README.md)
- [Protocol index](../../../docs/protocol/README.md)
- [Release truth source](../../../RELEASE_READINESS.md)
