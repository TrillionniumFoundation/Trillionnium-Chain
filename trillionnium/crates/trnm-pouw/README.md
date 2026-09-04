---
status: legacy-research
owner: Trillionnium Chain maintainers
last_verified: 2026-09-04
applies_to: main@b2d485e5641614ea0ca34ebf80a5f7843ff1e6d9
---

# `trnm-pouw`

> **Maturity:** `legacy-research`  
> **Repository release status:** follow [`RELEASE_READINESS.md`](../../../RELEASE_READINESS.md). A green crate test is not repository or mainnet readiness.

Legacy-named PoCO/PoUW task, proof, TEE, ZK, metering, and settlement compatibility implementation.

## Responsibilities

- Retain task/proof validation and migration-era compatibility behavior used by legacy gates and research paths.
- Validate TEE/ZK proof metadata, metering, timeout, challenge, receipt, and settlement constraints in its supported paths.
- Provide adversarial fixtures for proof-backend normalization and fail-closed behavior.

## Non-responsibilities and production boundary

- The crate name does not grant payout authority and must not imply token issuance from work-unit evidence.
- It is not the canonical Day-1 state-transition engine; value-changing support must exist in `trnm-runtime` and the CometBFT path.
- Feature-gated real-backend bridges and fixtures are not proof of deployed production verification.

The binding production-candidate architecture is documented in
[`TRNM_CANONICAL_RUNTIME_FREEZE_2026-07-28.md`](../../../docs/architecture/TRNM_CANONICAL_RUNTIME_FREEZE_2026-07-28.md).
Where this README and an older report disagree, the runtime freeze and current
release-readiness document take precedence.

## Source layout

- `src/`: task lifecycle, proof binding, metering, challenge/resolve, backend adapters, and tests.
- `fixtures/tee/`: bounded attestation examples.
- `fixtures/zk/`: positive and negative backend/payload normalization corpus.

## Required invariants

- Proofs bind task, worker, model/input/result, backend identity/version, and public inputs without ambiguous normalization.
- Unsupported backend/version combinations and malformed metadata fail closed.
- Timeout, challenge, resolution, and receipt replay transitions are monotonic and idempotent where specified.
- Metering evidence is attribution/accounting input and cannot mint value independently.

A change that can affect consensus, signing bytes, object identity, balances,
authorization, replay handling, persistence, or finality must add a regression
test that fails before the change and passes after it. Tests from a legacy or
research path may not be cited as evidence for the canonical path.

## Build and test

Run from `trillionnium/`:

```bash
cargo check -p trnm-pouw --locked
cargo test -p trnm-pouw --locked
```

Additional evidence:

- `cargo test -p trnm-pouw --lib --locked`
- `bash scripts/v2/v1_proof_backend_ci_gate.sh`
- Canonical payout/settlement acceptance additionally requires `trnm-runtime` and CometBFT evidence.

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

- Separate canonical proof-verification interfaces from legacy task-state code.
- Complete production backend audits, trusted-setup/key governance, long fuzzing, and cross-implementation vectors before activation.

These gaps are intentionally visible. They may be closed only by implementation
and reproducible evidence; wording changes alone cannot close them.

## References

- [Workspace guide](../../README.md)
- [Crate catalog](../README.md)
- [Documentation standard](../../../docs/DOCUMENTATION_STANDARD.md)
- [Architecture index](../../../docs/architecture/README.md)
- [Protocol index](../../../docs/protocol/README.md)
- [Release truth source](../../../RELEASE_READINESS.md)
