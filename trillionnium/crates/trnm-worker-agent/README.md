---
status: client-integration
owner: Trillionnium Chain maintainers
last_verified: 2026-09-04
applies_to: main@b2d485e5641614ea0ca34ebf80a5f7843ff1e6d9
---

# `trnm-worker-agent`

> **Maturity:** `client-integration`  
> **Repository release status:** follow [`RELEASE_READINESS.md`](../../../RELEASE_READINESS.md). A green crate test is not repository or mainnet readiness.

Worker-side task polling, adapter normalization, execution, retry, receipt, and audit tooling.

## Responsibilities

- Poll/accept assigned work, invoke configured execution adapters, normalize A2A/MCP results, and submit commit/reveal or receipt material.
- Apply bounded retry, timeout, hash/provenance validation, and audit export behavior.
- Expose worker/operator CLI flows and evidence generation.

## Non-responsibilities and production boundary

- Does not authorize itself as a validator, operator, or payout authority.
- Must not hold production keys insecurely or treat local command success as finality.
- Adapter aliases and external tool output are untrusted input.

The binding production-candidate architecture is documented in
[`TRNM_CANONICAL_RUNTIME_FREEZE_2026-07-28.md`](../../../docs/architecture/TRNM_CANONICAL_RUNTIME_FREEZE_2026-07-28.md).
Where this README and an older report disagree, the runtime freeze and current
release-readiness document take precedence.

## Source layout

- `src/adapter*`: adapter contracts, parsing, normalization, provenance, errors, and retry policy.
- `src/assigned*.rs`: assigned-task processing.
- `src/audit*`: audit log/export/query formatting.
- `src/command_runtime*` and `src/cli.rs`: command execution and operator interface.
- `src/tests*`: adversarial parsing, retry, receipt, timeout, and integration regressions.

## Required invariants

- Every submission binds task, worker identity, input/model/result hashes, nonce, and transaction hash.
- Untrusted adapter output is size-bounded, normalized once, and rejected on ambiguity.
- Retries are capped, idempotent, and do not create duplicate on-chain actions.
- Local success remains pending until canonical finality is verified.

A change that can affect consensus, signing bytes, object identity, balances,
authorization, replay handling, persistence, or finality must add a regression
test that fails before the change and passes after it. Tests from a legacy or
research path may not be cited as evidence for the canonical path.

## Build and test

Run from `trillionnium/`:

```bash
cargo check -p trnm-worker-agent --locked
cargo test -p trnm-worker-agent --locked
```

Additional evidence:

- `cargo test -p trnm-worker-agent --locked`
- `bash scripts/v2/run_worker_receipt_gates.sh`
- `TRNM_TX_CLI=... bash scripts/v2/run_worker_receipt_gates_real_cli.sh`

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

- Integrate secure key custody/remote signing, canonical finality verification, and production adapter sandboxing.
- Publish a single end-to-end worker lifecycle and failure/recovery contract.

These gaps are intentionally visible. They may be closed only by implementation
and reproducible evidence; wording changes alone cannot close them.

## References

- [Workspace guide](../../README.md)
- [Crate catalog](../README.md)
- [Documentation standard](../../../docs/DOCUMENTATION_STANDARD.md)
- [Architecture index](../../../docs/architecture/README.md)
- [Protocol index](../../../docs/protocol/README.md)
- [Release truth source](../../../RELEASE_READINESS.md)
