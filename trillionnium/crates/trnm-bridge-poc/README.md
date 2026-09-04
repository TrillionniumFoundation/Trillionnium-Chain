---
status: deferred-research
owner: Trillionnium Chain maintainers
last_verified: 2026-09-04
applies_to: main@b2d485e5641614ea0ca34ebf80a5f7843ff1e6d9
---

# `trnm-bridge-poc`

> **Maturity:** `deferred-research`  
> **Repository release status:** follow [`RELEASE_READINESS.md`](../../../RELEASE_READINESS.md). A green crate test is not repository or mainnet readiness.

Cross-chain relay heartbeat and settlement-loop proof of concept.

## Responsibilities

- Model relay liveness, proof submission, nonce/replay handling, settlement finalization, compensation, and recovery behavior.
- Exercise fail-closed cross-domain bindings and adversarial integration cases.
- Provide research evidence for a future bridge boundary.

## Non-responsibilities and production boundary

- Bridge is outside the frozen Day-1 canonical scope.
- This crate does not establish production light-client security, deployed relayers, or audited asset custody.
- PoC settlement must not be exposed as canonical value movement.

The binding production-candidate architecture is documented in
[`TRNM_CANONICAL_RUNTIME_FREEZE_2026-07-28.md`](../../../docs/architecture/TRNM_CANONICAL_RUNTIME_FREEZE_2026-07-28.md).
Where this README and an older report disagree, the runtime freeze and current
release-readiness document take precedence.

## Source layout

- `src/relay_heartbeat.rs`: relay health/liveness model.
- `src/x2_settlement_loop.rs`: settlement state machine and recovery/compensation paths.
- `tests/`: replay, transition, validation, heartbeat, compensation, and workflow matrices.

## Required invariants

- Every message binds source/target chain and bridge domains, action, nonce, payload/receipt hash, and finality anchor.
- Nonces are one-time within a domain; altered replay fails closed.
- Finalization is terminal and compensation/reversion transitions are explicit.
- No external proof selects its own trusted validator set or checkpoint.

A change that can affect consensus, signing bytes, object identity, balances,
authorization, replay handling, persistence, or finality must add a regression
test that fails before the change and passes after it. Tests from a legacy or
research path may not be cited as evidence for the canonical path.

## Build and test

Run from `trillionnium/`:

```bash
cargo check -p trnm-bridge-poc --locked
cargo test -p trnm-bridge-poc --locked
```

Additional evidence:

- `cargo test -p trnm-bridge-poc --locked`
- [Bridge settlement receipt-binding smoke contract](../../../docs/runbooks/bridge_settle_receipt_binding_smoke.md)

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

- Choose and formally specify the light-client/finality model, relayer trust, reorg policy, rate limits, pause, and recovery.
- Require independent audit, multi-relayer soak, economic analysis, and canonical runtime integration before activation.

These gaps are intentionally visible. They may be closed only by implementation
and reproducible evidence; wording changes alone cannot close them.

## References

- [Workspace guide](../../README.md)
- [Crate catalog](../README.md)
- [Documentation standard](../../../docs/DOCUMENTATION_STANDARD.md)
- [Architecture index](../../../docs/architecture/README.md)
- [Protocol index](../../../docs/protocol/README.md)
- [Release truth source](../../../RELEASE_READINESS.md)
