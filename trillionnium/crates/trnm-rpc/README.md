---
status: operator-read-surface
owner: Trillionnium Chain maintainers
last_verified: 2026-09-04
applies_to: main@b2d485e5641614ea0ca34ebf80a5f7843ff1e6d9
---

# `trnm-rpc`

> **Maturity:** `operator-read-surface`  
> **Repository release status:** follow [`RELEASE_READINESS.md`](../../../RELEASE_READINESS.md). A green crate test is not repository or mainnet readiness.

Legacy/operator HTTP, durable-read, event, capability, oracle, relay, and audit query service.

## Responsibilities

- Serve bounded query and operational endpoints over state snapshots, event sources, and durable SQLite read models.
- Normalize task, account, capability, audit, oracle, relay, health, and market-facing responses.
- Provide fail-closed request parsing, path/query guards, and CLI/service wiring.

## Non-responsibilities and production boundary

- Is not the CometBFT consensus engine and cannot finalize state.
- Existing endpoints are not all public stable APIs; only explicitly frozen contracts may be promised externally.
- Adapter fallback is not a substitute for a durable canonical indexer or infinite history.

The binding production-candidate architecture is documented in
[`TRNM_CANONICAL_RUNTIME_FREEZE_2026-07-28.md`](../../../docs/architecture/TRNM_CANONICAL_RUNTIME_FREEZE_2026-07-28.md).
Where this README and an older report disagree, the runtime freeze and current
release-readiness document take precedence.

## Source layout

- `src/http.rs`, `src/ingress*.rs`, `src/dispatch.rs`: HTTP and request routing.
- `src/durable_read.rs`, `src/persistence.rs`, `src/node_events/`: retained read model and event sources.
- `src/capability.rs`, `src/account_*`, `src/read_query.rs`: query/authorization helpers.
- `src/relay*.rs`, `src/oracle_validation.rs`, `src/market_*`: deferred/adjacent surfaces.
- `src/health.rs`: health and readiness reporting.

## Required invariants

- Unknown paths, duplicate/unknown query keys, smuggling, encoded slashes, oversized inputs, and malformed identifiers fail closed.
- Responses are versioned and errors have stable machine-readable classes before public support.
- Read fallbacks never invent missing pre-history or convert incomplete data into a finalized claim.
- SQLite read-model updates are atomic, replayable, and bound to canonical source height/hash.

A change that can affect consensus, signing bytes, object identity, balances,
authorization, replay handling, persistence, or finality must add a regression
test that fails before the change and passes after it. Tests from a legacy or
research path may not be cited as evidence for the canonical path.

## Build and test

Run from `trillionnium/`:

```bash
cargo check -p trnm-rpc --locked
cargo test -p trnm-rpc --locked
```

Additional evidence:

- `cargo test -p trnm-rpc --locked`
- Public-contract changes require parser negatives, schema tests, replay/bootstrap tests, and frontend contract tests.

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

- Complete the durable canonical indexer, historical replay/bootstrap, lag calculation, retention, and explorer API.
- Generate OpenAPI/JSON Schema and SDKs from a single versioned source rather than hand-maintained adapters.

These gaps are intentionally visible. They may be closed only by implementation
and reproducible evidence; wording changes alone cannot close them.

## References

- [Workspace guide](../../README.md)
- [Crate catalog](../README.md)
- [Documentation standard](../../../docs/DOCUMENTATION_STANDARD.md)
- [Architecture index](../../../docs/architecture/README.md)
- [Protocol index](../../../docs/protocol/README.md)
- [Release truth source](../../../RELEASE_READINESS.md)
