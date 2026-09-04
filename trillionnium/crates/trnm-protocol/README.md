---
status: canonical-consensus-critical
owner: Trillionnium Chain maintainers
last_verified: 2026-09-04
applies_to: main@b2d485e5641614ea0ca34ebf80a5f7843ff1e6d9
---

# `trnm-protocol`

> **Maturity:** `canonical-consensus-critical`  
> **Repository release status:** follow [`RELEASE_READINESS.md`](../../../RELEASE_READINESS.md). A green crate test is not repository or mainnet readiness.

Versioned typed wire and canonical object schema for the production-candidate runtime.

## Responsibilities

- Define canonical transaction commands, accounts, tasks, fee policy, monetary state, object keys, and deterministic identifiers.
- Validate bounded field shapes before state execution.
- Provide the single protocol vocabulary shared by `trnm-runtime` and `trnm-consensus-app`.

## Non-responsibilities and production boundary

- Does not verify network transport, store state, charge fees, or mutate balances.
- JSON/Serde convenience representations are not automatically a stable cross-language wire contract unless explicitly frozen.
- Legacy `trnm-types` values are not interchangeable with canonical protocol objects by name alone.

The binding production-candidate architecture is documented in
[`TRNM_CANONICAL_RUNTIME_FREEZE_2026-07-28.md`](../../../docs/architecture/TRNM_CANONICAL_RUNTIME_FREEZE_2026-07-28.md).
Where this README and an older report disagree, the runtime freeze and current
release-readiness document take precedence.

## Source layout

- `src/lib.rs`: v1 command and object types, validation, key derivation, commitment helpers, and unit tests.

## Required invariants

- Every consensus-visible type and enum is explicitly versioned or frozen before external use.
- Object-key derivation is domain separated and stable.
- Unknown command versions and unsupported variants fail closed.
- Bounds for strings, collections, integers, hashes, and payload size are validated before execution.
- Signing bytes, transaction identity, and result commitments must be unambiguous and reproducible.

A change that can affect consensus, signing bytes, object identity, balances,
authorization, replay handling, persistence, or finality must add a regression
test that fails before the change and passes after it. Tests from a legacy or
research path may not be cited as evidence for the canonical path.

## Build and test

Run from `trillionnium/`:

```bash
cargo check -p trnm-protocol --locked
cargo test -p trnm-protocol --locked
```

Additional evidence:

- `cargo test -p trnm-protocol --locked`
- Protocol changes must also pass canonical-input fuzz smoke and the CometBFT vertical-slice gate.

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

- Publish machine-readable golden vectors for every canonical command and negative decoding case.
- Add a formal compatibility matrix covering wire, object, application, store, and snapshot versions.

These gaps are intentionally visible. They may be closed only by implementation
and reproducible evidence; wording changes alone cannot close them.

## References

- [Workspace guide](../../README.md)
- [Crate catalog](../README.md)
- [Documentation standard](../../../docs/DOCUMENTATION_STANDARD.md)
- [Architecture index](../../../docs/architecture/README.md)
- [Protocol index](../../../docs/protocol/README.md)
- [Release truth source](../../../RELEASE_READINESS.md)
