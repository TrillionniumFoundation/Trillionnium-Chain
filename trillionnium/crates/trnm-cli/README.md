---
status: client-operator-tool
owner: Trillionnium Chain maintainers
last_verified: 2026-09-04
applies_to: main@b2d485e5641614ea0ca34ebf80a5f7843ff1e6d9
---

# `trnm-cli`

> **Maturity:** `client-operator-tool`  
> **Repository release status:** follow [`RELEASE_READINESS.md`](../../../RELEASE_READINESS.md). A green crate test is not repository or mainnet readiness.

Native transaction, query, wallet, template, and wait tooling.

## Responsibilities

- Construct and submit supported transactions, query read surfaces, manage local wallet material, render responses, and wait for outcomes.
- Provide strict parsing and stable machine-readable output modes for automation.
- Bridge local operator workflows to the currently supported RPC/canonical interfaces.

## Non-responsibilities and production boundary

- Is not an HSM/KMS and must not be described as secure production custody.
- Local files or command exit success do not establish finality.
- Legacy query/transaction modes are not automatically canonical or publicly stable.

The binding production-candidate architecture is documented in
[`TRNM_CANONICAL_RUNTIME_FREEZE_2026-07-28.md`](../../../docs/architecture/TRNM_CANONICAL_RUNTIME_FREEZE_2026-07-28.md).
Where this README and an older report disagree, the runtime freeze and current
release-readiness document take precedence.

## Source layout

- `src/cmd.rs`: command definitions.
- `src/tx/` and `src/tx_handlers.rs`: transaction parsing, output, waiting, and local state.
- `src/query/` and `src/query_handlers.rs`: query parsing and rendering.
- `src/wallet.rs`: local wallet behavior.
- `src/template.rs`: transaction/template support.

## Required invariants

- Ambiguous flags, duplicate fields, malformed hashes/IDs, and unsafe output paths fail closed.
- JSON output is versioned and stable before automation relies on it.
- Secrets are never printed to normal logs or embedded in generated evidence.
- Wait logic distinguishes submitted, accepted, finalized, rejected, and timed-out states.

A change that can affect consensus, signing bytes, object identity, balances,
authorization, replay handling, persistence, or finality must add a regression
test that fails before the change and passes after it. Tests from a legacy or
research path may not be cited as evidence for the canonical path.

## Build and test

Run from `trillionnium/`:

```bash
cargo check -p trnm-cli --locked
cargo test -p trnm-cli --locked
```

Additional evidence:

- `cargo test -p trnm-cli --locked`
- `cargo test -p trnm-cli --test mvp_smoke --locked`

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

- Add remote signer/HSM interfaces, explicit exit-code contract, shell completion, and generated reference docs.
- Align all transaction builders with `trnm-protocol` canonical envelopes and remove legacy ambiguity.

These gaps are intentionally visible. They may be closed only by implementation
and reproducible evidence; wording changes alone cannot close them.

## References

- [Workspace guide](../../README.md)
- [Crate catalog](../README.md)
- [Documentation standard](../../../docs/DOCUMENTATION_STANDARD.md)
- [Architecture index](../../../docs/architecture/README.md)
- [Protocol index](../../../docs/protocol/README.md)
- [Release truth source](../../../RELEASE_READINESS.md)
