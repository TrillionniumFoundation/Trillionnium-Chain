---
status: supported-consumer-boundary
owner: Trillionnium Chain maintainers
last_verified: 2026-09-04
applies_to: main@b2d485e5641614ea0ca34ebf80a5f7843ff1e6d9
---

# `trnm-finality-types`

> **Maturity:** `supported-consumer-boundary`  
> **Repository release status:** follow [`RELEASE_READINESS.md`](../../../RELEASE_READINESS.md). A green crate test is not repository or mainnet readiness.

Node-independent finality wire types, signing helpers, and certificate structures.

## Responsibilities

- Define the minimal finality receipt/certificate data needed by external consumers.
- Own canonical signing bytes and cryptographic verification primitives shared with `trnm-finality-verifier`.
- Keep receipt consumers independent from the complete node package.

## Non-responsibilities and production boundary

- Does not decide validator lifecycle or fetch validator sets.
- Does not prove state membership unless the required AppHash/proof material is supplied.
- Does not make a receipt trustworthy without a trusted chain identity and validator-set anchor.

The binding production-candidate architecture is documented in
[`TRNM_CANONICAL_RUNTIME_FREEZE_2026-07-28.md`](../../../docs/architecture/TRNM_CANONICAL_RUNTIME_FREEZE_2026-07-28.md).
Where this README and an older report disagree, the runtime freeze and current
release-readiness document take precedence.

## Source layout

- `src/protocol.rs`: finality protocol structures and canonical message rules.
- `src/crypto.rs`: signing and verification helpers.
- `src/lib.rs`: narrow re-export surface.

## Required invariants

- Chain ID, height, block/AppHash, validator identity, voting power, and signature domain are bound without ambiguity.
- Duplicate validators and malformed keys/signatures are rejected.
- Threshold arithmetic is overflow safe and defined in voting-power terms.
- Unknown versions and trailing/unbound fields fail closed.

A change that can affect consensus, signing bytes, object identity, balances,
authorization, replay handling, persistence, or finality must add a regression
test that fails before the change and passes after it. Tests from a legacy or
research path may not be cited as evidence for the canonical path.

## Build and test

Run from `trillionnium/`:

```bash
cargo check -p trnm-finality-types --locked
cargo test -p trnm-finality-types --locked
```

Additional evidence:

- `cargo test -p trnm-finality-types --locked`
- Every released protocol version requires positive, tampered, duplicate, wrong-chain, stale-set, and insufficient-threshold vectors.

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

- Add checked-in cross-language golden fixtures and an explicit deprecation policy before public SDK stabilization.

These gaps are intentionally visible. They may be closed only by implementation
and reproducible evidence; wording changes alone cannot close them.

## References

- [Workspace guide](../../README.md)
- [Crate catalog](../README.md)
- [Documentation standard](../../../docs/DOCUMENTATION_STANDARD.md)
- [Architecture index](../../../docs/architecture/README.md)
- [Protocol index](../../../docs/protocol/README.md)
- [Release truth source](../../../RELEASE_READINESS.md)
