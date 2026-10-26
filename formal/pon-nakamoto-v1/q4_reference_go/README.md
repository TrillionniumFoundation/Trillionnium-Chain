# Q4 dual-signed renewal independent wire oracle (research only)

**Status:** fully separate research oracle. It does **not** validate an admitted parent, permissions, withdrawal, release, state root, nonce/balance, actual content availability, W1 work, network transmission, finalized client confirmation, or local FinalUse. `Validate` observes caller-supplied *claims* about the old parent/lease and actual containing height; neither a passing result nor its JSON is an authorization or a replacement for the original PoN M06/M07/kernel.operations owners. Never feed its result back as a privileged token or rewrite old Q4 bytes/profiles.

### What it checks

- Exact 1,187-byte PNX1/tag22 envelope framing; network, requester sender, fee/nonce/expiry and **real requester Ed25519 signature** over the original `H("tx-sign", unsigned)` digest.
- Canonical QDL2 version-2 344-byte old and successor leases, full immutability except window/revision, exact demand identity, bounded maximum 1,000-block lease validity, checked `expires+100` retention and Q4 overlap at the **caller-supplied actual height**.
- Exact QWA2 684-byte previous/successor source statements, canonical 584-byte QWT1 manifests, purpose/shape/field/profile/hash identities, independently recomputed source-record/frontier/layer/output-meter hashes, and **real source Ed25519 signature** over `H("qualified-task-source-sign-v2", unsigned QWA2)`.
- Old source sequence + 1 and immutable model, input, work profile, matrix task, recipe, source, financial and output meter identities. The old lease and statement must come from an independently checked active parent, not an untrusted network response.
- Exact native SHA-256 domain framing for transaction/lease/source-statement IDs; sampled malformed packet tests and fully re-signed invalid successor controls.

Uses **only Go's standard library** and intentionally does not depend on the project's Rust verifier. No real network, model, storage or source key is used.

### Local commands

```sh
cd formal/pon-nakamoto-v1/q4_reference_go
go test ./... -count=1
go vet ./...
go run ./cmd/q4reference < q4-reference-development-vector.json
```

Expected fixed public-development fixture IDs:

| Field | SHA-256 digest |
| --- | --- |
| PNX1 transaction ID | `133e6e6588018bdb8cc5888cd35e9daa5202fdcaa1e458951b3ecb3dd2ee3233` |
| successor QDL2 lease ID | `bbb982203bb12668be298fcae53ec89f1600098da691133d7a068d931af2f880` |
| successor QWA2 source statement ID | `6566c9ed51e887d5f0e3ac0cb32bb95141f71ae873ffc1c2456b2b50607991b0` |

The input fixture uses deterministically generated **public development test keys only** (not production secrets). CLI accepts one bounded JSON object with exact lowercase hex fields `network`, `parameters`, `old_lease`, `old_source_statement`, `signed_transaction`, `containing_height`; it rejects other fields, noncanonical values and oversize input. It prints a research-only receipt, not proof of inclusion.

### Strict nonclaims / next integration

Native Rust `ed25519-dalek` strict rejection of torsion/noncanonical points is not proven equivalent to `crypto/ed25519.Verify` for every hostile encoding. Independently compare weak/small-order/invalid R,S vectors against the original verifier before granting any security parity claim. Current positive and ordinary tamper cases do not close this gap.

Before P0-B can close, **native M05/M06/M07 + Hepta kernel.operations** must use original signed source/requester owners and actually authenticated parent state; persist dispatch intent before I/O, fence Unknown/lost-ACK, reconcile with a separately verifying Node client, and demonstrate simultaneous full-32-slot retention/reclaim, reorganization and 3 independently controlled source operators. A permissive standalone oracle cannot substitute for those runtime/wire/hardware facts. P0-C W1 cost hardness and P1-C DAA activation remain separately open.

This is subordinate to `docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md`; it does not modify any installed consensus rule, signed domain or storage namespace.
