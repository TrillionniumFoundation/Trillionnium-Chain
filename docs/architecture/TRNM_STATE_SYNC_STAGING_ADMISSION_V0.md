# State-sync staging admission v0

Primary module: M13. Consumer: M07 durable snapshot adapter and M17 conformance.
Status: candidate contract amendment; source-local tests are not independent
acceptance, authenticated networking, physical durability or activation evidence.
The single development plan remains
[Plan v2](../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md).

## Manifest admission

Every admitted chunk has a nonempty byte payload. A snapshot declaring N chunks
therefore needs at least N total bytes, as well as the existing maximum capacity
and digest constraints. Reject an impossible declaration with `InvalidManifest`
before opening a session. The canonical manifest encoding and digest do not change.
An oversized incoming chunk must still be rejected without changing accounting;
its test uses a feasible manifest so it reaches that separate admission boundary.

## Staging identity and effects

After complete snapshot verification and `begin_staging`, the returned identity
must have a nonzero generation and a nonzero staging digest. The existing durable
file adapter already creates a strictly positive successor generation and binds
its staging digest to the manifest and generation. A different target cannot
turn a zero identity into an accepted install merely by repeating it in a receipt.

Reject invalid staging identities with `InvalidStagingIdentity` before any
`write_chunk` or `commit_staging_cas` call. Do not invoke `abort_staging` with an
untrusted identity: it cannot identify a safe deletion scope. The adapter/operator
must reconcile any allocation made by `begin_staging`; this check cannot undo an
untrusted adapter's side effects or certify that its backing storage is safe.

A valid staging identity does not itself grant finality or validate a snapshot.
Existing trust-path, chunk-root, recomputed-state-root and expected-current-root
checks remain mandatory. After a commit attempt, existing uncertain-commit and
receipt-mismatch handling still prohibits destructive abort.

## Retained replay

The public integration suite exercises nonempty-chunk feasibility, both zero
identity fields, unchanged serving state, exact callback order, write failure,
commit uncertainty, and accepted positive controls. It uses an explicit test
proof verifier and does not claim real consensus or device evidence.

```bash
cargo test --manifest-path trillionnium/Cargo.toml -p trnm-state-sync-v0 --all-targets --locked
cargo test --manifest-path trillionnium/Cargo.toml -p trnm-durable-file-adapters-v0 --all-targets --locked
cargo test --manifest-path trillionnium/Cargo.toml -p trnm-production-adapter-conformance-v0 --all-targets --locked
```

No schema/hash, lockfile, runtime authority or production flag changes. Independent
M13 producer and durable-adapter consumer review remains required before acceptance.

## Immutable verification results

`VerifiedTrustPathV0` can be created only inside the module's full trust-path
verification routine. Its anchor, terminal checkpoint, link count and path digest
are private and exposed through read-only, by-value accessors. A caller cannot
skip checkpoint verification with a struct literal, nor mutate a genuine result
to point to an unverified checkpoint before manifest admission.

`VerifiedSnapshotV0` likewise has private fields and read-only accessors. Only
complete chunk commitment and application-root verification produce it. Copying
or cloning a result preserves its verified facts; modifying an accessor's returned
copy cannot change the result. Neither type provides a public unchecked/default
constructor or deserializer.

This is a source-level API tightening. Consumers must replace field reads with
accessor calls; consumers that constructed or mutated these results directly
must instead call the verification routines. The tracked staging consumer has
been updated. Frozen wire/hash encodings, protocol digests, lockfiles and
production flags are unchanged. Verification adapters and the configured trust
anchor remain trusted inputs: a caller-supplied accept-all verifier is still a
fixture, not cryptographic evidence. Immutability does not establish freshness,
revocation or independent release acceptance.

The public verification-seal tests use counting/rejecting adapters and valid
controls to check successful issuance, pre-verifier structural rejection,
adapter errors, accessor-copy isolation and state-root mismatch rejection.
Four compile-fail doctests must reject external construction and mutation of
both result types. They are explicitly included in the existing required Rust
baseline's documentation-test command, not assumed to run under `--all-targets`:

```bash
cargo test --manifest-path trillionnium/Cargo.toml -p trnm-state-sync-v0 --doc --locked
```
