# Release PQ V1 callback-phase quorum and staged shadow

[`pq_bundle_callback_quorum.hepta`](pq_bundle_callback_quorum.hepta) is the
native **math phase** of the V0 callback. It shares the complete genuine
ML-DSA-65 signer preflight and equations with
[the standalone scoped quorum](PQ_QUORUM.md), retaining immutable pinned DER
SPKIs, the original role threshold, input-order duplicate and membership
checks, exact signature widths, signature slots, and scratch clearing.
It has the same borrowed input layout, capacity and return type.

There are two distinct entrypoints with compile-time-selected modes. The
published strict scoped quorum still rejects mismatched root network and
generation before math. The callback entrypoint insists on a canonical signed
transcript and the caller-selected exact role, but deliberately does not check
transcript network and generation against the provisioned root. In the
[original owner](../../../trillionnium/crates/trnm-release-bundle/src/pq_release.rs),
those checks run **after** the V0 callback, so a mathematically invalid
signature must fail at the callback even when the metadata also names the
wrong network or generation. Omitting the later state guard would not be
equivalent to the original owner.

The roster passed to this entry is independently trusted and immutable, not
keys proposed by the release. A callback math result is not an authenticated
snapshot or the original Rust callback's private same-call token. It cannot
authorize, publish, advance state, change custody or replace the production
path.

## Staged qualification

[`qualify_release_pq_callback.py`](../../tests/qualify_release_pq_callback.py)
drives the actual native unsigned candidate, stable root-role identity,
signature-set locator, canonical signing message, callback-phase math and
[post-callback state/checkpoint proposal](PQ_BUNDLE_CHECKPOINT.md), in that order. The Python qualification driver
performs the original outer role/declared-content comparisons and compares
actual native digest outputs against the immutable declarations. Each phase is
run through its own pinned emitted machine image. This is explicitly not a
single native owner, reusable token, or deployable adapter. No precomputed
validity flags enter any native phase; one supplied metadata descriptor and
one immutable signature roster drive the sequence.

The locked [Rust fixture](../../tests/rust_release_pq_callback_reference.rs)
uses the actual unmodified `PqReleaseAuthorityV1::accept_bundle` and returns
only public snapshots, metadata, keys, and signatures from ephemeral synthetic
roots. It checks complete, correctly signed V0 bundles and compound errors,
including bad signature before wrong root, genuine valid signatures with wrong
root or stale checkpoint, wrong locator before state, insufficient binding
before unsigned checks, duplicate roster, and mathematically valid cross-role
signatures outside the selected pin set. The shadow and original compare both
the public outcome and the shadow's first failed stage. On success both native emitters must derive
the same checkpoint returned by the actual locked Rust authority; on refusal
neither side produces a checkpoint or advances its state. The proposal itself
is not a verified quorum token. No production keys are
read, generated keys never leave the offline Rust process, and core dumps are
disabled.

The synthetic root invariant includes all required roles; missing-role and
live persisted/rotation behavior are not covered here. The post-state layer
still requires an independently obtained fresh checkpoint in non-synthetic use.
The original same-call token, trusted live snapshot source and durable
transition remain unported/unclaimed. The staged driver also replays every
public fixture through [one linked shadow qualification call](../../platform/release_pq_shadow/README.md).
That shadow keeps each successful phase internal to the call; it does not
replace production Rust or export an authorization token.

```sh
python3 -I -S -B hia/tests/qualify_release_pq_callback.py \
  --output /tmp/new-release-pq-callback
```


## Hosted evidence

The [dedicated read-only workflow job](../../../.github/workflows/hia-native-migration.yml)
runs all three genuine Release PQ qualifiers against the exact PR or push source.
It leaves the General/component matrix and existing deadlines unchanged. The
[hosted evidence driver](../../tools/qualify_release_pq_ci.py) retains bounded
source receipts on both sides, each actual process's output and terminal result,
locked Rust compiler events and named native/Rust cases. Its strict readback
rejects missing cases, stale head/tree/attempt, copied generic PASS markers,
noncanonical or linked files, and fallback images. The upload excludes
compiled binaries, target directories, signing input, and process environments.
A hosted success is still only scoped shadow qualification, not authorization.
