# Cell activation requires a current publication authorization

Status: component enforcement and regression coverage; **HOLD_NO_GO** for a
complete updater, installation service, or autonomous activation. This extends
the existing M15 release authority kernel. It does not grant FinalUse, select a
PoN chain, provision an offline root, or supply independently fresh storage.

## Reproduced gap

In Chain `59f75acd1d4261972b8aaa45e0c36259fcafd45c`,
`PqReleaseAuthorityV1` remembered only the current content digest for each role.
A `CellActivation` event required the same digest as the latest `CellManifest`,
but did not check that manifest's signed expiry or root generation. Two valid
activation signatures could therefore authorize:

- content whose publication authorization had already expired, including at the
  exact expiry boundary; or
- content published under a previous root after the publisher keys had been
  retired by a valid old-and-new-quorum root rotation.

The activation metadata itself still had a fresh expiry, current root
generation, correct checkpoint and increasing activation version. Those checks
did not establish current approval by the separate publication role.

Two new tests reproduced this on the unchanged production source: both expected
`UnpublishedActivation` but received `Ok(VerifiedPqReleaseV1)`. The filtered
pre-fix run passed the existing activation test and failed both new tests.

## Enforcement

The private current-release record now retains the signed content digest, root
generation and expiry of each accepted metadata event. Before accepting a new
activation, the authority requires the latest manifest to satisfy all three
conditions:

| Manifest fact | Required at activation acceptance |
| --- | --- |
| Content digest | Equal to the activation's signed content digest |
| Root generation | Equal to the authority's current root generation |
| Expiry | Strictly later than the trusted owner time supplied for this acceptance |

An activation-role quorum cannot renew the publication-role authorization. The
current publisher may approve the same content again using a higher manifest
version, current checkpoint and current root generation. A new activation can
then pass its own distinct quorum and monotone version checks. Root rotation
continues to retain all role versions, content history and retired keys.

Rejection occurs before any checkpoint, role version, time floor or accepted
event count changes. The content getter remains a historical sequencing
observation; reading it is not a current activation authorization.

## Recovery and compatibility

`recover_pinned` reconstructs these publication facts from the existing signed
events, and runs the same acceptance checks while replaying. Recovering a valid
journal does not renew a publication or promote it into a later root generation.
A subsequently submitted activation must still satisfy the current manifest
checks. A journal containing an activation that relied on the former gap is
rejected; recovery must not grandfather that authorization.

No signed message, event encoding, checkpoint domain or public wire type changes
in this fix. The new fields are private derived state already bound into each
signed release event. A storage owner must retain those events and its trusted
fresh checkpoint; a digest-only snapshot cannot replace them.

## Verification

The regressions use real ML-DSA-65 signatures and separate publication and
activation key quorums. They cover the expiry boundary, recovery of the accepted
manifest, root rotation with publisher retirement, refusal of the old publisher's
signatures, and fresh same-content publication followed by a valid activation.
The existing content-rollback, monotone-version, root-rotation, bundle-binding
and retained-history tests remain in the same crate. The local post-fix run
passed all 18 crate tests, with zero failed or ignored tests. The crate has no
doc tests. Scoped strict Clippy for all targets, package formatting, and both
local Markdown links in this document also passed. These are component checks;
the integrated candidate still needs its complete source and CI gates.

From the repository root, using the pinned Rust toolchain and locked dependency
graph:

```bash
bash scripts/project-preflight.sh
cargo test --locked --offline --manifest-path trillionnium/Cargo.toml \
  -p trnm-release-bundle
cargo clippy --locked --offline --manifest-path trillionnium/Cargo.toml \
  -p trnm-release-bundle --all-targets -- -D warnings
```

This enforces publication freshness when the kernel accepts a new activation
event. It does not automatically deactivate already running content, provide a
live authority owner for the installer, or prevent restoration of every owner,
witness and backup to the same old state. The owner must serialize current
revocation checks and accepted activation state with independently fresh durable
state at its effect boundary. See the existing
[current-authority and TAP 21 boundary](PQ_RELEASE_CURRENT_AUTHORITY_AND_TAP21_V1.md)
and [recovery/release/transport boundary](PQ_RECOVERY_RELEASE_TRANSPORT_BOUNDARIES_V1.md).
