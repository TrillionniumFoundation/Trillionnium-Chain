# Paper Raid Chain release-candidate SBOM and provenance gate

This gate produces deterministic CycloneDX 1.5 evidence for the two Chain
binaries named by Integration's `canonical-chain.live_binaries` lock:

- `trnm-consensus-app` / `trnm-cometbft-app`
- `trnm-finality-verifier` / `trnm-research-receipt-v2`

Both are isolated, byte-identical `release` builds. `trnm-chain-cli` remains a
separately pinned internal Review harness and is deliberately outside this
candidate artifact set. The receipt executable keeps its V2 CLI name for
compatibility while its candidate artifact authority is `receipt_v4`.

The Chain component also binds two distinct source drivers. The historical
`live_driver_sha256` continues to identify the legacy vertical-E2E spike, while
`strict_review_driver_sha256` identifies
`run_paper_raid_v4_review_chain.sh`, the capability-separated strict Review
ceremony. They are not interchangeable, and both digests are carried through
the deterministic SBOM/provenance evidence.

The checked component lock's unique `canonical-chain` object must bind the exact
clean Chain revision, Git source tree, `Cargo.lock`, `rust-toolchain.toml`, and
the exact ordered binary set and executable digests. It must also carry the
exact Paper Raid V4 Hepta signing authority. That object is canonicalized and
hashed into the evidence. Unrelated Integration readiness and Hepta/Nakama/BFF fields are not
part of the Chain identity, so their later update does not invalidate the same
Chain bytes or create a self-referential lock hash. A stale Chain object is
still rejected; do not calculate candidate evidence against an earlier Chain
lock and relabel it later.

## Run the immutable gate

First commit the Chain candidate and update Integration's component lock to that
exact revision/tree/input set. The Chain worktree must be clean, all locked Cargo
sources must already be locally available, and the evidence destination must not
exist. Its physical parent directory must be owned by the invoking uid and must
not be group- or world-writable. Integration must also contain canonical
`scripts/paper-raid-chain-release-producer-v1.json` and its atomic release
evidence publisher.

```bash
bash scripts/check-paper-raid-chain-sbom.sh \
  /absolute/path/to/trillionnium-integration/components.lock.json
```

The gate archives the committed Chain tree, takes single non-symlink snapshots
of the Integration lock and producer contract, and runs `cargo metadata
--frozen` for the dependency closure. It then performs the same two `cargo
build --frozen --release` commands in two fresh, isolated `CARGO_TARGET_DIR`
directories, requires byte identity, and requires each digest to equal the
external Integration lock. `SOURCE_DATE_EPOCH` is the real Git commit time; it
is not a fabricated evidence timestamp.

Before deleting the transient A/B builds, the gate hands them, the Cargo/tool
evidence, SBOM, and provenance to Integration's fail-closed publisher. On PASS,
Integration atomically publishes a revision-derived directory containing:

- `manifest.json`
- `sbom.cdx.json`
- `provenance.json`

All three files use canonical sorted JSON. The SBOM deliberately omits CycloneDX
`timestamp` and `serialNumber`; a dummy time or random UUID would make identical
inputs produce different evidence. The provenance file likewise contains no run
time, host identifier, temporary path, or random serial.

Publication verifies the exact three-file artifact set through retained directory
identities and uses `RENAME_NOREPLACE`, followed by file and directory `fsync`.
A concurrent target creation, path substitution, symlink, FIFO, extra artifact,
or build-scratch cleanup failure therefore prevents PASS.

## What is bound and rejected

The generator takes the non-dev normal/build dependency closure from Cargo
metadata and resolves every member against `Cargo.lock`. Registry package
checksums, workspace manifests, workspace custom build scripts, the Git
revision/tree, Rust toolchain file, Integration lock, generator, verifier, gate,
canonical `cargo --version --verbose` / `rustc -vV` evidence, and both
binary SHA-256 values are bound into the SBOM/provenance pair. Cargo's absolute
IDs for workspace path packages are normalized to a source-root-relative
manifest identity; registry and Git package IDs remain complete. Therefore a
random extraction directory cannot change or leak into the canonical output.
The verifier reconstructs the complete canonical documents from those original
inputs rather than checking a subset of fields.

The gate fails closed on source or evidence symlinks, duplicate JSON keys,
duplicate package IDs/lock identities/live-binary identities, a missing package
or resolve node, lock/metadata checksum drift, a missing or substituted binary,
build-script drift, non-canonical JSON, volatile timestamp/serial fields, and
any byte difference between the isolated builds. The offline negative suite does
not invoke Cargo:

```bash
python3 scripts/test-paper-raid-chain-sbom.py
```

The self-test builds the same synthetic metadata fixture under two different
absolute source roots, requires byte-identical SBOM and provenance documents,
and asserts that neither temporary path occurs in the result.

## Release-candidate boundary

This is provenance for the exact `cargo_profile=release` Paper Raid Integration
candidate. It proves the two locally built bytes and their dependency/source
inputs; it does not turn them into a production validator, mainnet release,
signed distribution, hardened container image, or cross-platform reproducibility
claim. The prior debug/three-artifact evidence remains historical evidence bound
to its original Chain revision, tree, and script digests; this producer neither
accepts nor relabels it.

Paper Raid Receipt V2 remains scientific-finality evidence. Ranking, reward,
score, and economic eligibility remain false. Integration must pin both output
digests and both binary digests before calling the next immutable candidate
reproducible; this source implementation alone is not execution evidence.
