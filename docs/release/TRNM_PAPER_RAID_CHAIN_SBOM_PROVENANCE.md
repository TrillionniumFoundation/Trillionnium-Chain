# Paper Raid Chain debug-candidate SBOM and provenance gate

This gate produces deterministic CycloneDX 1.5 evidence for the three Chain
binaries named by Integration's `canonical-chain.live_binaries` lock:

- `trnm-consensus-app` / `trnm-cometbft-app`
- `trnm-node` with `legacy-harness` / `trnm-chain-cli`
- `trnm-finality-verifier` / `trnm-research-receipt-v2`

The checked component lock must bind the exact clean Chain revision, Git source
tree, `Cargo.lock`, `rust-toolchain.toml`, and the exact ordered binary set. A
stale Integration lock is rejected; do not calculate candidate evidence against
an earlier Chain lock and relabel it later.

## Run the immutable gate

First commit the Chain candidate and update Integration's component lock to that
exact revision/tree/input set. The Chain worktree must be clean, all locked Cargo
sources must already be locally available, and the evidence destination must not
exist. Its physical parent directory must be owned by the invoking uid and must
not be group- or world-writable.

```bash
mkdir -p /absolute/private/evidence-parent
bash scripts/check-paper-raid-chain-sbom.sh \
  /absolute/path/to/trillionnium-integration/components.lock.json \
  /absolute/private/evidence-parent/chain-paper-raid-candidate
```

The gate archives the committed Chain tree, takes a single non-symlink snapshot
of the Integration lock, and runs `cargo metadata --frozen` for the dependency
closure. It then performs the same three `cargo build --frozen` commands in two
fresh, isolated `CARGO_TARGET_DIR` directories and requires every output to be
byte-identical. `SOURCE_DATE_EPOCH` is the real Git commit time; it is not a
fabricated evidence timestamp.

On PASS the new directory contains:

- `trillionnium-chain-paper-raid.cdx.json`
- `trillionnium-chain-paper-raid.provenance.json`

Both files use canonical sorted JSON. The SBOM deliberately omits CycloneDX
`timestamp` and `serialNumber`; a dummy time or random UUID would make identical
inputs produce different evidence. The provenance file likewise contains no run
time, host identifier, temporary path, or random serial.

Publication verifies the exact two-file artifact set through retained directory
identities and uses `RENAME_NOREPLACE`, followed by file and directory `fsync`.
A concurrent target creation, path substitution, symlink, FIFO, extra artifact,
or build-scratch cleanup failure therefore prevents PASS.

## What is bound and rejected

The generator takes the non-dev normal/build dependency closure from Cargo
metadata and resolves every member against `Cargo.lock`. Registry package
checksums, workspace manifests, workspace custom build scripts, the Git
revision/tree, Rust toolchain file, Integration lock, generator, verifier, gate,
canonical `cargo --version --verbose` / `rustc -vV` evidence, and all three
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

## Debug-candidate boundary

This is provenance for the exact `cargo_profile=debug` Paper Raid Integration
candidate. It proves the three locally built bytes and their dependency/source
inputs; it does not turn them into a production validator, mainnet release,
signed distribution, hardened container image, optimized release-profile build,
or cross-platform reproducibility claim. In particular, `trnm-chain-cli` remains
a frozen `legacy-harness` diagnostic used by the live Integration driver. Its
presence in this SBOM does not make it a production state-transition authority.

Paper Raid Receipt V2 remains scientific-finality evidence. Ranking, reward,
score, and economic eligibility remain false. Integration must pin both output
digests and the three binary digests before calling the next immutable candidate
reproducible; this source implementation alone is not execution evidence.
