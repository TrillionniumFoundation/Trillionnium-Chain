# HEPLCP04 interoperability evidence

This evidence binds Chain source `297bb40798ca1b4e4a987ef00582067282cda4e9`
to the unchanged Hepta codec and coordinator from
`afd2c91b3b9ef75ab9a174e3af772ad322118f7a`.
The Chain commit is a fixed historical input; a later head of PR #907 does not
inherit these observations.

## What executed

The isolated Rust exporter compiled the two complete original crates and the
original checkpoint codec listed in [SOURCE_MANIFEST.json](SOURCE_MANIFEST.json).
It replayed a historical HEPLCP02 prefix, then constructed three **synthetic**
local policy/Selection/next-use suffixes: AdoptCandidate, DeferCandidate and
RetainParent. The retained output contains 15 checkpoint cuts and 24 original
Rust signing payloads. These are codec/coordinator interoperability vectors.

The first native export is recorded in
[native-export-attempt1.json](native-export-attempt1.json). A second execution in
a fresh workspace used `cargo run --locked --offline`, reproduced the exact
106,963-byte output and checked all 89 source files plus all 94 workspace inputs
before and after execution. Its unmodified result and streams are retained:

- [reproduction/RESULT.json](reproduction/RESULT.json)
- [reproduction/stdout.json](reproduction/stdout.json)
- [reproduction/stderr.log](reproduction/stderr.log)

The output SHA256 is
`b873d6f0606100ec8a3246548009b6afda5aa9fbc55e2bd85a4c6fed7fd81a46`.
The historical original input is
`evidence/hepta-real-native-adoption-20261108/chain-reader/adopt-v1/completed.bin`,
SHA256 `49687e0ece90dceb6409978616700c0b32ec342631a1941994ae3b7a886a7496`.

## Reproduce

The [entry point](reproduce_native.py) requires a clean checkout of the exact
Hepta commit, a Chain checkout containing these files and the original input,
cached Cargo dependencies, and two fresh external directories:

```sh
RUSTUP_TOOLCHAIN=1.96.0 python3 -B evidence/heplcp04-interop-20261111/reproduce_native.py \
  --hepta-source /absolute/path/to/exact-hepta-source \
  --chain-source /absolute/path/to/chain-source \
  --workspace /absolute/path/to/fresh-isolated-workspace \
  --output /absolute/path/to/fresh-output
```

The [workspace manifest](isolated-workspace.toml),
[exporter package manifest](exporter-package.toml),
[lockfile](isolated-Cargo.lock) and [exporter](exporter.rs) are pinned by the
entry point. The manifests are an explicit assembly shim for the two original
crates and codec. They do not build or qualify the complete Hepta binary.
The exporter does not change the production codec or its signing domains.

The Python tests replay [native-fixture.json](native-fixture.json), compare all
24 signing payloads and apply hostile checkpoint mutations. The dedicated CI
lane replays committed vectors; it does not claim fresh Rust generation in CI.
The unchanged full source guard remains required for CI head and prospective
merge checkouts. Local sparse validation must retain the guard's refusal and
must not be described as complete tracked-worktree acceptance.

## Boundary and retained failures

This run established **zero ordinary complete learning/adoption/consumption
loops**. It did not execute an optimizer, independent evaluator, ordinary C,
model installation, CURRENT publication or withdrawal, FinalUse, settlement,
or whole daemon/Root cold recovery. Receipt digest reconstruction does not
verify signatures, authenticate policy/owners or prove independent custody.
The reader remains read-only with DENY_ALL authority and HOLD_NO_GO status.

The initial preflight rejected a nonconforming local branch name. The initial
Python run found three duplicate-keyword helper errors in one test method.
Their original logs are retained alongside the corrected development run;
renaming the branch and helper parameters did not relax the assertions.
Static review is recorded separately in [STATIC_REVIEW.json](STATIC_REVIEW.json)
and does not claim execution. Frozen-commit validation records are written
outside the repository to avoid changing the very tree being tested.

The first local commit attempt was rejected because the fresh checkout had no
Git author identity. The local validation commit uses an explicitly named
machine identity, without changing global configuration. Publishing through
GitHub may create a different commit object; its complete tree must match the
locally tested tree. Original failed commit logs are retained in
[attempts/freeze-initial](attempts/freeze-initial).

The original failed unittest stream and the resulting whitespace-check output
contain significant trailing spaces. Those two exact streams use explicit
base64 JSON containers with original path, byte length and SHA256 instead of
editing their bytes. Decode the data field with base64 and verify its SHA256:
[failed unittest](attempts/reader-attempt1.stderr.log.raw.json) and
[whitespace observation](attempts/freeze-second/staged-whitespace.stdout.raw.json).
All other retained logs remain their original raw bytes.
