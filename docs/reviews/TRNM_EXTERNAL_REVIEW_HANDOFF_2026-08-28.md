# Trillionnium Chain external-review handoff

Date: 2026-08-28 (Asia/Shanghai)

This file is a reviewer handoff for one immutable source snapshot. It is not a
release approval, a production deployment authorization, or a replacement for
the repository's release-readiness and machine-truth sources.

## Snapshot identity

| Field | Value |
|---|---|
| Repository | `TrillionniumFoundation/Trillionnium-Chain` |
| Visibility | Private |
| Review ref | `refs/heads/docs/chain-poco-bft-mainline-20260825` |
| Tested source commit | `3e6bdf1938ca409b8a32db922548bf6232391a7a` |
| Tested source tree | `2cb6c0acfb4c7308adbca22cda36ecae01c778fb` |
| Tested source parent | `8d715a3f8b5114c49f52765f48685774f8ab2da1` |
| Source relation to `origin/main` | Linear descendant; `origin/main` at review preparation was `e73d1a930991f0e308bf72854b334b6191c7fcc3` |
| Source worktree | `/home/alex/projects/worktrees/trillionnium-chain/poco-mainline-20260825` |
| Source status at test start | Clean (`git status --porcelain=v2` contained no paths) |

The branch tip may move by a docs-only commit when this handoff is published.
The tested code identity above is the one to use when interpreting code-test
results. Verify the published tip and the docs-only delta with:

```sh
git fetch --prune origin
git rev-parse HEAD
git rev-parse HEAD^{tree}
git diff --name-status 3e6bdf1938ca409b8a32db922548bf6232391a7a HEAD
```

The last command must show only this handoff file (or be empty if the document
is distributed separately).

## Authority and current truth

The repository's active authority hierarchy is:

1. [`RELEASE_READINESS.md`](../../RELEASE_READINESS.md) for release posture;
2. [`docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md`](../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md)
   and its manifest for execution and gate order;
3. [`docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_ENGINEERING_EVIDENCE_CONTRACT_V1.md`](../development/TRNM_AI_NATIVE_BLOCKCHAIN_ENGINEERING_EVIDENCE_CONTRACT_V1.md)
   for evidence shape and invalidation rules;
4. [`config/consensus-mainline.json`](../../config/consensus-mainline.json) for
   machine-readable consensus truth.

At this snapshot the machine truth is deliberately pre-cutover:

```text
consensus_mainline=native-poco-bft
protocol_target=poco-bft-v0
stage=G1-native-host-incomplete
production_candidate=false
production_consensus_activation=false
cometbft.role=migration-residue-only
cometbft.production_dependency=false
cometbft.cleanup_eligible=false
```

These flags are authoritative. The branch is a candidate engineering source,
not a production-ready chain. Open blockers are listed in the `blockers` array
of `config/consensus-mainline.json` and in
[`docs/protocol/poco-bft-v0/IMPLEMENTATION_GAP_REGISTER.md`](../protocol/poco-bft-v0/IMPLEMENTATION_GAP_REGISTER.md).

## Bound inputs

The following hashes were checked against the committed files used by the
canonical plan manifest:

```text
plan_sha256=aba99ae6be2ff8a4aac4d6355e1f778e49a7075a80b09453f16984f85bb0b6cd
assessed_commit=8198fea0307eb368df34ff77ffc272a6b0e655ec
assessed_tree=a1be71bba1b54c428493d186fafb656d081b31a9
machine_truth_sha256=19baef8a393d235b4f87a1351e2b8cdf2e7bb1f2eea8770ecc67d3e18966c6be
protocol_manifest_sha256=ca41347d4559934e706aea13d242625e905b99d956b6187f7df449c1c27299aa
evidence_contract_sha256=f524f06e3395ce5a097a6ce98ff06c4863c68cbfbd18a4a91dfff451dfe1f401
cargo_lock_sha256=ee1e9a8382092a397f1b041107cf6b86e468d521af3aa7963e5f6e714e6c3382
```

The assessed plan commit/tree is an ancestor of the tested source commit. The
code tip contains subsequent hardening commits; therefore an older plan
assessment must not be silently presented as a complete assessment of the
newer code tip.

## Validation ledger

The following checks were run from the canonical physical checkout before the
source push. “Pass” means that the named check returned success; it does not
promote the branch or close the open blockers.

| Check | Result | Scope / notes |
|---|---|---|
| `bash scripts/project-preflight.sh` | Pass | `warnings=2`, `errors=0`; project boundary and remote policy checks |
| `bash scripts/ci/check_canonical_development_plan.sh` | Pass | One active plan; manifest and four bound inputs verified |
| `bash scripts/ci/check_poco_bft_mainline_truth.sh --pre-cutover` | Pass | Native PoCO-BFT mainline; production and activation flags remain false |
| `git diff --check` | Pass | No whitespace errors in the committed source snapshot |
| Tracked-secret / packaging review | Pass for current tracked tree | No tracked private key, token, cloud credential, submodule, or symlink was found; see exclusions below |
| `cargo test -p trnm-poco-lab-validator --lib -- --test-threads=1` | **Outcome not recorded** | The process later disappeared after a gateway interruption; final exit code and libtest summary were not captured. This is not test evidence of pass or fail. Reviewer must rerun it. |
| GitHub Actions after push | Not a pass | Run `33133507578` (`legacy-local-harness-preflight`) completed **failure** before the harness: the runner's Cargo offline-cache stamp expected `72e254afa47d8b92fe8803b35869990bcfaa7f8106d9f0d4ecb45d127fbe150b`, while this snapshot's locked file is `ee1e9a8382092a397f1b041107cf6b86e468d521af3aa7963e5f6e714e6c3382`; run `33133507597` (`rust-l1-nightly-health`) was still in progress when recorded and had already skipped its Rust test steps after the same cache check failed |

The full validator test command intentionally remains an explicit
`unverified` item. No test count, green status, or release conclusion should be
derived from the missing process result.

The two run IDs above were triggered for the tested source commit
`3e6bdf1938ca409b8a32db922548bf6232391a7a`, before the later docs-only handoff
commit. The cache-stamp mismatch is a CI runner/input-alignment blocker; it is
not evidence that the local validator command passed or failed. The nightly
run's eventual conclusion should be checked directly rather than inferred from
this snapshot.

## What is and is not in the review source

The Git push contains the committed repository tree only. It does not include
local ignored build or runtime state. In particular, do not archive or force-add
any worktree directory:

- `trillionnium/target/` and other `target/` directories are build output;
- `trillionnium/run/` and nested `run/` directories can contain node keys,
  databases, WALs, snapshots, state, and logs;
- local stashes, including the unverified terminal-barrier WIP, were not applied;
- all keys, databases, logs, and binaries used by local validation remain local.

The tracked evidence set contains historical/private operational material such
as host labels, LAN topology, ports, and filesystem paths. The repository is
private, but a reviewer must treat those files as confidential and must redact
them before redistribution. This handoff does not reproduce those values.

## Reproduce the snapshot

Use the canonical physical directory name because the preflight script checks
the project boundary:

```sh
git clone --branch docs/chain-poco-bft-mainline-20260825 \
  --single-branch \
  https://github.com/TrillionniumFoundation/Trillionnium-Chain.git \
  trillionnium-chain
cd trillionnium-chain

test "$(git rev-parse 3e6bdf1938ca409b8a32db922548bf6232391a7a^{tree})" = \
  2cb6c0acfb4c7308adbca22cda36ecae01c778fb
git status --porcelain=v2
git diff --check

bash scripts/project-preflight.sh --audit
bash scripts/ci/check_canonical_development_plan.sh
bash scripts/ci/check_poco_bft_mainline_truth.sh --pre-cutover

# Full focused validator run; record the exit code and complete libtest output.
cargo test -p trnm-poco-lab-validator --lib -- --test-threads=1
```

The Rust toolchain and locked dependency cache must be available locally for
the Cargo-backed checks. Reviewers should record the exact toolchain, host,
working directory, commit/tree, command, start/end time, exit code, and artifact
hashes in their own evidence bundle.

## Review boundaries

Please review the native PoCO-BFT candidate as an engineering snapshot. In
particular, independently assess Core/Safety authority, signer custody and
watermark recovery, authenticated networking, ordered finalization, state
sync, migration/export ceremony, crash and power-loss assumptions, dependency
closure, and the negative/fail-closed paths. Do not infer production readiness
from legacy CometBFT fixtures, local unit tests, queued CI runs, historical audit
documents, or this handoff itself.

No change was made to `main`, no pull request was opened automatically, and no
deployment or production activation was performed by this handoff.
