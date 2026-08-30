# Trillionnium Chain sync and external-blocker closure audit — 2026-08-30

Status: **candidate audit / non-normative / no release promotion**

## Scope and exact source separation

The Chain remote was fetched with prune from:

```text
repository = TrillionniumFoundation/Trillionnium-Chain
remote = origin
url = https://github.com/TrillionniumFoundation/Trillionnium-Chain.git
synced_base = origin/feature/chain-a18-repository-truth-ci-hardening-v1-20260830
synced_base_commit = 1663abd8935be4e5819f5ff0c7ded250a3664097
worktree = /home/alex/projects/worktrees/trillionnium-chain/g1-external-blocker-closure-20260830
branch = feature/chain-g1-external-blocker-closure-20260830
code_closure_commit = c0e309743f9696c8ee8bc035ff4c427df4d0eb25
code_closure_tree = 3b46b2e72879afb4750aab61ebab955ef2c375d1
```

`git fetch origin --prune` completed successfully.  The separate configured
`legacy-shared` remote still points at the removed
`TrillionniumFoundation/Trillionnium.git`; `git fetch --all --prune` therefore
reports that stale remote, which was not used as an authority and was not
rewritten.

The latest related remote refs observed during this audit were:

| work | remote tip (tree) | exact source reviewed | remote result |
| --- | --- | --- | --- |
| A20 tombstone GC | `9bf9ef2f0cf18183f5a5b0ec459e8affae4d8df5` (`43b00a053971405a8eeb4e4c581d04eaee9ade59`) | `9dfee13c02c0f3f291f838109419405fbab8c435` (`550f50b9c210b030e0acf2f6d4147293a9b92df3`) | exact A20 workflow failed; required baseline passed; payload job was actor/runner-policy blocked |
| A21 sealed native receipt verifier | `b58665a783c0e1bcceb33455acde65ee6ada4034` (`edbbc4fa2649cc480da89377488ed32fa36928d2`) | `c05364e7324fe3ff2c4a8b22322698a0cddd5dc1` (`a8626c41ea26bfb808d5a4aba07082849077954e`) | exact required baseline and payload checks passed; PR jobs skipped by policy |
| A22 capability inventory | `8e6c2fb5b9f2dd6d60f2b7fb00ac8382b95ba18d` (`07f212c3eef977c93e71f6aaada852fc6dfc7cf5`) | safe scanner parent `7a9c1bc85dd190a8cbf13da53020b86e6e676092` (`0f67b37e754d5bd65e605f75189dca98f9a22dd6`) | inventory job passed |

The A20/A21/A22 branch tips are divergent automation branches.  A20's history
contains a write-capable/self-modifying publisher and broad tree churn; A21
contains the historical one-shot verification lineage; A22's current workflow
is read-only but is still not the canonical branch.  None of those branch tips
was merged.  The reviewable A22 scanner was ported as the single safe source
file in commit `7772c820af9e04b9b6f1d8bb7047e33448a5056e`.
All six inspected remote/source commits are unsigned GitHub objects, not
release-signature or independent-review evidence.

## Candidate slices carried locally

- G1 recovery/status owner and explicit Core-ack boundary (`6556fd9d5`), with
  client-transport failures isolated per connection (`0049ff9c1`);
- A19 content-addressed SQLite terminal-finalization history
  (`a34ae75d5`, `75308f1d3`, `4541832ea`, `b82bfe90c`, `56f637686`,
  `8e39213f3`);
- A20 schema-v2 replay tombstone compaction, authenticated purge seam,
  parent/child identity fences and global inventory bound (`603bccc32`,
  `50bf6cdc1`, `7cbca1090`), plus bounded replay-WAL resources
  (`53d5818e8`);
- deterministic A22 capability inventory (`7772c820a`), which reports
  `files=2072`, `traits=178`, `authority_traits=29`, `verified_mints=37`,
  `findings=5`, severity `{candidate-p0:4, review-required:1}`, report SHA-256
  `f02d378bef30705b1e0d27c4cabc28e12c213e9b0041a30c6610f899cc5e2473`;
- G1 process-host generation successor and three-block proof-horizon fences
  (`c0e309743`), both checked before queue/WAL side effects.  The real-process
  fixture now explicitly makes temporary roots 0700 so the production path
  fence remains strict; no production activation flag changed.

## Verification boundary

At the code-closure commit, the following local checks passed (Cargo commands
were run sequentially):

```text
project-preflight --dev/--staged = passed (no errors)
G1 process-host e2e = 4 passed, 0 failed (single-threaded)
trnm-poco-node tx-admission-wal lib = 158 passed, 0 failed
payload replay recovery gate = 78 library tests plus cross-process/socket matrices passed
trnm-poco-node strict Clippy with g1-process-test-support = passed
native execution v0 boundary = 45 tests + 6 doc-tests passed
Quint AI-native foundation formal = passed (2,500 samples)
PoCO-BFT v0 formal/proto gates = passed
candidate boundary batch and cargo-offline/mixed-trust policy gates = passed
```

The post-code-closure six-host read-only probe is recorded in:

```text
/tmp/trnm-20260830-post-143401-readiness.json
/tmp/trnm-20260830-post-143401-fleet.json
/tmp/trnm-20260830-post-143401-baseline.txt
/tmp/trnm-20260830-post-143401-acceptor.txt
```

It observed six inventory hosts with no probe failures, fault tools and native
toolchains observable, and an epoch spread of four seconds.  It explicitly
reported `build=false`, `validator_run_completed=false`,
`multihost_run=false`, `geo_wan_evidence=false`, and `production=false`.
This is readiness/observation only; it is not real validator finality,
campaign, HSM, power-loss, audit or soak evidence.

## Repository and administrative blockers retained

The canonical execution ledger still reports `repository_open=14`,
`settings_open=1`, and `external_open=6`.  The 14 repository rows remain
truthfully partial/open because production Core/Safety ownership, arbitrary
proposal/finality execution, production CheckTx/signing/broadcast, persistent
network/state-sync, cross-store atomicity, migration authority, and long
history/scale contracts are not present.  The six external rows are unchanged:

- `EXT-REVIEW-001` — independent exact-source review and mutant replay;
- `EXT-G1-CAMPAIGN-001` — real 4/7/31/100-process, multi-host,
  multi-operator/custody campaign;
- `EXT-ANCHOR-HSM-001` — non-exportable device-backed key and external
  monotonic anti-rollback anchor;
- `EXT-POWERLOSS-001` — physical interruption/controller-cache/reboot matrix;
- `EXT-AUDIT-001` — independent consensus/crypto/economics/red-team audit;
- `EXT-SOAK-ACTIVATION-001` — 72-hour chaos, 7-day public testnet,
  30-day candidate soak and signed governance activation.

Read-only GitHub checks found `main` unprotected (`protected=false`, no
repository rulesets) and issues #40–#46 still open.  The repository API also
reported `private=false`/`visibility=public`; this was not changed, and should
be independently checked against the intended private-repository policy.  No
issue, branch protection, visibility, PR, merge, workflow trigger, key-custody,
power-cycle or production state was changed by this audit.

All candidate and production flags remain false:

```text
production_candidate = false
production_consensus_activation = false
public_testnet_ready = false
release_ready = false
```

This note records the exact source and honest evidence boundary.  It does not
convert local fixtures/readiness into external evidence; any source, toolchain,
dependency, configuration, validator set, key policy or external artifact
change invalidates downstream evidence under the canonical plan.
