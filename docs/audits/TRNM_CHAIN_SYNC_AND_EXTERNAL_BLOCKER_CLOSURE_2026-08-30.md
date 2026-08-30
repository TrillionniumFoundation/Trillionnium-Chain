# Trillionnium Chain sync and external-blocker closure audit — 2026-08-30

Status: **candidate audit / non-normative / no release promotion**

## Scope and source separation

The private Chain remote was fetched with prune from:

```text
repository = TrillionniumFoundation/Trillionnium-Chain
remote = origin
url = https://github.com/TrillionniumFoundation/Trillionnium-Chain.git
synced_base = origin/feature/chain-a18-repository-truth-ci-hardening-v1-20260830
synced_base_commit = 1663abd8935be4e5819f5ff0c7ded250a3664097
worktree = feature/chain-g1-external-blocker-closure-20260830
```

`git fetch origin --prune` completed successfully.  A separate configured
`legacy-shared` remote still points at a removed repository and fails when
included in `git fetch --all`; it was not used as an authority and was not
rewritten.

The newest Chain ref observed during this audit was:

```text
origin/feature/chain-a20-p2-tx-tombstone-gc-v1-20260830
observed_tip = a5d9e64102fa87090d92ddf842f60270515c0a78
```

Its Rust/schema/doc work was reviewed read-only.  The tip also contains a
hosted workflow that self-modifies and removes repository files, requests
write permission, commits and pushes from the workflow, and publishes a
candidate from an actor-controlled path.  That workflow and its one-shot
finalizer were deliberately not merged.  The local branch carries only the
reviewable candidate tombstone implementation (`603bccc32`, `50bf6cdc1`).

## Candidate slices carried locally

- G1 candidate Unix recovery/status owner and explicit Core-ack boundary
  (`6556fd9d5`);
- A19 content-addressed SQLite terminal-finalization history
  (`a34ae75d5`, `75308f1d3`, `4541832ea`, `b82bfe90c`, `56f637686`);
- A20 schema-v2 replay tombstone compaction and authenticated purge boundary
  (`603bccc32`, `50bf6cdc1`);
- mixed-trust/offline CI policy and external-evidence validation hardening;
- stale candidate-package and legacy-freeze manifests repaired to the current
  source inventory.

All slices remain candidate-only.  The machine flags
`production_candidate` and `production_consensus_activation` remain `false`.

## Verification boundary

Local checks included Rust formatting/check/clippy and focused tests for the
recovery owner, native application, SQLite history and transaction tombstone
contracts; the Quint foundation and PoCO-BFT v0 formal candidate runs passed
with their declared sample counts.  The six-host LAN probe found all inventory
hosts reachable and toolchains/fault tools observable.  These are repository
or readiness observations, not accepted external consensus evidence: no
validator run, multi-host finality campaign, HSM custody, physical power-loss
test, independent audit, or soak/activation record was manufactured.

## External blockers retained

The six registered external blockers remain open: exact-source independent
review, real 4/7/31/100-node campaign, external HSM/monotonic anchor custody,
physical power-loss/controller-cache recovery, independent consensus/
cryptography/economics/red-team audit, and 72-hour/7-day/30-day soak plus
authorized activation.  GitHub branch protection and required-check settings
are also external administrative state and remain unverified.

This audit is an immutable source note only; changing a covered source,
toolchain, dependency, configuration, validator set or external artifact
invalidates downstream evidence under the canonical plan.
