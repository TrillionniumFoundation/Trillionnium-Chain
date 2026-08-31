# Trillionnium Chain operations manual

Status: **candidate-only; no public-testnet, production, or activation runbook**.

This document describes safe handling of the current Native PoCO-BFT candidate.
It does not authorize validator deployment. The machine-readable status source is
`config/consensus-mainline.json`; generate the exact commit/tree projection with
`scripts/ci/generate_release_status_v1.py`.

## 1. Hard operating boundary

The only future production consensus route is Native PoCO-BFT. CometBFT,
`trnm-consensus-app`, `trnm-node`, legacy CLI/simulator binaries, and historical
devnet packages are migration residue or differential fixtures. Operators must
not start them as a public-testnet or production finality authority.

The default `trnm-poco-node` path intentionally exits with failure while host and
production activation flags are false. Do not patch around this gate, change the
constants, wrap the command in a restart loop, or treat a candidate subcommand as
a validator daemon.

## 2. Exact-source preflight

Before any candidate execution, capture and retain:

```bash
set -euo pipefail
git fetch --prune origin
git status --porcelain --untracked-files=all
git rev-parse HEAD
git rev-parse 'HEAD^{tree}'
sha256sum \
  docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md \
  docs/development/plan-manifest-v1.toml \
  config/consensus-mainline.json \
  config/repository-policy-v1.json \
  trillionnium/Cargo.lock
python3 scripts/ci/check_repository_truth_v1.py
python3 scripts/ci/generate_release_status_v1.py --check-deterministic \
  --output /tmp/trnm-release-status-v1.json
python3 scripts/ci/check_external_evidence_v1.py \
  --output /tmp/trnm-external-evidence-status-v1.json
```

Refuse execution if the worktree is dirty, the exact source tuple differs from
the approved tuple, a required digest differs, or a validator reports failure.
A cached remote reference is not contemporaneous evidence.

## 3. Build and repository baseline

Use the pinned toolchain and lockfile:

```bash
rustup toolchain install 1.95.0 --profile minimal \
  --component rustfmt --component clippy
rustup override set 1.95.0
cd trillionnium
cargo fmt --all -- --check
cargo check --workspace --all-targets --locked
```

The GitHub-hosted checks `repository-truth`, `rust-baseline`, and
`external-evidence-contract` must complete on the exact pull-request head. A
skipped, queued, cancelled, stale-head, synthetic-merge-only, or manually copied
result is not evidence.

## 4. Candidate-only process commands

The binary exposes two bounded G2 evidence commands:

```text
prepare-g2-manifest-bound-candidate-v2 \
  <absolute-run-root> <absolute-manifest> <manifest-sha256>

run-g2-manifest-bound-candidate-v2 \
  <absolute-run-root> <absolute-manifest> <manifest-sha256> \
  <process-pin-checksum>
```

Use a newly created, operator-owned private run root on a local Linux test host.
Pin the canonical manifest and compare the returned checksums. Never place
secrets, production keys, real validator identities, or production state in a
candidate run root.

Successful candidate output is explicitly non-production. It does not establish:

- persistent authenticated P2P networking;
- a live pacemaker, proposal/finality loop, or validator voting;
- production signer/HSM or external anti-rollback protection;
- production application execution, state sync, or migration cutover;
- physical power-loss durability or multi-host safety/liveness;
- public-testnet, release, or activation readiness.

## 5. Keys and signer safety

Do not load a production private key into the candidate process. Production
signing remains blocked until a device-backed non-exportable key, external
monotonic watermark, quorum custody, rotation/revocation procedure, namespace
anti-rollback, and cloned-state rejection are independently demonstrated and
accepted under `EXT-ANCHOR-HSM-001`.

Any observed double-sign, watermark regression, identity mismatch, stale safety
state, ambiguous durable acknowledgement, or state-root mismatch is a stop event:
terminate the campaign, preserve read-only artifacts, revoke or isolate affected
keys, and do not restart voting.

## 6. External evidence ingestion

Evidence that cannot be produced by source code belongs in
`docs/evidence/external/submissions/` and must satisfy
`trnm-external-evidence-v1`. Validate ordinary submissions with:

```bash
python3 scripts/ci/check_external_evidence_v1.py
```

The release gate is intentionally stronger:

```bash
python3 scripts/ci/check_external_evidence_v1.py --require-all \
  --source-commit "$(git rev-parse HEAD)" \
  --source-tree "$(git rev-parse 'HEAD^{tree}')"
```

It must fail until all independent review, multi-host campaign, HSM/anchor,
physical power-loss, audit/red-team, long-soak, and governance records are
accepted for the exact source. Do not weaken this failure to unblock a release.

## 7. Incident and recovery posture

Until production gates close, the safe response to an uncertainty is to stop and
retain evidence rather than attempt continued consensus participation. Preserve:

- exact commit/tree/config/lockfile digests;
- signed raw protocol and signer traces;
- safety-store, signer-journal, checkpoint, application-root, and state-sync
  metadata as read-only copies;
- host, filesystem, controller, kernel, time-source, HSM and custody identities;
- the last independently verified finalized certificate and application root.

Recovery must occur in a fresh process and, where required, on an independently
controlled host. Never edit a journal, reset a watermark, copy a validator data
directory, or reuse a key to make recovery appear successful.

## 8. Promotion prohibition

No operator may set or represent `production_candidate`,
`production_consensus_activation`, `public_testnet_ready`, or `release_ready` as
true based on this manual. Promotion requires every canonical gate, required
GitHub setting, independent review, and exact-source external evidence record to
be accepted under the current development plan.
