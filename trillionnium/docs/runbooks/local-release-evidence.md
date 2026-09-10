# TRNM Local Native Release Evidence Runbook

Status: local evidence procedure; not public-network proof

## Goal

Produce a reproducible, hashed evidence packet for the native PoCO node and validator path without overstating what a local run proves.

## Preconditions

- use the canonical repository remote;
- record branch and commit before running tests;
- require a clean worktree for release evidence;
- use the pinned Rust toolchain and committed lock file;
- keep private keys outside the evidence directory;
- reserve enough disk for logs, snapshots, and fault artifacts.

## Recommended sequence

```bash
./scripts/project-preflight.sh --dev
cd trillionnium
cargo test --workspace --locked
```

Then run the repository's native release and fault gates for:

- four-validator quorum and finality;
- message authentication and anti-replay;
- round change and restart recovery;
- partition stall/progress/heal behavior;
- state-root, balance, escrow, and receipt consistency;
- worker-agent and real CLI submission;
- governance, emergency pause, challenge, timeout, and slashing;
- benchmark and resource regression checks.

## Evidence layout

```text
run/health/evidence-<UTC>/
  summary.txt
  manifest.txt
  commands.log
  environment.txt
  hashes.txt
  raw/
```

`summary.txt` should include:

```text
repository_url=
git_branch=
git_head=
git_status_summary=
generated_at_utc=
rust_toolchain=
chain_id=
validator_set_id=
evidence_scope=local-native-poco
historical_evidence_only=false
public_network_ready=false
```

## Integrity checks

- hash every generated artifact;
- copy commands verbatim into `commands.log`;
- record exit codes and start/end timestamps;
- preserve raw logs, not only summaries;
- confirm all validators report the same committed height, block identity, and state root;
- verify rollback and replay commands from the generated packet;
- reject symlinks or paths that escape the evidence root.

## Interpretation

A local PASS proves only that the exact checkout passed the selected local gates. It does not prove authenticated internet topology, geographic fault tolerance, production key custody, long-duration load, public anti-spam safety, or mainnet readiness.

The handoff discipline is intentionally auditable, replayable, and rollback-aware so that one green terminal session cannot be misrepresented as a release conclusion.
