# Trillionnium Chain Operations

## Canonical operating boundary

The only supported consensus path is the native Rust implementation in `trnm-node`.

```text
trnm-chain-node -> native validator protocol -> deterministic state transition -> AppHash
```

No external consensus process, adapter, sidecar, protocol bridge, compatibility fixture, or release artifact may be used as consensus authority.

## Build

```bash
cd trillionnium
cargo build -p trnm-node --features self-consensus --bins --locked
cargo build -p trnm-cli --locked
```

Expected binaries:

```text
target/debug/trnm-chain-node
target/debug/trnm-chain-validator
target/debug/trnm-chain-cli
target/debug/trnm-sim
```

## Validation gates

Run the policy and dependency checks before node tests:

```bash
bash scripts/project-preflight.sh --audit
bash scripts/ci/check_self_consensus_only.sh
```

Run the core deterministic and BFT gates:

```bash
cd trillionnium
cargo test --workspace --locked
./scripts/check_bft_4node_smoke.sh
./scripts/check_bft_restart_recovery.sh
./scripts/check_bft_message_auth.sh
./scripts/check_bft_round_change.sh
./scripts/run_consensus_fault_matrix.sh
```

A local pass is development evidence only. Public-network claims require reproducible multi-host evidence with hardware, topology, latency, packet-loss, workload, commit, configuration, and raw-result identities recorded.

## Node separation

Operate each validator with separate:

- process identity and service account;
- validator signing key and anti-equivocation database;
- node configuration and data directory;
- RPC and P2P listener;
- logs, metrics, backups, and recovery evidence.

Never package private validator keys into images, release archives, test fixtures, or repository history.

## Start and stop

Use the native devnet scripts for controlled development runs:

```bash
cd trillionnium
./scripts/devnet_up.sh
./scripts/devnet_down.sh
```

Before restart or replacement, capture branch, commit, binary hashes, configuration hashes, chain identity, validator identity, latest finalized height, AppHash, and rollback anchor.

## Failure handling

Fail closed on any of the following:

- conflicting votes or reused signing state;
- chain ID or genesis mismatch;
- state-root disagreement;
- non-contiguous durable height;
- replayed or unauthenticated consensus message;
- validator-set transition without the required authorization;
- corrupt WAL, checkpoint, snapshot, or state database.

Do not auto-repair a consensus identity mismatch. Preserve evidence, isolate the node, restore from a verified source, and rejoin only after root and height convergence are proven.

## Release evidence

Every rehearsal or handoff must bind evidence to:

- repository and branch;
- full commit SHA and clean worktree state;
- binary and configuration hashes;
- genesis and chain ID;
- validator set and voting power;
- test profile and fault schedule;
- replay and rollback commands;
- generated UTC timestamp.

The release truth source is `RELEASE_READINESS.md`.
