# Trillionnium Chain (TRNM)

TRNM is a Rust-native Layer 1 for decentralized AI compute, built around the project's self-developed **Proof of Consumption (PoCO)** consensus and settlement protocol.

## Canonical native path

```text
signed transaction
  -> trnm-mempool
  -> trnm-chain-node
  -> trnm-chain-validator quorum
  -> trnm-state / trnm-pouw
  -> state root and finality receipt
```

The repository does not delegate block consensus to a third-party engine. Ordering, validator execution, voting, finality evidence, PoCO task validity, challenge handling, and settlement remain TRNM-native responsibilities.

## Rust workspace

The active workspace is `trillionnium/`.

| Crate | Responsibility |
| --- | --- |
| `trnm-node` | Native node, validator, operator CLI, recovery, voting, and finality orchestration |
| `trnm-pouw` | PoCO task lifecycle, verification, challenge, resolve, and settlement rules |
| `trnm-state` | Versioned state, balances, governance state, replay state, and roots |
| `trnm-executor` | Conflict detection and deterministic execution-group research |
| `trnm-mempool` | Admission, deduplication, priority, fairness, and backpressure |
| `trnm-rpc` | Transaction submission and stable query surfaces |
| `trnm-finality-types` | Native block, vote, quorum, proof, and receipt types |
| `trnm-finality-verifier` | Independent verification of native finality receipts |
| `trnm-worker-agent` | Worker execution and on-chain submission workflow |
| `trnm-cli` | User and operator transaction/query commands |
| `trnm-bench` | Performance and fault-measurement tools |
| `trnm-types` | Shared protocol types |
| `trnm-bridge-poc` / `trnm-oracle` | Experimental integration surfaces, not Day-1 production claims |

## Quick start

Requirements:

- Rust toolchain pinned by `rust-toolchain.toml`;
- Node.js 20+ for `web4-frontend/`;
- Git, Bash, Python 3, and SQLite tooling where required by runbooks.

Run the Rust workspace:

```bash
cd trillionnium
cargo test --workspace --locked
```

Run a local native simulation:

```bash
cd trillionnium
cargo run -p trnm-node --bin trnm-sim -- \
  --config configs/node1.toml \
  --block-ms 5 \
  --max-blocks 6 \
  --demo-tasks 8 \
  --demo-keys 3 \
  --parallel-workers 4
```

Run the frontend checks:

```bash
cd web4-frontend
npm ci
npm run ci:check
```

## Protocol documentation

- Native PoCO consensus and settlement: `trillionnium/docs/protocol/poco-proof-of-consumption-v1-draft.md`
- Native consensus policy: `docs/architecture/TRNM_NATIVE_POCO_CONSENSUS_POLICY_2026-09-11.md`
- Repository documentation index: `docs/README.md`
- Operator handbook: `OPERATIONS.md`
- Security policy: `SECURITY.md`
- Release truth source: `RELEASE_READINESS.md`

## Development boundary

A feature is not considered implemented merely because a simulator or isolated crate test passes. Consensus-critical claims require reproducible evidence through the native node and validator path, including deterministic roots, quorum verification, replay rejection, crash recovery, partition safety, value conservation, and stated resource limits.

## Current status

The project remains under active development. Local development and fault-test assets exist, but public-testnet and mainnet readiness require additional closure around authenticated multi-host networking, validator lifecycle, secure key custody, slashing, state synchronization, observability, durable indexing, long-duration fault tests, and independent security review.
