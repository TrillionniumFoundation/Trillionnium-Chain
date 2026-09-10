# Trillionnium Chain Project Boundary

This repository is the active development root for the TRNM chain and its self-developed PoCO consensus and settlement protocol.

## Canonical scope

- Native node and validator protocol
- PoCO task validity, consumption settlement, challenge, and resolution
- Versioned state, state roots, replay protection, balances, and governance
- Mempool, execution scheduling, RPC, worker-agent, CLI, finality proofs, and operator tooling
- Chain-facing bridge, oracle, contract, and frontend integration boundaries

## Repository rules

- Active development occurs on branches matching the project branch policy.
- `main` and `master` are protected integration branches.
- The canonical remote is `TrillionniumFoundation/Trillionnium-Chain`.
- Cargo path dependencies must remain inside this repository boundary.
- Game/server/product repositories must not be imported into the chain workspace.
- Consensus-critical claims require native node/validator evidence, not isolated mocks or documentation-only assertions.
