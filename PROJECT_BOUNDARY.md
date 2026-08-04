# Trillionnium Chain Boundary

- Project ID: `trillionnium-chain`
- Canonical root: `/home/alex/projects/trillionnium-chain`
- Lane: `chain-consensus`
- Private remote: `TrillionniumFoundation/Trillionnium-Chain`
- Legacy shared source: `legacy-shared` (fetch-only)

## Owns

Consensus, canonical runtime and state, mempool/RPC/node interfaces,
genesis/validator/operator tooling, and the canonical AppHash/proof/finality
semantics consumed by other projects.

## Does not own

World gameplay/campaign/economy logic, Hepta services, Nakama authoritative
match state, or cross-repository E2E orchestration. Game packages and sibling
working-tree Cargo paths are forbidden here.
