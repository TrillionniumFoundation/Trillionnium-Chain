# trnm_chain_devnet_v1

`trnm_chain_devnet_v1` is a signed, loopback-only integration package for the native Trillionnium Chain development network. It is not public-testnet or mainnet release evidence.

The package contains:

- `bin/trnm-chain-node` — native signed-command ingress, proposal coordination, block/state commit, read RPC, and finality receipts;
- `bin/trnm-chain-validator` — independent native validator process with durable Ed25519 anti-equivocation state;
- `bin/trnm-chain-cli` — key generation, command submission, query, and benchmark interface;
- configuration, schemas, checksums, and local operator scripts required by the package manifest.

## Boundary

Only the self-developed consensus implementation is supported. The package must not bundle, invoke, download, or depend on an external consensus process or adapter.

## Evidence scope

A successful package smoke run proves only that the exact package can execute its local fixture. It does not prove secure multi-host networking, public validator operation, economic security, or release readiness. Use the repository root `RELEASE_READINESS.md` for current status.
