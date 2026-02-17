# Legacy EVM Contracts (Archived)

This folder contains historical Solidity contracts from an earlier EVM-phase design.

## Status
- **Archived / reference-only**
- **Not** part of the current production path

## Current Mainline
Trillionnium is now implemented as a sovereign Cosmos SDK chain under `chain/` with:
- on-chain workload module (`x/workload`)
- worker staking/slashing/unbonding lifecycle
- governance-configurable workload denom (`workload_denom`)
- Python worker runtime under `worker/`

Keep these contracts for historical context and potential future interoperability work only.
