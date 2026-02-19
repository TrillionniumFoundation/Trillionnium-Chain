# Trillionnium Chain (TRNM) - Project Summary

## Vision
Sovereign Layer 1 blockchain for Decentralized AI Compute (Proof of Useful Work, PoUW).

## Mainline Status (Current)
- **Execution path**: Cosmos SDK chain (`chain/`) + Python worker runtime (`worker/`)
- **Consensus/Economics**: Worker stake + governance-controlled slashing + task-fee burn
- **Denom model**: `x/workload` economic denom is governance-configurable via params (`workload_denom`, default `utrnm`)

---

## Workspace Topology

### ACTIVE (production path)
1. `chain/`
   - Sovereign Cosmos SDK chain
   - Core module: `x/workload`
   - Implemented lifecycle:
     - `create-task` (escrow to module)
     - `update-task` (on completion burns 100% bounty)
     - `register-worker` (100,000 minimum stake lock)
     - `slash-worker` (authority-only, 1..50%, min remaining stake guard)
     - `request-unbonding` / `finalize-unbonding` (cooldown exit)
     - `extend-unbonding` (authority-only, bounded extension)
   - Added structured audit events for task + worker lifecycle
   - Added standardized module error codes for lifecycle failures

2. `worker/`
   - Python runtime for off-chain execution / listener flow
   - Retained as core off-chain execution component

### EXPERIMENTAL / RESEARCH
1. `core/`
   - Tokenomics and simulation scripts
2. `tasks/`
   - Example packaged workloads
3. Other strategy/sandbox folders in workspace
   - kept for experimentation; not authoritative for chain mainline

---

## Tokenomics Targets
- **Worker minimum stake**: 100,000 TRNM
- **Max slash per event**: 50%
- **Task fee policy**: 100% burn on completion
- **Base denom**: `utrnm` (default; runtime controlled by `workload_denom` params)

## Repository
- **GitHub (private)**: https://github.com/ProfAlexQI/TrillionniumChain
- **Local path**: `~/.openclaw/workspace/TrillionniumChain`

## Operator Quick Start
```bash
cd chain
ignite chain serve
```

## Recent Hardening Highlights
- Slashing order fixed: validate remaining stake before burn
- Unbonding extension capped
- Authority restrictions enforced for slash / unbonding extension
- Keeper tests stabilized (valid addresses + mock bank)
- Added edge/integration tests for:
  - slash boundaries
  - unbonding boundaries
  - params-driven denom behavior across task/slash/finalize flows
