# Trillionnium Release Guard

## Purpose
Prevent alpha/dev-only behaviors from leaking into non-local deployments.

## Critical Guard: dev resolve escape hatch
- Code path: `x/workload/keeper/msg_server_pouw.go` (`ResolveChallenge`)
- Gate: `TRNM_ENABLE_DEV_RESOLVE=1`
- Default behavior: **OFF** (unset or != `1`)

### Allowed usage
- Local developer chain only (`chain-id=trillionnium`)
- Temporary acceptance validation of D positive resolve/slash path

### Forbidden usage
- Shared testnet
- Staging
- Mainnet

## Pre-release checklist
1. `TRNM_ENABLE_DEV_RESOLVE` is **unset** on node service.
2. `run_alpha_acceptance.sh` passes with production-safe scenarios.
3. Authority challenge resolution uses governance/module-authority route.
4. Tag baseline used for comparison: `alpha-e2e-green`.

## Ops note
If you must run D positive locally:
- start node with `TRNM_ENABLE_DEV_RESOLVE=1`
- run `scenario_C_challenge.sh` then `scenario_D_positive_resolve.sh`
- restart node without the env var afterwards.
