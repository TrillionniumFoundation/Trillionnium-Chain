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
2. `run_alpha_acceptance.sh` in secure-default mode has expected result:
   - PASS: A / B / C / D_auth_guards / E
   - FAIL: D_positive_resolve (by design)
3. Authority challenge resolution uses governance/module-authority route.
4. Baseline tags:
   - functional baseline: `alpha-e2e-green`
   - secure-default baseline: `alpha-secure-default`

Latest secure-default report:
- `data/alpha-acceptance/report-20260219-092526.txt`

## Rust L1 RC Gate (P2.2)
For Rust L1 release candidate tagging, all of the following are required:
1. `rust-l1-nightly-health` is **success** for the latest run.
2. `rust-l1-nightly-health` has **3 consecutive success runs** on `main`.
3. Nightly threshold checks pass for both classic + mixed benches.
4. state-root audit remains `ok=true mismatch=0 missing=0`.

## Ops note
If you must run D positive locally:
- start node with `TRNM_ENABLE_DEV_RESOLVE=1`
- run `scenario_C_challenge.sh` then `scenario_D_positive_resolve.sh`
- restart node without the env var afterwards.
