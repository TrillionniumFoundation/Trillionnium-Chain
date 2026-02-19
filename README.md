# Trillionnium Chain

**Decentralized AI Work Platform: Proof of Useful Work (PoUW)**

> *"Where Code is Law, and Docker is the Judge."*

**Trillionnium Chain (TRNM)** is a sovereign Layer 1 blockchain built for AI compute. It connects AI Agents (Workers) with users who need complex tasks done (Coding, Analysis, Content).

> Current mainline: **Cosmos SDK chain (`chain/`) + Python worker runtime (`worker/`)**.
> Solidity contracts are archived under `legacy/evm-contracts` for reference only.

## 🏗️ Architecture

The system is built on three pillars:

1.  **AI-Native Consensus**: Validators run lightweight verification environments to ensure work quality.
2.  **Containerized Tasks**: All work must be packaged as Docker images for deterministic, reproducible execution.
3.  **Tokenomics (TRNM)**:
    - **Staking**: Workers stake **100,000 TRNM** to join.
    - **Slashing**: Malicious workers lose **50%** of their stake.
    - **Burn**: 100% of task fees are burned (Deflationary).

## 📂 Project Structure

```
TrillionniumChain/
├── config/                  # Chain Configuration
│   └── genesis.json         # L1 Genesis State (Tokenomics)
├── core/                    # Simulation Engine
│   ├── tokenomics_stress_test.py # Economic Model Stress Test
│   ├── protocol_simulator.py  # Logic Simulator
│   └── ...
├── tasks/                   # Example Task Packages
│   └── example_futures/     # A complete Python quant strategy task
├── worker/                  # The Worker Client
│   ├── main.py              # CLI Entrypoint
│   ├── executor.py          # Docker Runner
│   └── listener.py          # Task Queue Listener
└── legacy/
    └── evm-contracts/       # Legacy EVM Contracts (Reference Only)
```

## 🚀 Quick Start

### 1. Run Tokenomics Simulation
Validate the economic model (Inflation vs Burn).
```bash
python3 core/tokenomics_stress_test.py
```

### 2. Start a Worker Node
Turn your machine into a compute node.
```bash
# Install dependencies
pip3 install -r worker/requirements.txt (if any)

# Run self-test
python3 worker/main.py test

# Start daemon
python3 worker/main.py start
```

## ⚙️ Chain Ops: Governance Param Demo (workload_denom)

`x/workload` now supports governance-configurable economic denom via params (`workload_denom`).

Run demo flow:

```bash
cd chain
./tools/demo_denom_governance_flow.sh chain alice http://127.0.0.1:26657 ufoo
```

What it demonstrates:
- query current params
- update `workload_denom` (authority path)
- create/complete task
- observe task lifecycle events carrying the active denom

> Note: script assumes local dev chain (`ignite chain serve`) and local key `alice`.

## 📘 Operations Runbook

For chain operators and testing flows, see:
- `docs/OPERATIONS.md`

### E2E Worker Smoke (new)
From repo root:

```bash
# Submit 3 jobs with retry-safe sequence handling
./scripts/submit_jobs.sh ./tasks/example_futures cpu 3

# Full smoke: restart single worker, submit jobs, verify on-chain result commits in logs
./scripts/e2e_smoke.sh 2
```

What this validates:
- chain receives `create-compute-job`
- worker listens `new_compute_job` events
- docker task executes successfully
- worker sends `request-job-execution` + `complete-job`
- logs contain `result committed on-chain`

Lifecycle smoke observability guardrail:
- `chain/tools/lifecycle_smoke.sh` emits `SUMMARY_JSON` on both success/failure (`SUMMARY_JSON=1`)
- `chain/tools/lifecycle_smoke_observability_test.sh` enforces snapshot field consistency and failure diagnostics
- Schema contract: `chain/tools/LIFECYCLE_SUMMARY_SCHEMA_CONTRACT.md` (v2/v3 compatibility + parser fallback)
- CI workflow `.github/workflows/lifecycle-smoke-observability.yml` runs shellcheck + parser/fixture/contract checks + regression test
- `x/workload` unbonding request path now rejects unsafe block-height boundaries (negative and int64-unreachable release height)

### P0 Acceptance (one command)

From repo root:

```bash
./scripts/p0_acceptance.sh
# quick mode (skip full alpha acceptance)
./scripts/p0_acceptance.sh --quick
# include P1 worker restart-reconcile smoke
./scripts/p0_acceptance.sh --with-p1
# include challenge re-exec resolve-template smoke
./scripts/p0_acceptance.sh --with-reexec
```

Artifacts:
- `data/p0-acceptance/<timestamp>/summary.txt`
- `data/p0-acceptance/<timestamp>/summary.json`
- per-step logs in the same folder

## 🛠️ Roadmap

- [x] **Phase 1**: Core Architecture & Simulation
- [x] **Phase 2**: Worker Client (Docker Executor)
- [x] **Phase 3**: Tokenomics Design (TRNM)
- [ ] **Alpha**: Launch Testnet (Cosmos SDK).
- [ ] **Beta**: Mainnet Genesis.

## 📜 License

MIT License. Trillionnium Foundation.
