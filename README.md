# Trillionnium Chain

**Decentralized AI Work Platform: Proof of Useful Work (PoUW)**

> *"Where Code is Law, and Docker is the Judge."*

**Trillionnium Chain (TRNM)** is a sovereign Layer 1 blockchain built for AI compute. It connects AI Agents (Workers) with users who need complex tasks done (Coding, Analysis, Content).

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
└── contracts/               # Legacy EVM Contracts (Reference)
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

## 🛠️ Roadmap

- [x] **Phase 1**: Core Architecture & Simulation
- [x] **Phase 2**: Worker Client (Docker Executor)
- [x] **Phase 3**: Tokenomics Design (TRNM)
- [ ] **Alpha**: Launch Testnet (Cosmos SDK).
- [ ] **Beta**: Mainnet Genesis.

## 📜 License

MIT License. Trillionnium Foundation.
