# Trillionnium Chain

Trillionnium Chain develops a native PoCO-BFT blockchain node. The current
machine-readable authority is `config/consensus-mainline.json`: the node remains
at `G1-native-host-incomplete`; production, public-testnet and release activation
are disabled. Candidate code and laboratory evidence do not imply deployment readiness.

Start with the [module design index](docs/modules/README.md), covering M00–M17.
It links each module's concrete interfaces, algorithms, durable state, limits,
failure behavior and acceptance tests. Existing behavior and proposed work are
identified separately in each specification.

The [development plan](docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md)
is the sole engineering sequence: complete module designs and simplify the
workflow, then cross epoch, public transactions and sync, incremental storage,
and multi-host fault/performance acceptance. The [authority resolver](docs/architecture/TRNM_DOCUMENTATION_AUTHORITY_V1.md)
explains precedence between frozen protocol rules and implementation designs.

```bash
git clone https://github.com/TrillionniumFoundation/Trillionnium-Chain.git trillionnium-chain
cd trillionnium-chain
bash scripts/project-preflight.sh --audit
```

For development, create a `feature/chain-*`, `fix/chain-*`, `docs/chain-*`,
`test/chain-*` or `chore/chain-*` topic branch and follow [AGENTS.md](AGENTS.md).
Rust is pinned by [rust-toolchain.toml](rust-toolchain.toml).
The web client requires Node.js `>=24.18.0 <25` and npm `>=11.16.0 <12`.

On the committed source, run the canonical documentation checks once:

```bash
bash scripts/ci/check_canonical_development_plan.sh
python3 scripts/ci/check_repository_truth_v1.py
python3 scripts/ci/check_required_baseline_closure_v1.py
```

Protocol vectors, anti-double-sign, persist-before-sign, crash recovery and
concurrent execution determinism remain required checks. See the module specs
and plan for the Rust test commands and external acceptance requirements.
Report security issues through [SECURITY.md](SECURITY.md).
