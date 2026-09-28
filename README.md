# Trillionnium Chain — PoN / Hepta-PoH

Trillionnium Chain is being refactored into a **Nakamoto-style neural-work chain and
public model commons**. Hepta nodes contribute locally learned parameters from authorized
real tasks; independent evaluation, expert/router composition and reproducible model
releases return useful capabilities to network users through free public parameters
and a bounded, funded basic inference tier.

**PoCO-BFT is retired as the new-development target.** PoN uses work competition,
independent validation, cumulative work, difficulty adjustment and probabilistic
confirmations, not consumption-weighted votes or QC/TC finality. Existing PoCO source
and frozen proofs remain legacy-only until an explicitly versioned migration. This
repository does not yet claim an implemented/qualified PoN work primitive or live network.

Start with the [sole development plan](docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md),
[PoN domain specification](docs/protocol/pon-nakamoto-v1/README.md), and
[all eighteen module specifications](docs/modules/README.md).
[Machine target](config/pon-nakamoto-v1.json) separates architecture choice from
[legacy runtime truth](config/consensus-mainline.json); all production flags remain false.

The machine-readable authority is `config/consensus-mainline.json`; its legacy runtime
identifiers do not override the explicit selected `development_target`.
The existing web client requires Node.js `>=24.18.0 <25` and npm `>=11.16.0 <12`.

```bash
git clone https://github.com/TrillionniumFoundation/Trillionnium-Chain.git trillionnium-chain
cd trillionnium-chain
bash scripts/project-preflight.sh
python3 scripts/ci/check_pon_documentation_v1.py
python3 scripts/ci/test_pon_documentation_v1.py
python3 formal/pon-nakamoto-v1/test_reference.py
bash scripts/ci/check_canonical_development_plan.sh
```

These document/reference checks are not neural-work security, model efficacy or runtime
acceptance. Follow [AGENTS.md](AGENTS.md), the existing protected integration path and
[rust-toolchain.toml](rust-toolchain.toml). Report security issues via [SECURITY.md](SECURITY.md).
