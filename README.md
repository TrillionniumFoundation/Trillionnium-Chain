# Trillionnium Chain

Trillionnium Chain is a Rust implementation and qualification workspace for
Proof of Neural Work (PoN), native ledger execution, and content-addressed Cell
delivery for Hepta model artifacts.

## Development entry point

The [AI-native blockchain development plan](docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md)
is the single execution plan. It defines the existing PN0–PN6 stages, interface
owners, acceptance criteria, and source-specific observations. Component tests
and controlled model runs do not establish independent network qualification
or authorize production activation.

| Area | Current technical reference |
| --- | --- |
| Source ownership and portability | [Implementation inventory](config/portability-inventory-v1.json) |
| Native account growth and authenticated working state | [Growth profile V2](docs/protocol/pon-nakamoto-v1/details/NATIVE_ACCOUNT_GROWTH_V2.md) |
| Chain observations and Hepta effect boundaries | [Hepta handoff](docs/protocol/pon-nakamoto-v1/details/HEPTA_HANDOFF.md) |
| Model runtime, inherited parameters, and resource observations | [Runtime guide](scripts/llm_runtime_README.md) |
| Complete Cell releases and retention responsibilities | [Cell retention](docs/development/specs/pon/CELL_RETENTION_V1.md) |
| Funding, metering, payments, and external-effect reconciliation | [Native budget adapter](docs/development/specs/pon/NATIVE_BUDGET_ADAPTER_V1.md) |
| Recovery and versioned migration | [Recovery and migration](docs/protocol/pon-nakamoto-v1/RECOVERY_MIGRATION.md) |

## Source and validation

The native workspace is in `trillionnium/`. Protocol reference implementations
and conformance controls are in `formal/`; controlled runners and source-integrity
checks are in `scripts/`. Read [AGENTS.md](AGENTS.md) and run
`bash scripts/project-preflight.sh` before development.

For a focused check of the native complete-release CLI:

```sh
cargo test --manifest-path trillionnium/Cargo.toml --locked   -p trnm-data-availability --test cell_release_cli
```

Record the actual Chain and Hepta commits, build profile, binary identities,
configuration, and test scope with every result. A changed head needs its own
applicable evidence. Transport completeness, accepted chainwork, useful model
improvement, local installation authority, and governed deployment are separate
facts owned by the interfaces in the development plan.
