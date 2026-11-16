# Trillionnium Chain

Trillionnium Chain is an experimental native application and chain research
workspace. The retained Rust implementation supplies the current application
components and reference behavior while the HIA migration proceeds.

The project does not claim a qualified production consensus, public testnet, or
production release. Current status belongs to
[the consensus declaration](config/consensus-mainline.json),
[the implementation inventory](config/portability-inventory-v1.json), and
[the HIA migration ledger](config/hia-migration-v1.json).

## Start here

- [Development boundary](AGENTS.md)
- [Canonical development plan](docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md)
- [Documentation authority](docs/architecture/TRNM_DOCUMENTATION_AUTHORITY_V1.md)
- [Release readiness](RELEASE_READINESS.md)
- [HIA implementation and qualification](hia/README.md)

## Repository map

| Path | Purpose |
| --- | --- |
| `trillionnium/` | Cargo workspace, 26 retained Rust packages, and their executable tests |
| `hia/` | HIA sources, native foundations, Rust comparison oracles, and qualification tools |
| `config/` | Protocol parameters, source inventories, explicit status, and evidence contracts |
| `scripts/` | Development, CI, evidence readers, and retained runtime support |
| `formal/` | Independent reference models and research contracts |
| `docs/` | Specifications, architecture, security scope, and the canonical plan |
| `evidence/` and `qualification/` | Original observations and their verification inputs |
| `.github/workflows/` | Required checks and separately scoped research workflows |

Historical observations retain their original source identities and failures.
A path recorded inside a historical contract identifies that contract's frozen
source; it is not a requirement to restore an obsolete implementation in the
current tree. Use the contract's pinned revision and existing archive readers.

## Development and validation

Work on an allowed development branch and run the project preflight before
editing or building:

```sh
bash scripts/project-preflight.sh
cargo metadata --locked --manifest-path trillionnium/Cargo.toml --format-version 1
cargo fmt --manifest-path trillionnium/Cargo.toml --all -- --check
```

Run the retained Rust tests and strict static checks for the source being
changed. The required CI also checks exact source identity, negative controls,
evidence readers, and local documentation links:

```sh
cargo test --locked --manifest-path trillionnium/Cargo.toml --workspace --all-targets --all-features
cargo test --locked --manifest-path trillionnium/Cargo.toml --workspace --doc --all-features
cargo clippy --locked --manifest-path trillionnium/Cargo.toml --workspace --all-targets --all-features -- -D warnings
python3 scripts/ci/check_repository.py
python3 scripts/refresh_distributed_source_inventory.py --check
```

When adding or removing current Rust/configuration inputs, regenerate the
embedded distributed source inventory with
`python3 scripts/refresh_distributed_source_inventory.py`. Keep historical
policies and signed domains unchanged during source cleanup; update only the
reviewed current source bindings that actually changed.
