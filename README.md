# Trillionnium Chain (TRNM)

> **Current release posture:** **Not release-ready.** The binding decision is
> [`RELEASE_READINESS.md`](RELEASE_READINESS.md); historical passes, legacy
> simulators, individual crate tests, or frontend checks must not be generalized
> into public-testnet or mainnet readiness.

Trillionnium Chain is a Rust-native Layer 1 research and engineering project for
task-based AI compute settlement. The sole production-candidate state-transition
path is:

```text
CometBFT -> trnm-consensus-app -> trnm-runtime -> committed state/AppHash
```

`trnm-protocol` owns the canonical typed transaction and object model.
`trnm-runtime` owns deterministic business-state transitions.
`trnm-consensus-app` owns ABCI++, durable storage, snapshots, validator
lifecycle, and AppHash. The older `trnm-node` binaries are frozen legacy
harnesses and are not production evidence.

## Repository map

```text
.
├── trillionnium/          # Rust workspace and canonical-chain implementation
│   └── crates/            # 18 versioned crates, each with a module contract
├── contracts/             # Rust external-contract MVPs; not host-runtime closure
├── web4-frontend/         # Read-only-first Next.js operational surface
├── docs/                  # Canonical indexes, architecture, protocol, runbooks
├── config/                # Alert policy, SLO, and freeze configuration
├── scripts/               # CI, evidence, release, and engineering automation
├── OPERATIONS.md          # Repository/operator handbook
├── SECURITY.md            # Security-reporting policy and scope
└── RELEASE_READINESS.md   # Current release truth source
```

The repository responsibility boundary is defined in
[`PROJECT_BOUNDARY.md`](PROJECT_BOUNDARY.md).

## Maturity and scope

The frozen Day-1 candidate includes accounts, balances, sequential nonces,
gas/fees, task escrow, worker acceptance, commit/reveal, paid consumption,
challenge/resolution/settlement, deterministic expiry, validator lifecycle, and
minimal execution events **only where they execute through the canonical
CometBFT path**.

The following remain deferred or release-blocking according to current truth
sources:

- dynamic public account-key onboarding;
- threshold governance and production timelock;
- staking/unbonding/jail/slashing;
- authenticated multi-host deployment and cross-host recovery;
- HSM/KMS/remote-signer lifecycle;
- durable indexer and complete explorer API;
- production bridge, oracle, external-contract, and general ZK execution;
- external security audit, SBOM/provenance closure, and long fuzz/soak evidence.

Do not hide these items by changing wording. Close them only with code,
operations, and reproducible evidence.

## Build and test

The Rust toolchain is pinned by `rust-toolchain.toml`.

```bash
# Main Rust workspace
cargo test --manifest-path trillionnium/Cargo.toml --workspace --locked

# External-contract MVP workspace
cargo test --manifest-path contracts/Cargo.toml --workspace --locked

# Documentation integrity
python3 scripts/ci/check_documentation_integrity.py

# Frontend
cd web4-frontend
npm ci
npm run ci:check
```

Canonical multi-validator evidence uses scripts under
`trillionnium/scripts/consensus/`. A successful local run remains development
evidence until the applicable multi-host, security, recovery, and operational
acceptance criteria are met.

## Module documentation

Every active Rust workspace member has a colocated `README.md` defining its
responsibilities, non-responsibilities, maturity, invariants, tests, and
activation conditions.

- [Rust workspace guide](trillionnium/README.md)
- [Rust crate index](trillionnium/crates/README.md)
- [Module catalog and maturity matrix](docs/MODULE_CATALOG.md)
- [Documentation standard](docs/DOCUMENTATION_STANDARD.md)

The module catalog distinguishes canonical, supported-consumer, operator,
client, legacy, test-only, and deferred/research surfaces. Directory presence or
test volume does not change that classification.

## Documentation entry points

- [Documentation center](docs/README.md)
- [Architecture index](docs/architecture/README.md)
- [Protocol index](docs/protocol/README.md)
- [Runbook index](docs/runbooks/README.md)
- [Release evidence index](docs/release/README.md)
- [Canonical runtime freeze](docs/architecture/TRNM_CANONICAL_RUNTIME_FREEZE_2026-07-28.md)
- [Operations handbook](OPERATIONS.md)
- [Security policy](SECURITY.md)
- [External-contract status](contracts/README.md)
- [Web4 frontend](web4-frontend/README.md)

## Contribution and evidence rules

1. Work through a review branch and pull request; do not force-push protected
   `main` or bypass independent review.
2. Bind claims to an exact commit and distinguish local, loopback, single-host,
   multi-host, public-testnet, and mainnet evidence.
3. New protocol capability must enter `trnm-protocol`, execute in
   `trnm-runtime`, route through `trnm-consensus-app`, and converge across
   validators before being called implemented.
4. Unknown versions and payloads fail closed.
5. Value movement requires an explicit funding source; proof, metering, or
   consumption evidence cannot mint value by itself.
6. Update module docs, tests, fixtures, migration notes, and the maturity catalog
   in the same pull request as behavior changes.
7. Never treat archived plans or dated evidence packs as the current release
   decision.

## Security

Read [`SECURITY.md`](SECURITY.md) before reporting a vulnerability. Do not place
unpatched exploit details in a public issue. The current policy explicitly
requires verification of the private-reporting route before external release.

## License

MIT; see [`LICENSE`](LICENSE).
