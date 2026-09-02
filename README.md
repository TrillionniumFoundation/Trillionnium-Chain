# Trillionnium Chain

Trillionnium Chain is the Rust implementation of the Trillionnium native
PoCO-BFT Layer 1. The repository contains the deterministic consensus kernel,
canonical protocol and application state transitions, safety persistence,
signer journal, node candidate, finality verification, migration tooling,
operator controls, and source-bound evidence gates.

## Current status

**Native PoCO-BFT v0 is the only future production consensus route.** The current
repository remains an engineering candidate:

- `stage=G1-native-host-incomplete`;
- `production_candidate=false`;
- `production_consensus_activation=false`;
- public-testnet readiness is false;
- release readiness is false;
- the default `trnm-poco-node` path remains fail-closed.

Protected `main` remains the canonical destination. Draft PR #62 on
`work/plan-v2-full-gap-closure-20260902` is the sole selected integration
successor. The plan assesses ancestor baseline
`af691ea5005e1f0262e90c4fc878ba0a70dbe7ea`
(tree `af09e389b1a462b3839508b7ef305596c76384c6`); current source and
prospective-merge identities are derived at verification time.

The selected line combines the descriptor-bound A04/A19/A23 source train, the
Node Commit Ledger, persistent deterministic 1/2/4/8-worker execution
equivalence, one active development plan, and machine-checked M00-M17 source and
technical-document coverage. These are implementation-present,
acceptance-pending facts. They do not establish public-testnet, production,
release, protocol-freeze, or activation authority.

The machine-readable authority is `config/consensus-mainline.json`. The sole
active execution, modularization, team, and promotion plan is
`docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md`.
The stable module contract reference is
`docs/modules/TRNM_MODULE_TECHNICAL_REFERENCE_V1.md`, and exact primary source
ownership is in `config/module-coverage-v1.toml`.
`RELEASE_READINESS.md` is a human-readable projection, not a second authority.

Development-document history is kept in Git history, not in an active archive,
agent-prompt, package-plan, sprint-board, or continuation tree. CI rejects a
second plan, recreated retired trees, stale active references, orphan or
multiply owned crates, module dependency cycles, and missing module
contract/SLO/testkit entries.

## Target architecture

The target is an 18-module system for a roughly 40-50 person team:

```text
versioned contracts
  -> deterministic domain cores
  -> bounded adapters
  -> node composition
  -> out-of-band global control plane
```

Consensus, SafetyRules, deterministic execution scheduling, canonical state
commit, finality, checkpointing, and whole-node recovery stay in the low-latency
in-process hot path. Remote signer/HSM, DA workers, state-sync download, RPC and
indexing, proof generation, telemetry, and global planning may be isolated.

The global control plane may observe, allocate bounded operational resources,
and stage reversible signed plans, but it cannot sign, vote, finalize, create an
authoritative state root, bypass SafetyRules, erase evidence, or activate
production.

The active workspace is `trillionnium/Cargo.toml`. Use Cargo metadata,
`docs/development/module-registry-v1.toml`, and
`config/module-coverage-v1.toml` rather than this overview when exact membership
or ownership is required.

CometBFT, `trnm-consensus-app`, and `trnm-node` are excluded migration residue.
They may support historical differential replay and one-way migration only;
they cannot authorize a release, deployment, fallback, or readiness claim.

## Prerequisites

- Rust `1.95.0`, pinned by `rust-toolchain.toml`;
- Git;
- Python 3.11 or newer for repository and evidence validators;
- for `web4-frontend`: Node.js `>=24.18.0 <25` and npm `>=11.16.0 <12`.

## Checkout and baseline verification

```bash
git clone https://github.com/TrillionniumFoundation/Trillionnium-Chain.git
cd Trillionnium-Chain
rustup toolchain install 1.95.0 --profile minimal --component rustfmt --component clippy
rustup override set 1.95.0
bash scripts/ci/check_canonical_development_plan.sh
python3 scripts/ci/check_module_coverage_v1.py
python3 scripts/ci/check_repository_truth_v1.py
python3 scripts/ci/check_blocker_execution_v1.py
python3 scripts/ci/check_external_evidence_v1.py
cd trillionnium
cargo fmt --all -- --check
cargo check --workspace --all-targets --locked
```

The protected branch binds stable actor-independent checks named by
`config/repository-policy-v1.json`. A skipped, queued, cancelled, stale-head,
synthetic-merge, different-source, or self-authored result is not acceptance.
The bounded fuzz smoke is not a long-running fuzz campaign. A green external
evidence contract validates schema and fail-closed behavior; it does not mean
that independent real-world evidence already exists.

## Development and evidence

Start all engineering work from the canonical plan. The compact machine files in
`docs/development/` identify the assessed baseline, 18-module boundary, and
current release train. Module-level technical contracts live under
`docs/modules/`; protocol specifications live under `docs/protocol/`; immutable
external-evidence submissions live under `docs/evidence/external/`; operator
procedures live in `OPERATIONS.md` and `docs/runbooks/`.

Required external facts include independent protocol/package review, real
4/7/31/100-process multi-host campaigns, device-backed HSM and monotonic-anchor
evidence, physical power-loss recovery, independent
consensus/cryptography/economic audits and red team, and completed 72-hour,
7-day, and 30-day wall-clock campaigns plus governance authorization.

Do not convert simulations, shortened runs, local SIGKILL tests, local file
watermarks, fixtures, self-review, or unsigned summaries into production
claims.

## Security and contribution policy

Report vulnerabilities according to `SECURITY.md`; do not publish an unpatched
exploit in a public issue or pull request. Critical paths are covered by
`.github/CODEOWNERS`. Every change must identify its exact source tuple, primary
module, affected contracts and invariants, tests and retained mutants,
downstream evidence invalidation, and explicit non-claims using the pull-request
template.

The repository is MIT licensed; see `LICENSE`.
