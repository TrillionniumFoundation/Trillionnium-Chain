# Trillionnium Chain

Trillionnium Chain is the Rust implementation of the Trillionnium native
PoCO-BFT Layer 1. The repository contains the deterministic consensus kernel,
canonical protocol and state transition, safety persistence, signer journal,
node candidate, finality verification, migration tooling, operator controls,
and evidence gates.

## Current status

**Native PoCO-BFT v0 is the only future production consensus route.** The current
repository is still a source-bound engineering candidate:

- `production_candidate=false`;
- `production_consensus_activation=false`;
- public-testnet readiness is false;
- release readiness is false;
- the default `trnm-poco-node` startup path intentionally refuses activation.

CometBFT, `trnm-consensus-app`, and `trnm-node` are excluded migration residue.
They may be used only for historical differential replay and one-way migration
work; they cannot authorize a release, deployment, fallback, or readiness claim.

The machine-readable authority is `config/consensus-mainline.json`. The canonical
execution and promotion contract is
`docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md`.
`RELEASE_READINESS.md` is a human-readable projection, not a second authority.
A commit-bound projection can be generated with:

```bash
python3 scripts/ci/generate_release_status_v1.py --check-deterministic
```

## Active architecture

The active workspace is `trillionnium/Cargo.toml`. Its security-critical path is:

```text
authenticated ingress / state sync
  -> trnm-poco-node
  -> trnm-consensus-core
  -> trnm-consensus-safety-rules
  -> trnm-consensus-safety-store / trnm-consensus-signer-journal
  -> trnm-native-application / canonical execution and state root
  -> finality and light-client verification
```

Important active packages include:

- `trnm-consensus-types`: bounded canonical wire and signing types;
- `trnm-consensus-crypto`: verification-only consensus cryptography boundary;
- `trnm-consensus-core`: deterministic, I/O-free PoCO-BFT transition kernel;
- `trnm-consensus-safety-rules`: authoritative vote/timeout safety policy;
- `trnm-consensus-safety-store`: durable safety-state journal and readback;
- `trnm-consensus-signer-journal`: intent/signature journal with watermark seam;
- `trnm-native-application`: canonical application validation/execution boundary;
- `trnm-poco-node`: fail-closed host and candidate process compositions;
- `trnm-state`, `trnm-runtime`, and `trnm-protocol`: canonical application state;
- `trnm-finality-types` and `trnm-finality-verifier`: consumer verification API.

Use Cargo metadata rather than this overview when exact workspace membership is
required.

## Prerequisites

- Rust `1.95.0`, pinned by `rust-toolchain.toml`;
- Git;
- Python 3.11 or newer for repository/evidence validators;
- for `web4-frontend`: Node.js `>=24.18.0 <25` and npm `>=11.16.0 <12`.

## Checkout and baseline verification

```bash
git clone https://github.com/TrillionniumFoundation/Trillionnium-Chain.git
cd Trillionnium-Chain
rustup toolchain install 1.95.0 --profile minimal --component rustfmt --component clippy
rustup override set 1.95.0
python3 scripts/ci/check_repository_truth_v1.py
python3 scripts/ci/check_external_evidence_v1.py
cd trillionnium
cargo fmt --all -- --check
cargo check --workspace --all-targets --locked
```

Every pull request must run the actor-independent GitHub-hosted checks
`repository-truth`, `rust-baseline`, and `external-evidence-contract`. A skipped,
queued, stale-head, synthetic-merge, or self-authored result is not acceptance
evidence.

## Candidate node boundary

The default node is deliberately not a production daemon. Candidate-only G2
commands exist for exact manifest-bound local process evidence:

```text
trnm-poco-node prepare-g2-manifest-bound-candidate-v2 \
  <absolute-run-root> <absolute-manifest> <manifest-sha256>

trnm-poco-node run-g2-manifest-bound-candidate-v2 \
  <absolute-run-root> <absolute-manifest> <manifest-sha256> \
  <process-pin-checksum>
```

Those commands do not prove production networking, validator signing, voting,
pacemaker/finality, HSM custody, state sync, power-loss recovery, or activation.
See `OPERATIONS.md` before executing any candidate fixture.

## Evidence and promotion

External blockers are accepted only through the schema and validator under
`docs/evidence/external/`. The release form of the validator fails closed unless
all required evidence is independently signed and bound to the exact commit and
tree. Required real-world evidence includes independent protocol review, real
4/7/31/100-node multi-host campaigns, an external HSM/monotonic anchor, physical
power-loss recovery, independent audits/red team, and completed 72-hour/7-day/
30-day wall-clock campaigns plus governance authorization.

Do not convert simulations, local SIGKILL tests, local file watermarks, shortened
soak, or self-review into production claims.

## Security and contributions

Report vulnerabilities according to `SECURITY.md`; do not publish an unpatched
exploit in a public issue or pull request. Critical paths are covered by
`.github/CODEOWNERS`. Changes must identify the exact source tuple, affected
invariants, tests and mutants, invalidated downstream evidence, and explicit
non-claims using `.github/pull_request_template.md`.

The repository is MIT licensed; see `LICENSE`.
