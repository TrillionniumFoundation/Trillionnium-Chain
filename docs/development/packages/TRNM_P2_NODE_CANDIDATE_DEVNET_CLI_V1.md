# TRNM P2 node candidate devnet CLI v1

Status: **repository candidate; no Gate, public-testnet, production, release, or activation credit**

## Purpose

This package exposes the already implemented bounded Native PoCO laboratory
runtime through an explicit operator-facing binary:

```text
trnm-poco-candidate-devnet-validator
```

It does not change the default `trnm-poco-node` startup path. The production
node remains fail-closed while host-complete and production-candidate flags are
false.

## Authority ordering

The command requires the following ordering:

```text
explicit --acknowledge-candidate-only
  -> clean absolute argument and bound validation
  -> external Unix peer-lease authority preflight
  -> exact current executable identity
  -> manifest/config/topology/validator-set/workload verification
  -> local candidate role-key loading
  -> externally fenced persistent authenticated mesh
  -> fresh h1-h3 native commissioning
  -> one Core/Safety/Application owner
  -> generation-aware pacemaker and bounded multi-height loop
  -> signed terminal report or explicit process-1 parked handoff
```

The external lease authority is probed before `LoadedValidatorConfig::load`
can open any local test key or create `runtime-authority-v1`. The runtime probes
it again while establishing each directed authenticated session. Every backend
error is fail-stop.

## Invocation

Start the separately provisioned candidate lease daemon using private absolute
paths:

```bash
trnm-poco-lab-peer-lease-daemon \
  --socket /absolute/private/fence/peer-lease.sock \
  --journal /absolute/private/fence/peer-lease.journal \
  --ready-file /absolute/private/fence/ready
```

Then run one validator from its exact deployment bundle:

```bash
trnm-poco-candidate-devnet-validator \
  --acknowledge-candidate-only \
  --run-root /absolute/deployment/validator-root \
  --config /absolute/deployment/validator-root/public/configs/VALIDATOR.json \
  --peer-lease-socket /absolute/private/fence/peer-lease.sock \
  --report /absolute/deployment/validator-root/candidate-report.json \
  --duration-seconds 300 \
  --max-blocks 100
```

All paths must be absolute and free of `.`/`..`. Config and report paths must be
below the run root. A report cannot target immutable `public/` or `secret/`
inputs. Duration, block count, and lease transport timeout are hard-bounded.
The exact running binary hash must match the deployment config.

A completed report returns exit status `0`. The explicit process-1 parked
handoff returns status `75`. Argument, preflight, configuration, runtime, safety,
or evidence failure returns status `2` and no readiness claim.

## Formatting and publication provenance

The pinned Rust 1.95.0 formatter was executed by an isolated read-only
qualification job. A separate publisher verified a content-addressed Git bundle
before advancing the package branch. The one-shot publishing workflow deleted
itself from the published tree.

```text
formatted_commit=eb0f1de90d2baa5d0f8a7ef1975d7914bd9d4af9
formatted_tree=a39f46aab1a42d25dcda39468cf56016a956f427
format_scope=three candidate-devnet Rust files only
one_shot_workflow_present=false
runtime_semantics_changed=false
```

Because GitHub suppresses or marks recursive bot-authored workflow execution as
action-required, this documentation-only successor deliberately retriggers all
exact-head checks under the repository actor. It does not alter runtime code,
protocol truth, authority, readiness, or activation state.

## Repository verification

The package must pass on the exact unchanged head:

```bash
cargo fmt --manifest-path trillionnium/Cargo.toml --all -- --check
cargo check --manifest-path trillionnium/Cargo.toml \
  -p trnm-poco-lab-validator --all-targets --locked
cargo clippy --manifest-path trillionnium/Cargo.toml \
  -p trnm-poco-lab-validator --all-targets --locked -- -D warnings
cargo test --manifest-path trillionnium/Cargo.toml \
  -p trnm-poco-lab-validator --lib --locked candidate_devnet
cargo run --manifest-path trillionnium/Cargo.toml \
  -p trnm-poco-lab-validator \
  --bin trnm-poco-candidate-devnet-validator -- --help
python3 scripts/ci/check_repository_truth_v1.py
bash scripts/ci/check_poco_bft_mainline_truth.sh --pre-cutover
```

A real multi-validator execution is external campaign evidence and must not be
fabricated by this package. Its deployment bundle must be generated for the
exact candidate binary and its output must be accepted through the external
evidence contract.

## Closed repository sub-gap

The following repository-owned seam is implemented as a candidate:

```text
operator-visible bounded persistent devnet validator entry
  + explicit external peer fencing
  + exact deployment/binary binding
  + local candidate role keys
  + existing Core/Safety/Application/pacemaker runtime
```

This does not close `P2-NODE-001`. It removes the absence of an operator-visible
bounded CLI, but the complete blocker still requires production-grade external
signing and watermark authority, host attestation, cross-platform P2P identity,
process-2 start/catch-up, production state sync, transaction ingress/broadcast,
real multi-host execution, physical-fault evidence, and accepted audit/soak.

## Non-claims

```text
candidate_devnet_validator_cli=true
candidate_devnet_external_fence_required=true
candidate_devnet_local_test_keys=true
candidate_devnet_hsm_authority=false
candidate_devnet_host_attestation=false
candidate_devnet_public_testnet_ready=false
candidate_devnet_production_activation=false
validator_runtime_started=false
multi_host_campaign_closed=false
p2_node_exit=false
g1_exit=false
production_candidate=false
production_consensus_activation=false
release_ready=false
```
