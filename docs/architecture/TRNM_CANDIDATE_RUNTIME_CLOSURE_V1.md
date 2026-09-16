# Trillionnium bounded candidate runtime closure v1

Status: **repository implementation present / exact-source qualification required / no production or release promotion**

## Purpose

This contract records the candidate validator runtime that already exists across
`trnm-poco-lab-validator` and the private `trnm-poco-node` authority owner.  It
prevents the repository from describing the project as if only an inert node
boundary existed while also preventing the bounded laboratory composition from
being mistaken for a production validator.

The machine companion is `config/candidate-runtime-closure-v1.toml`; the
fail-closed validator is `scripts/ci/check_candidate_runtime_closure_v1.py`.

## Smoke versus semantic acceptance

`check_candidate_runtime_closure_v1.py` is a fast source-contract smoke gate.
Its `required_tokens` and `forbidden_tokens` checks catch accidental feature
wiring and promotion-flag drift only. A passing result does not establish
control-flow, inter-process replay, crash recovery, consensus liveness, or
security semantics; the report marks this scope as `lexical-smoke-only`.

The single runtime execution entry point is
`scripts/ci/check_runtime_semantic_gate_v1.py`. It has four required slots for
P0.1--P0.4. Each slot must receive an exact runner command through its named
`TRNM_SEMANTIC_*_COMMAND` environment variable and be invoked with `--run`.
Report-only mode returns `NOT_RUN`; `--require` returns non-zero until every
required command has actually executed successfully. No absent command or
source token can be recorded as semantic evidence.

Example (replace the command with the repository's exact integration test):

```bash
export TRNM_SEMANTIC_P01_COMMAND='cargo test --manifest-path trillionnium/Cargo.toml -p trnm-poco-lab-validator --test candidate_devnet_cli -- --exact four_to_seven_restart_replay'
python3 scripts/ci/check_runtime_semantic_gate_v1.py --run --require
```

The command slots intentionally remain unconfigured until the corresponding
runtime path exists. This keeps the gate honest while giving P0 implementation
one stable, machine-readable acceptance boundary.

## Repository-owned runtime chain

The candidate-only devnet command requires an explicit non-production
acknowledgement, an absolute manifest-bound run root, and a separately running
peer-lease authority.  The authority is preflighted before validator config can
open local role keys or create runtime state.

The commissioned owner thread then retains one joined runtime containing:

1. the real Native PoCO `Core` and strict consensus verification;
2. the SQLite SafetyStore and signer journal;
3. durable native execution and application state;
4. the private proposal-validation P/D/C/K journal;
5. the independent whole-node checkpoint;
6. the persistent authenticated directed LAN mesh;
7. the generation-aware pacemaker;
8. bounded collectors, relay, private runtime control, restart journal, signed
   metrics, final state, and run report.

For an ordinary proposal, the existing owner chain is:

```text
Core Proposal
  -> durable validation obligation
  -> claimed Core validation request
  -> native execution + durable P
  -> Core-issued application-seal authority
  -> durable Core D
  -> exact Safety C
  -> durable application K
  -> whole-node checkpoint CAS
  -> Core StorageAck
  -> inert exact signing request
  -> signer journal
  -> checkpoint CAS
  -> Core SignatureReady
  -> verified outbound Vote
```

Authenticated quorum and timeout certificates are applied to the same Core
owner.  A released finalization is retained as a linear owner, applied through
the native application, freshly read back, persisted to Safety, checkpointed,
and acknowledged before deferred effects are released.

## What this closure establishes

This closure establishes that the repository contains a bounded, continuous,
real-process candidate runtime rather than only disconnected interfaces or a
one-shot fixture.  It also establishes that the candidate package remains in
the `lab` build group and is excluded from `node-prod-v0`.

The validator checks both metadata and source call sites.  A boolean alone is
not sufficient: the command, mesh, pacemaker, P/D/C/K owner, finalization owner,
workflow, and build-closure edges must remain present at the same source.

## Fail-closed external boundary

The following remain explicitly absent and are required to remain false in this
closure:

- a device-backed non-exportable HSM or KMS signing authority;
- an independently administered external monotonic signer anchor;
- host attestation;
- cross-process authenticated-frame replay authority across process restart;
- production cross-platform transport qualification;
- independently operated multi-host campaign evidence;
- physical power-loss and controller-cache-loss evidence;
- independent consensus, cryptography, economics, and red-team acceptance;
- 72-hour, 7-day, and 30-day wall-clock soak evidence;
- public-testnet, production-candidate, release, governance, or activation
  authority.

A successful candidate runtime test is repository evidence for implementation,
not proof that any external fact occurred.  No local key, simulated clock,
shortened run, self-review, or source-controlled status field can close those
external blockers.

## Acceptance

Repository acceptance requires the validator below to pass on the same exact
unchanged PR head and prospective merge source:

```text
python3 scripts/ci/check_candidate_runtime_closure_v1.py
cargo fmt --manifest-path trillionnium/Cargo.toml --all -- --check
cargo check --manifest-path trillionnium/Cargo.toml \
  -p trnm-poco-lab-validator --all-targets --locked
cargo test --manifest-path trillionnium/Cargo.toml \
  -p trnm-poco-lab-validator --lib --locked candidate_devnet
cargo test --manifest-path trillionnium/Cargo.toml \
  -p trnm-poco-lab-validator --test candidate_devnet_cli --locked
```

Independent multi-host and hardware campaigns remain separate acceptance
predicates and may not be inferred from those commands.
