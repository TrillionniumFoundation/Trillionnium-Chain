# Production authority session v0

Status: implementation contract; exact-source Rust and consumer acceptance pending; not an activation record.
Primary module: M15. Authority providers: M03/M07/M08. Development order remains exclusively in the canonical Plan v2.

## Purpose

`ProductionAuthoritySessionV0` closes the information loss between the existing durable authority ledger and production composition. `RecoveryDispositionV0::Resume` identifies only operation binding, durable stage and sequence. Those fields are useful for diagnosis, but they do not carry the facts digest or record digest needed to distinguish an exact idempotent replay from a substituted acknowledgement.

The session therefore receives an explicit readback function for the durable adapter's already-authenticated current `AuthorityReceiptV0`. A resumed summary without that full receipt does not restore write authority. A `Clean` result accompanied by a retained receipt is also inconsistent. The session validates node identity before and after fallible adapter calls and retains the complete current receipt only after every check succeeds.

## Stage contract

The only legal sequence is:

```text
Prepared
  -> ApplicationSealed
  -> SafetyPersisted
  -> SignIntentPersisted
  -> SignatureConfirmed
  -> FinalityApplied
  -> CheckpointConfirmed
  -> OutboundPublished
```

`begin_prepared` either creates sequence zero or returns the byte-identical retained `Prepared` receipt. `advance` accepts exactly one successor. A new receipt must bind the same operation, requested stage and facts, increment the durable sequence by one and change the record digest. Same-stage response-loss replay is allowed only when the complete receipt equals the retained receipt. Stage skips, operation substitution, facts substitution, zero digests and sequence overflow fail closed before authority can advance.

Before every fallible write, the session changes its local readiness to `Recovering` and drops the cached receipt. Any adapter error or identity drift therefore requires a fresh complete recovery; callers cannot continue using a stale in-memory success. Quarantine remains terminal until an independently authorized recovery changes the durable authority.

## Authority boundary

The composition session does not decide application validity, construct Safety facts, sign, verify finality, create checkpoints, publish frames or activate production. It persists only facts supplied by the relevant authority owner. Each producer must prove its exact fact before requesting the corresponding transition. The readback closure is part of trusted composition and must call the durable adapter's authenticated, closed-world current-receipt API; a cache or caller-constructed receipt is non-conforming.

This is an additive compatibility path. The existing generic host API remains available. Adoption into the sole persistent validator requires the durable file coordinator, node authority wrapper and downstream stage owners to use this session or expose an equivalent complete-receipt contract, followed by crash/restart and consumer qualification.

## Required verification

At minimum, exact-source qualification must cover:

- clean recovery and inconsistent clean-plus-receipt rejection;
- resumed summaries with missing, stale or substituted complete receipts;
- every legal successor and every skip/reorder;
- response loss after each durable append followed by exact recovery and replay;
- operation, identity, facts, stage, sequence and record-digest substitution;
- sequence exhaustion, quarantine and adapter failure before/after durable write;
- real durable-file and node-authority consumers, process restart and retained record-chain validation.

The local unit tests in `trnm-poco-node-production-v0` cover the closed stage order and clean-session construction only. They do not substitute for fixed-toolchain compilation, durable consumer tests, physical power-loss evidence, HSM/anchor evidence, multi-host campaigns, independent review or release authorization.

Suggested entry points:

```bash
cargo test --manifest-path trillionnium/Cargo.toml \
  -p trnm-poco-node-production-v0 --all-targets --locked
cargo test --manifest-path trillionnium/Cargo.toml \
  -p trnm-durable-file-adapters-v0 -p trnm-poco-node-authority --all-targets --locked
cargo clippy --manifest-path trillionnium/Cargo.toml \
  -p trnm-poco-node-production-v0 --all-targets --locked -- -D warnings
cargo fmt --manifest-path trillionnium/Cargo.toml --all -- --check
```

A successful source or unit check does not change `production_candidate`, public-testnet, release or activation truth.
