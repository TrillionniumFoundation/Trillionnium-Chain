# Production authority session v0

Status: implementation contract; exact-source Rust and consumer acceptance pending; not an activation record.  
Primary module: M15. Authority fact producers and consumers: M03/M06/M07/M08. Development order remains exclusively in the canonical Plan v2.

## Purpose

`ProductionAuthoritySessionV0` closes the information-loss seam between the durable authority ledger and production composition. `RecoveryDispositionV0::Resume` identifies only operation binding, durable stage and sequence. Those fields are useful for diagnosis, but they do not contain the facts digest or record digest needed to distinguish an exact idempotent replay from a substituted acknowledgement.

The session receives an explicit readback function for the durable adapter's authenticated current `AuthorityReceiptV0`. A resumed summary without that complete receipt does not restore write authority. `Clean` accompanied by a retained receipt is inconsistent. Node identity is checked before and after every fallible coordinator call, and a complete receipt is retained only after the returned receipt and fresh readback agree exactly.

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

`begin_prepared` has three legal cases:

1. create the initial `Prepared` record at sequence zero;
2. replay the exact retained `Prepared` receipt after response loss;
3. after an exact `OutboundPublished` terminal receipt, begin the coordinator-validated parent-bound next operation at the next durable sequence.

`advance` accepts exactly one successor stage. A newly applied receipt must bind the same operation, requested stage and facts, increment the durable sequence by one and change the record digest. A same-stage replay is accepted only when the complete returned and read-back receipts equal the retained receipt. Stage skips, reordering, operation substitution, facts substitution, zero digests and sequence exhaustion fail closed.

Before every fallible write, local readiness changes to `Recovering` and the cached receipt is discarded. Any adapter error, lost acknowledgement, identity drift or post-write readback mismatch therefore requires a fresh complete recovery. Quarantine never grants write readiness.

## Authority boundary

The session owns orchestration state only. It does not decide application validity, construct Safety facts, sign, verify finality, create checkpoints, publish frames or activate production. The relevant authority owner must prove and supply the exact facts digest before requesting its stage transition.

The readback function is a trusted composition port and must call the durable coordinator's authenticated, closed-world current-receipt API. A cache or caller-constructed receipt is non-conforming. The generic host remains available for compatibility; production adoption requires the durable file coordinator and node authority wrapper to use this session, or expose an equivalent complete-receipt contract, followed by full crash and consumer qualification.

## Required verification

Exact-source qualification must cover at least:

- clean recovery and inconsistent clean-plus-receipt rejection;
- resumed summaries with missing, stale or substituted complete receipts;
- every legal successor and every skip or reorder;
- response loss after every durable append followed by exact recovery and replay;
- operation, identity, facts, stage, sequence and record-digest substitution;
- sequence exhaustion, quarantine and coordinator failure before and after durable write;
- first operation, terminal operation and parent-bound next operation;
- durable-file and node-authority consumers, independent process restart and complete record-chain validation.

The local crate regressions cover the complete in-memory lifecycle, recovery after a lost acknowledgement, missing and substituted readback, stage skips, exact replay, terminal-to-next operation and quarantine. They do not substitute for fixed-toolchain compilation, durable consumer tests, physical power-loss evidence, HSM/anchor evidence, multi-host campaigns, independent review or release authorization.

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

A successful source, unit or consumer check does not change `production_candidate`, public-testnet, release or activation truth.
