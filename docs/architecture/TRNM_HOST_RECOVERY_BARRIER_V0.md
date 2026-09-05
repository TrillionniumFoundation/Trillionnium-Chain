# Persistent host identity, recovery, and process-stage barrier v0

Primary modules: M15 for host composition and M03 for the candidate file
adapter. Consumers: authority adapters, production-shaped node composition, and
M17 qualification. This is a stable implementation contract under the
[canonical Plan v2](../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md),
not a release, production, or activation record.

## Identity and generic-host readiness

A generic `PersistentValidatorHostV0` captures one validated `NodeIdentityV0`
at construction. A different chain, validator, application, or generation
cannot be adopted by changing an adapter behind that host; it requires a
separately constructed and recovered host. Identity is checked before and after
recovery and authority application, and around I/O polling. This does not
authenticate an arbitrary malicious adapter or replace trusted composition and
exclusive lifecycle ownership.

`recover()` first sets `Recovering`, before calling a fallible adapter. Only a
successful response with the same identity and, for Resume, a valid operation
binding can restore `Ready`. Errors, invalid resumed bindings, and unwinding
must not retain readiness from a previous successful recovery. Quarantine
remains a non-ready disposition.

`prepare_bound_ingress()` rejects malformed input before calling the authority
adapter. Such a peer/input error does not revoke a valid recovery barrier.
Immediately before Begin application, readiness becomes Recovering. A write may
have occurred despite a failed or lost acknowledgement; an adapter error or an
invalid returned binding, stage, facts digest, or record digest leaves the host
non-ready. Only the complete validated receipt restores Ready. No implicit retry
is performed. Fresh adapter recovery and exact idempotent replay resolve an
uncertain write. The host does not remint an operation, reset a sequence, or
invent a durable fact.

I/O unavailability and malformed ingress remain local errors, not consensus
invalidity or automatic invalidation of otherwise known durable authority.
Polling after authority uncertainty is blocked until recovery succeeds.

## Candidate process-stage progression

The candidate-only `trnm-candidate-persistent-host` process exposes three
commands behind the explicit `--acknowledge-candidate-only` flag:

```text
status
prepare
advance
```

`prepare` keeps the generic host boundary for `BoundIngressV0 -> Prepared`.
Before reporting success it drops the original file owner, reopens the exact
root and identity, validates the authority chain again, and requires exact
receipt readback.

`advance` opens the reviewed `FileAuthorityCoordinatorV0` directly because the
generic host deliberately owns no application, Safety, signer, finality, or
checkpoint fact producer. The command accepts only a non-zero opaque fact
digest and one exact stage from:

```text
ApplicationSealed -> SafetyPersisted -> SignIntentPersisted
 -> SignatureConfirmed -> FinalityApplied -> CheckpointConfirmed
 -> OutboundPublished
```

The process recovers the current durable receipt, requires the requested stage
to be either its exact successor or an exact idempotent replay of the current
stage, and delegates one `AuthorityCommandV0::Advance`. For a new stage it
recomputes the expected sequence and hash-chain record digest from the current
receipt before accepting the adapter response. For a replay it requires the
complete returned receipt to equal the recovered receipt. It then releases the
file lock, reopens the root in a fresh owner, validates the full chain, and
requires exact readback before printing success.

A skipped stage, zero or substituted fact, changed binding, unexpected
sequence, changed record digest, missing Prepared record, stale next-height
parent, or fresh-readback mismatch fails closed. Every invocation is a new
process, so the process regression exercises lock release, journal reopen, and
recovery between stages rather than retaining an in-memory coordinator.

The process treats fact digests as inert bytes. Reaching a stage name does not
prove that an application was executed, SafetyRules persisted, a signer was
called, a QC finalized, a checkpoint was externally anchored, or a frame was
published. In particular, `SignatureConfirmed`, `FinalityApplied`, and
`CheckpointConfirmed` remain journal labels until their respective M03/M08
producers and consumers are integrated and independently qualified.

## Verification boundary

`host_recovery_tests` contains thirteen actual generic-host tests covering
repeated recovery errors, invalid Resume, adapter panics, Begin failure before
and after recording, receipt substitutions, identity changes, invalid initial
identity, and positive controls for peer/I/O errors and exact Begin replay.

`candidate_persistent_host_process` additionally covers:

- status before any authority record;
- exact Prepared replay and substitution rejection across processes;
- seven separate-process successor appends through `OutboundPublished`;
- fresh status recovery after each stage;
- same-stage exact replay without sequence movement;
- same-stage fact substitution, skipped stage, missing prior record, zero fact,
  and unknown-stage rejection;
- a parent-bound next-height Prepared record after the prior operation reaches
  `OutboundPublished`.

```bash
cargo test --manifest-path trillionnium/Cargo.toml \
  -p trnm-node-boundary-v0 --lib --locked
cargo test --manifest-path trillionnium/Cargo.toml \
  -p trnm-durable-file-adapters-v0 \
  --test candidate_persistent_host_process --locked
cargo test --manifest-path trillionnium/Cargo.toml \
  -p trnm-poco-node-production-v0 \
  -p trnm-production-adapter-conformance-v0 --all-targets --locked
```

Run the repository-pinned compiler, formatting, strict Clippy, dependency, full
consumer, exact-head, and prospective-merge gates on one unchanged source before
acceptance. The reference coordinator, injected faults, and opaque fact digests
are test/candidate mechanisms: they do not prove hardware durability, real
signing, authenticated networking, liveness, state sync, multi-host operation,
physical power-loss recovery, external audit, production readiness, or network
activation.
