# Ordinary learning recovery: implementation design

Reviewed source: `TrillionniumFoundation/hepta-private-ci` at
`2bb02f144c9405791281c2cbfa5e7fd39a591b05` (PR #5566).
This is a source review and implementation design. It is not a new runtime
qualification, a patched product, or evidence that a production owner exists.

## Current behavior

`circuit_learning_delivery.rs` durably claims the exact initial request digest
before its first `LearningIterationHandleV1::submit`. Once claimed, delivery
uses `readback`. `LearningIterationRuntimeBootstrapV1::process_readback`
restores the original checkpoint and authenticates retained stage evidence,
but performs no stage or checkpoint write. Delivery acknowledges only a
terminal coordinator. A stopped first submit therefore leaves a nonterminal
checkpoint that automatic delivery can authenticate forever without advancing.

This behavior is intentional in existing tests:
`readback_missing_or_partial_checkpoint_never_creates_or_resumes_work` and
`actual_delivery_preserves_pending_without_backend_and_claimed_with_closed_owner`.
Keep their pure-readback semantics. Changing `readback` to `submit` would change
the public recovery contract and expose the dispatch/receipt/checkpoint gap.

Explicit `process` can already resume an authenticated partial checkpoint.
`partial_and_completed_recovery_preserve_deadlines_and_only_resume_after_authentication`
checks that mechanism with synthetic owner ports. It does not establish
durable reconciliation of an original external training or evaluation job.

## Why the current contract is insufficient for automatic resumption

`CheckpointedIterationPorts::restore` reads original Root/registered CURRENT,
then calls `LearningIterationStageOwnerPortsV1::validate_recovery(snapshot)`.
That method returns only `()`. It does not state whether the next stage was
never dispatched, is still running, finished before its receipt checkpoint,
was cancelled, or has unknown remote effect. `execute_stage` returns only a
receipt/error and has no opt-in indication that a concrete implementation
atomically reconciles those cases. The top-level owner trait documents the
required stable-operation duty, but a comment is not an implemented durable
job owner. The implementations inspected in the qualification are fixtures.

Existing Cell Evaluation/attestation readback validates original outputs and
signatures. It neither owns a trainer job nor supplies a replacement evaluator
execution service. Published-generation readback likewise observes selection
and committed next-task use; it does not mint either authority.

## Minimal safe change

1. Keep `Readback`, `process_readback` and `reconcile_circuit_learning_v1`
   read-only.
2. Add `LearningIterationHandleV1::resume_registered` and a separate internal
   command mode. It requires an existing original checkpoint; `None` remains
   `CommitUncertain`. It never creates genesis, replaces owners, rewrites the
   request, or renews the deadline.
3. Add an explicit opt-in `resume_registered_stage` method to both stage and
   aggregate owner ports. Its default must return `OwnerUnavailable`, rather
   than falling back to `execute_stage`. The checkpoint wrapper forwards it
   only after its existing exact-scope checks. Existing generic providers must
   therefore fail closed until they implement actual original-job recovery.
4. The concrete host-owned implementation must reconcile and decide inside its
   original durable operation ledger, not return a `NotStarted` flag that a
   different caller later turns into a dispatch. This avoids a separate
   check/dispatch race. The method may return an authenticated original stage
   receipt, or a typed pending/uncertain/terminal refusal. It may start work only
   when the original ledger proves it has not been sent, and only under the
   same stable key and original deadline.
5. Add `resume_circuit_learning_v1` rather than changing the existing reconcile
   API. The supervised ordinary delivery loop may use this explicit mode for
   an already-claimed operation only after the installed owner has opted in.
   Terminal receipts still go through the existing exact digest ACK.

The runtime should share the existing restored-checkpoint authentication and
stage/checkpoint loop. Registration policy and stage execution policy must be
named enums, not positional booleans. Resume must validate the current Fleet,
Root, trust/revocation, frozen scope and original receipt signatures before any
owner recovery call that could dispatch new work. Recheck original deadline
and admission after waits and before checkpoint advancement as today.

## Durable original stage owner

The stage key must commit the original operation, request/initial digest,
stage, predecessor head, actor/owner identity, frozen profile/scope and original
deadline. It must be stable across process restart and must not include a fresh
timestamp, replacement account, replacement runtime or newly selected model.

| Durable state | Recovery action |
| --- | --- |
| No existing original learning checkpoint | `CommitUncertain`; no genesis or dispatch |
| Original stage admission proved not sent | Atomically retain that admission and dispatch the same stable stage key under the original deadline |
| Start intent persisted, ACK absent | Query the original provider/request identity; do not resubmit merely because a list omits it |
| Original job running | Poll/recover the same job; no duplicate job, account switch or renewed timeout |
| Original job succeeded, stage receipt uncheckpointed | Recover exact original outputs/costs/signatures, authenticate, then CAS the receipt |
| Receipt checkpoint committed, ACK absent | Observe original CURRENT and return it; do not repeat work |
| Failed/cancelled/timed-out job | Preserve original result and reconcile termination; no fresh training attempt |
| Provider effect or original identity unknown | Preserve `CommitUncertain`/owner-unavailable; no dispatch |
| All stages terminal | Reauthenticate current evidence and ACK only the exact terminal head |

Remote submission can remain uncertain when the provider offers neither an
idempotency key nor queryable original request identity. A local ledger cannot
convert that uncertainty into proof of no effect. The design preserves HOLD
in that case; it cannot promise eventual progress for arbitrary providers.

## Stage-specific requirements

| Stage | Original source required for resume |
| --- | --- |
| Experience | Original authenticated completed task and retained source/deletion/revocation frontier |
| Dataset | Same authorized data projection and immutable dataset receipt; no ambient rebuild |
| Training | Original durable job identity, account/runtime, submission state, timeout/cancel state, exact candidate and full cost records |
| Evaluation | Original frozen protocol/holdout ownership and original experiment outputs; no repeated holdout exposure to manufacture missing history |
| Proposal | Original same-proposal-id native registry/anchor result; reject changed payload and preserve existing idempotent append checks |
| Selection | Existing independent signed selection and current artifact/withdrawal evidence; no fixture signer |
| NextUse | Existing published CURRENT/FinalUse and committed distinct-task journal receipt; no replayed external action |

## Required regressions before native qualification

- Existing pure readback tests continue to perform zero stage calls and zero
  checkpoint writes for missing/partial histories.
- Resume with no original checkpoint performs zero dispatches/writes.
- Resume against an owner that has not opted in fails before dispatch.
- Failure after remote Start but before stage receipt checkpoint queries the
  same original job and records one training execution, including after actual
  owner/daemon restart.
- A failed/unknown query never creates a second job; same operation, stage,
  provider, account and deadline remain fixed.
- Known completed original job is checkpointed once; lost checkpoint ACK is
  recovered by CURRENT readback with no repeated stage work.
- Partial history reauthenticates retained signatures/actor separation before
  recovery; expired/incomplete, revoked, foreign-scope and wrong-owner cases
  dispatch no work. A fully completed valid history may be read after expiry.
- Selection and NextUse preserve real original owners and a distinct next task;
  NoUpdate still needs those stages.
- Exercise exact ordinary `ObjectiveStart -> Circuit completion -> delivery ->
  registered Resume -> terminal ACK` after a real process stop/restart, with
  original raw records and complete costs. Component tests alone do not close
  the user-facing gate.

No runtime patch is supplied because a default permissive Resume would claim a
job-recovery capability absent from the reviewed implementation. The first
implementation cut should be the concrete durable owner and its recovery
regressions, followed by the opt-in runtime mode and ordinary-loop wiring.
