# TrillionniumChain PoUW V1 Release Notes

Date: 2026-02-18

## Summary

PoUW (Proof of Useful Work) task settlement flow is now implemented as a challengeable lifecycle:

1. `submit-result` (worker submits deterministic result hash)
2. `challenge-result` (challenger opens dispute within window)
3. `resolve-challenge` (authority resolves success/fail)

This replaces the previous one-shot `update-task` completion behavior for normal operations.

---

## New Tx Messages

- `MsgSubmitResult`
- `MsgChallengeResult`
- `MsgResolveChallenge`

CLI tx commands now include:

- `chaind tx workload submit-result [task-id] [result-hash] [result-uri]`
- `chaind tx workload challenge-result [task-id] [reason] [evidence-uri]`
- `chaind tx workload resolve-challenge [task-id] [challenge-succeeded] [final-result-hash] [memo]`

## New Query APIs

- `Query.Challenge`
- `Query.ChallengeAll`

CLI query commands now include:

- `chaind query workload list-challenge`
- `chaind query workload show-challenge [id]`

## New Data Structures

- `Challenge` object store (`id`, `taskId`, `challenger`, `worker`, status, deposit, reason, evidence, heights)
- `Task` extended fields:
  - `challengeDeadlineHeight`
  - `challenger`
  - `challengeId`

## Economic Flow (V1)

### On `challenge-result`
- Challenger deposit is transferred from challenger account to workload module account.

### On `resolve-challenge` (challengeSucceeded=true)
- Worker is slashed per parameter.
- Challenger deposit is refunded.
- Task moves to `SLASHED`.

### On `resolve-challenge` (challengeSucceeded=false)
- Challenger deposit is partially burned (`challenger_slash_percent`).
- Remainder refunded to challenger.
- Task finalized as completed and task bounty burn policy applied.

### Auto finalize
- In EndBlock, tasks in `RESULT_SUBMITTED` status are auto-finalized once challenge window expires.

## Deprecation

- `update-task` remains available for compatibility but is deprecated for normal PoUW settlement.
- Deprecated path now emits deprecation event to encourage migration.

## Reliability Fixes Included

- CLI smoke flow stabilized by waiting for tx commit before state assertions.
- Guarded against ambiguity when first challenge ID is `0` by using task status semantics (not `challengeId != 0`) to determine challenged state.
