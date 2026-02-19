# TrillionniumChain PoUW V1 Release Notes

Date: 2026-02-18

## Summary

PoUW (Proof of Useful Work) task settlement flow is now implemented as a challengeable lifecycle (canonical):

1. `accept-task` (bind worker)
2. `commit-result` (commit hash)
3. `reveal-result` (reveal deterministic result hash)
4. `challenge-result` (challenger opens dispute within window)
5. `resolve-challenge` (authority resolves success/fail) or EndBlock auto-finalize after window expiry

This replaces the previous one-shot `update-task` completion behavior for normal operations.

Compatibility:
- `submit-result` remains available as a legacy path for older integrations.

---

## New Tx Messages

- `MsgAcceptTask`
- `MsgCommitResult`
- `MsgRevealResult`
- `MsgChallengeResult`
- `MsgResolveChallenge`

CLI tx commands now include:

- `chaind tx workload accept-task [task-id]`
- `chaind tx workload commit-result [task-id] [commit-hash]`
- `chaind tx workload reveal-result [task-id] [result-hash] [result-uri] [reveal-salt]`
- `chaind tx workload challenge-result [task-id] [reason] [evidence-uri]`
- `chaind tx workload resolve-challenge [task-id] [challenge-succeeded] [final-result-hash] [memo]`
- `chaind tx workload submit-result [task-id] [result-hash] [result-uri]` (legacy compatibility)

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
- In EndBlock, tasks in `REVEALED` status are auto-finalized once challenge window expires.
- `RESULT_SUBMITTED` is retained only as a legacy alias name in source compatibility.

## Deprecation

- `update-task` remains available for compatibility but is deprecated for normal PoUW settlement.
- `submit-result` remains available as legacy compatibility path; canonical production flow is commit/reveal.
- Deprecated path now emits deprecation event to encourage migration.

## Reliability Fixes Included

- CLI smoke flow stabilized by waiting for tx commit before state assertions.
- Guarded against ambiguity when first challenge ID is `0` by using task status semantics (not `challengeId != 0`) to determine challenged state.
