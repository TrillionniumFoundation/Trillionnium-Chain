# Deterministic re-execution verification profile v1 candidate

Status: **candidate-non-normative; globally disabled**.

## Statement

The verifier proves only that the frozen deterministic runtime, given the exact input commitment and seed, reproduces the committed output and trace for one `(task, lease, attempt)` under one exact profile hash.

Required bindings:

```text
task_id
lease_id
attempt
runtime_digest
input_commitment
output_commitment
seed
trace_root
profile_id/profile_version/profile_hash
accepted_order_height/accepted_order_block_id
```

A profile ID without the committed hash is invalid. Runtime, model, tokenizer, compiler, kernel, precision or seed drift creates a different statement.

## Result state

```text
ResultPending
 -> ChallengeWindow
 -> ResultFinal             (deadline with no challenge or rejected challenge)
 -> ResultRejected          (upheld challenge)
```

The Order block remains finalized throughout. A challenge is a new ordered transition.

## Failure classes

- malformed evidence: terminal input rejection;
- deterministic mismatch: invalid result;
- backend unavailable: retryable unavailable, never success and never automatic invalidity;
- profile disabled/expired/revoked: admission or evaluation rejection;
- unknown profile: rejection, no fallback;
- subjective profile: may produce an opinion record only, never objective result/settlement/PoCO authority.
