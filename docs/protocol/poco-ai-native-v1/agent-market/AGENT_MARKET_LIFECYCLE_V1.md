# Agent/capability/task lifecycle v1 candidate contract

Status: **candidate-non-normative; globally disabled**.

## Authorization chain

```text
Agent controller
 -> CapabilityGrant(scope, shared budget, height window, lanes)
 -> SessionKeyGrant(capability, generation, lane subset, expiry)
 -> AgentTransaction(operation, lane, nonce, charge)
```

Every child may only narrow its parent. The transaction is admitted only when the capability and session are live, operation and lane are allowed, nonce equals the exact next nonce, and shared budget can reserve the charge. Failed execution consumes neither nonce nor budget.

## Task lifecycle

```text
Draft -> Open -> Leased -> Active
Active -> Paused -> Active
Active -> Checkpointed -> Migrating -> Active
Open|Leased|Paused -> Cancelled -> Refunded
Active|Paused -> TimedOut -> Refunded
Active -> Completed -> ResultPending
```

One task attempt has at most one live accepted lease. Migration requires an exact accepted checkpoint, creates a successor lease/revision, and retains the old provider/escrow/audit obligations.

## Economic boundary

This contract reserves and releases escrow. It does not decide result validity, provider payment, slash, reward, burn, treasury movement or PoCO weight.
