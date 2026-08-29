# G2B Agent, capability and task-market package v1

Status: **MODULE_CLOSED_CANDIDATE for independent lifecycle model / canonical wire and global state blocked**

Package ID: `G2B_AGENT_MARKET_V1`
Agent: `A12`
Upstream DA candidate: `a4db1b42110b37e3db55f0810631092ce2a3f54d`.

## Closed candidate surface

- controller/session identity distinction;
- attenuated operation scope and shared spend budget;
- per-session allowed nonce lanes and exact sequential nonce consumption;
- Task offer plus funded escrow reservation;
- Bid, one accepted Lease, provider activation, checkpoint, pause/resume, migration, cancel, timeout and refund;
- idempotency and terminal-state rejection;
- negative corpus for scope escalation, expiry/revocation, cross-lane replay, duplicate lease, budget overflow, migration without checkpoint and double refund.

## Invariants

1. A session cannot exceed its parent capability's operations, lanes, time window or shared budget.
2. One authorization consumes exactly one expected nonce only after the transition succeeds.
3. Parallel lanes share one capability budget; lane isolation is not budget duplication.
4. A task attempt has at most one live accepted lease.
5. Escrow is reserved before a lease becomes active.
6. Migration extends a committed checkpoint and cannot erase obligations.
7. Terminal states reject further ordinary transitions.
8. Refund is exactly once and cannot exceed remaining escrow.

## Command

```bash
bash scripts/ci/check_agent_market_model_v1.sh
```

## Remaining gaps

- accepted `AgentTransactionV1` bytes and second binary parser;
- root/controller key rotation and recovery policy;
- committed-set capability proofs;
- complete model/tool/endpoint/privacy resource schemas;
- authenticated global JMT integration and Order proof authority;
- cross-plane Verify/Settlement joins and process fault evidence.

## Non-claims

```text
g2b_exit=false
agent_transaction_wire=false
global_state_authority=false
node_integration=false
production_candidate=false
```
