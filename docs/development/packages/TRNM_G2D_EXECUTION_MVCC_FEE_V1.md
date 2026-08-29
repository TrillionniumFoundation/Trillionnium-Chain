# G2D deterministic execution, MVCC and fee package v2 replay

Status: **MODULE_CLOSED_CANDIDATE for A13-owned bounded execution surfaces / G2D remains BLOCKED_UPSTREAM**

Package ID: `G2D_EXECUTION_MVCC_FEE_V1`  
Agent: `A13`  
Exact base: PR #33, `feature/chain-a12-g2b-agent-market-v2-20260830@a21285eeb90b2f1adf027cbed8039e37a05e1f6d`, tree `a3dbf4c7c7b9a5b06643b75ad951af73b893087b`.

## Candidate surfaces closed

- actual bounded in-process Rust worker pool;
- immutable parent-snapshot speculation;
- canonical transaction-index validation and deterministic conflict re-execution;
- worker-count invariance for 1/2/4/8 workers;
- explicit read/write/version commitments;
- `Success`, `Reverted` and `OutOfResource` receipts;
- four resource counters, checked fee arithmetic and sorted block-end deltas;
- payer/fee-sink conservation;
- execution receipts explicitly deny settlement, economic, PoCO-weight and global-JMT authority;
- exact source binding to replayed A12 PR #33.

## Commands

```bash
bash scripts/ci/check_g2d_source_binding_v2.sh
bash scripts/ci/check_mvcc_serial_equivalence_model_v1.sh
```

## Remaining blockers

- accepted `AgentTransactionV1` bytes/domains and operation row from A10/A12;
- production runtime and process integration;
- canonical application JMT inclusion, finalized Order proof and anti-rollback from A16/G1;
- A15-authorized balance and settlement movement;
- whole-node crash/recovery and multi-host evidence.

## Non-claims

```text
g2d_exit=false
agent_transaction_wire=false
application_jmt_authority=false
settlement_authority=false
node_integration=false
production_candidate=false
production_consensus_activation=false
```

Changes to A12 source pins, declared access semantics, fee schedule, receipt format, JMT carrier or finality proof invalidate A14–A17 evidence.
