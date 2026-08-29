# G2D deterministic execution, MVCC and fee package v1

Status: **MODULE_CLOSED_CANDIDATE for the independent serial-equivalence model / canonical runtime and JMT blocked**

Package ID: `G2D_EXECUTION_MVCC_FEE_V1`
Agent: `A13`
Upstream Agent/Market candidate: `22057ba70c4ba2a1922dbbd02562f5ff960664f0`.

## Closed candidate surface

- explicit read object/version sets and one declared write target;
- parent-snapshot speculative execution;
- canonical transaction-index validation;
- deterministic re-execution on stale speculative reads;
- `Success`, `Reverted`, and `OutOfResource` receipts;
- four resource counters and checked fee arithmetic;
- sorted block-end fee-delta reduction;
- deterministic state, receipt, resource and fee roots under worker counts 1/2/4/8 and varied speculative schedules.

## Invariants

1. Canonical transaction index, not worker completion order, determines committed effects.
2. Every successful write consumes the exact current version and increments it once.
3. Stale speculation is re-executed against the canonical prefix.
4. Reverted and out-of-resource outcomes write no application object but retain an explicit receipt and deterministic fee.
5. Resource and fee arithmetic is checked and nonnegative.
6. Fee deltas sum to zero after sorted reduction.
7. Execution emits typed economic intents only; it cannot pay, refund, slash, burn, credit treasury or create PoCO weight.
8. A local model root is not the application JMT root.

## Command

```bash
bash scripts/ci/check_mvcc_serial_equivalence_model_v1.sh
```

## Remaining gaps

- canonical `AgentTransactionV1` decoding and authorization;
- production deterministic runtime/profile and complete meter schedule;
- actual parallel Rust worker pool and fork-aware overlays;
- authenticated JMT writes and inclusion proofs;
- Node/Order finalization, restart and state-sync integration;
- independent implementation replay over canonical CEV1 bytes.

## Non-claims

```text
g2d_exit=false
real_runtime_integrated=false
application_jmt_authority=false
node_integration=false
settlement_authority=false
production_candidate=false
```
