# G2B Agent, capability and task-market package v2 replay

Status: **MODULE_CLOSED_CANDIDATE for A12-owned assurance surfaces / G2B remains BLOCKED_UPSTREAM**

Package ID: `G2B_AGENT_MARKET_V1`  
Agent: `A12`  
Exact base: PR #32, `feature/chain-a11-g2a-da-fullrep-v2-20260829@2fb72d01e49350d3b5dad158a6eaada37c0794b5`, tree `62fc26484927cbb9d7aa75a8c094d909e31b1537`.

## Candidate surfaces closed in this replay

- controller/session identity distinction;
- attenuated operation scope, nonce lanes and shared spend budget;
- Task/Bid/Lease/Escrow/checkpoint/pause/resume/migrate/cancel/timeout/refund lifecycle;
- exactly-once nonce and refund behavior;
- deterministic controller generation and controller/recovery rotation model;
- stale-session invalidation after controller rotation;
- recovery quorum uniqueness and threshold checks;
- deterministic committed capability/session state root;
- model, tool, endpoint and privacy-scope attenuation;
- retained negatives for replay, escalation, duplicate lease/refund, stale generations and recovery misuse.

## Commands

```bash
bash scripts/ci/check_agent_market_model_v1.sh
bash scripts/ci/check_agent_market_replay_v2.sh
```

The v2 extension is deliberately non-cryptographic. It freezes transition semantics and commitments but cannot create accepted CEV1 authorization, signatures, Order membership or global state authority.

## Remaining blockers

- accepted `AgentTransactionV1` wire bytes, domains and second binary parser;
- accepted A08/A10 operation and transport interfaces;
- cryptographic root/controller/recovery signatures and committed-set proofs;
- canonical application JMT and finalized Order proof carrier from A16/G1;
- durable Rust/process integration, crash/replay and whole-store anti-rollback;
- A14 result/challenge and A15 settlement joins.

## Non-claims

```text
g2b_exit=false
agent_transaction_wire=false
cryptographic_authority=false
global_state_authority=false
node_integration=false
production_candidate=false
production_consensus_activation=false
```

Any change to A08–A11 source pins, operation assignments, AgentTransaction encoding, DA namespace or whole-node root authority invalidates this package and every downstream A13–A17 result.
