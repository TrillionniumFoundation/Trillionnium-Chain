# G2E settlement and economic-conservation package v2 replay

Status: **MODULE_CLOSED_CANDIDATE for A15-owned settlement/risk surfaces / G2E remains BLOCKED_UPSTREAM**

Package ID: `G2E_SETTLEMENT_ECONOMICS_V1`  
Agent: `A15`  
Exact base: PR #35, `feature/chain-a14-g2c-verify-challenge-v2-20260830@0ef40883e160f646158b6e483a69e2371fda989e`, tree `e1df009018c1d3f2967bdb905bdd96ab3cb6ea06`.

## Candidate surfaces closed

- immutable task/lease/result/profile/price/policy/escrow/bond intent;
- policy-derived provider/protocol/verifier/burn/refund/slash movements;
- separate escrow and bond assets;
- exact response-loss replay, nonce conflict and failure atomicity;
- per-asset conservation for final, rejected, cancelled and expired paths;
- related-party, stale-price, wrong-asset, insolvency and overflow rejection;
- deterministic economic-risk commitment independent of input ordering;
- payer/provider, provider/verifier and challenger conflicts-of-interest;
- provider and beneficial-owner Sybil concentration caps;
- provider/challenger bond minimums and wash-funding rejection;
- PoCO-weight and governance activation remain explicitly ineligible.

## Commands

```bash
bash scripts/ci/check_g2e_source_binding_v2.sh
bash scripts/ci/check_g2e_replay_v2.sh
```

## Remaining blockers

- accepted Agent/DA/Order/Execution/Result proof carriers;
- canonical application JMT inclusion and whole-node CAS;
- durable Rust/process implementation and independent replay;
- production asset registry, treasury/burn/issuance custody and governance;
- multi-host adversarial campaigns and G5 eligibility proof.

## Non-claims

```text
g2e_exit=false
canonical_settlement_receipt=false
application_jmt_authority=false
poco_weight_eligible=false
governance_activation=false
production_candidate=false
production_consensus_activation=false
```
