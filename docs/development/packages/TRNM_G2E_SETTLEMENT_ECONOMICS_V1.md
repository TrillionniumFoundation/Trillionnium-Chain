# G2E settlement and economic-conservation package v1

Status: **MODULE_CLOSED_CANDIDATE for independent settlement/conservation model / canonical JMT and governance blocked**

Package ID: `G2E_SETTLEMENT_ECONOMICS_V1`
Agent: `A15`
Upstream result candidate: `a2fa81505b62836f386ac1967549b5ca694a4dd4`.

## Closed candidate surface

- immutable `SettlementIntentV1`-shaped input bound to task, lease, result, payer, provider, asset, escrow, bond, price root, policy root, maturity and idempotency nonce;
- policy-derived provider payment, protocol fee, verifier reward, burn, consumer refund and bond disposition;
- separate escrow and bond assets;
- exact replay after response loss and nonce-conflict rejection;
- terminal paths for final result, rejected result, cancellation and expiry;
- per-asset conservation including treasury, burn and bond buckets;
- fail-closed insolvency, stale-price, wrong-asset, related-party, overflow, premature maturity and unknown-status cases;
- explicit PoCO-weight ineligibility.

## Invariants

1. Caller input never selects terminal payment amounts.
2. A result must be mature and bound to the exact task/lease/profile facts.
3. Every asset conserves independently; burn is an explicit terminal bucket.
4. Escrow and bond cannot be paid/refunded/slashed twice.
5. Exact retry returns the same receipt; same nonce with different intent fails closed.
6. Result rejection refunds escrow and applies the frozen bond policy without rewriting Order or result history.
7. Related-party policy is checked before economic state changes.
8. Settlement receipt does not grant PoCO weight before G5.

## Command

```bash
bash scripts/ci/check_settlement_conservation_model_v1.sh
```

## Remaining gaps

- canonical multi-asset and fee-schedule schemas/hash roots;
- accepted Agent/DA/Order/Execution/Result proofs;
- application JMT inclusion and whole-node CAS;
- durable crash/response-loss implementation and two independent replayers;
- complete solvency, MEV, Sybil/cartel and governance simulations;
- production treasury/burn/issuance authority and G5 eligibility.

## Non-claims

```text
g2e_exit=false
canonical_settlement_receipt=false
application_jmt_authority=false
poco_weight_eligible=false
governance_activation=false
production_candidate=false
```
