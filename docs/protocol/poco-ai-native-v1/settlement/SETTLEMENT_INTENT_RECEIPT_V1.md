# Settlement intent and receipt v1 candidate contract

Status: **candidate-non-normative; globally disabled**.

`SettlementIntentV1` is immutable and chain-derived. It binds the admitted transaction, task/lease/result, verification profile, DA/Order/execution roots, payer/payee, escrow/bond assets and objects, fee/price/policy roots, maturity height, expiry and idempotency nonce.

`SettlementReceiptV1` is the only transition allowed to move economic state. Amounts are derived from the committed policy and available escrow/bond state; a caller cannot supply provider payment, refund, reward, slash, burn or treasury amounts.

Terminal paths are exactly-once:

- mature `ResultFinal`: provider payment, protocol fee, verifier reward, burn, refund and bond release;
- `ResultRejected`: escrow refund and policy-derived provider-bond slash/reward/treasury split;
- cancelled or expired task: escrow refund and bond release;
- unknown, immature, insolvent, stale-price, wrong-asset or related-party-forbidden intent: no state mutation.

All assets conserve independently. Settlement-derived reputation and PoCO weight remain ineligible until a separate G5 governance/economic activation proof.
