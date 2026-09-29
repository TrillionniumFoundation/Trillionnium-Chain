# M12 Finite reward, service fees and free-use conservation

Revision: invariant-driven revision2. The selected target remains `pon-nakamoto-v1`.
[Sole development plan](../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md); [precise invariant/test registry](../../config/pon/invariants-v2.json).

## Scope and ownership

Actual native/Python release and quota accounting, not external monetary value.

This is an implementation boundary, not a claim of a complete native node or independent acceptance.

## PoN State machine

### M12.ClaimContributionReward

Claims pay once under exact root membership; unclaimed budget refunds at a reserved deadline even if old candidates have retired. Publish reserves due capacity; claim updates balance/nullifier/remaining together; mandatory expiry returns remainder.

**Atomic/commit boundary:** Publish reserves due capacity; claim updates balance/nullifier/remaining together; mandatory expiry returns remainder.

### M12.ConsumeSponsoredQuota

Verify bound provider, deadline, positiveunits, prepaidfunds and consumer signature over provider nonce. Debit prepaid units*1024, pay fee and provider, leave consumer balance untouched. It does not imply learning/export permission.

**Atomic/commit boundary:** Atomic nativecommand transition; effects journal separately records actual delivery.

## M12.FiniteReleaseLiability

**Invariant:** Claims pay once under exact root membership; unclaimed budget refunds at a reserved deadline even if old candidates have retired.

**Preconditions:** Exact installed revision2 context; current local owner and immutable task/evidence identities. Storage-only and controlled-attestation premises are explicitly labelled in their tests.

**Atomic boundary:** Publish reserves due capacity; claim updates balance/nullifier/remaining together; mandatory expiry returns remainder.

**Failure schedule:** Maturity and claim deadline; Repeated proof with new nonce; Unclaimed budget; Empty old release retirement.

**Expected result:** Claims pay once under exact root membership; unclaimed budget refunds at a reserved deadline even if old candidates have retired.

**Resource and retention rule:** 20-block maturity plus1000-block claim window;16 due slots per height shared with tasks and quotas.

## Concrete regression selectors

`formal/pon-nakamoto-v1/test_native_execution.py::NativeExecutionTests.test_unclaimed_release_budget_refunds_at_reserved_deadline`

`formal/pon-nakamoto-v1/test_native_execution.py::NativeExecutionTests.test_three_signed_release_generations_preserve_payout_and_retirement`

These selectors identify actual test functions, not a class-name count. A binding checker cannot label a test passed; the separate exact-source command receipt must show execution and outcome.

## Module-specific threat and residual work

Replay, uncompensated liabilities, expiry starvation, sponsor self-traffic and orphaned external payouts.

Funded GPU capacity, market sustainability, fee adaptation and independent economic acceptance remain absent.

No assertion of independent operators, physical durability, ordinary Hepta execution or future model efficacy follows from local fixtures.

## Current source and verification

- [`formal/pon-nakamoto-v1/ledger.py`](../../formal/pon-nakamoto-v1/ledger.py).
- [`trillionnium/crates/trnm-mvcc-fee/src/pon_executor.rs`](../../trillionnium/crates/trnm-mvcc-fee/src/pon_executor.rs).

Run the relevant native package and exact Python test selectors through the protocol CI lane. Preserve source hashes, failures, backend, filesystem and process/host scope. Historical evidence is never relabelled as current.
