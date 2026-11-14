# M12 Finite reward, service fees and free-use conservation

Revision: invariant-driven revision3. Selected target: `pon-nakamoto-v1`.
[Sole development plan](../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md); [exact invariant registry](../../config/pon/invariants-v2.json).

## Scope and ownership

Actual native/Python release and quota accounting, not external monetary value.

The claims below apply to their named component and tests, not to an independently accepted full native node.

## PoN State machine

### M12.ClaimContributionReward

Claims pay once under exact root membership; unclaimed budget refunds at a reserved deadline even if old candidates have retired. Publish reserves due capacity; claim updates balance/nullifier/remaining together; mandatory expiry returns remainder.

**Atomic/commit boundary:** Publish reserves due capacity; claim updates balance/nullifier/remaining together; mandatory expiry returns remainder.

### M12.ConsumeSponsoredQuota

Verify bound provider, deadline, positiveunits, prepaidfunds and consumer signature over provider nonce. Debit prepaid units*1024, pay fee and provider, leave consumer balance untouched. It does not imply learning/export permission.

**Atomic/commit boundary:** Atomic nativecommand transition; effects journal separately records actual delivery.

## M12.FiniteReleaseLiability

**Invariant:** Claims pay once under exact root membership; unclaimed budget refunds at a reserved deadline even if old candidates have retired. Terminal tasks/quotas can retire after deadline without allowing a new nonce to recreate their identity or reuse old consumer consent.

**Scope:** Actual native/Python release and quota accounting, not external monetary value.

**Atomic boundary:** Publish reserves due capacity; claim updates balance/nullifier/remaining together; mandatory expiry returns remainder. Task/quota IDs bind genesis context, creator, creation nonce and the complete reserved parameters; remaining-zero retirement occurs only after deadline.

**Failure schedule:** Maturity and claim deadline; Repeated proof with new nonce; Unclaimed budget; Empty old release retirement.

**Expected result:** Claims pay once under exact root membership; unclaimed budget refunds at a reserved deadline even if old candidates have retired. Terminal tasks/quotas can retire after deadline without allowing a new nonce to recreate their identity or reuse old consumer consent.

**Resource and retention rule:** 20-block maturity plus1000-block claim window;16 due slots per height shared with tasks and quotas.

## Concrete regression selectors

`formal/pon-nakamoto-v1/test_native_execution.py::NativeExecutionTests.test_unclaimed_release_budget_refunds_at_reserved_deadline`

`formal/pon-nakamoto-v1/test_native_execution.py::NativeExecutionTests.test_three_signed_release_generations_preserve_payout_and_retirement`

`formal/pon-nakamoto-v1/test_native_execution.py::NativeExecutionTests.test_terminal_task_retirement_cannot_reopen_same_resource_id`

`formal/pon-nakamoto-v1/test_native_execution.py::NativeExecutionTests.test_spent_quota_retirement_preserves_consent_identity`

These exact functions contain executable assertions. The registry only checks binding; actual outcomes and source/input identities belong to the separate qualification report.

## Module-specific threat and residual work

Replay, uncompensated liabilities, expiry starvation, sponsor self-traffic and orphaned external payouts.

Funded GPU capacity, market sustainability, fee adaptation and independent economic acceptance remain absent.

## Current source and verification

- [`formal/pon-nakamoto-v1/ledger.py`](../../formal/pon-nakamoto-v1/ledger.py).
- [`trillionnium/crates/trnm-mvcc-fee/src/pon_executor.rs`](../../trillionnium/crates/trnm-mvcc-fee/src/pon_executor.rs).

No test binding or local campaign grants independent acceptance, ordinary Hepta execution or production activation. Preserve the exact source, profile and environment of every outcome.
