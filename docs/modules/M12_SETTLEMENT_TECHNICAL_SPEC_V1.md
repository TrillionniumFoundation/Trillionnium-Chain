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

## Executed evidence and scope

[Responsibility-level evidence navigation](README.md#responsibility-and-evidence) reads
measured commits from immutable receipts. The module's entries in
[module-maturity-v1.json](../../config/pon/module-maturity-v1.json) identify actual callable
owners, controlled entrypoints, backends, persistence and exact observed test selectors.
Run `python3 scripts/ci/report_module_evidence.py --module M12` from the repository
root to see subject-byte and complete recorded-runtime matches separately, plus scenarios
not observed in each package. A byte match is not a new test run or product acceptance.
Historical v1/v3/v4 results are never repinned. The sole plan selects further work.

## Frozen evaluation and consent continuation

See [E3](../protocol/pon-nakamoto-v1/details/EVALUATION_BUNDLE.md) for exact bytes,
owner boundaries and failure schedules. No public export or future-window authority
is created by a frozen artifact. The following additional regressions are executable:

- `formal/pon-nakamoto-v1/test_evaluation_bundle.py::SettlementObservationTests.test_mutating_both_summary_and_evaluator_score_does_not_authorize_reward`.
- `formal/pon-nakamoto-v1/test_evaluation_bundle.py::SettlementObservationTests.test_zero_marginal_candidate_creates_no_ledger_or_reward`.
- `formal/pon-nakamoto-v1/test_evaluation_bundle.py::SettlementObservationTests.test_undeclared_bundle_cannot_be_read_from_summary_as_authority`.

## Mandatory expiry receipts through the native cache

Funded task/quota/release expiry emits its canonical receipt before ordinary transaction receipts. The existing native session preserves and verifies this prefix, including empty blocks and mixed 16-expiry/transaction blocks. This does not change subsidy, fees or durable ownership.

- `formal/pon-nakamoto-v1/test_native_session.py::ExpiryAndBudgetTests.test_sixteen_expiry_receipts_precede_same_block_transaction`.
- `formal/pon-nakamoto-v1/test_native_session.py::ExpiryAndBudgetTests.test_empty_expiry_block_runs_through_real_ledger_and_restart`.
- `formal/pon-nakamoto-v1/test_native_session.py::ExpiryAndBudgetTests.test_expiry_receipt_drop_reorder_and_substitution_cannot_be_rehashed`.
- `formal/pon-nakamoto-v1/test_native_session.py::ExpiryAndBudgetTests.test_real_quota_and_release_expiry_share_existing_receipt_semantics`.
