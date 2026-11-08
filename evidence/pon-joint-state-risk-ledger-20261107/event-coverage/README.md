# EC1 finite event coverage evidence

The retained run is a complete **finite mathematical execution-model check**.
It is not a native node run, an authenticated network law, or a confirmation
security probability. All actual-world and production qualifications remain
false.

## Retained result

- [Original model inputs, derived events and exact risk arithmetic](run-001/event-coverage.json):
  SHA-256 `28350946e8879f7c897e8bb3ef4a779ef1669ec61d98734cdbbd771fc3660276`.
- [Attempt and source-hash receipt](run-001/attempt.json): PASS; relevant source
  files were hashed before and after the run and matched.
- [Full unit-test log](unittest.log) and [verification receipt](verification.json):
  **21 tests passed**. These are component checks, not whole-repository CI.

## Concrete checks

The two-confirmation family contains four probability leaves, three
history-specific confirmation starts, and 32 automatically derived subsequent
observation/selection-cut comparisons. Each path pays two `1/16` allowances.
The exact probability of at least one recorded failure is `31/256`, below the
shared `1/8` allowance. A declaration containing only the first opportunity
would cover `1/16`; EC1 refuses that omission.

Retained negative controls refuse an omitted second start, an omitted failing
leaf, a shifted start history, and future-outcome labels attached to an
unchanged prefix. The tests additionally reject a child whose prefix merely
truncates another child's record, source-prefix disagreement, missing leaf
executions, invalid raw confirmations, censored record tails, invalid cuts,
duplicated allocations, insufficient conditional allowances and overspent
path budgets.

The transient-removal family restores the inclusion before the next explicit
observation. Its original observation-only comparisons report no failure.
EC1 detects the intervening original selection and obtains exact model risk
`1/16`.

The inventory/progress families both have inventory `0` or `8` with equal
probability, and honest reference progress `0` or `2` with equal probability.
Their different joint couplings yield derived model failure probabilities
`0` and `1/2`. The evidence recomputes the marginals and failures from the
complete model records; it does not infer independence from those marginals.

## Reproduce

From the repository root, use the commands and exact scope in
[CERTIFICATE_EVENT_COVERAGE_V1.md](../../../formal/pon-nakamoto-v1/CERTIFICATE_EVENT_COVERAGE_V1.md).
The evidence command requires a new directory and will not overwrite this
run. The JSON retains every original input family and all source hashes.

The original native `Execution` model and the existing conditional risk bank
are reused without changes. No real adversary, physical clock, hidden
inventory, work-resource reduction, or all-world trace is certified here.
