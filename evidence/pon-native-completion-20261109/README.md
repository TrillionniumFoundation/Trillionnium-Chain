# Complete native admission before completion priority

Base: PR #821, `e798d7125724d4b9f98c24d00cc80031f2eab4a9`, tree
`f77b6240b845425e0fc75e88abb09e6cfa3a71c0`. This is a scheduling-boundary
continuation. A–G joint acceptance and production remain **HOLD_NO_GO**.

## Change

The previous public and History paths could promote after W1 verification,
before complete parent/task, M06, State/output and transaction readback checks.
Only the original storage owner now constructs `NativeAdmissionCompletion`,
after that complete relation inside the original transaction and immediately
before its original commit. The private token grants scheduling eligibility;
it is not a commit receipt or new admission authority. Current parent, owner,
epoch, time and commit fences still apply, including later failures.

Ordinary held, prepared-held, detached, Growth and shared/exclusive History
carry the original live CPU checkpoint. There is no repeated W1/State/M06
execution, new reservation or deadline. Trusted local metered helpers without
a bound public request return before the added scheduling hash/checkpoints.
The signed resource namespace advances to
`resource-revision-r18-native-completion-v1`; numeric budgets and worker limits
are unchanged. Exact profile vectors and rejection of the old namespace remain
part of the retained tests.

## Evidence scope

Six shared red/green controls cover the admission paths, bad State, bad receipts,
valid/repeated work and cold honest History. The cold control has zero initial
credit, no warmup and the same two-second test deadline on both versions. This
is not a production History default: existing page/sync budgets and the original
four-second host-pressure deadline are unchanged. A prepared-held control covers
both State backends directly; it does not qualify the dynamic large-snapshot
fallback above eight MiB.

The first baseline Cargo command compiled but selected zero tests because its
exact module filter was wrong; its wrapper rejected that observation. The
separate corrected command selected and passed the original one test, followed
by a complete source-after check. Both observations and all formatting or later
build/test failures are preserved. Static reviews under `review/` are not
execution logs. Final committed-source results and the subsequent evidence-only
commit relationship will be recorded in the delivery observation.

On the clean original #821 source, nine existing finite-model suites ran all
255 tests successfully. Their precise commands and source pins are in
`review/def-python-commands.json`. This verifies the declared finite behavior;
it supplies no all-algorithm bound or complete-history theorem. The general
cost contract retains 12 unknown L/U endpoints and MU1 retains 32.

## Open qualification

The review snapshot `review/ag-closure-matrix-review.md` records A–G conditions
and the exact D/E/F modules. Actual work-family completeness, durable total CPU
accounting across all entry/reopen/crash boundaries, same-budget Hepta four-arm
FinalUse, real classical/quantum cost bounds, initial and hidden progress,
lifetime/tail composition and native branch migration remain open.

A cold unpromoted request can exhaust its starting allowance before the final
token. At near one-CPU execution with only a 100 ms reserve and 0.25 CPU/second
refill, continuous CPU is limited to about 133 ms. That estimate assumes that
execution rate; an actual 0.25-CPU host cap changes the timing. Small-fixture
success cannot qualify all allowed State sizes. The local validation host lacks
the original root-owned `trnmponpublic.slice`; component results do not replace
that campaign. No larger credit, warmup or deadline closes this obligation.

The A/C process-exit correction continues #820 separately. Its source and
results are not this #821 continuation's acceptance. Same-version proof-backend,
WAN, cold-start, long-run and churn gates, independent FinalUse and production
activation remain unqualified.
