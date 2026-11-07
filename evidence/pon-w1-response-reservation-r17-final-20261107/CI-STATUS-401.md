# 401 CI failure readback supplement

**HOLD / NO-GO remains.** This supplement records newly observed failures on
head `40194538c7d74d860f9f0460d9f5f886df13281c` and its actual prospective
merge `06110d0bd0a285c249e2b6db9352fe131acc8939`. Their tested tree is
`977db7f413da494051d84ed3eecd1eb0522dfd12`. These records are separate
from the historical f97 campaign and History audits in the main report.

## Source-specific CI snapshot

During 2026-11-07 **18:50:56–18:51:11 UTC**, the workflow endpoints reported
7 successful, 2 failed and 7 still-running workflows. Job endpoints reported
66 successful, 9 failed, 27 still-running and 3 skipped jobs. The endpoints were
read over an interval, not as one atomic scheduler snapshot. Later progress
must be read from its own timestamps.

[The complete snapshot](validation/final-pr-publication/ci-snapshot.json)
retains the workflow/job identities and failed steps. All nine observed failed
jobs' complete original logs and their download receipts are retained in
[the log inventory](validation/ci-401-failed-job-logs/summary.json).
These include both fresh-service lanes, historical-artifact retrieval, the
ROOT F0 diagnostic, both cross-architecture from-zero lanes, both protocol
contract lanes and the original campaign. The status alone does not establish
a cause for every failed job.

## Protocol-contract: named tests passed; confirmation target failed

Both complete original protocol-contract archives were downloaded and checked
against their GitHub SHA256 digests:

| Lane | Artifact | Original ZIP SHA256 |
| --- | --- | --- |
| head | 13586450816 | `ff3c6d106368790dc50873d2ccf9b8e4385bbc13f86db25fa95320b70777ca5b` |
| prospective merge | 13586635491 | `11f787362d086b651f6af06e4147a21709ab7958eb3277e1fdcec6de2ed0cf6d` |

Each lane actually executed the same five named native selectors. Each
invocation returned exit 0 without a process timeout, with one named test
executed and passed. Formatting passed. The service and sustained report
acceptance stages passed; the sole recorded failure was
**`CONFIRMATION_TARGET`** at confirmation-report acceptance.

| Original finite offer | head | prospective merge |
| --- | ---: | ---: |
| Unique business transactions required per phase | 1 | 1 |
| Original window | 4 seconds | 4 seconds |
| Baseline independent confirmation | 1/1 | 1/1 |
| Baseline successful confirmation time | 3.011656873 s | 3.092963829 s |
| Pressure workers | 16 | 16 |
| Pressure independent confirmation | **0/1** | **0/1** |
| Pressure unconfirmed / unknown | 1 / 0 | 1 / 0 |
| Pressure Submit ACKs inside original window | 7/7 | 7/7 |
| Pressure History network responses inside original window | 3/3 | 3/3 |
| Pressure independent page replays accepted inside window | 2/3 | 2/3 |
| Pressure replay verification error | `PUBLIC_REQUEST_DEADLINE` | `PUBLIC_REQUEST_DEADLINE` |

Seven ACKs are not seven independently confirmed business transactions.
Successful History network responses do not establish successful native page
replay. The deadline remains a service outcome, not consensus invalidity.
The Host records retain the original resource contract and report no Host
readiness errors; the manifests do not record a native test assertion failure.

The terminal records say `native_execution_completed=true` because all five
planned child invocations returned, and `finalization_completed=true` because
the terminal record was written. They also preserve
`acceptance_passed=false` and the legacy `execution_finished=false`.
Neither execution closure nor finalization is service acceptance.
The original confirmation reports remain present with matching pre-validation
and retained digests, even though the legacy accepted-report field is null.

Source commit/tree and each lane's binary digest are stable within that lane.
The preparation receipt and final workflow source receipt use different source
kind labels for the prospective merge; the actual commit/tree agree. The two
lanes do not have identical binary digests. No cross-lane binary equivalence is
claimed.

[Machine-readable triage](ci-401-failure-triage.json),
[head original manifest](validation/ci-401-protocol-artifacts/13586450816/files/from-zero-native/manifest.json),
[merge original manifest](validation/ci-401-protocol-artifacts/13586635491/files/from-zero-native/manifest.json),
[head complete ZIP](validation/ci-401-protocol-artifacts/13586450816/artifact.zip),
and [merge complete ZIP](validation/ci-401-protocol-artifacts/13586635491/artifact.zip)
retain the actual observations.

This localizes the failed acceptance criterion. It does not attribute the missed
target to one production change, prove anonymous fairness, establish a work-cost
lower bound, or qualify WAN, capacity, tail latency or economic break-even.
The published production head is unchanged by this evidence supplement.
