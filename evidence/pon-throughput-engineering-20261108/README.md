# Native throughput engineering continuation

Status: **HOLD_NO_GO**. This continuation starts from user-pinned source
`dbc1ca09c3db57ae683671a0e7c37ca0aca01f71` and preserves both original
acceptance families. The [execution profile](../../formal/throughput-v1/EXECUTION_PROFILE_V1.md)
is the implementation and observation scope; the existing development plan
remains the sole plan.

## Original acceptance remains separate

| Gate | Original obligations | This host observation |
| --- | --- | --- |
| Host service | Strictly before 4 seconds; 0.25 CPU, 2 GiB, zero swap, 256 PIDs; 16 hostile producers; original depth and cumulative work | Prerequisites failed; owned original campaign not started |
| Complete campaign | 30 seconds per phase; 3 runs x 3 phases x 3 rounds; 0/24/24 attack load; original controller and independently enforced receiver budgets | No new campaign executed by this continuation |

The original Host observer found neither the required root-owned parent cgroup
nor its reviewed systemd unit and kernel limits. Its retained result reports
`FIXED_PARENT_IDENTITY`, `KERNEL_OBSERVATION_UNAVAILABLE`,
`ORIGINAL_FINITE_LIMITS` and `REVIEWED_UNIT_BYTES`. No replacement parent or
relaxed time/resource allowance is used. Missing execution is not a zero
confirmation measurement and is not a pass.

## Scope and early execution

The baseline MVCC library command on the exact pinned source passed 141 tests,
with 9 ignored and no failures. Its original source-bound receipt and log are
retained. Development checks then passed 5 new account-conflict controls,
30 Node request-observation tests, 26 execution-report controls and 65 phase
reader controls. These development commands ran before the final source freeze;
they are not final-source or throughput acceptance evidence.

The first account-conflict development build failed on a missing renamed
**test-only** StateInputs field in a Growth test initializer. The correction
updates that initializer; the failed build and following pass both remain.
A source-pin check also rejected a stale generated inventory hash; refreshing
that exact pin preserved the checker and its HOLD result.

Frozen-source native validation and syscall evidence will be retained in a
subsequent evidence-only publication commit, with their own exact source
identities. Until those records exist, this document grants no additional
execution result.
