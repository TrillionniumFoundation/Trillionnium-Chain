# Scope of the retained four-second failure diagnosis

This is readback and source inspection of the original `da1374a` observations.
No additional native campaign was run for this diagnosis. The relevant History,
scalar CPU, Host and durable epoch implementation files remain byte-identical
to that source. This continuation changes only a cancellation test in
`public_v3.rs`.

Original data and reproducible readers are in the
[hosted package](hosted-readback/README.md), with
[phase summaries](hosted-readback/readback/fresh-service-replay-phases.json).

## Where the two pressure runs stop

| Event, relative to the four-second start | Original | Fresh challenge |
| --- | ---: | ---: |
| Seven successful Submit replies completed | 1.569933425 s | 2.308114039 s |
| First independent client replay begins | 1.670235565 s | 2.405251684 s |
| Successfully replayed pages within window | 2 | 0 |
| Last replay begins | 3.966815440 s | 2.405251684 s |
| Last failing phase | page `cpu_wait` | packet `work` |
| Last replay error | `PUBLIC_REQUEST_DEADLINE` | `PUBLIC_REQUEST_DEADLINE` |

The original final page begins with only 33.185 ms remaining. Its epoch-open
span lasts 92.201653 ms wall and 0.237011 ms caller CPU. The following CPU-wait
span is only 4.809 microseconds: it observes an already-expired deadline. No
packet work is entered. This does not show a 92 ms scalar refill wait.

The fresh client's first CPU wait is 399.652601 ms, followed by 90.548891 ms
packet-context wall time and 1.100883426 s work wall time (67.316409 ms caller
CPU). That first W1 fails before admission. Its enclosing replay has
71.003650 ms caller CPU, including 66.335808 ms in 1,046 nested Host checks.
These nested values are not additive.

## What the source establishes

The caller uses `receive_public_page_from_before_observed(&mut verifier, ...)`,
which selects `Owner::Exclusive`, rather than the shared Node mutex path. The
observed wall-minus-CPU difference cannot be called shared-owner lock waiting.
See [History import](../../trillionnium/crates/trnm-pon-node/src/ingress/history_import.rs).

The cold remote History account starts with zero credit. Its 100 ms start
reserve and 250 ms/second refill explain an approximately 400 ms first reserve.
The original baseline runs also show this wait. Removing it, prewarming the
account or granting additional burst would change the retained resource
contract. See [scalar CPU](../../trillionnium/crates/trnm-pon-node/src/ingress/public_v3/scalar_cpu.rs).

`admit_packet()` marks verified completion only after `verify_history_work()`
succeeds. `LiveRequestCpu::observe_sample()` permits a waiting continuation only
for verified completion. The fresh first W1 never reaches that point; its long
work span cannot be attributed to a post-verification refill continuation.

Each real W1 progress boundary checks the original Host control. The current
implementation already removes adjacent duplicate checks and retains boundary
controls. `KernelBudget::check()` checks boot identity, parent metadata, current
thread membership and five limits files. Its measured CPU is a useful lead;
omitting reads, reducing boundaries or reusing an old resource verdict would
weaken the contract. See [Host checks](../../trillionnium/crates/trnm-pon-node/src/host_kernel_parent.rs).

Epoch open also includes durable metadata operations in
[`begin_ordinary_public_service_epoch()`](../../trillionnium/crates/trnm-pon-node/src/store/operator_continuous_owner.rs).
The present aggregate timer does not separate SQLite, Host checks and scheduling.
It therefore does not establish the cause of the original 92 ms interval.

## Server and Host observations have different scopes

The successful server-side Submit requests spend only 2.033–3.817 microseconds
(original) and 2.144–6.342 microseconds (fresh) in their CPU-wait phases. Both
cohorts have zero mutation CPU refusals and clock failures; remaining credit at
shutdown is approximately 1.999976 s and 1.995567 s of the original 2 s burst.
The per-request spans are stronger evidence than refusal counts alone, since a
successful refill wait need not increment a refusal counter.

Queue backpressure is observed 213 and 468 times. The fresh second successful
Submit has 91.781496 ms paid-task queue wall time; its other successful Submits
have approximately 1.5–6.1 ms. This measures a queue phase, not its complete
internal scheduling or contention cause.

The original Host `cpu.max` is `25000 100000`. Its whole-run before/after
`nr_throttled` increases from 4 to 1193. That proves throttling occurred during
the approximately 121-second enclosing observation. It does not attribute the
increment to a particular four-second cohort or page, and cannot uniquely
explain the 92 ms or 1.1 s intervals.

## Remaining diagnostic obligation

No safe runtime correction is confirmed by these observations. The next bounded
diagnostic should preserve the existing workload, deadline, budgets, cold
account semantics, confirmation requirement and failure classifications:

1. Record reserve attempts, actual budget-sleep counts/spans and remaining
   deadline at existing `begin_cpu()` points.
2. Split the existing epoch-open span between domain lookup and durable begin,
   and retain the exclusive/shared owner mode.
3. Measure the existing Host substeps without changing their reads or decisions,
   and retain per-cohort parent `cpu.stat` endpoints as Host totals, not
   per-request attribution.

Existing real-boundary, Host-change, expiry, settlement and cold-restart controls
remain required. This diagnostic proposal grants no successful-service status
and is not an implemented performance improvement.
