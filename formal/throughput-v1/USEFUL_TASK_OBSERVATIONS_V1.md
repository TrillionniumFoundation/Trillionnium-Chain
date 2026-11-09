# Useful-task observation coverage v1

Status: **implemented historical observation adapter / HOLD_NO_GO**. The
[four-axis contract](README.md), original resource profiles, deadlines and
confirmation rules remain unchanged. The sole development plan remains
authoritative.

## Input and purpose

[`useful_task_metrics.py`](useful_task_metrics.py) imports the existing
externally pinned 44-record SmolLM/Cell corpus. It calls the original
[`cell_model_metrics.py`](cell_model_metrics.py) reader, retaining that reader's
complete release, command, authority, model, training and failure checks. It
starts no native work and has no input switch that can declare an independently
accepted useful task.

The adapter adds one observation report, `trnm-useful-task-observation-report-v1`.
It does not change an existing input, stored report, native protocol or signed
domain. Direct Python projection also checks every supplied record's SHA-256 and
Git blob identity. The CLI checks the externally supplied manifest SHA-256 and
uses the original bounded, regular-file reader. Every imported cost retains its
original source path, byte digests and JSON pointer.

The report distinguishes receipt labels, request labels and independently
accepted business tasks. The actual corpus contains three training receipts,
25 training stages, 18 selected command receipts and 64 action-scoring forward
records over the same 32 fixture request labels in two model arms. These are
retained observation slots. They are not an exhaustive original business offer
census, independent customers, authenticated invocations or 64 useful tasks.
Repeated operation labels remain visible; they do not cause a cost record to be
discarded or provide a useful-task identity.

## Complete useful-task throughput stays unknown

The useful numerator requires independently accepted, uniquely identified
business tasks under the original acceptance contract. Its denominator requires
the matching complete observation window and original attempt census. The
historical corpus supplies neither. Both `unique_independently_accepted_tasks`
and `tasks_per_second` remain null, with machine-readable reasons for:

- missing independent demand and original authorization;
- missing independent future-task acceptance;
- operation and fixture labels that do not establish business-task identity;
- incomplete failed, cancelled, unpublished and other-owner attempt coverage;
- missing common monotonic window.

The original two model arms retain their 16/32 results and **NoUpdate**. Training
costs survive that outcome. Independent future-task effects, old-capability
retention, model adoption and net value remain unknown. The component action
scoring rate remains named as such; it is not generated token throughput.

## Cost scopes and unknowns

| Observed values | Retained scope | Missing coverage |
| --- | --- | --- |
| Worker-stage CPU, wall and I/O values | Each original training stage, with byte and pointer provenance | Whole worker lifetime, other processes, all attempts and authenticated meters |
| Process wall and command elapsed values | Original enclosing observations, retained separately | A common clock and complete nonoverlapping lifetime coverage |
| Successful acquisition and cache materialization | Complete declared release under the original historical cohort | All provider CPU, physical wire bytes, packing and global attempts |
| Original failed acquisition and controlled refusal | Both nonzero command returns and their observed elapsed values | Failure CPU, omitted/cancelled/unpublished attempts and recovery costs |
| Model scoring execution | Each original forward record and original component projection | Independent usefulness, load-to-response, future evaluation and full iteration costs |

The 25 stage CPU fields have a reported arithmetic sum of **130,011,484,774 ns**.
This is an arithmetic summary of the retained stage measurements, not an
authenticated complete task cost. Original stage endpoints are absent from
this corpus; independent interval-overlap verification is false. Enclosing
process or command durations are never added to stage values. Likewise the
reader never combines all command elapsed values into an end-to-end latency.
CPU, wall time, I/O bytes, network bytes, energy and money remain separate units.

An unobserved cost is null. Its known partial arithmetic sum and missing-slot
count remain visible. Observed zero is preserved as zero; an empty or entirely
unknown collection does not manufacture zero. CPU-only worker-stage GPU fields
do not establish complete global GPU cost. The failed transfer's observed
2.049700966999808-second command duration remains present alongside its unknown
process-family CPU and physical network costs.

The fixed corpus omits other existing preparation records, including packing
and release preparation, as well as any complete proof/propagation/recovery
cost census. `cost_coverage` names these limits rather than claiming that the
underlying work did not happen. All complete task cost fields remain null. A
later adapter must bring its own bounded original records, independent pins,
clock and scope contracts; it cannot fill these gaps with an aggregate claim.

## Reproduction

```sh
python3 -B formal/throughput-v1/test_useful_task_metrics.py -v
python3 -B formal/throughput-v1/useful_task_metrics.py \
  --manifest evidence/pon-throughput-20261108/cell-model/input-manifest.json \
  --manifest-sha256 9e3c64afcd03bb17ac8746d1146a98c78d214000ccaf71ed2aed0ea96a6a3d25 \
  --output /tmp/useful-task-observations-new.json
```

A valid report returns **1 for HOLD**; invalid input or refused output returns
2. Optional output is create-only and outside the source tree. The stdout report
and saved report have identical bytes. The input pin and both reader file hashes
are recorded. Successful parsing, source binding and arithmetic do not
authenticate original execution, clocks, meters, independent operators or
evaluation. Native origin, independent evaluation certification, adoption and
production activation flags remain false.
