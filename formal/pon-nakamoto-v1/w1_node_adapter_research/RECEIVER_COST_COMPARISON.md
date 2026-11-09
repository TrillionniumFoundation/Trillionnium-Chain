# Matched development-Node receiver cost

## Scope and decision

This continuation measures a cold receiver process for the same canonical PNH1
packet in two arms: **N**, the original native Node path, and **P**, the existing
scheduled-SHA STARK adapter followed by that same native Node path. It adds no
production verifier dispatch, work credit, proof-only admission or activation
authority. Qualification remains **HOLD_NO_GO**.

The [R4 report](../w1_public_stark_research/ROUND4_REPORT.md) establishes an
eight-proof A/B backend improvement and an independent-verifier regression. Its
native inner-call reference excludes startup, input reads and Node admission.
Those numbers are not an N/P receiver comparison. The later tagged-SHA3 profile
is a different profile and is not silently substituted into this adapter.

No current end-to-end improvement is asserted by this implementation. A measured
local comparison, a transport experiment, a fresh proving experiment and original
production-service qualification are distinct results.

## Two actual paths

| Cost or operation | N: native | P: proof plus native |
| --- | --- | --- |
| Independent operator plan and canonical packet reads | Included | Included |
| Independent header, artifact and live Node context binding | Included | Included |
| Public witness and two proof reads, scans, decoding and planning | Absent | Included |
| Durable proof-start reservation and final owner snapshot | Absent | Included |
| Proof archive persistence | Absent | Included |
| Independent SHA and arithmetic preprocessing and both PCS checks | Absent | Included |
| Fresh Node open, native admission, activation and exact readback | Included | Included |
| Event output, result serialization, fsync and process exit | In external process total | In external process total |
| Real network send/receive or queueing | Not measured | Not measured |

The new `native-admit FIXTURE NEW_OUTPUT` command reads only
`operator-plan.json` and `packet.bin`. It checks canonical packet bytes, the
independently expected complete header and A/B artifact commitments, then invokes
the real development Node. It never fabricates a verified-proof capability.

The original `exercise` command still spends the original persistent proof-start
reservation, checks both complete proofs and invokes native admission. Exact
duplicate admission shortcuts are excluded from this experiment by giving every
sample a new Node directory. Existing archive and admission schemas retain their
meaning; diagnostic metrics use `trnm-w1-receiver-metrics-v1` and
`trnm-w1-native-admission-metrics-v1`.

## Fixed experiment and accounting

[run_receiver_comparison.py](run_receiver_comparison.py) fixes the order
**NPPNNPPN**, with four fresh receiver processes per arm. All eight receive one
retained packet; the four P processes use the same existing proof pair. The campaign reports
**one distinct input task, four proof replays, and zero newly generated proofs**.
A complete new proving experiment, if run separately, needs its own source and
output receipts; it cannot change the meaning of these replay counts.

The harness uses Linux `fork/exec/wait4`. Each child's user CPU, system CPU,
maximum RSS, exit status, raw output and real pre-exec kernel readback are
retained. The common pre-exec Python observation is included in both arms.
Consequently maximum RSS describes the complete measured process, including
pre-exec observation, rather than the Rust program alone.

The external clock starts before fork and ends after wait4. It includes startup,
input I/O, Node work, reporting and teardown. Rust's `outer_seconds` starts
inside main. Stage timers cover disjoint workload phases; nested proof and native
details must not be added again. The reader requires the exact phase sequence and

$$
\sum \text{disjoint phase times}
\leq \text{Rust outer time}
\leq \text{external process time},
$$

up to one microsecond of floating-point representation tolerance. Stage sums are
not a replacement for the external total. Started stages without a completed
observation remain unfinished; missing work is never filled with zero.

Owner initialization and final status inspection are separately timed and retained.
They are not hidden inside a receiver median and are not silently free in any
deployment model. The comparison measures instrumented processes; it does not
claim that instrumentation, OS caches or shared-host contention disappear.

## Actual input bytes

The retained `fixtures/node-input-v1` inputs have the following sizes:

| Application input | Bytes |
| --- | ---: |
| Canonical native packet | 49,508 |
| Public statement | 377,290 |
| Scheduled-SHA proof envelope | 3,142,981 |
| Packed-arithmetic proof envelope | 454,085 |
| P: packet plus statement plus both proofs | **4,023,864** |

This is approximately **81.2770 times** the canonical native packet, for this
particular fixture. It is a file-length comparison, not measured network traffic.
The independent 1,126-byte operator plan is shared local provisioning and is
reported separately. Protocol framing, signatures, retransmission and remote
availability are not inferred. R4's 49,506-byte raw header/work input and its
different task-family payload medians keep their original scope.

## Conditions for a local comparison

The reader does not use exit zero as admission success. It checks complete real
proof verification in P, the unchanged native admission path in both arms, fresh
genesis, the same block identity, current exact storage/activation observations,
all four durable proof-start slots, fixed input hashes and all eight planned
attempts.

The source, binary, harness and input snapshots must agree before and after.
Kernel membership, visible ancestor limits and CPU affinity must match for every
before/child/after observation. Expected quota, memory, swap and PID values can
also be supplied explicitly. Missing or changed kernel readback yields
`INCOMPLETE_OR_INCOMPARABLE`, with no qualified medians. Failed, timed-out,
cancelled or incomplete attempts stay in the record and cannot be removed to
construct a successful subset.

The focused source snapshot is not a complete dependency/build attestation. Bind
a separate original `verify_ci_source.py` receipt with `--source-receipt` when
running from the frozen, fully materialized, clean commit. The existing complete
source verifier and its negative tests remain unchanged.

Even a local comparison PASS leaves `end_to_end_benefit=NOT_MEASURED`,
`receiver_count_break_even=null`, and production qualification unestablished.
This benign single-packet experiment does not contain sixteen hostile producers,
seven independent honest requests, a live service queue, independent WAN owners
or the original production cgroup parent.

## Running the comparison

Build and validate this independent Cargo workspace explicitly; the production
workspace's default test command does not include it.

```sh
bash scripts/project-preflight.sh
cargo +1.95.0 build --release --locked \
  --manifest-path formal/pon-nakamoto-v1/w1_node_adapter_research/Cargo.toml
python3 -B -m unittest discover \
  -s formal/pon-nakamoto-v1/w1_node_adapter_research/tests \
  -p test_receiver_comparison.py -v
```

Use the actual binary SHA-256 and an absent output directory. Run inside the
resource owner being measured; the harness does not create or alter a cgroup.

```sh
python3 -B formal/pon-nakamoto-v1/w1_node_adapter_research/run_receiver_comparison.py \
  --repo /absolute/checkout \
  --binary /absolute/w1-node-adapter-research \
  --expected-binary-sha256 ACTUAL_SHA256 \
  --fixture /absolute/checkout/formal/pon-nakamoto-v1/w1_node_adapter_research/fixtures/node-input-v1 \
  --proof /absolute/checkout/formal/pon-nakamoto-v1/w1_node_adapter_research/fixtures/node-input-v1 \
  --output /absolute/new-measurement-directory \
  --cpu-count 2 --rayon-threads 2 --timeout-seconds 120 \
  --expected-cpu-max '200000 100000' \
  --expected-memory-max 2147483648 \
  --expected-memory-swap-max 0 --expected-pids-max 256
```

These flags are expectations, not a mechanism to enforce limits. Supplying a
number does not prove the kernel applied it. The original one-quarter-CPU,
2 GiB, zero-swap, 256-PID, four-second contract requires its own actual readback
and retained deadline outcomes. A timeout is not completed admission or a
cryptographic rejection.

## When receiver count can help

For a fixed workload and one common additive cost unit, let the incremental
sender cost be `ΔP`, and the incremental complete per-receiver cost be `ΔR`.
For `n` equivalent receivers, the incremental total is `ΔP + n ΔR`.
With nonnegative sender overhead and nonnegative receiver overhead, increasing
receiver count cannot produce a total-cost saving. A positive amortization
threshold requires a negative per-receiver increment and a fully stated sender
cost. This conditional algebra supplies neither missing measurements nor an
all-strategy cost bound.

CPU seconds, wall latency, bytes and memory remain separate units. Queue-to-final-
ACK latency must be measured as a critical path; it is not a sum of medians or
proof generation time divided by receiver count. Full transport, a production
proof-replacement profile and independent security qualification remain open.

## Evidence status

The [continuation record](evidence/receiver-cost-20261109/README.md) distinguishes
actual checks and measurements from failed setup, interrupted execution and
remaining gates. Historical R4 results and original qualification refusals are
unchanged.
