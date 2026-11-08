# Native execution and throughput observations

This continuation extends the exact [four-axis contract](README.md). Deadlines,
resource ceilings, confirmation rules and activation gates remain unchanged.
The code and evidence remain **HOLD_NO_GO**.

## Two original contracts

| Property | Original Host service | Original complete campaign |
| --- | --- | --- |
| Business window | Strictly before 4 seconds | Original 30 seconds per phase |
| Planned load | Baseline / 16 hostile producers | Baseline / from-zero / late-product: 0 / 24 / 24 |
| Confirmation denominator | One original target in each of two phases | Three runs, three phases, three rounds: 27 slots |
| Resource identity | 0.25 CPU, 2 GiB, zero swap, 256 PIDs, original root-owned parent | Original controller 4 CPU / 16 GiB / nice 10, with separately recorded receiver/verifier placement |
| Confirmation | Original depth and cumulative-work rule | Original depth and cumulative-work rule |

Controller ceilings do not describe the receiver's enforced limits. Placement
and kernel observations remain required. A thirty-second result cannot replace
a failed four-second result. Missing execution, startup failure, cancellation,
missing reports and unobserved rounds retain their original denominators.
Component tests and historical readback grant neither gate.

## Native observations

The existing optional request observer retains two separately versioned
extensions. Its original 19 submit phases and inclusive parent links remain.

- `error_timing` records first dispatch and terminal errors independently,
  each with its own phase, typed cause and same-observer monotonic timestamp.
  Subsequent errors cannot relabel an earlier event. Error appearance, response
  delivery, connection close and final task-owner close are distinct.
- `reactor_io` records returned read/write wrapper calls for Hello, Challenge,
  Solution, Ready, Body and Response. It retains progress, no-progress and error
  counts, wall time, reactor-thread CPU and unknown-clock counts. Read-buffer
  preparation is included. Time between calls, authentication and physical
  network framing are outside this interval.

Both extensions use existing nonblocking diagnostic capture. Lost capture,
overflow and unknown clocks withhold complete totals. Wrapper returns are not
syscall counts; application bytes are not physical network bytes. Disabled
observation does not start the new clocks.

Existing SQL commit-call observations retain four native call sites and their
returned, failed, abandoned, in-flight and unknown-clock counts. They are API
measurements, not WAL bytes or device durability measurements. System-call
traces remain separate diagnostics unless their exact source, process, resource
envelope and window are bound to the original campaign. The bounded
[`sqlite_syscall_profile.py`](sqlite_syscall_profile.py) reader binds raw trace,
executable and source-receipt hashes, pairs unfinished calls only within their
original TID, uses each call's own resolved fd path, and retains ambiguous,
failed and unclosed calls. Returned WAL write bytes and syscall elapsed time
are not device bytes, CPU time, fsync durability or throughput qualification.

## Deterministic state work

The ordinary classical executor already validates exact point/prefix reads,
uses bounded scoped workers, commits in canonical order and permits at most one
canonical replay per transaction. Its new account conflict hint extends the existing sender
nonce hint to the recipient of an exactly shaped PNX1 transfer.

The borrowed set contains at most two identifiers per already bounded
transaction. A conflict suppresses only a disposable parent-state prediction.
Every transaction still undergoes full preparation and signature, context and
expiry validation. Prepared results and state/fee errors are consumed in
canonical order. Unknown operations retain
exact-read conflict detection. PQ and Growth retain their canonical state owner.

For the existing 256-transfer common-recipient fixture with multiple senders
and 2, 4 or 8 workers, the full-speculation oracle performs 256 predictions and
255 replays. The new path performs one
prediction and 255 direct canonical applications: 256 state applications, with
the same 256 signature verifications. These operation counts do not establish
a CPU ratio, TPS improvement or service qualification. Differential controls
compare complete state, receipts, roots, errors and signatures for worker counts
1, 2, 4 and 8. Hidden task-payment dependencies retain their one-replay path.

The native peer poller passes its already established absolute end into every
protected RPC. A failed request and later retry consume the same lifetime. The
actual TCP regression stalls two calls and checks socket closure, failure
counts, retained cursor and unchanged parent state.

## Existing data and task boundaries

The [Cell persistent transport](../../trillionnium/crates/trnm-data-availability/src/cell/network/persistent.rs)
retains an absolute session deadline, bounded request/connection/byte allowances
and verified partial chunks. Existing tests cover manifest then payload,
connection reuse, multi-provider rarest-first scheduling, malformed frames,
cancellation and explicit resume. Those capabilities are separately validated.
The public signed ingress profile is not migrated to multiple requests per
connection by this change.

Public ordering retains bounded task and commitment records. Weights stay in
the separately verified Cell data plane. Existing task owners distinguish
accepted, pending, terminal, cancelled and uncertain external effects. An
observation or socket closure does not release an uncertain operation or
establish model adoption. Complete real learning-to-next-task and independent
WAN qualification remain distinct requirements.

## Failure-preserving report

[`execution_report.py`](execution_report.py) reads pinned original Host and/or
campaign bytes and reports the families separately. It reuses the original
readers and retains failed/absent runs in the 27-round campaign denominator.
The strict successful-campaign reader remains unchanged.

CPU, application I/O, named owner waits, queue waits, actual first errors,
owner lifetime, typed cancellation and recovery coverage have explicit scopes.
Successful, unfinished and missing calls and unknown clocks are separate
counts. Cumulative wait sums never become request latency percentiles.
The new statistics sections distinguish known-only and complete-cohort
p50/p95/p99 and require minimum sample counts 2/20/100. Retained original
readbacks keep their original descriptive statistics and scope. Incomplete
coverage withholds the new complete-cohort tails.

The reader exits 1 for valid retained **HOLD** evidence and 2 for invalid input.
It starts no native execution and never changes admission. Output is create-only.
Historical data without new extensions remains unknown in those fields.

```sh
python3 -B formal/throughput-v1/test_execution_report.py -v
python3 -B scripts/ci/test_pon_public_v3_phase_read.py -v
cargo test --manifest-path trillionnium/Cargo.toml --locked -p trnm-mvcc-fee --lib
cargo test --manifest-path trillionnium/Cargo.toml --locked -p trnm-pon-node --lib request_observ
cargo test --manifest-path trillionnium/Cargo.toml --locked -p trnm-pon-node --lib peer_polling
cargo test --manifest-path trillionnium/Cargo.toml --locked -p trnm-data-availability --lib persistent
```

Exact frozen source verification, retained outcomes and original Host
prerequisites accompany execution claims. See the
[retained engineering evidence](../../evidence/pon-throughput-engineering-20261108/README.md).

