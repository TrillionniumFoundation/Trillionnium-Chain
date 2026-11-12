# SP27-02: native source, evidence boundaries, and mechanism qualification

## Current conclusion

**Mechanism status: UNKNOWN.** The separately identified CI batch at Chain
`8ebcdb01016946a131f9067ebe1ace39b9c4f260` contains one fixed-order pair:
the no-pressure arm independently confirmed its one business operation and the
16-worker arm did not, within the original four-second window. The receiver
accepted all seven honest submissions in both arms; the pressure arm later
failed to finish independent History replay by that deadline. This is a real
finite-window service outcome. It does not identify which combination of
arrival load, transport, queueing, verification, client CPU, or scheduling caused
the failure. The original job failure and qualification flags are retained.
See the [original CI audit](batches/ci-43052900246/CI_AUDIT.md) and
[machine-readable identity](batches/ci-43052900246/CI_AUDIT.json).

The raw observer also rules out a stronger but incorrect description of this
pair: **the 370 `WORK:Transcript` responses were not 370 fresh arithmetic
replays**. There were 52 native transcript replays and 318 cached mathematical
refusals. This distinction is checked against the executed source and original
packet bytes, not inferred from the error label. The
[rejection-path receipt](batches/ci-43052900246/REJECTION_PATH_AUDIT.json) is
16,486 bytes with SHA-256
`1f5a41b547925f0e5c51633de906aa1e5d3831030b151f6fa6fc862de23576b7`.

## What is original, and what remains unverified

| Evidence | Verified identity or limitation |
| --- | --- |
| New CI source | Commit `8ebcdb01016946a131f9067ebe1ace39b9c4f260`; tree `1b887f5fe57c6c3875ad28b8cc26bd83a8f77b83`; before/after source readbacks agree |
| Execution | Run `43052900246`, job `130634539770`, artifact `13871459353` |
| Original artifact bytes | 8,297,569 bytes; SHA-256 `8b21d753e0ac85ffdca7bc3e0a5f953d4dfffb24c7a10cc9ae394dcfe6590307`; 282 ZIP entries checked |
| Actual native executable | `from-zero-native/public_v3_from_zero`; 11,849,144 bytes; SHA-256 `03d0dada775a2531876ce796192b59d27d78f86848e053de554ee70e281eb387` |
| Original pair report | `from-zero-native/confirmation/report.json`; 11,152,091 bytes; SHA-256 `4a4ec5d92810f51df792a2f1f08e4af4c9cb47c107c5ed3e3a8e2ef71dae9a1d` |
| Prior local SP27-02 diagnosis, patch, and `PUBLIC_HOST_KERNEL_PARENT` failure | **NOT_VERIFIED**: no corresponding original was found in the bounded Library/title and local audit searches; prior prose is not a replacement for a log, source, or executable |

The audit binds the new source, binary, and run. It does not retroactively bind
an earlier local failure to that source or host. A chat summary cannot supply
the missing earlier path, errno, permissions, cgroup membership, binary hash,
or failure time. The search scope and primary file hashes are recorded in the
[CI audit](batches/ci-43052900246/CI_AUDIT.md). Public readbacks are the
[run](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/43052900246),
[job](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/43052900246/job/130634539770),
and [artifact](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/43052900246/artifacts/13871459353).

The historical reader issue is now a separate verified fact: the old inclusive
endpoint predicate disagrees with native semantics, but re-reading all six
original historical ZIPs found zero affected native rows. V1 and V2 regenerate
identical historical events. See the [raw-corpus result](reader_v2/RAW_CORPUS_RESULT.md),
which preserves source strata, planned denominators, exact-cutoff checks, false
native-gate cases, and the actual SP27-06 consumer receipt. This is a boundary
repair and corpus audit, not a retroactive claim of measured overcount.

## Host contract and resource interpretation

The executed
[host_kernel_parent.rs](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/8ebcdb01016946a131f9067ebe1ace39b9c4f260/trillionnium/crates/trnm-pon-node/src/host_kernel_parent.rs#L363-L420)
is an unprivileged checker. `KernelBudget::open` returns
`PUBLIC_HOST_KERNEL_PARENT` for several different predicates: a nonabsolute
input; failed canonicalization; a canonical path outside the one approved
parent; a spelling different from its canonical path; or a directory/owner/
group-or-other-writable-mode mismatch. The code alone cannot decide which
predicate failed in the missing local original. A canonicalization failure
does not identify its underlying filesystem error.

The fixed parent is `/sys/fs/cgroup/trnmponpublic.slice`. The checker separately
requires cgroup-v2 support, calling-thread membership, a stable boot and
directory identity, finite limits, zero CPU burst, and zero swap. On subsequent
checks it reopens the actual files and rejects replaced identities, changed
limits, and changed membership. The budget is at most 0.25 CPU, 2 GiB memory,
and 256 tasks; it is not permission to allocate a fresh parent for every
listener. These gates remain part of the experiment. See
[limit validation](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/8ebcdb01016946a131f9067ebe1ace39b9c4f260/trillionnium/crates/trnm-pon-node/src/host_kernel_parent.rs#L70-L128)
and [live checks](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/8ebcdb01016946a131f9067ebe1ace39b9c4f260/trillionnium/crates/trnm-pon-node/src/host_kernel_parent.rs#L335-L361).

The new CI readbacks report the same boot
`e4467231-e96e-4736-9409-b547a3dc1666`, device/inode `31/7066`, root-owned 0755
parent, `cpu.max=25000 100000`, `cpu.max.burst=0`,
`memory.max=2147483648`, `memory.swap.max=0`, and `pids.max=256` before and after.
UID/GID are `1001/1001`, `NoNewPrivs=1`, and the capability bounding mask is zero.
Read errors and final Host errors are empty. The exact fields and original
member hashes are in [CI_AUDIT.json](batches/ci-43052900246/CI_AUDIT.json).

The actual runner holds the cooperative, root-owned nonblocking parent lease
across the experiment and records a fresh parent. This excludes another
cooperating fixture owner; it does not establish a dedicated physical CPU,
exclusive cpuset, or continuous absence of unrelated host load. Before/after
`pids.current=1` samples cannot establish what ran between them. The receiver,
pressure clients, reader, and independent verifying client share this process
and bounded parent. Independent validation here means a separate native
verifier state, not independently allocated compute. See the exact
[runner](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/8ebcdb01016946a131f9067ebe1ace39b9c4f260/scripts/ci/run_from_zero_host.py)
and [lease](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/8ebcdb01016946a131f9067ebe1ace39b9c4f260/scripts/ci/public_fixture_host_lease.py).

## The packet construction and the furthest demonstrated verification stage

The original constructor receives public task matrices and context. It writes
the PNW1 prefix and A/B fields, initializes the claimed product C and trace to
zero, and searches bounded trace/ticket hashes. A target hit replaces the trace
claim without evaluating the product or acquiring a valid proof. This yields
sixteen recorded false packets before honest-chain production. Each pressure
worker repeatedly submits its selected packet; the stream is not a newly
constructed false proof on every call. Sources are
[proof_prefix/trial](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/8ebcdb01016946a131f9067ebe1ace39b9c4f260/trillionnium/crates/trnm-pon-node/examples/support/w1_from_zero.rs#L6-L27),
[search_from_zero](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/8ebcdb01016946a131f9067ebe1ace39b9c4f260/trillionnium/crates/trnm-pon-node/tests/public_v3_from_zero.rs#L109-L170),
and the [fixed replay builder](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/8ebcdb01016946a131f9067ebe1ace39b9c4f260/trillionnium/crates/trnm-pon-node/tests/public_v3_from_zero.rs#L1257-L1271).

Ordinary classical service startup installs a bounded exact rejection cache.
The default has 256 slots and a 30-second lifetime. Its key binds the work
profile, challenge, task, target, and complete proof bytes. A current context
check and paid body processing precede it. A cache hit remains a refusal and
passes the original cancellation checkpoint; it never creates `VerifiedWork`.
On a miss the default native verifier checks the proof statement and replays
the transcript. A mismatch then returns `WorkError::Transcript` before product
correction and the final verified-work constructor. These are distinct
branches with the same external error. See
[default cache installation](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/8ebcdb01016946a131f9067ebe1ace39b9c4f260/trillionnium/crates/trnm-pon-node/src/ingress/public_v3/work_rejection.rs#L17-L35),
[hit/miss branches](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/8ebcdb01016946a131f9067ebe1ace39b9c4f260/trillionnium/crates/trnm-crypto-primitives/src/pon_work/rejection_cache.rs#L187-L267),
and the [native transcript comparison](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/8ebcdb01016946a131f9067ebe1ace39b9c4f260/trillionnium/crates/trnm-crypto-primitives/src/pon_work.rs#L768-L851).

The raw fields distinguish those branches:

| Actual path among `WORK:Transcript` records | Count | Native started/returned | `full_replay_started` | Cached return | `full_work_thread_cpu_ns` | `dispatch_thread_cpu_ns` |
| --- | ---: | --- | --- | --- | ---: | ---: |
| Native transcript rejection, publication retained | 52 | true / true | true | false | 63,327,517 | 85,716,388 |
| Exact cached mathematical refusal | 318 | false / false | false | true | 10,995,295 | 148,028,774 |
| Both paths | 370 | mixed | mixed | mixed | 74,322,812 | 233,745,162 |

The 52 native returns, together with the exact verifier branch, establish that
those calls reached the transcript digest comparison after completing its
replay. They did not reach product correction or valid-work creation. This is
source-based stage inference from a completed native return, not a retained
per-tile trace. The other 318 calls did not execute native transcript arithmetic
on that invocation. All 370 observer body digests match one of the sixteen
original false requests. All client request lengths and recorded digests also
match those bytes. Identical repeated bodies do not uniquely pair individual
client/server calls across clocks. Exact record IDs and per-packet counts are
in the [path receipt](batches/ci-43052900246/REJECTION_PATH_AUDIT.json).

The legacy `full_work_started` field is true for both groups because its
interval encloses the verification attempt, including a cache lookup. It is
not a transcript-replay indicator. Likewise, `full_work_thread_cpu_ns` is nested
inside dispatch CPU. Adding these columns would double count. A W1 cheap
rejection can also occur within this interval before `BeforeReplay`; an
early-reject control must name its exact branch and inspect
`work_rejection.cache.full_replay_started`, rather than assume the legacy
field must be false. The enclosing source is
[public_dispatch_submit](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/8ebcdb01016946a131f9067ebe1ace39b9c4f260/trillionnium/crates/trnm-pon-node/src/ingress/public_v3.rs#L1827-L1885).

## The pair's first observed terminal divergence

Baseline independently confirms at `2,704,367,684 ns`. In pressure, all seven
honest submit acknowledgments return by `1,270,197,394 ns`. Three independent
History page replays succeed. The fourth response ends at `3,877,883,009 ns`,
its replay starts at `3,877,903,180 ns`, and replay terminates with
`PUBLIC_REQUEST_DEADLINE` at `4,066,591,277 ns`. No independent final confirmation
object is produced. The original final gate is false; Host error-code lists
remain empty. These records locate the terminal incomplete replay but do not
make its delay a proven effect of native W1 cost. Earlier transient events must
remain visible when identifying the first anomaly. See the
[original timeline](batches/ci-43052900246/CI_AUDIT.md).

There are 386 pressure calls: 370 transcript refusals, 15 I/O resource-temporary
errors, and one frame deadline. The report records 425 accepted connections,
569 queue-backpressure events, zero mutation-CPU refusals, and nonzero final
stored credit. Thus stored-CPU exhaustion is not an observed mechanism in this
pair. Aggregated concurrent queue waits do not form a wall-clock critical path.
The baseline precedes pressure, and the business release is itself conditional
on an initial completed pressure call. This permits order, startup, cache, and
shared-resource explanations alongside receiver verification. Source ordering
and release behavior are visible in the
[phase body](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/8ebcdb01016946a131f9067ebe1ace39b9c4f260/trillionnium/crates/trnm-pon-node/tests/public_v3_from_zero.rs#L1333-L1421)
and [pair invocation](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/8ebcdb01016946a131f9067ebe1ace39b9c4f260/trillionnium/crates/trnm-pon-node/tests/public_v3_from_zero.rs#L1738-L1776).

Native confirmation uses a later `Instant::now() < end` check after examining
the returned confirmation object. A recorded endpoint below T cannot override
a false final gate. The new reader retains both facts; source lines
[1519-1524](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/8ebcdb01016946a131f9067ebe1ace39b9c4f260/trillionnium/crates/trnm-pon-node/tests/public_v3_from_zero.rs#L1519-L1524)
and the [frozen reader contract](reader_v2/CONTRACT_V2.md) define that boundary.

## Minimum controls required for a causal claim

The four pressure strata below define the controls needed to interpret a
mechanism claim. They were subsequently executed as a separate minimum-dose
balanced campaign at run `43131129970`, with all 13 planned operations confirmed.
Its observed result and limitations are given below. The earlier original health
batch at run `43125548321` is separately verified as 3/3 under source
`0bc51795a978494af1b4659712ecf78c290c1a88`; its
[audit](batches/ci-43125548321/HEALTH_CI_AUDIT.md) and
[strict consumer receipt](batches/ci-43125548321/HEALTH_V2_CONSUMER_RECEIPT.json)
bind that result. This does not supply health credit for a subsequent campaign.
Health-gate executions and failures
must be published as their own source/binary/run batch. An unavailable Host or
failed repeated no-pressure control produces `NO_GO`, a first-divergence record,
and no further pressure samples.

Before a pressure block, obtain repeated no-pressure confirmation under the
same four-second window, source, binary, original 0.25-CPU/2-GiB parent, workload,
permissions, and verification rules. Retain actual lease ownership, host and
process identity, limits before/during/after where available, other concurrent
work, and cpuset/residency evidence if exclusive physical resources are claimed.
An unverified exclusivity claim remains unverified. Neither the native checker
nor these diagnostics may create a replacement parent, expand quota or deadline,
or move participants to extra compute to manufacture a healthy result.

| Stratum | Variable isolated and legality | Arrival/load and stage evidence | Stop condition specific to the stratum |
| --- | --- | --- | --- |
| Transport | Exercise the public negotiation, ticket, framing, and paid admission path without W1 replay. Declare the exact wire-valid native operation and stopping stage. A small `Head` request is not an equal-byte control for a 99,043-byte submit. | Freeze connection policy and a protocol-valid way to match bytes or analyze byte/connection strata separately. Record offered and received bytes, arrival times, failed negotiation, queue admission, and absence of W1 arithmetic. | Unexpected W1 execution, inability to obtain a lawful comparable body, or unmatched arrival/load outside the preregistered tolerance. |
| Early-reject | Choose one well-defined invalid W1 statement that fails a named native cheap check while preserving legal transport and matching body size. It remains mathematically invalid and must not be accepted. | Freeze the particular Length/Version/Field/Task/Target or pre-W1 branch; do not pool them. For a W1 cheap check require no full replay, with the exact native error and complete observer record. A pre-W1 choice additionally has no legacy full-work interval. | Unexpected acceptance, a different rejection branch, native transcript replay, or unusable stage coverage. |
| Late-reject | Pass transport, current context, task and ticket checks; reject after transcript replay. The proof relation is deliberately false. Separate fresh-proof and exact-reuse identities. | Keep original cache policy. Record native-start/return, replay-start, cache-hit/publication, realized load, and complete proof identity. Cached returns belong to their measured path; they cannot be relabeled late arithmetic rejection. | Unexpected acceptance, rejection at an earlier stage, insufficient native replay exposure for the declared treatment, or uncontrolled cache-state carryover. |
| Valid-expensive | Supply a genuinely native-valid proof, including product correction and valid-work construction. Admission and state changes may legitimately follow; this is not an invalid-packet control. | Record producer preparation and failed search, native verification and acceptance, parent/duplicate effects, queueing, and independent business confirmation. Use equal initial state and a declared admissible workload; valid work that changes the business state introduces another variable. | Business identity/state becomes incomparable, duplicate or parent errors replace the intended valid path, or verification/producer cost is missing. |

All strata stop at the original deadline, on Host/permission/resource mismatch,
observation loss or counter overflow, unknown CPU accounting, invariant failure,
or a failed healthy sentinel. Retain interrupted and unstarted planned operations
in the denominator. Do not retry a failed block without retaining it under its
original identity. No post-window drain or later independent replay earns
on-time confirmation.

After health qualification, use a predeclared randomized or balanced order. A
minimal exploratory block can run the four strata in a selected order and then
the reverse order, with fresh declared state and no-pressure sentinels bracketing
the block; publish the selected order before execution and the seed if selection
is randomized. Those few runs qualify
the controls and expose order effects; they are not automatically enough for a
causal population estimate. Freeze the replication/precision rule before
examining the outcome and stop if the healthy baseline ceases to hold.

Keep the old pair unchanged. For a separately named causal-control batch,
predeclare the same absolute business release schedule across all arms within
the original four seconds, or explicitly estimate the end-to-end effect that
includes the existing pressure-dependent release delay. Quietly mixing those
two schedules would change the estimand. Log the actual arrival schedule at the
receiver, since a worker-count match does not establish equal offered or admitted
load in a closed-loop client.

At minimum retain request identities and bytes, planned versus actually started
businesses, transport/queue wait, native stage facts, receiver and client CPU
scopes, Host samples, deadline and cancellation events, state/admission results,
and independent confirmation. Normalize clocks only through recorded clock
anchors. Treat nested cost intervals as nested; a logical independent client
sharing the parent can consume the same bounded budget. Report per-source and
per-stratum results, paired differences and uncertainty only from the eventual
qualified repeated design. A sole successful control followed by a failed
pressure arm remains an observation, not causal proof.

The implemented new campaign chooses a deterministic balanced order
`H H H / T E L V / H / V L E T / H`, with fresh state and a single fixed-time
offering per worker. It makes no randomized-selection claim. Its exact controls,
legality, body matching, minimum attained-stage witness, and stopping rules are
documented in the [experiment entry point](README.md#separate-balanced-stage-campaign).
In particular, the transport/codec control is not a pure socket control, and
valid genesis siblings include protocol state effects as well as proof replay.
The raw results of that new selector belong in a separate identified batch.

## Actual balanced controls and the remaining causal gap

The [original stage batch](batches/ci-43131129970/README.md) is source
`ff35430d27eea56dd803e05aa6d48573e37ed4c9`, tree
`ccf72585d2ac3b361ec169a62a607d7bce055582`, run `43131129970`, job
`130895252279`, artifact `13906427974`. Its exact ZIP SHA-256 is
`c56b845bda15360abe3e45b2b3d3893d0990984220afd5bdcfb754b6e1bb9f82`.
The independent provenance audit binds seven real Git source blobs, four
compiled-module hashes, the retained executable and original run declarations.
All 28 native Host readbacks, including each phase's before/after samples,
preserve the original limits and permissions. Boot identity is
`36bd2fe4-42b9-44b3-adb8-4cfb340b6021`; the same hostname in another CI run is not
evidence of the same boot or resource instance. The lease establishes exclusive
ownership among cooperating fixtures. Physical CPU dedication remains unverified.

The native collector and the frozen strict reader both qualify the result as
`COLLECTED_CONTROL_SERIES`. All 13 positions were attempted, invoked and
completed; unstarted and incomplete counts are zero. The five initial/sentinel
health controls and all eight pressure phases independently confirmed before
the original four-second cutoff with native final gates true. The native
first-divergence field is null; no later success was substituted for a failure.
The frozen SP27-06 analyzer actually consumed all 13 planned business operations.
An independent root invocation reproduced all 13 derived output files byte for
byte from the same immutable original input directory.

Each arm has two phase observations. Every pressure phase actually started 16
calls, each with a 99,043-byte canonical body; all 16 were body checked and reached
the declared target stage. The two late-reject phases and two valid-expensive
phases each observed 16 native full replays with zero rejection-cache returns.
Transport and early-reject reached their designated codec/context rejection
stages with no full-work start. The absent full-work cost values are retained
as unknown. This supports the implemented stage separation at this dose.

It does not isolate a unique liveness mechanism. Endpoint differences include
actual scheduling and queueing. The first transport phase accepted requests
between 101.696 and 158.349 ms; reverse valid accepted them between 158.180 and
160.572 ms. Other pressure phases accepted them around 101.38--105.39 ms.
Matching request count and bytes therefore did not match instantaneous arrival
load. Valid inputs also exercised admission, fork/state processing and storage.
Caller-thread CPU fields exclude scoped workers; nested spans and sums of
concurrent request waits cannot be treated as complete verifier cost or elapsed
critical-path delay.

At this fixed 16-single-call dose all arms confirmed: transport at 2.861469 and
2.721623 s, early reject at 2.798110 and 2.794678 s, late reject at 2.901256 and
2.900983 s, and valid expensive at 3.020800 and 3.081921 s. These are phase-epoch
endpoints, not release-relative service latencies. The
[descriptive statistics](batches/ci-43131129970/descriptive_statistics_v1/README.md)
retain both clocks and the paired/order descriptions without claiming an
inferential estimate from n=2 per arm. This series did not reproduce the old
closed-loop 386-call pressure failure. It neither proves general liveness under
attack nor refutes every dose-dependent attack hypothesis. Native stage
identifiability is supported; the original failure's unique cause remains
**UNKNOWN**. No additional pressure run was used to seek a preferred outcome.

The extra health batch at run `43131129775` is separately 3/3 under the same
source and executable but a different boot. It is not pooled with the earlier
`43125548321` health batch or the five in-campaign controls. Their timings do
not establish a source-induced speedup.

## Reproduce the path readback

This command reads the retained raw report and fixed Git objects. It does not
run the executable, generate traffic, mutate the Host, or overwrite an existing
receipt. Use a new output filename:

```sh
bash scripts/project-preflight.sh
python3 -B research/sp2027/02_receiver_liveness/audit_ci_rejection_paths.py \
  /absolute/path/ci-43052900246-13871459353/from-zero-native/confirmation/report.json \
  --source-repo . \
  --output /absolute/path/REJECTION_PATH_AUDIT.json
```

The script SHA-256 is
`12aaed3cc98c5838c462112a456a9e9b1d3fcbb6019535d943c2920bb9a0df59`.
It verifies the fixed report digest, exact Git blob identities for nine source
files, both request-digest domains, complete observer coverage, the two mutually
exclusive refusal paths, and actual recorded CPU values. The derived receipt is
separate from original raw records and is saved read-only. Permission bits are
a local guard; content hashes and the original artifact identity are the
reproducible integrity binding.

The supported result is native confirmation failure in this finite original
pair, together with a reproducible separation of replay and cached refusal.
The interpretation that every transcript refusal incurred full replay is
refuted by its own observer records. The causal mechanism of the confirmation
failure, its repeatability, and any independent deployment or attacker-cost
advantage remain **UNKNOWN**. The minimum-dose stage controls are now qualified
and observed, and the complete Agent 01 cost history/model is integrated in the
companion English manuscript. Those completed results do not supply matched
arrival timing, complete scoped-worker CPU attribution or a causal reproduction
of the old sustained-pressure failure. Their distinct claims and remaining
limits are summarized in the [coordinator handoff](COORDINATOR_HANDOFF.md).
