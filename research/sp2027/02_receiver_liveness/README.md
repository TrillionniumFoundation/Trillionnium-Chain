# SP27-02: native receiver liveness and evidence

## Scope and current interpretation

This task branch preserves an identified, fixed-order CI pair and the historical
reader. The causal mechanism is **UNKNOWN**. A single baseline 1/1 and pressure
0/1 pair does not establish an attack effect. Two separately identified CI health
batches each completed three unpressured controls within the same four-second
window. They are not pooled. A third, separately namespaced native campaign
completed its own three initial healthy controls, eight balanced stage controls,
and two healthy sentinels. All 13 business operations independently confirmed
under the strict native gate. The four arms each produced two confirmations and
all 16 actual body-checked target-stage witnesses per phase. This minimum
16-single-call dose did not reproduce the original closed-loop failure. It does
not establish a general absence of an attack or identify the cause of the old
failure. Actual arrival times differed despite equal request counts and bytes.

The old local `PUBLIC_HOST_KERNEL_PARENT` failure, diagnostic draft, and patch
remain **NOT_VERIFIED**: no matching original was recovered. The error has
several native causes. It is not a diagnosis of a missing cgroup by itself.

The shared conference plans, catalog, and coordination directories are owned by
the coordinator and are outside this task's changes.

## Evidence entry points

- [Native source and mechanism analysis](SOURCE_AND_MECHANISM.md).
- [Exact original-contract preservation](SOURCE_PRESERVATION.json): the original
  native Host checker and fixed systemd resource configuration are byte-identical;
  removing the three new module declarations reproduces the original parent
  test file, including the historical pair and helper.
- [Actual source-validation archive and command ledger](validation/ff354-source/MANIFEST.json)
  for `ff35430d27eea56dd803e05aa6d48573e37ed4c9`: exact source readback,
  locked release build, formatting, four Rust unit controls, strict Clippy,
  negative Host/source/reader controls and authorized branch publication.
  These checks are separate from native service outcomes.
- [New CI batch audit](batches/ci-43052900246/CI_AUDIT.md), with its original
  failure, fixed order, source/run/Host identity and descriptive statistics.
- [Byte-exact archive reconstruction](batches/ci-43052900246/ARTIFACT_PARTS.json).
  The split files are consecutive bytes of the original ZIP, not reserialized
  JSON. The manifest binds each part and the entire archive.
- [Rejection-path audit](batches/ci-43052900246/REJECTION_PATH_AUDIT.json): 52
  native verifier replays and 318 rejection-cache returns among the 370
  `WORK:Transcript` responses. The legacy `full_work` span also covers cheap
  checks and cache reads; it is not a full-replay counter.
- [Versioned reader and actual 06 consumer](reader_v2/README.md),
  [frozen contract](reader_v2/CONTRACT_FREEZE.json), and
  [independent root acknowledgment](reader_v2/ROOT_ACK.json).
- [Actual six-ZIP historical audit](reader_v2/RAW_CORPUS_RESULT.md): 35 phases,
  93 planned operations, 13 confirmed, 32 observed/unconfirmed, 48 unstarted;
  zero credited-count changes under V2. These are coverage totals, not a pooled
  success-rate estimate across different execution profiles.
- [Independent healthy CI batch](batches/ci-43125548321/HEALTH_CI_AUDIT.md):
  three confirmations at 3,182,777,296, 3,093,116,433 and 3,099,623,590 ns;
  source `0bc51795a978494af1b4659712ecf78c290c1a88`, run `43125548321`,
  job `130876572920`, artifact `13902664465`. Its separate
  [strict readback receipt](batches/ci-43125548321/HEALTH_V2_CONSUMER_RECEIPT.json)
  binds original files without rewriting the producer's V1 records.
- [Separate same-source healthy CI batch](batches/ci-43131129775/README.md):
  three confirmations at 1,800,867,959, 1,792,501,261 and 1,801,097,967 ns;
  source `ff35430d27eea56dd803e05aa6d48573e37ed4c9`, run `43131129775`,
  job `130895251212`, artifact `13907325153`. Its Host boot differs from both
  the previous health batch and the stage campaign. Cross-batch timing changes
  are not attributed to the source revision.
- [Actual balanced stage campaign](batches/ci-43131129970/README.md),
  [independent source/binary/Host audit](batches/ci-43131129970/STRATA_CI_AUDIT.json),
  and [actual frozen analysis/06 consumption](batches/ci-43131129970/strata_analysis_v1/CONSUMER_RECEIPT.json):
  source `ff35430d27eea56dd803e05aa6d48573e37ed4c9`, run `43131129970`,
  job `130895252279`, artifact `13906427974`. All 13 planned positions were
  attempted, invoked and completed; none were omitted or incomplete. Every
  native final gate was true and every endpoint was strictly below T.
- [Independent root health reconsumption](batches/ci-43131129775/ROOT_ACK.json)
  and [independent root stage/06 reconsumption](batches/ci-43131129970/ROOT_ACK.json).
  These are actual repeated analysis invocations in the current task environment,
  not additional native experiments or an acknowledgment by the historical
  SP27-06 author or coordinator.
- [Current measurement/root collaboration acknowledgment](strata_analysis_v1/CURRENT_MEASUREMENT_ACK_20261112.json)
  binds the unchanged contract digests and actual reciprocal byte readback.
- [Stage campaign descriptive statistics](batches/ci-43131129970/descriptive_statistics_v1/README.md):
  phase endpoints, release-relative latency, actual offered/accepted timing,
  stage coverage, nested cost scopes, queue sums and paired descriptions.
- [Coordinator handoff](COORDINATOR_HANDOFF.md) covers the supported/refuted/unknown
  claims, complete Agent 01 integration, actual registration uncertainty and
  the two isolated draft PRs.
- [Sibling CI failure readback](validation/ff354-source/SIBLING_CI_READBACK.json)
  preserves the actual QROM failures at the executed source. The failing fixed
  pin predicates and all nine relevant files match the earlier source and common
  entry point. This is not a waiver, a successful base-branch test, or an all-CI-green claim.

## Reproduce the analysis without running an experiment

Use a new, absolute output path for each command. The analysis does not mutate
raw records or run a native pressure workload.

```sh
bash scripts/project-preflight.sh
python3 -B -m unittest discover \
  -s research/sp2027/02_receiver_liveness/reader_v2 -p 'test*.py'
python3 -B research/sp2027/02_receiver_liveness/batches/ci-43052900246/reconstruct_artifact.py \
  --out /absolute/new/location/ci-43052900246-13871459353.zip
python3 -B research/sp2027/02_receiver_liveness/reader_v2/consume_native_v2.py ci-pair \
  --zip /absolute/new/location/ci-43052900246-13871459353.zip \
  --out /absolute/new/location/pair-v2-readback
```

The exact archive is 8,297,569 bytes, SHA-256
`8b21d753e0ac85ffdca7bc3e0a5f953d4dfffb24c7a10cc9ae394dcfe6590307`.
The original GitHub identifiers are run `43052900246`, job `130634539770`,
artifact `13871459353`, at source
`8ebcdb01016946a131f9067ebe1ace39b9c4f260`.

Historical original-ZIP reproduction is documented in
[the historical audit](reader_v2/RAW_CORPUS_RESULT.md). The companion original
minimal capsule has SHA-256
`a95d5051d117adfec54bc1d6d47e04f851504234344c0cc076fd57607de3e7a0`
and remains available in the exact Papers input commit
`c49c769fb3b08ee8f60c993c8ca6be2a4600246f` at
`research/sp2027/06_confirmed_goodput/inputs/native_archives_20261111/native_originals.tar.xz`.
The direct ZIP audit independently verifies the original retained executables.

## Native health execution

The source-owned workflow `.github/workflows/sp27-receiver-controls.yml` binds
its exact commit and tracked tree, prepares the release executable outside the
measured quota, then enters the original `run_from_zero_host.py` boundary.
It retains source identities, the actual executable, its build transcript,
Host receipts, raw phases and the final health decision on every outcome.

The commands inside that source-bound CI are:

```sh
python3 scripts/ci/run_sp27_receiver_controls.py --prepare \
  --out "$TRNM_CI_RECEIPT_DIR/sp27-receiver-controls"
python3 scripts/ci/run_from_zero_host.py -- \
  python3 scripts/ci/run_sp27_receiver_controls.py \
  --out "$TRNM_CI_RECEIPT_DIR/sp27-receiver-controls"
```

The receipt directory, immutable source receipt, exact expected Git SHA and real
GitHub job identity must be supplied by the checked workflow. Do not invent job
IDs, run the binary as root, relax resource limits, or replace a native Host
failure with a successful fixture. Direct bare-binary execution does not satisfy
this execution contract.

Each health phase keeps the original 4,000,000,000 ns window and the original
0.25 CPU / 2 GiB / zero swap / 256 task Host contract. It reuses the same acquired
seven signed packets with fresh receiver and verifier state. Health requires the
original native final gate, strict endpoint `< T`, exact business/state checks,
and complete observations. Collector exit zero denotes completed collection;
`NO_GO` remains a failed scientific qualification. The workflow makes that
qualification a separate failing CI step and preserves the report.

The actual three-control batch qualifies only its unpressured health outcome.
Its archive is 5,389,637 bytes, SHA-256
`db8960d8388dadb29450e525de1e3eaa71a2ae87d5d897c0e1ce9afb711bf312`.
Use the batch's create-only `reconstruct_artifact.py --out /absolute/new/file.zip`
to reconstruct its exact original bytes.

## Separate balanced stage campaign

The new selector is
`sp27_receiver_campaign::balanced_native_stage_controls_stop_on_unhealthy_sentinel`.
The source-owned workflow is `.github/workflows/sp27-native-stage-controls.yml`.
It uses the original Host runner and preserves all original limits, permissions,
the four-second per-phase deadline, and the 90-second outer native timeout.
Its source-owned execution commands are:

```sh
python3 scripts/ci/run_sp27_strata_controls.py --prepare \
  --out "$TRNM_CI_RECEIPT_DIR/sp27-receiver-strata"
python3 scripts/ci/run_from_zero_host.py -- \
  python3 scripts/ci/run_sp27_strata_controls.py \
  --out "$TRNM_CI_RECEIPT_DIR/sp27-receiver-strata"
```

The predeclared order is `H H H / T E L V / H / V L E T / H`. This is a balanced
forward/reverse order, not a randomized trial. Every phase starts a fresh native
receiver, independent verifying client, server, and rejection cache. It reuses
the same seven honest packets. Each pressure phase plans 16 workers with one
call each at the same 100-ms traffic-epoch offset; there are no retry loops.
The business path starts independently of pressure completion. All four arms
must have equal canonical Submit-body lengths and distinct per-worker bodies.
Actual call starts, lateness, accepted connections, body checks, reached stages,
CPU costs and queue waits remain observations, not assumed equal exposure.

| Arm | Intervention and input legality | Required native stage witness |
| --- | --- | --- |
| T: transport/codec | Paid Submit wrapper with the late input's first `PNH1` magic byte changed; packet codec is deliberately invalid | Actual body check; `HEADER_CODEC` at decode; context and work unstarted |
| E: early reject | Canonical codec; one canonical matrix element changes the task while preserving the late header, challenge, target and ticket | Decode accepted; context rejects `WORK:Task`; full work unstarted |
| L: late reject | Original from-zero target-hit construction; failed attempts and exhausted construction remain in the acquisition history | Context accepted; native full replay actually observed; work rejects `WORK:Transcript` |
| V: valid expensive | Sixteen independently mined valid empty genesis siblings; full preparation cost retained | Native full replay accepts and Submit completes; state/fork effects explicitly retained |

T includes bounded codec work and is not a pure socket-only intervention. V
includes admission, execution, fork choice and storage, so its difference from
L cannot be interpreted as a pure verifier CPU contrast. A single attained
stage witness establishes input-stage identifiability only; it does not prove
all 16 offerings reached that stage. Unknown or unmatched connections stay in
the original observer denominator.

The first failed initial control or sentinel, Host/identity failure, native
panic, lost observer coverage, unexpected invalid acceptance, unidentifiable
stage, or state-integrity failure stops the series as `NO_GO`. A pressure-phase
business failure is retained as an outcome and is not itself a collection
failure. The raw started, invoked, completed and unstarted counts are separate.
Timeout or incomplete output cannot receive fabricated completion credit.
This minimum dose is different from the old 386-call closed-loop pressure
phase; no equivalence of attack exposure is assumed.

### Observed stage campaign

The exact original ZIP is 8,016,966 bytes, SHA-256
`c56b845bda15360abe3e45b2b3d3893d0990984220afd5bdcfb754b6e1bb9f82`.
All 265 ZIP members and the retained 12,504,464-byte executable were independently
verified. The executable SHA-256 is
`52093ac76963ae8bb2a2e9b17bfb23fe82e706bf6b45f5aacc788a751a66bcd5`.
The five healthy endpoints span 2,616,533,703 to 2,857,806,807 ns. The pressure
endpoints, measured from each phase's original traffic epoch, are:

| Arm | Forward endpoint (ns) | Reverse endpoint (ns) | Strict confirmations | Actual target-stage bodies per phase |
| --- | ---: | ---: | ---: | ---: |
| Transport/codec | 2,861,468,990 | 2,721,622,917 | 2/2 | 16 |
| Early reject | 2,798,110,260 | 2,794,677,509 | 2/2 | 16 |
| Late reject | 2,901,255,562 | 2,900,983,219 | 2/2 | 16 |
| Valid expensive | 3,020,800,036 | 3,081,921,311 | 2/2 | 16 |

Every pressure phase actually started 16 calls and checked 16 matching bodies
of 99,043 bytes each. Both late phases and both valid phases observed 16 full
native replays and zero cached rejections. The transport and early phases
stopped at their required earlier stages; their absent full-work CPU values
remain unknown rather than being replaced with zero. Arrival timing was not
equal: the first transport phase and reverse valid phase had materially later
offer/accept tails. Queue waits are sums over requests, not a critical path;
recorded caller-thread CPU excludes scoped workers and is not complete W1 cost.
There are two observations per arm and one balanced sequence. No significance,
population effect or mechanism claim is inferred from these endpoints.

Reconstruct and analyze into new paths:

```sh
python3 -B research/sp2027/02_receiver_liveness/batches/ci-43131129970/reconstruct_archive.py \
  --out /absolute/new/location/ci-43131129970-13906427974.zip
python3 -m zipfile -e /absolute/new/location/ci-43131129970-13906427974.zip \
  /absolute/new/location/ci-43131129970-originals
python3 -B research/sp2027/02_receiver_liveness/audit_strata_ci.py \
  --input /absolute/new/location/ci-43131129970-originals/sp27-receiver-strata \
  --out /absolute/new/location/ci-43131129970-analysis \
  --experiment-id ci-43131129970-job-130895252279-artifact-13906427974
```

The create-only reconstruction checks the exact whole archive and part hashes.
The ZIP contains the original source/run declarations, executable, build logs,
Host/lease records, acquisitions, phase starts/invocations, complete raw phases,
and the native report. Reanalysis does not rewrite them or generate traffic.

The [independent analysis contract](strata_analysis_v1/CONTRACT.md) has its own
[freeze](strata_analysis_v1/CONTRACT_FREEZE.json). The audit consumes the original
prepared/executed source identities, retained executable and all raw phases,
then actually invokes the unchanged SP27-06 analyzer when the native business
identities and strict readback can be bound. A missing report produces an
analysis-side diagnostic, not a fabricated collector report. New consumer
receipts must be filed with the actual new CI batch.

## Interpretation boundaries

The original lease proves cooperating fixture ownership of the bounded parent;
it does not prove physical CPU dedication. Logical independent confirmation
still shares the parent's CPU budget with the receiver and client threads.
Inclusive nested timing spans cannot be added to obtain exclusive costs or an
expected speedup. The original mutation CPU meter reports zero refusals in the
new pair, so this batch does not establish exhaustion of that meter.

The actual retained Agent 06 consumer was executed on both the new pair and the
historical original records. The current independent implementations acknowledge
that result and the frozen digests. No prior Agent 06 author/coordinator signoff
is manufactured by these receipts. Submission registration likewise requires an
actual external receipt and remains distinct from source and manuscript status.
