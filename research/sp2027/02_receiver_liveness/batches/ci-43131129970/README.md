# Balanced native stage-control batch: CI 43131129970

This is a separate original batch. The original fixed-order pair and both
standalone health batches remain intact. The audits execute no native program
and do not create missing observations.

## Exact identities and preserved source

| Item | Observed identity |
|---|---|
| Source commit | `ff35430d27eea56dd803e05aa6d48573e37ed4c9` |
| Source tree | `ccf72585d2ac3b361ec169a62a607d7bce055582` |
| Run / attempt | `43131129970` / `1` |
| Job | `130895252279` |
| Artifact | `13906427974` |
| Original ZIP bytes | `8016966` |
| Original ZIP SHA-256 | `c56b845bda15360abe3e45b2b3d3893d0990984220afd5bdcfb754b6e1bb9f82` |
| Retained executable bytes | `12504464` |
| Retained executable SHA-256 | `52093ac76963ae8bb2a2e9b17bfb23fe82e706bf6b45f5aacc788a751a66bcd5` |
| Native host / boot ID | `runnervm7aw5e` / `36bd2fe4-42b9-44b3-adb8-4cfb340b6021` |

The [run](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/43131129970),
[job](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/43131129970/job/130895252279),
and [source commit](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/ff35430d27eea56dd803e05aa6d48573e37ed4c9)
are bound by saved API metadata and actual source/compiled/run readbacks. The
independent provenance audit checked all seven declared source files against
actual Git blobs and all four compiled module hashes against those bytes.

The same source produced the byte-identical retained binary in the additional
standalone health run 43131129775. Its boot ID differs. Matching hostnames do not
establish identical hosts or unchanged physical scheduling.

## Actual fixed-window result

The native report is `COLLECTED_CONTROL_SERIES`: 13 planned, 13 attempted,
13 helper-invoked, 13 complete phases, 0 incomplete and 0 unstarted. All 13
business transactions were independently confirmed with strict endpoint `< T`
and the preserved original final gate true. The original window is always
4000000000 ns. The native first-divergence is `null`.

| Index | Actual phase | Confirmation endpoint, ns | Confirmed |
|---:|---|---:|---:|
| 0 | initial health 0 | 2673502700 | 1 |
| 1 | initial health 1 | 2617861904 | 1 |
| 2 | initial health 2 | 2857806807 | 1 |
| 3 | transport 0 | 2861468990 | 1 |
| 4 | early-reject 0 | 2798110260 | 1 |
| 5 | late-reject 0 | 2901255562 | 1 |
| 6 | valid-expensive 0 | 3020800036 | 1 |
| 7 | midpoint healthy sentinel | 2616533703 | 1 |
| 8 | valid-expensive 1 | 3081921311 | 1 |
| 9 | late-reject 1 | 2900983219 | 1 |
| 10 | early-reject 1 | 2794677509 | 1 |
| 11 | transport 1 | 2721622917 | 1 |
| 12 | terminal healthy sentinel | 2700994493 | 1 |

Each pressure phase offered 16 workers with one call each, zero retries, and a
common scheduled slot of 100000000 ns. Canonical Submit bodies are 99043 bytes
each. The source declares that equal offered schedules do not imply equal
realized arrival times, network traffic, queue exposure, or CPU consumption.
Those observed quantities remain in the raw records and frozen analysis.

Every pressure phase actually started 16 calls, retained 16 matched checked
bodies, and observed 16 target-stage witnesses. Both late-reject phases and
both valid-expensive phases recorded 16 complete native replays each, with no
cached rejection. Transport and early-reject phases recorded zero complete
native replays. Exact stages, per-connection queues, deadlines, errors,
cancellation/closure fields, and nested CPU scopes are preserved in
`strata_analysis_v1/phase_table.json` and `connection_records.jsonl`.

The five healthy phases passed, and all eight pressure phases satisfied their
control-integrity checks. Stage qualification and business confirmation are
separate checks; a pressure phase's collection success alone never credits a
transaction.

## Identity, Host, and resource scope

All 265 regular ZIP members passed full CRC and SHA-256 readback, including the
actual executable, preparation/execution manifests, full input acquisitions,
13 raw phases, per-phase markers/indices/Host files, and retained native state.
The native identity before and after matches. Source and executable identities
before and after agree with the actual saved bytes.

Runner Host observations preserve `cpu.max=25000 100000`, `cpu.max.burst=0`,
`memory.max=2147483648`, `memory.swap.max=0`, `pids.max=256`, UID/GID 1001,
`NoNewPrivs=1`, and zero bounding capabilities. Before/after read-error
collections are empty. Both global native Host readbacks and the 26 per-phase
readbacks pass unchanged eligibility checks. The fresh cooperative parent lease
and its identity agree before and after. Exclusive physical-CPU use remains
`NOT_ESTABLISHED`; the producer, receiver, and independent client share the fixed
parent's resource budget.

The native child took 54134029355 ns wall and 9483126000 ns CPU, exit 0, with no
timeout under the original 90-second child cap. The separate Host snapshot
interval is 89510853000 ns. Complete native control-input acquisition reports
732009246 ns wall and 174794390 ns process CPU. The broader acquisition-index
scope reports 851863843 ns wall and 217693698 ns CPU; these nested intervals must
not be added. Valid-expensive includes actual admission/state/storage effects
and is not a pure intervention on proof-verification CPU.

## Interpretation

The bounded 16-by-one schedule did not reproduce a confirmation loss in either
repetition of any arm. This is a descriptive result for this source, binary,
host, schedule, and small sample. It does not establish attack impossibility or
an equivalence bound. It does not reproduce the earlier pair's sustained
386-call pressure dose, execution order, cache history, source or host. The old
pair's result remains preserved and its causal interpretation remains open.
Overall mechanism status is `UNKNOWN`; publication/public-network/production
qualification flags remain false.

## Reconstruct original bytes and repeat the read-only audits

`ARTIFACT_PARTS.json` describes three consecutive original ZIP byte slices. No
archive member was rewritten or repackaged. Reconstruction was actually run and
its full SHA-256 matched the platform digest. From the Chain repository root:

```bash
BATCH=research/sp2027/02_receiver_liveness/batches/ci-43131129970
python3 "$BATCH/reconstruct_archive.py" --out /absolute/new/artifact-13906427974.zip
GIT_NO_LAZY_FETCH=1 python3 "$BATCH/audit_original.py" \
  /absolute/new/artifact-13906427974.zip --source-repo . \
  --artifact-metadata "$BATCH/artifact-metadata.json" --out /absolute/new/provenance-audit
python3 "$BATCH/intake_original_zip.py" \
  --archive /absolute/new/artifact-13906427974.zip \
  --metadata "$BATCH/artifact-metadata.json" \
  --artifact-id 13906427974 --run-id 43131129970 \
  --head ff35430d27eea56dd803e05aa6d48573e37ed4c9 \
  --out /absolute/new/verified-originals
python3 -B research/sp2027/02_receiver_liveness/audit_strata_ci.py \
  --input /absolute/new/verified-originals/originals/sp27-receiver-strata \
  --out /absolute/new/frozen-analysis \
  --experiment-id ci-43131129970-job-130895252279-artifact-13906427974
```

All output paths must be new. `audit_original.py` is the exact audit source used
for `STRATA_CI_AUDIT.json`, SHA-256
`0b592ade14ce8849a075f9f417fc39878158c1f830496ae7091f15b7acde9826`.
The strict reader and frozen SP27-06 analyzer were actually executed on these
originals. Their receipt is `strata_analysis_v1/CONSUMER_RECEIPT.json`, SHA-256
`51e0e351a93f3fe70fef3e809c0e2204a1eb7dcfbe5c5fd9d7c3e03f8e66c8f1`.
This pinned provenance audit checks this observed complete batch; failed or
missing reports are retained by the intake and frozen analysis, never repaired.

`RAW_SHA256.json` records every original member's size, CRC, and SHA-256.
`BATCH_MANIFEST.json` hashes all delivered files at this freeze except itself;
separately appended coordinator acknowledgments are outside that frozen set.
