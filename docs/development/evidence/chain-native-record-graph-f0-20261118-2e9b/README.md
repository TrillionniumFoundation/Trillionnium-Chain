# Native metadata-insert graph reuse: unchanged F0 remains failed

**HOLD_NO_GO. The frozen #962 source completed 1/6 confirmations in the original
thirty-second phases and 0/6 scheduled four-second targets.** This evidence-only
successor preserves the original failure, all 6 rounds and all 42 planned packet
exposures. It changes no runtime, resource, deadline, source gate or business
predicate.

## Exact run and independent readback

- Tested source: `1380eaae3c902b3e17d5e5a7d73bf242b0366562`.
- Tested tree: `176e1a77202f6604823163fde07d5e51d6cc47ed`.
- Candidate: [Draft #962](https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/962).
- Original run: [44356270247](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/44356270247), attempt 1, job `134985105101`.
- Runner: `GitHub Actions 1000189688`; actual job start `2026-11-18T17:36:43Z`.
- Original artifact: `14455766451`, 17,509,272 bytes, SHA-256
  `ba7317fdbc7da70965c277323ca0a4321ab5692945322bc906c086b92d6bc872`.
- Original report: `execution/raw/report.json`, 12,109,679 bytes, SHA-256
  `68dd117050f4773df835f89b63316f766697c59b8698cfd4afe54024f4863f04`.
- Actual retained ELF: 13,243,784 bytes, SHA-256
  `6f77f0636d9b8ac3c4ba3d8b7081a1bc796f1d359bab31eb515e28b96a2479ec`.

[f0-original.zip](f0-original.zip) retains every original provider member, including
the ELF, actual native report, databases, partial results, preparation controls,
source receipts, original logs, workflow outcomes and cleanup observations.
[f0-readback.py](f0-readback.py) verifies the provider ZIP hash and size, all
443 inventory entries, the three unchanged before/after source pairs, the
source-bound ELF and the seven original preparation controls. It imports the
unchanged original readers and verifies all twelve Python blob SHA-256 pins
before invoking their original predicates.

The independent receipt is [f0-independent-readback.json](f0-independent-readback.json),
SHA-256 `5522130615560d4f63e638fff6608712e71934c073d772a132e28492df684e36`.
The exact reader source hash is
`5a7455e2e00370aca9858cacef5ea0603c0cade7418dfe6458ffd0d44701f140`.
Its successful exit means this retained failure was reproduced by readback.
It does not make the native business test pass.

The original native selector exited **101**. Original readers still reject
`BASELINE_MUST_PASS` and
`F0_ALL_SIX_SCHEDULED_FOUR_SECOND_TARGETS_REQUIRED`.
Source verification, the fixed compiler/dependency preparation and all seven
native preparation controls succeeded. Original finalization still reports
`complete_success=false`; all exact owned services are known empty. The workflow
business and finalization steps therefore remain failed, while source retention
and artifact upload succeeded.

## Original business denominator

The workload remains 1,024 seed transfers in four seed blocks, 21 business blocks
per phase, baseline plus valid-work ROOT pressure, three scheduled rounds per
phase at 1/5/9 seconds, 24 external ROOT actors, the original 30-second phase,
one M06 worker, a 0.25-CPU/2-GiB public Host and the original separately bounded
controller. No drain, smaller workload or altered confirmation predicate is
credited.

| Actual phase | Original 30-second confirmations | Scheduled 4-second targets | Timely network ACKs | Planned packet exposures |
| --- | ---: | ---: | ---: | ---: |
| Baseline | 1/3 | 0/3 | 14 | 21 |
| Valid-work ROOT | 0/3 | 0/3 | 4 | 21 |
| Total | **1/6** | **0/6** | **18** | **42** |

The first baseline confirmation ended at phase time 25.507888471 seconds,
24.507888471 seconds after its scheduled start. The second round stopped at
the original deadline without confirmation; the third was unobserved. ROOT's
first round stopped without confirmation and its other two rounds were
unobserved. An ending timestamp on a failed round is not a confirmation.

Twenty-three planned packets had no observed attempt. One other planned packet
had attempts but no timely ACK. There were 29 actual submission attempts,
including retries; these do not replace the 42 original planned exposures.
The complete original rows are retained. ACKs do not establish independent
History replay or transaction confirmation.

## Actual work and CPU

[cost-profile.py](cost-profile.py) rereads the four original provider ZIPs and the
actual retained SQLite records and deltas. [cost-profile.json](cost-profile.json)
contains the full observations, including incomplete imports, graph frequency,
packet/phase work, original preparation, CPU credit flow, application bytes,
controller measurements and retained database sizes.

| Frozen native source | Original run | Original 30-second confirmations | Scheduled 4-second targets |
| --- | --- | ---: | ---: |
| `7e3e454f` | 44315121617 | 1/6 | 0/6 |
| `eeef078c` (#959) | 44328450170 | 0/6 | 0/6 |
| `e6af21fd` (#960) | 44335832525 | 2/6 | 0/6 |
| `1380eaae` (#962) | 44356270247 | 1/6 | 0/6 |

These executions used different GitHub runner allocations and completed different
amounts of work. They do not provide paired causal speed estimates. In particular,
baseline Host checkpoint CPU per observed call was about 55.38 microseconds in
this run, compared with about 24.80 microseconds in #960. A lower call count or
lower total cost from less completed service cannot establish an improvement.

| Current observed scope | Baseline | Valid-work ROOT |
| --- | ---: | ---: |
| History imports observed | 8 | 0 |
| History client thread CPU (ns) | 5,425,864,517 | 0 observed imports |
| Nested Host checkpoint calls | 82,046 | 0 observed imports |
| Nested Host checkpoint CPU (ns) | 4,543,810,044 | 0 observed imports |
| Whole public phase process CPU (ns) | 8,376,872,630 | 8,691,669,137 |
| Whole public phase process wall (ns) | 34,583,361,761 | 34,893,774,157 |
| Original controller cgroup CPU delta (microseconds) | 2,488,082 | 4,062,319 |

ROOT never reached a History request or client import. Its zero import counters
mean no work was observed in that scope, not that ROOT service was inexpensive
or successful. The receiver persisted five business blocks, while the
independent client persisted none. The baseline receiver persisted fourteen
business blocks and the independent client seven.

Baseline client account-graph observation recorded 62 calls and
4,372,566,638 CPU ns. The one activation recorded 1,456,895,059 CPU ns and
6,507,189,945 wall ns. Its `submit_result` Host bucket recorded 21,171 checks and
1,179,128,248 CPU ns. The other principal Host buckets were `commit`
(35,056 checks; 1,939,593,798 CPU ns), `admission_prepare`
(16,637; 925,323,283 CPU ns) and `work` (8,792; 476,400,581 CPU ns).

Under ROOT pressure, the receiver recorded 338 admission calls, 350 State reads
and 357 account-graph observations. Their nested CPU totals were respectively
5,088,959,656; 4,271,822,809; and 3,654,899,693 ns. These counters describe actual
successful and failed work and are not added to one another or to whole-process
CPU. The next repair must address actual repeated work while preserving current
owner, storage, cancellation and budget checks.

The retained baseline databases contain twelve receiver blocks and six client
blocks with unchanged complete account Roots and no actual account deltas.
These are observed eligibility/frequency facts. They are not a measurement of
saved graph visits or a substitute for the failed business gate. No graph result
is granted across another transaction or an uncontrolled write.

## Memory, bytes and remaining cost limits

All six original controller resource boundaries were observed and independently
validated; all 24 ROOT actor processes were reaped. The original
`cpu.stat`, `memory.current` and `memory.peak` reads remain in the archive.
Controller CPU covers that actual cgroup and its descendants from before phase
launch to reaping/phase exit; it excludes earlier honest-miner preparation and
the separately owned public phase.

| Retained measurement | Baseline | Valid-work ROOT |
| --- | ---: | ---: |
| Controller cgroup lifetime memory peak at after-reap (bytes) | 80,191,488 | 126,967,808 |
| Public process procfs lifetime peak RSS (bytes) | 71,852,032 | 118,562,816 |
| Public process kernel RUSAGE_SELF peak RSS (bytes) | 71,540,736 | 118,456,320 |
| Retained receiver SQLite file (bytes) | 4,317,184 | 2,834,432 |
| Retained client SQLite file (bytes) | 3,366,912 | 2,002,944 |

The retained honest-miner SQLite file is 5,505,024 bytes. These database sizes
describe the original retained files, including duplicated shared state;
they do not measure physical write traffic, peak disk use or storage byte-seconds.
No WAL/SHM file is invented when absent from the original archive. Cgroup peaks
are whole controller-service lifetime peaks including prior preparation/phases,
not per-phase deltas or per-actor RSS. Public process peaks are separate
diagnostics. Their sum would not establish a simultaneous whole-system peak.

[provider-timing.json](provider-timing.json) preserves the actual provider API
response for this run. It reports one Ubuntu job with `total_ms=0` and
`duration_ms=0`, and `run_duration_ms=2009000`. The zero billable fields are
provider-reported accounting fields, not zero physical consumption or a known
price. Run duration includes queueing and cannot be treated as CPU time.

Full physical cost remains **UNKNOWN**. Exact physical I/O/network traffic,
concurrent whole-system RSS, storage byte-seconds, energy, monetary cost and
complete research/tool/provider acquisition overhead are not supplied by these
measurements. The report grants no production activation, general service
fairness, independent-operator, WAN, Sybil or reward qualification.

## Reproduction

From this repository root, with the unchanged original Python readers available:

```sh
python3 -B docs/development/evidence/chain-native-record-graph-f0-20261118-2e9b/f0-readback.py --archive docs/development/evidence/chain-native-record-graph-f0-20261118-2e9b/f0-original.zip --out /tmp/chain-record-f0-readback.json
python3 -B docs/development/evidence/chain-native-record-graph-f0-20261118-2e9b/cost-profile.py --out /tmp/chain-record-f0-cost-profile.json
```

Both outputs must be previously absent. The cost reader uses the SHA-bound
original ZIPs retained in this branch's preceding evidence commits. This performs
read-only evidence reconstruction and does not rerun F0. The frozen tested
runtime remains on #962; this successor adds only this evidence directory.
