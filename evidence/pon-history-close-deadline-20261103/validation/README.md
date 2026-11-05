# History completion: source-bound execution recovery

This follow-up records actual execution after environment recovery. It keeps the
[original recovered-candidate record](../README.md) and its pending
[historical status](../status.json) intact. No old failure is replaced by a later
success. **All-blocker closure, public readiness and activation remain false.**

## Changes and exact sources

The production correction at `9f04640877078204d367f753eba684d94e705a74` adds the
original-deadline success fence after mandatory CPU settlement and epoch closure
in the two ordinary History wrappers. It preserves cleanup-error priority,
original native errors, closed epoch state, paid CPU and durable packet facts.
It does not preempt native I/O, roll back a committed operation, grant execution
authority or establish a public-service wall bound.

The pinned formatter subsequently found two remaining assertion-layout changes
in the recovered test file. They were corrected and the first failure retained.
The signed-DAG comparison also gained bounded failed-sample diagnostics, emitted
after all original measurements and full report persistence. It retains all 18
samples, deadlines, resource checks, actual Host requirements and final assertions.
Its new output has not by itself qualified the original integration fixture.

| Source | Tree | Execution scope |
| --- | --- | --- |
| `3898f6a6dc65105bd4e3b52c94cc7625102f66da` | `9c5df9c0ec1d223ec0a189a61644b099d9a72b46` | Nine selected native controls; original formatter and strict workspace Clippy; source contracts and locked graphs. |
| `8a74a9e42a9efbc52d83e861f64f03efd40f1406` | `3d3ab7ff49c7f0b9109ba9e5ede1362cf6b290e7` | Fresh release rebuild after the concurrent witness-test correction; the same nine controls plus the original store CAS regression; source-bound checks below. |

The second source changes only the original store witness test and its source
pin. An already-observed client asserts the intended local consistency refusal;
a fresh unobserved client still reaches the real owner's CAS refusal. Exact
retries, skipped/wrapped sequence refusals, continued client usability and the
unchanged durable witness head remain asserted. Concurrent proof-scope documents,
root-value sharing, Cell controls and all other source are preserved.

## Executed checks and limits

| Check | `3898f6a6` | `8a74a9e4` |
| --- | --- | --- |
| Release libtest build | PASS | PASS, fresh rebuild |
| Selected native controls | 9 passed, 0 failed/ignored | 10 passed, 0 failed/ignored |
| Strict Clippy | PASS, entire workspace/all targets/all features | PASS, same original command |
| Original formatter | PASS | PASS |
| Source-pin / negative-integrity controls | 34 + 34 passed | 34 + 34 passed |
| Source pins | 376 verified | 376 verified |
| Embedded native inventory | Earlier unchanged inventory retained | 1,157 paths, direct checker PASS |
| Locked Linux main / fuzz graphs | 26/138 and 1/106 workspace/resolved packages | Same complete graphs, offline PASS |
| Repository contract | 1,842 local links verified | 1,842 local links verified |
| Complete source identity | Before/after clean and identical | Before/after clean and identical |
| Original test-profile and service qualification | OPEN | OPEN |

Native controls use the repository's unmodified **release** profile:
optimization level 3, no debug information, debug assertions off and overflow
checks off. The original test profile has different settings. These functional
results **do not close the original test-profile build, ARM CPU, complete
workspace, public Host or original confirmation-budget gates**. No
`CARGO_PROFILE_*`, `RUSTFLAGS` or `CARGO_ENCODED_RUSTFLAGS` override was used.
Rust 1.95.0 and the pinned provider were supplied through their actual paths;
no qualification flag, native guard or acceptance bound was bypassed.

The first native executable is SHA-256
`cf5a51d7a24e913576859b4821a61509c8bf28f5ea47f0d55dbe38168b729ed5`.
The composed executable is SHA-256 `8c2b4d00a6008848d044025887db9ad508020aa7d56358ebba08f254ac293cc9`.
Compiler artifact/profile, before/after identity, source identity, commands,
exit status, output digests and named results are retained. The nine controls
repeated on a second source are not new independent experiments or additional
unique controls.

The three new controls cover late success, retained native errors, cleanup,
original account identity, durable valid-packet admission, already-paid CPU,
exact retry without repeated W1 work and cold reopen. They expire before native
completion. No separate executed case isolates timely native success expiring
only during settlement/epoch closure, and no new cleanup-failure case was
injected. Static placement and preserved error propagation must not be described
as those missing runtime observations.

## Failed and incomplete attempts retained

| Observation | Outcome |
| --- | --- |
| First recovered formatter invocation at `9f046408` | Exit 1; two assertion layouts subsequently corrected. |
| Direct Cargo invocation at local checkpoint `a7efe604` | Normal loader directory incomplete; only the owned build interrupted, exit 130; no native test result. |
| Subsequent original test-profile build at `a7efe604` | rustc SIGKILL, Cargo exit 101; no native test pass. |
| Fresh original test-profile build at `a7efe604` | Session disappeared without terminal receipt or new test executable; **UNKNOWN**, not a pass. |
| First fuzz locked-graph check at `3898f6a6` | Offline resolution failed because `libfuzzer-sys` was absent; original locked online resolution then passed without source/lock changes. |

Only owned compilation caches were reclaimed. The old successful executable was
compressed and round-trip hash checked before removal from its build cache.
Source, Git object dependencies, failures and receipts were retained. Resource
recovery is not a performance or qualification result.

## The older confirmation failure

The retained artifact from [run 41686753154](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41686753154),
job `126096954170`, binds older source
`116a3caf6046dd0db3caf1d0797e636c35c877b8`. The ZIP was read as data only;
its SHA-256 is `a1c2bd158d07392b2997b551199fbb692a3b473d3f1d2affdf43d39f457bf06d`.
The [honest-path extraction](retained-116a-honest-path.json) identifies exact
members and JSON pointers. Executables and workload-generation material are
not included in this evidence folder.

Five named protocol tests pass, but the separate acceptance manifest retains
`failures=["CONFIRMATION_TARGET"]`, `passed=false` and
`execution_finished=false`. The ordinary baseline completes seven submissions,
seven History imports, seven replays and confirmation in 2.790815017 seconds.
The paired finite run completes seven submissions but only two History imports
and replays. Its third History attempt ends at 4.001762 seconds with a challenge
stage `IO: Resource temporarily unavailable (os error 11)` result; confirmation
does not occur in the original four-second window. Unstarted template stages
are not executed hangs.

This narrows the observation to the honest sync/confirmation path. A client
challenge error does not identify the server implementation's root cause. Empty
Host-error lists do not establish capacity. Calling-thread CPU excludes other
workers; nested intervals cannot be added as disjoint costs. The finite same-host
observation supplies no WAN, independent-operator, work-hardness or public
amplification claim. It does not establish that the separate signed-DAG Host
fixture mismatch caused this failure.

## Remaining acceptance gates

The [neural work specification](../../../docs/protocol/pon-nakamoto-v1/NEURAL_WORK.md),
[consensus specification](../../../docs/protocol/pon-nakamoto-v1/CONSENSUS.md) and
[public-readiness contract](../../../docs/protocol/pon-nakamoto-v1/details/PUBLIC_READINESS.md)
retain their original acceptance conditions:

- Same-target cheapest legal work, preprocessing/reuse, effective heterogeneous
  output and quantum assumptions require separately reviewed evidence.
- Original confirmation windows and complete campaigns require their original
  denominators, budgets, actual Host and exact source. ACKs and release-profile
  functional results do not satisfy them.
- Independent operators/evaluators, frozen WAN campaigns, long-term retrieval,
  prospective model benefit and durable external effects cannot be established
  by adding local processes, keys or static assertions.
- DAA/confirmation settings remain development parameters. Model scores do not
  become chain work; confirmation grants no local execution power.

The `3898f6a6` and `8a74a9e4` CodeQL aggregates succeeded. Other workflow outcomes and
non-atomic snapshots are in [CI readback](ci-readback.json). That source-specific
success does not certify newer source or these acceptance gates. The PR
remains a draft integration candidate.

## Audit files

[Status](status.json) records typed scopes and open gates.
[Execution records](execution-records.json) preserve original receipts and
observations. [Raw logs](raw-logs.json.gz) is gzip-compressed JSON containing the
complete selected stdout/stderr and driver snapshots, with no compiled binary.
[File manifest](manifest.json) binds archived entries and evidence files by byte
length and SHA-256.
