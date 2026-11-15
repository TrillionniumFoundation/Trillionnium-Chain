# R4 research Node adapter: one shared-quota pressure observation

## Result and qualification

**HOLD / NO-GO.** One fixed campaign launched 23 independent fresh adapter
processes into one owned cgroup: 16 malicious requests (four typed mutations,
four repetitions each) and seven legitimate requests repeating one actual
Node-generated fixture. All 23 executions were observed and all 23 exits were
collected with `wait4`. There were zero completed cryptographic rejections and
zero completed native admissions. All 23 processes ended with `SIGKILL` after
the deadline; these are incomplete executions, not cryptographic rejections.

No request emitted the first `BeforeProof` checkpoint or a final exercise
receipt. No recorded checkpoint establishes entry into proof verification. Each
request's precise final execution stage is unknown. Input loading, independent
binding, shape admission and bundle persistence precede that checkpoint in
the source, but missing logs do not locate the last instruction executed. It does not measure a completed late PCS rejection under this quota. The four
malicious proofs were independently qualified as shape-valid typed late failures
in the separate preflights described below.

After every worker exited, both the controller and an independent observer
checked its unique output location. No `receiver-node` directory or database
was created for any of the 23 requests. Missing `exercise.json` and missing
`node_opened` reports remain unknown in the receipts; filesystem absence is a
separate observation. No unobserved exit is counted as success or rejection.

This is a finite negative diagnostic of a research adapter, not a production
slice, a single Node service or a universal rejection-cost bound. The seven
legitimate requests are independent processes using the same fixture, not seven
distinct production submissions. This observation does not prove a general
service-starvation claim or quantify the cheapest lawful physical strategy.

## Exact limits and time boundary

The kernel initially reported `cpu.max = 25000 100000`, `cpu.max.burst = 0`,
`memory.max = 2147483648`, `memory.swap.max = 0` and `pids.max = 256`. These
correspond to 0.25 CPU, 2 GiB RAM, zero swap and a maximum of 256 tasks. Every
blocked child was moved to this cgroup and its membership was checked before
its gate was released. All descendants inherit the cgroup. The worker inherited
eight-CPU affinity and `RAYON_NUM_THREADS=8`; the quota still limits total CPU.
The sentinel also belongs to the cgroup and is included in its resource counts.

The deadline was fixed at exactly four seconds after the first attempted fork,
before the launch loop. It was not reset after the last process started. The
controller ran outside the workload cgroup. Its actual scheduling and cleanup
times must be retained:

| Event | Seconds after the first attempted fork |
| --- | ---: |
| First child gate released | 0.002315029 |
| Last child gate released | 0.042419212 |
| All 23 adapter executions had been observed | 1.009297562 |
| Declared deadline | 4.000000000 |
| Controller observed the expiry | 4.072751647 |
| Owned `cgroup.kill` requested | 4.075439652 |
| `cgroup.kill` returned | 4.075496438 |
| Last worker exit collected | 4.213890717 |
| Workload cgroup absence confirmed | 4.262711254 |
| Controller observation finished | 4.455564439 |

The kill request was 75.439652 ms after the declared deadline. This run does
**not** establish a hard four-second termination or cleanup guarantee. The
20-second systemd runtime cap was a backup, not the observed termination path.

The last kernel snapshot before the kill recorded memory peak **175,022,080
bytes**, task peak **24** (23 workers plus the sentinel), and zero `oom`,
`oom_kill`, memory-limit and task-limit events. The kernel cgroup had already
disappeared when subsequent reads were attempted; those missing reads remain
in the raw record. The smaller systemd-reported `MemoryPeak` is retained but is
not substituted for the observed kernel peak.

Kernel CPU usage increased by **1.052663 seconds** from the campaign-start
snapshot to the snapshot before the kill. Worker `wait4` totals are 0.841371
seconds user CPU and 0.241195 seconds system CPU. They have different boundaries:
worker totals include work before migration and through exit; cgroup totals
include the sentinel and work charged to the cgroup. They are not expected to
be identical and are not universal bounds.

Initial limit mismatches abort without an unconstrained fallback. Subsequent
snapshots retain observed limits, but this harness does not implement a
continuous limit-drift abort. Setup, input copies, mutation, the controller and
observer are outside the workload quota. Worker input reads, public binding,
proof scanning, bundle persistence and any subsequent verification/admission
are inside it. The machine was shared; coordination cleared the team's heavy
jobs, not unrelated host activity. Preflight load averages are retained, and no
machine-wide load series was sampled during the four-second campaign.

## Separate functional preflights

Before the measured campaign, the same immutable v4 binary executed exactly
five independent fresh exercises under the separate setup job's larger budget.
They are outside the four-second workload budget and are not ABBA performance
samples. Four mutator processes changed existing real proofs; no new proof was
generated. Every failure preserves proof length, canonical wire structure and
the transcript-bound fields, using the existing typed mutator.

| Preflight | Observed outcome | Outer seconds | Peak RSS KiB |
| --- | --- | ---: | ---: |
| Valid fixture | Both proofs verified; actual Node admission and activation succeeded | 1.270593369 | 122,912 |
| SHA final fold value | `SHA_PROOF:InvalidOpeningArgument(FinalPolyMismatch)` | 0.822721600 | 64,332 |
| SHA final authentication sibling | `SHA_PROOF:InvalidOpeningArgument(CommitPhaseMmcsError(CapMismatch))` | 0.769561533 | 63,900 |
| Arithmetic final fold value | `ARITHMETIC_PROOF:InvalidOpeningArgument(FinalPolyMismatch)` | 1.319424872 | 123,172 |
| Arithmetic final authentication sibling | `ARITHMETIC_PROOF:InvalidOpeningArgument(CommitPhaseMmcsError(CapMismatch))` | 4.378274605 | 123,192 |

The SHA controls reached `BeforeShaVerify`; the arithmetic controls first
passed SHA verification and reached `BeforeArithmeticVerify`. All four rejected
before `ProofVerified` and before opening a receiver Node. The adapter returns
an exercise receipt with exit status zero for these controlled proof failures;
the receipt's exact error and stage, not the process exit code alone, define
the successful negative control. The slow arithmetic-authentication observation
is retained without replacement or selection.

The total is **28 exercise processes: 5 preflight + 23 campaign**, plus four
typed mutator processes and zero fresh proving executions. No production
activation was performed. The adapter uses actual native Node APIs in a
research namespace and retains native W1 verification for fresh admission;
its development SQLite boundary remains unqualified for production owned I/O.

## Identity and retained evidence

The executed binary SHA-256 is
`271ac45cc709d1d6e91e9ff78c004668e5e4d2a690e3b4e963220e750bcbeb1b`.
The root Node worktree was at `7a7dfb9002406f4345a57e416d7a36504461c0df`
with frozen uncommitted v4 adapter source. HEAD alone does not identify this
binary: the input manifest includes exact source copies and hashes for the
adapter, backend, native crate sources and Cargo files. This source observation
is separate from the root's original release-build receipt.

The SHA proof is component 5, magic `W1P3SCS4`, **3,142,981 bytes**, SHA-256
`af66da05a9ebab9f0f9224b7b7df19aa6fa8949152fcf714a95797a000728218`.
The arithmetic proof is component 4, magic `W1P3APC3`, **454,085 bytes**, SHA-256
`b5ae0d59d060d6fd5c965e31f1ee3c082d3e2cad72a1002f191082c27395cb04`.
They originate in the root's actual Node fixture campaign, not the earlier
retained/dense backend ABBA. Independent operator-plan, expected-header and
expected-artifact material remains fixed for every request and mutation.

All original source/binary/input files, all copied inputs and the manifest
were unchanged at the independent post-run check. The durable measurement job
is `1a1b9afa6de-12894-160e`. Its remote evidence directory is
`/home/qian-qi/work/chain-w1-node-pressure-20261108-f16ac-r4-01`.

The principal machine-readable records are [final-summary.json](final-summary.json),
[campaign-01/result.json](campaign-01/result.json),
[inputs/manifest.json](inputs/manifest.json) and
[independent_cleanup.json](independent_cleanup.json). Raw checkpoints, stderr,
exec-attempt timestamps, cgroup samples, `wait4` resources, complete preflight
logs and individual output directories are retained. Source and input copies
are inventoried before and after the run. Binary/proof/database files remain
at their pinned remote paths and have individual hashes in the final inventory.

The first archive is retained unchanged. Its collector captured its own stdout
before the collector printed its final receipt; the final archive adds that
completed log, stage status, the launch driver, this explanation and the final
summary. It does not replace or alter a measured sample. The final archive
inventory checks the hash of every included file before adding it.

## Reproduction boundary

The three execution scripts are [prepare_node_pressure.py](prepare_node_pressure.py),
[run_node_pressure.py](run_node_pressure.py) and
[collect_node_pressure.py](collect_node_pressure.py). They are fixed to the
declared fixture, source and binary identities. Copy them into a new external
directory, retain a coordination clearance, and use a new output namespace;
existing directories cause refusal. Run preparation once, then the campaign
once, then independent collection. The preparation script intentionally makes
five real functional calls, outside the pressure budget. The finalizer only
reads the completed experiment and packages evidence; it performs no further
verification or proving. Do not silently update expected hashes or relabel a
later run as this observation.

## Integrated archive

The [complete immutable observation archive](node-pressure-evidence-final.tar.gz)
contains the original README and all 949 recorded members. The visible README
clarifies that an absent checkpoint is not a proof of each worker's final
program counter; no raw observation or archive byte was changed.
