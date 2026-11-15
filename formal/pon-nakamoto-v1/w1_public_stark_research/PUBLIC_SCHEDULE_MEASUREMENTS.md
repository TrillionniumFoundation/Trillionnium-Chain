# Public schedule SHA: retained complete-proof comparison

**HOLD_NO_GO.** This campaign measures a research producer-plus-receiver chain.
It shows a smaller and faster proof pipeline than the previous packed STARK,
with a slower verifier. It does not close the native or production end-to-end
benefit gate.

## Observed results

Eight fresh complete W1 proving executions were independently verified: four
per variant, across two distinct input fixtures. Each fixture used order ABBA.
A is original SHA component 1 plus packed arithmetic component 4. B is public
schedule SHA component 5 plus the same packed arithmetic component 4. Both used
identical fields, hash construction, FRI parameters and independent verifier
preprocessing.

| Observed median, four runs per variant | A | B | B versus A |
| --- | ---: | ---: | ---: |
| Complete prepare + prove + verify processes | 14.5193950535 s | 11.862382255 s | −18.30% |
| Prove process | 12.834679348 s | 10.3773001965 s | −19.15% |
| Verify process | 0.972320643 s | 1.0685001415 s | **+9.89%** |
| Maximum process RSS within pipeline | 2,035,728 KiB | 1,463,658 KiB | −28.10% |
| Statement + both proof envelopes | 5,187,028 bytes | 3,978,068 bytes | −23.31% |

The pipeline column is the median of each run's summed process times. A sum of
separate phase medians is not generally equal to that value. Payload lengths
vary slightly across inputs because the FRI query multiproof frontiers differ.

| Input and per-variant count | A pipeline | B pipeline | A verify | B verify |
| --- | ---: | ---: | ---: | ---: |
| retained, two each | 15.171203795 s | 12.889063205 s | 0.967997451 s | 1.018858107 s |
| dense, two each | 13.8694737785 s | 10.582560131 s | 0.9724783975 s | 1.068560584 s |

Both input-specific pipeline medians improve; both input-specific verifier
medians regress. Every sample, including the slower verifier observations, is
retained. There is no claim of a production distribution, statistical tail
bound, universal memory limit, or host exclusivity.

The retained B SHA envelope is 3,146,949 bytes with SHA-256
`11423125f0f5cde3accbcd46f221386c3005d2e72e0e30020b4ae9850acf9085`.
Its arithmetic proof remains 453,861 bytes with SHA-256
`2b96cb7c32e34ab22ba39e1de424281b6d20b7811cff24ba769cf2e6cb67a988`.
Its exact public statement remains 377,290 bytes with SHA-256
`d8b06f64c5e3ff0242e1fe30110280be56fe9eca9cfb55086f7ed7ab5bdb3b6c`.

## Reproduction and source binding

The base is published commit `cc836dfc13ef0006eb0878abd8cb5eca9a76bec0`.
The campaign manifest pins all Rust files, Cargo files, both executable hashes,
all raw/prefix fixtures and independent expected inputs before and after all
runs. Those before/after snapshots are equal. The runtime SHA source has SHA-256
`88557607225e402b6f16ec7edffb7c8b90ddfe14cc7e87a2640042a205011a64`.
After measurement, the scanner test fixture and tests were expanded to include
the new actual full proof. Runtime Rust and both measured release executables
were unchanged by this testing addition. The final exact-commit check receipt
is distinct from the campaign's original source snapshot.

The release build used Rust 1.95.0, Cargo.lock-pinned P3 0.8.0, native CPU flags,
eight Rayon threads, the same eight-CPU affinity for both variants, an 800%
CPU quota and a 4 GiB cgroup memory limit. The host was shared. Per-stage logs
include observed system load, CPU/memory pressure and actual cgroup values.
The experiment did not establish a worst-case production resource bound.

Use [run_schedule_abba.py](run_schedule_abba.py), passing an isolated repository,
new output directory and `fixtures/round4-schedule`. It runs both release
examples from `target-r4-native/release/examples`. A source/binary mismatch or
failed proof cannot count as a successful sample. The original complete
campaign directory is
`/home/qian-qi/work/chain-w1-scheduled-sha-measurements-20261108-f16ac-r4-01`.
Its durable execution job is `1a1b9848b98-12894-14d8`.

Summary: [summary.json](evidence/public-schedule-r4/summary.json).
Source and complete per-run observations:
[manifest.json](evidence/public-schedule-r4/manifest.json).

## Controls and independent review

The full native tests and all-targets strict Clippy passed. These include ten
new SHA relation checks and a genuine four-row PCS integration proof; those
small test proofs are excluded from the eight complete W1 execution count.
The actual retained component 5 proof is now also tested by the allocation
observer and fixed-shape mutations alongside the four historical profiles.

[run_schedule_controls.py](run_schedule_controls.py) reuses the committed generic
control helpers and produces **zero new proofs**. Its 24 verifier processes
comprise one full positive, eleven ordinary negatives, four typed late failures
and eight shape failures. Both SHA and arithmetic receive two late mutations:
`FinalPolyMismatch` and `CommitPhaseMmcsError(CapMismatch)`. Shape failures must
stop before any completed verification phase; they cannot substitute for late
cryptographic rejection. All 24 controls and twelve mutation producers passed,
with unchanged pre/post source, executable and original-input hashes. Their
resource observations are finite observations under shared-host load.

The independent static review matched the nine retained compression helpers
against the Cargo-pinned official source after comments/whitespace/type-name
normalization. They were identical; the sigma helper restricts the same formula
to the two big-sigma rotations. The only round operand change is the schedule's
two independently fixed u16 limbs. The review found no blocking relation or
public-binding issue. It did not rerun Rust tests, timing measurements, or
establish a complete cryptographic theorem.

The profile retains the conditional RBR estimate of 63.95384529640614 bits and
explicit unresolved concrete NI, lifecycle, restricted-tree hash and quantum
bounds. The estimate is not a PQ128 result.

## Retained failures and remaining gap

The first 60-second worktree checkout timed out at 63% and rolled back its new
path. The exact prior attempt was inspected before a separate 300-second retry
succeeded. The first Rust build failed because an upstream limb helper was
private and three tests lacked an explicit Goldilocks type. The fix defined the
same two-u16 split locally and named the field in the tests. Those failures and
their logs remain retained; no failed run was relabeled as a successful test.

Raw and prefix fixtures were prepared before this experiment. Mining/search,
common prefix creation, network transport and Node admission are outside this
pipeline measurement. The median new total payload is still about 80.36 times
the 49,506-byte native candidate, and the public statement alone is 7.62 times
that candidate. Historical native timing is not inserted into this ABBA table.
Any current native reference must be reported separately with its own source,
input, resource and time-window receipt.

## Observed verifier cost shift and exact source receipt

Within the separate recorded verification phases, SHA independent preprocessing
has median 45.8565695 ms for A and 202.0868175 ms for B. SHA proof verification
falls from 261.727286 ms to 177.207567 ms; canonical planning rises from
13.493809 ms to 19.9938645 ms. The larger independently rebuilt public table
therefore accounts for a substantial measured cost increase, while the narrower
proof reduces the PCS verification phase. This is consistent with the overall
verifier regression. Phase medians should not be added to reconstruct the
median process wall time.

The [exact code-commit receipt](evidence/public-schedule-r4/exact-code-commit-checks.json)
binds commit eb944645cc3e30af5955edf9dbbcb43488fa38c1. Both clean tracked-source
receipts agree; the Cargo graph/lockfile, formatting, 57 Rust tests, strict
Clippy, repository/Markdown checks, 50 repository negatives and 43 source
integrity negatives all passed. Runtime Rust/Cargo and both measured binaries
match the original ABBA hashes. The expanded scanner tests are explicitly
identified as subsequent test-only changes.

The [raw observation archive](evidence/public-schedule-r4/raw-observations.tar.gz)
retains 298 nonbinary campaign/control/check files. Its
[index](evidence/public-schedule-r4/raw-observations-index.json) records every
original byte count and SHA-256. Original proof/statement bytes remain at their
recorded campaign paths, and the actual component 5 SHA proof is additionally
retained as a repository scanner fixture.

## Separately timed current native reference

The later native reference uses the actual current pon_work::verify FullLimb
implementation through the v3 Node-adapter binary, with independently expected
header equality. It performs no Node admission, producer work, proof generation,
or STARK verification. Six fresh processes made 600 calls over the same two
inputs; each process made 100 sequential calls. CPU affinity, eight-thread
environment and 4 GiB process-group budget match the requested research settings.
The root explicitly paused its compilation for the declared second block;
the host still had external shared load.

| Input | Fresh processes / calls | Median inner native call | Median outer process, 100 calls |
| --- | ---: | ---: | ---: |
| retained | 3 / 300 | 1.7933015 ms | 0.215299514 s |
| dense | 3 / 300 | 1.7988155 ms | 0.215342903 s |

Inner call timing includes header.challenge() and FullLimb verification, but
excludes process startup and bounded raw/header reads; those are included in
outer process wall time. The first calls in each process range from 1.711136 ms
to 2.291451 ms. OS caches were not flushed. These repeated calls are not
independent cryptographic proofs, independent tasks, or a production Node
latency distribution. This later block is not pooled into or substituted for
the STARK ABBA campaign. The different timing boundaries do not support a
precise native-versus-STARK speedup factor; they do show that the current
research receiver remains far more expensive than the native primitive.

Binary SHA-256 is
14f123c6e51f5b9a3a54176bf55b9d7f5a424083af701411b8b2c41311790cbb.
All native-source, binary and raw/header fingerprints agree before and after
the block. A first setup attempt referenced an obsolete package name and failed
before any native call. It produced zero timing samples and is retained with
its traceback and exact executed script. The predeclared replacement kept the
same call count, input order and resource settings.

[Native summary](evidence/public-schedule-r4/native-reference-summary.json),
[raw native observations](evidence/public-schedule-r4/native-reference-observations.tar.gz),
and their [index](evidence/public-schedule-r4/native-reference-index.json) retain
the complete separate timing window and failed setup attempt.
