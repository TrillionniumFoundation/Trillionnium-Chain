# Original native W1 v2: executed x64 cost evidence

**This closes the claim that these two new producer arms were only compiled.**
It does not close minimum-cost hardness, public-service fairness, ARM64/GPU
coverage or production qualification. The default miner and all native source
remain unchanged by this evidence-only increment.

The original exact source is `e9c4bb0d3a324b1d79b7b99326512bfb707d0025`, tree
`28bb7cb923a415ccc30ff5eaac83ffd2b99dd13f`. Its actual focused CI run
[40490909605](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/40490909605),
job `122144305607`, completed successfully. The original cost step ran from
10:59:29 to 11:07:46 UTC on 2026-10-27. The capture itself measured **494.775912
seconds**, 489.980247 user CPU seconds and 4.502782 system CPU seconds. The maximum
waited-child RSS was 86,604 KiB; this is not aggregate machine memory. The host
was shared x86_64 Linux with Rust 1.95.0. The captured `cpu.max`/`memory.max` were
null and establish no resource reservation. There is no GPU or energy observation.

## Complete original data and identity

The downloaded artifact is `12729656639`,
`pure-pon-focused-e9c4bb0d3a324b1d79b7b99326512bfb707d0025-1`, exactly 8,715,707 bytes,
ZIP SHA-256 `81c480bbc24f27544fa007055fc6752657c1c1eb8a0a400a64adaeb741adb459`.
The whole ZIP passed its CRC checks. [GitHub provenance](github-provenance.json)
retains the actual step outcomes. [Original-file inventory](original-files.json)
retains all 29 original ZIP member names/sizes and hashes every selected original
file. The actual native binary is **not** a member of that artifact. Its original
before/after SHA-256, `b39bc71f44ce7ed2579ee289b4c2c8c3b4eaf88df56d31e3950d82de57167bd1`,
remains in [the unchanged capture](originals/cost/capture.json), together with
the compiler identity, build-profile description and raw exit status. We do not
manufacture an executable or hardware attestation from those observations.

The complete original cost gzip is retained as 28 ordered binary pieces under
`raw-gzip-parts/`. [The parts manifest](raw-cost-gzip.parts.json) specifies every
size, byte offset and SHA-256. Concatenation restores exactly 7,292,930 bytes,
SHA-256 `915f5bfd1095d7c7c6299cdf3c3140b5c983841967bf4ae3903f9f32a5d5bfb0`.
Its complete uncompressed log is **28,291,500 bytes**, SHA-256
`2c9bc3ee4a43b510c5f8597f072a79d40fbbea695e9333e852e55bd8df5e639f`.
No failed search, unsupported arm, setup cost or trial has been dropped.

The original source check verified 5,913 tracked entries at that commit. The
final source-check step also reported success; its status is in the GitHub job
metadata, while the ZIP retains the initial `source.json`. The v2 log embeds
exact SHA-256 values for its campaign driver, canonical W1 owner, low-rank owner
and Cargo lock. The readback verifies all four against the [frozen source
snapshot](source-snapshot.json), then executes the unchanged original checker
with `source_root` specified. Snapshot code is evidence only, not another
consensus owner or miner implementation.

## What actually ran

The original grid offered all **14 algorithms × 9 materials × 4 horizons
(1/8/64/256) × 2 preparation policies × 2 targets × 2 rounds = 4,032 cohorts**.
Each search allowed eight attempts. It completed **702,232 producer attempts**,
**93,740 winning calls** and **58,916 exhausted searches**. Unsupported cases
are retained and were not counted as successful work. The source-aware reader
checked every complete grid identity, setup policy, attempt/winner/exhaustion
sum, target result, paired complete-proof stream and native admission scope.

Both new low-rank arms actually executed **48,604 attempts and 6,452 winning
calls each**, with 128 complete and 160 unsupported offered cohorts each.
Their supported materials were zero, rank one and the two one-sided zero/rank-one
fixtures. Every winning proof passed the original production W1 primitive
verifier. Both arms had **zero native admission calls**: these structural test
materials do not acquire registered useful-task eligibility from primitive
acceptance. They cannot be described as demonstrated reward attacks.

For the genuine public genesis-maintenance material at the native target, the
original `Node.admit` was actually called successfully **10,464 times** across
all arms and preparation/horizon repetitions. There were **509 distinct winning
header contexts**, not 10,464 new finalized blocks or rewards. Across the whole
experiment there were 42,316 distinct queried header contexts and 5,659 winning
contexts. The derivation uses `(task, target, nonce)` within this single fixed
header context, with the nonce formula from the pinned native driver. Algorithms,
preparation policies and nested horizons deliberately share streams; their
repetitions do not become independent probabilistic samples.

## Representative paired costs

These five rows use the same **horizon 256, retained preparation, two rounds and
native target `7f…ff` (2^255−1)**. Each row charges two actual preparations and
all 512 searches, including misses and exhausted searches. CPU per winning call
is total producer CPU divided by observed winning calls, with failed searches
still in the numerator. A ratio below one means lower observed producer CPU
than `prepared-general` in that exact cohort. These two-round shared-host ratios
are not confidence intervals or reliable speedup guarantees.

| Material | Least-cost measured arm in this cohort | CPU ms / winning call | Arm / Prepared CPU | Attempts / winning calls | Native admission calls |
| --- | --- | ---: | ---: | ---: | ---: |
| zero | blocked-zero | 0.780153 | 0.879969 | 1,013 / 511 | 0 |
| zero-left-rank-one-right | blocked-one-zero-rank-one | 0.884296 | 0.949056 | 1,062 / 509 | 0 |
| rank-one | structured | 0.904919 | 0.995007 | 1,034 / 510 | 0 |
| genesis-maintenance | maintenance-split-limb | 0.903603 | 0.970999 | 1,055 / 509 | 509 |
| full-rank-field | prepared-general | 0.870306 | 1.000000 | 993 / 511 | 0 |

The matching harder `07…ff` (2^251−1) rows are also in
[the representative table](derived/representative-cohorts.csv). At that altered
target even the maintenance comparison is primitive-only. The complete group
reductions are retained losslessly, with source hashes, in
[the derived-file inventory](derived-files.json); the full raw log remains the
primary evidence.

Across **all 64 supported aggregate groups per new arm**, scalar low-rank cost
ranged from 0.818120 to 1.199999 times Prepared and was below Prepared in 15 groups;
paired low-rank ranged from 0.889774 to 1.401431 and was below Prepared in four
groups. Thus it would be wrong to say they were always slower than Prepared.
However, **neither new arm was the cheapest among all supported algorithms in
any aggregate group**. In the long-horizon representative groups the new arms
were more expensive than Prepared. This is evidence for continuing comparisons,
not for changing the default miner.

Producer timings include preparation plus every actual proof/challenge/ticket
attempt. They exclude verification, Node admission, report I/O and harness stream
hashing. Native seed acquisition and material construction are separately retained
in the complete original log and total capture wall time. These denominators do
not establish node DoS ratios, chain TPS, hardware fairness or a lower bound on
adversarial work. Correct-product/false-trace native replay remains a separate
problem; this evidence supplies no transparent proof.

## Reproduce the readback without rerunning the benchmark

From any checkout containing this evidence, choose a new output directory:

```sh
python3 evidence/pon-w1-native-v2-e9c4bb0-20261027/readback.py --out /tmp/pon-w1-v2-readback-new
```

The reader verifies every retained original/source file and gzip piece, restores
the complete original gzip, verifies its raw byte count/hash, executes the pinned
original source-aware checker and full-grid summarizer, and derives the explicit
deduplication and representative tables. It never invokes Cargo, a miner, a node
or a prover. The final actual [local readback process](readback-observation-002/terminal.json)
completed successfully; its raw stdout/stderr are retained. The first successful
readback and its earlier reader source remain separately preserved. The later
readback adds the whole-grid low-rank comparison, avoiding an inference based
only on the five long-horizon examples.

**OPEN:** execute this current 14-arm v2 graph on actual ARM64; measure a genuine
GPU implementation/hardware if available; energy and physical hardware
attribution; more rounds and independent hosts; the cheapest legal work across
other task structures and preprocessing; full proof and hostile public service.
Older ARM64 results for other producers do not substitute for this v2 experiment.
All hardness, production, useful-model and consensus-authority qualifications
remain false.
