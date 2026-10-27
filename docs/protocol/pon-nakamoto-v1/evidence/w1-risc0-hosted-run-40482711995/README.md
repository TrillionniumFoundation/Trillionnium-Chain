# Original hosted full-W1 proof attempt: 5400-second timeout

**Actual outcome: the real Composite STARK attempt timed out after
5400.001653586 seconds, returned 124, and retained no receipt.** Independent
receipt verification and proof attack controls were skipped by the original
workflow. This is a failed bounded attempt, not a completed proof or a successful
public-ingress/PQ qualification. No receipt from a later run is substituted here.

## Immutable original source and complete retention

| Identity | Value |
| --- | --- |
| Workflow run | [40482711995](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/40482711995) |
| Job | [122116759593](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/40482711995/job/122116759593) |
| Original source | `d96138532b656d767d1ef46f6db86e7effae485e` |
| Original source tree | `bcf061827dd81cbd4c29378ef53ebac23cd976be` |
| Original artifact | [12729397861](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/40482711995/artifacts/12729397861) |
| Complete original ZIP | 256,973 bytes, 47 members |
| ZIP SHA256, matching GitHub metadata | `faf9159385f77d02f1c01b493a04195092d82d7242d6c6250990c1af008dddb9` |
| Configured prover threads | `RAYON_NUM_THREADS=2` |
| Original proof limit | 5400 seconds, segment power limit 18 |

The complete ZIP and every original member are retained, including empty prover
stdout/stderr, raw ELF/program/input bytes, all process records, native samples,
source-before/after records and preflight/build logs. All extracted member bytes
were independently compared with the ZIP and hashed. The GitHub job log is the
connector's complete decoded text, retained separately; it is not presented as
the original HTTP transport encoding. Temporary signed download URLs are omitted.

Both original source identity checks reported the same exact commit/tree and
verified 5732 tracked entries / 748003221 tracked bytes. This later evidence
readback ran in a separate worktree; it is not a claim that the original run
started on a later source commit.

## Actual same-input measurements

The native benchmark invokes four implementations **sequentially**, 31 times
each. It does not mean four CPU cores. The minimum, median and maximum below were
recomputed from all retained raw samples and agree with the original report.

| Same fixed full-W1 input | Minimum | Median | Maximum |
| --- | ---: | ---: | ---: |
| Native production kernel | 0.395766 ms | **0.398401 ms** | 0.423929 ms |
| Native scalar reference | 0.396167 ms | 0.397208 ms | 0.419202 ms |
| Native limb kernel | 0.346973 ms | 0.348876 ms | 0.360172 ms |
| Complete relation recomputation | 0.389787 ms | 0.390909 ms | 0.401415 ms |

The whole 124-call native benchmark process took 0.063930670 seconds wall time,
0.047444 seconds user CPU and 0.001976 seconds system CPU. A separate single native
complete-relation execution reported 0.443999 milliseconds inside the operation.
These are observations on one hosted runner/input, not network throughput bounds.

The complete guest execution reported **13,364,385 user cycles, 62 segments,
0.172442696 seconds** inside execution, and a 228-byte journal identical to the
native result. Its containing process wall time was 0.214163578 seconds. The image
ID is `3ea1bcbf7900a32be73d7e78102de085562893732473667e1f3af07e585696b4`.
The raw guest ELF, ProgramBinary and fixed input hashes match the previously
retained optimized full-W1 experiment exactly; their hashes are in the readback.

The proof command started at **2026-10-27 09:45:18.368192 UTC** and finished its
bounded timeout at **11:15:18.369874 UTC**. No completed proof generation time,
receipt size, proof verification latency, worst-case bad-proof rejection time or
receipt-bound parameter report exists for this attempt. Those values are null,
not zero. The original execute output records a segment-power limit but no actual
per-segment size histogram, so a later calculator result is not fabricated for
this original attempt.

## Resource and verification limits

The original process wrapper reported only 0.015739 seconds user CPU, 0.002084
seconds system CPU and 13792 KiB waited-descendant RSS. These are retained exactly
but **must not be called the prover's CPU cost or peak memory**. As demonstrated
by the separate process-group controls, `RUSAGE_CHILDREN` can omit a grandchild
terminated together with its waiting parent. This original source had no periodic
process-group sampler. Total prover CPU and peak RSS remain unavailable.

The original host observation reported `MemTotal=16373452 kB`; this is host
capacity, not the proof's memory peak or a confirmed cgroup limit. Missing cgroup
files remain explicitly unavailable in the original JSON.

Before proving, the actual native differential controls passed 11 tests, the
standalone receipt boundary controls passed 6 tests, and backend strict Clippy
succeeded. Full guest execution passed and source identity remained unchanged.
These narrower successes do not change the proof timeout. The six receipt tests
are framing/budget controls, not a positive complete cryptographic proof test.

The original host wrote a receipt only after its own strict checks succeeded.
If it had returned an unsupported candidate before that point, this old source
could have lost the bytes. Here the observed outcome is timeout with no retained
receipt; neither successful nor rejected candidate generation is inferred from
absence. The later four-thread source has separate candidate-retention behavior
and remains an independent run.

## Files

- [Independent readback](independent-readback.json) records recomputed checks and unavailable outcomes.
- [Complete original ZIP](complete-original-artifact.zip) preserves the original compressed bytes.
- [Original artifact inventory](original-artifact-retention.json) binds all 47 member hashes.
- [Original timeout process record](original-artifact/prove.process.json) records the actual command, timestamps and exit.
- [Native raw benchmark](original-artifact/native-benchmark.stdout.log) contains all 124 sequential samples.
- [Complete decoded job log](github-job.decoded.log) includes the timeout and original upload result.
- [Original workflow](original-workflow.yml) records the fixed two-thread procedure.

This directory changes no runtime source, proof relation, consensus profile,
security parameter or admission policy. The complete original attempt remains
failed. No native replay, hash, signature or synthetic receipt is relabeled as a
succinct proof.
