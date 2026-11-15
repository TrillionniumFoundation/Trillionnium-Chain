# Independent checked-prefix three-arm experiment: HOLD

**The candidate failed the preregistered performance decision and was removed
from the default M06 source.** The sole native invocation completed with
`1 passed; 0 failed; 125 filtered out` in 16.25 seconds, but the unchanged decision
reader returned **exit 1, HOLD: 16 of 18 comparisons passed and two failed**.
A successful native cost-observation test is not a successful performance gate.
The complete [native log](raw/measurement.stdout), [process receipt](raw/measurement-result.json),
[decision output](raw/decision.stdout) and [decision receipt](raw/decision-result.json)
retain that distinction.

## Decision and retained failures

The [preregistration](comparison-preregistration.json) was written before any
timing sample for this candidate. It keeps the original v4 rules: at least 5%
paired-median improvement in all six primary comparisons, at most 10%
paired-median regression and at most 10% p95 regression in **every** one of the
nine cells against **each** historical reference. All six primary targets passed;
the following two p95 violations still make the complete decision HOLD.

| Keys / value bytes | Case | Reference | Paired-median regression | p95 regression | Required maximum |
|---|---|---|---:|---:|---:|
| 128 / 64 | First value changed under a same-root hint | Original a10 full map | 1.94% | **13.15%** | 10% |
| 4,096 / 512 | Last value changed under a same-root hint | Original a10 full map | 7.06% | **16.42%** | 10% |

The exact p95 regression fractions are `150127/1141644` and
`20777227/126528259`. Here p95 has its original nearest-rank definition:
`ceil(0.95 * 12) = 12`, the maximum of twelve samples. It does not establish a
population tail-latency estimate or statistical confidence. Paired-median
improvement is the median of the twelve round-matched fractional improvements,
not a ratio of separately computed medians. All eighteen comparison records and
all raw arm samples remain available; no sample was dropped, retried or relabeled.

The primary paired-median improvements were:

| Keys / value bytes | Unchanged state versus a10 | Last-value mismatch versus actual 40a |
|---|---:|---:|
| 128 / 64 | 53.15% | 28.23% |
| 1,024 / 512 | 27.61% | 44.30% |
| 4,096 / 512 | 35.77% | 36.70% |

These gains do not compensate for a failed required cell. They do not authorize
keeping this candidate in the default implementation.

## What was actually measured

This is an independently identified borrowed-prefix candidate, using an
allocation-free canonical comparison. It is distinct from the rejected upstream
candidate at `7dfee35b293cfc2964c4fd8e025c6e92355f02c2`, and was subjected to the
same decision, input matrix and scheduling rules. The arms were:

1. Original full-map binding from `a10c39025cdc03d3265b031d6547b11e0350da2c`.
2. Actual shared-map parent from `40a5ba25e40fd5eda5b04fc1c3811320d438de11`.
3. The registered checked-prefix candidate on base
   `b8116f65789a85148254f870c678a44f895316de` with dirty M06 source.

The [complete tested harness](candidate-tested/checked_prefix_three_arm_tests.rs.txt)
preserves the literal historical entry bodies and a private historical a10
`encode_for_cache`; neither reference silently calls the candidate encoder.
[Reference provenance](reference-provenance-before-format.json), the registration
and [pre-run peer review](pre-run-peer-review.json) record the shared unchanged
helpers and the independent reference checks. The timing loop retains complete
binding, result classification and output destruction.

The schedule contains nine cells: three sizes, each with unchanged, first-value
mismatch and last-value mismatch. Three arms run in the six registered
permutations, repeated twice, with twelve samples per arm and eight bindings per
sample. All **2,592** planned bindings returned their expected result: 864
successful bindings and 1,728 expected `COMMITMENT_ROOT` errors, with zero
unexpected or missing returns. The sole timing process ran from
`2026-11-04T08:25:20.264326+00:00` to
`2026-11-04T08:25:36.529498+00:00`; its measured process duration was
16.265138437 seconds. The [attempt marker](raw/timed-attempt.started.json) was
created exclusively before invocation to prohibit a second timing attempt.

The Cargo artifact reports M06 **opt-level 1**, with debug assertions and overflow
checks enabled. Its [build receipt](raw/build-result.json),
[compiler environment](raw/compiler-environment.stdout) and complete build
stdout/stderr are retained. The overall Cargo profile label does not imply that
M06 used optimization level zero.

## Source and executable binding

| Identity | SHA-256 |
|---|---|
| Candidate `pon_commitment.rs` | `d330e462e793ea187ccb525ac7e2c03c6009135860f09417b5dc74f348f0e832` |
| Candidate `pon_executor.rs` | `aa8ce1e89aa23a18fa5563b46fc9d43e9d834899a8301a8f70819c07e60d88b0` |
| Compiled three-arm harness | `015d1225d9773e5d85b0247352a1a31e9a8a264f85dff5e08746577a2a821aa0` |
| Native-input manifest | `d88c742223b09b2597aeefed95191869528410f2765e7d25a5a7f62cf6243430` |
| Executed M06 ELF | `3fd395f7145793fafb1a5653d128349e2fecefd17d1679304ae269df4c459d9b` |
| Preregistration | `5a6d1f93426df5faac0eec39b97c3712cc41a2885ec925ebd173bad98ba2428a` |
| Native observation stdout | `c0b5d65c9dbf60e8a89f0fb7a5d49d05520c33bfbb106d713f4948d96a8eb62f` |

The 1,192 native inputs include workspace sources and literal included inputs.
The four source captures before/after build and before/after measurement are
identical, and the executable hash was unchanged. This manifest does not bind
every repository document or workflow. The retained dirty-source snapshots
include neighboring Node files for provenance; this M06 invocation did not build
or measure Node behavior.

[Copy integrity](copy-integrity.json) records byte-identical copies of all 34 raw
files, including ten dirty-source snapshots. Snapshot source files carry an
additional `.txt` suffix in this archive and are not active native input. Four
recorder/helper files are retained with their original absolute paths unchanged;
they are archival scripts, not a portable build environment. No executable is
included. [Candidate integrity](candidate-tested-integrity.json) separately binds
all five tested M06 files and the complete [candidate patch](candidate-tested.patch).
That patch was applied to a fresh scratch copy of the b811 defaults and reproduced
all five candidate files byte-for-byte before restoration.

## Default restoration and scope

The [restoration record](default-restoration.json) verifies that
`pon_commitment.rs`, `pon_executor.rs` and `unchanged_snapshot_tests.rs` in both the
working tree and Git index were restored exactly to the identical 40a/b811
defaults. The candidate-only `canonical_comparison_tests.rs` and
`checked_prefix_three_arm_tests.rs` were removed from active source after archival.
No unrelated native source was changed by this restoration.

The earlier [two-arm observations and functional controls](../README.md) remain
under their own 40a dirty-source component manifest. They are not this run and do
not override this three-arm HOLD. Their favorable late-mismatch medians and the
retained 128-key first-miss regression are historical observations, not a default
promotion decision.

Complete-state traversal remains **O(N)**. This experiment did not close the
default late-mismatch or complete-state throughput blocker. It establishes no
O(k) total-work bound, physical memory bound, Node-owner throughput, durable
commit rate, public TPS, independent W1 confirmation, WAN capacity or final-source
acceptance. Final default-source validation must use its own later source and
executable identities.

## Re-read the saved decision without executing native code

From this directory, the following command reads the preserved log and must return
**exit 1 with HOLD**:

```sh
python3 compare_v4.py raw/measurement.stdout
```

This auxiliary re-read is not a benchmark rerun. The archive-time
[reader stdout](archive-reader-replay.stdout) is byte-identical to the original
decision output, and its exit 1 is retained in [copy integrity](copy-integrity.json).
The reader deliberately leaves `native_execution_verified` false; separate
process, source, executable and exact-selector receipts provide that narrower
execution provenance. No reader-only result is presented as a new native test.
