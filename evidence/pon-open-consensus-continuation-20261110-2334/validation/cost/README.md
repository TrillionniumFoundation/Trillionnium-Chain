# Cost evidence and native-log gate regressions

**Result: the bundled portable replay passed.** This directory retains the
original failed and successful controls, their byte hashes, the two complete
original GitHub job logs, and a complete historical V4 native archive. All new
execution here is Python reader/control replay. No native work was executed,
no public resource contract was qualified, and no consensus credit was added.

## Start here

From the repository root, with Python 3.11 or later:

```bash
python3 -B evidence/pon-open-consensus-continuation-20261110-2334/validation/cost/replay.py
```

The script verifies the [input manifest](INPUT_MANIFEST.json) and the 18 exact
[source file pins](source-pins.json), then writes results to a fresh temporary
directory and prints its location. It needs no network access, Cargo invocation,
Git object download, or third-party Python package. The matching repository
checkout supplies the current source and tests. `--repo` accepts another matching
checkout, and `--output` accepts a new or empty result directory.

The full 177-method CI contract also has retained original successful output.
To rerun that broader repository check in addition to the default replay:

```bash
python3 -B evidence/pon-open-consensus-continuation-20261110-2334/validation/cost/replay.py --include-ci-contract
```

The actual package-validation run used the default checks and an explicit
`--output evidence/pon-open-consensus-continuation-20261110-2334/validation/cost/portable-replay-01`.
Its [summary](portable-replay-01/summary.json) records **PASS**, verified inputs,
exact commands, expected/actual exits, source identities, and unchanged source
files after replay. The optional broad CI-contract switch was not rerun in this
packaging step; its original 177/177 result is preserved below.

## Observed results

| Control | Before repair | After repair / preserved outcome |
| --- | --- | --- |
| V4 lifecycle, same final 15 test methods | 76 failing subtests, exit 1 | 15 methods pass, exit 0 |
| Native gate, same final 9 test methods | 3 failures, exit 1 | 9 methods pass, exit 0 |
| Retained V2 fixed-material reader | Existing suite retained | 32 methods pass, exit 0 |
| Original hosted legal test span | Old gate rejects, exit 1 | New gate accepts, exit 0 |
| Original hosted factorial test spans | Old gate rejects, exit 1 | New gate accepts, exit 0 |
| Historical complete native V4 journal | Original native exit 0 | Current reader exit 0; original readback bytes identical |
| Historical SIGTERM native V4 journal | Original native exit -15 | Current reader exit 3, INCOMPLETE; original readback bytes identical |
| Complete repository CI contract, original capture | Full retained command | 177 methods pass, exit 0 |

The default portable replay executes eleven Python commands. The baseline reader
and workflow are copied into an isolated temporary overlay; the repository source
is not edited. The intended baseline failures must have their exact failure counts.
A different failure, an unexpected success, changed source pin, missing input,
or changed historical readback makes the overall replay fail.

### Original failure and success records

The [copy provenance](copy-provenance.json) records every copied original's source
capture path, package-relative destination, byte size and SHA-256. Original logs
and receipts were not rewritten to update temporary paths or timestamps.

- Lifecycle: [original corrected baseline](originals/before-fix-roster.result.json)
  and [raw failing output](originals/before-fix-roster.stderr.log), followed by
  [original repaired result](originals/after-fix.result.json) and
  [raw successful output](originals/after-fix.stderr.log).
- Gate: [original baseline](originals/native-gate-before-fix.result.json) and
  [raw failure](originals/native-gate-before-fix.stderr.log), followed by
  [original repaired result](originals/native-gate-after-fix.result.json) and
  [raw success](originals/native-gate-after-fix.stderr.log).
- Broad checks: [177-method CI result](originals/ci-contract.result.json),
  [complete CI output](originals/ci-contract.stderr.log),
  [32-method material-reader result](originals/retained-material-reader.result.json),
  and [complete material-reader output](originals/retained-material-reader.stderr.log).

The earlier [diagnostic failure](originals/before-fix.stderr.log) is preserved too.
Its 121 failed subtests include 45 generic-support cases that the old reader
already refused but with a different error label from an overly specific test
assertion. Those 45 are **not** additional reader acceptance defects. The corrected
same-test comparison is `before-fix-roster`: 3 material mutations, 72 specialized
support inversions, and 1 losing-proof digest mutation, totaling 76.

The tested baseline is `da1374a200022bc14dc2bd325cc9ba29dbcd24ab`. Its original
reader and workflow bytes are included under `before-fix-source/` with Git blob
IDs and SHA-256 in `source-pins.json`. Changed files are identified by their exact
bytes, not represented as an unchanged baseline commit or a new native execution.

## Original hosted logs

The complete unmodified logs are retained for
[job 129678540672](originals/hosted/gh-job-129678540672.log) and
[job 129678540829](originals/hosted/gh-job-129678540829.log).
The [portable extraction receipt](portable-replay-01/hosted-extraction.json)
records original hashes, byte sizes, original line ranges and derived span hashes.
Only GitHub's per-line timestamp prefix is removed. Extracted spans must also
match the earlier retained spans byte for byte.

Legal native actually passed 13 tests; the old gate expected 8. Factorial example
actually passed 11; the old gate expected 6. History import actually passed 33
with its one retained ignored fixture; the old gate expected 28 plus one ignored.
The new legal/example gates require their full named rosters, retain the existing
kernel requirements, and retain the original three History named requirements
plus five added deadline controls. No native test is skipped or newly counted as
executed by this package. Original workflow failures remain historical failures.

## Historical native V4 archive and provenance

The historical bytes come from published evidence commit
`c2297ad53fef1d9b552e657cfd205d583c91980d`, original repository path:

```text
evidence/pon-joint-resource-contract-20261109/archives/117-local-validation.tar.xz
```

This path is not in baseline checkout `da1374a`; its existing Git object was read
without modifying checkout source. The exact [compressed archive](historical-v4/published-originals/archives/117-local-validation.tar.xz)
is 976,596 bytes, SHA-256
`eeaa11ad8a6f565f989edf035d6cb5f59d45ed2956276c824b4daac7064ea8f6`.
Its [original file inventory](historical-v4/published-originals/inventories/117-local-validation-files.json)
binds all 105 files / 43,916,967 uncompressed bytes. Every member was verified both
during initial collection and again by the portable replay. The archive retains
the journals, executable and all original output. Uncompressed journals and a
duplicate executable are deliberately absent from the checked-in package; the
replay extracts only its needed journals into a temporary directory.

The [source/process validation](historical-v4/source-and-process-validation.json)
and retained [source-before](historical-v4/extracted-originals/final-native/v4-observation/source-before.json)
/[source-after](historical-v4/extracted-originals/final-native/v4-observation/source-after.json)
receipts bind native source `11791e2da79b69322271be2cffe03725165151d1`, tree
`162552848110fda532504b78865a16930bc6d9bb`. The Git tree relation and 26,124 entries
were independently checked during collection. Full historical worktree byte
verification remains the original recorder observation, not a newly recreated
checkout or new execution authentication.

The retained compressed executable decompresses to 903,328 bytes, SHA-256
`bd74dea5a8b1ddc57e86f1d181c3cdb287321dc0b9651e03b6f21adfcfe2f45a`,
matching the original loaded/before/after process identities. The native V4
example, producer, material constructor and fixed-material helper are unchanged
between that source and the current pinned files.

| Archive member under `final-native/v4-observation/` | Bytes | SHA-256 |
| --- | ---: | --- |
| `complete.jsonl` | 40,704,359 | `2ae1c73382b3d4bede8412c9ff725d6e51bf37ea50ff6810a84617c4c8ec6f04` |
| `terminated.jsonl` | 69,094 | `aa2bf4bddff47a234c36941091409a34013243555f2a254854695dea92430073` |

The [complete replay](portable-replay-01/historical-complete.result.json) retains
23,069 records, 936 cohorts, 1,888 searches/verified searches, 3,848 completed
attempts, 3,776 full verifier calls and 288 canonical candidates. Its output
matches the historical readback byte for byte.
The [terminated replay](portable-replay-01/historical-terminated.result.json)
retains nine records and its unfinished attempt with unknown unfinished cost.
Zero completed attempts is not zero consumed work.

The original historical READMEs and scratch manifest are retained under
`.original` suffixes, including the [publication README](historical-v4/published-originals/README.md.original)
and [initial replay README](historical-v4/README.md.original). Their paths describe
the original capture/publication layout and may name files not separately copied
here. They are preserved documents, not this package's navigation. Use this
README, the archive inventory and `replay.py` for the portable entry points.
Likewise, `originals/replay_hosted_gates.py` is the unchanged capture script with
its original machine paths; the portable replacement is [replay.py](replay.py).

## Scope and retained unknowns

The reader repairs frozen recipe binding, the exact 117-pair support matrix
(59 supported pairs), and proof-prefix/trace binding for every completed trial,
including losses. Synthetic controls do not execute W1. Historical native output
is not a new current-source cost run. The reader still does not replay the full
challenge-dependent relation or authenticate resource use.

No result proves the minimum cost of every legal strategy, real task demand,
model improvement, independent evaluator control, joint consensus security,
public service availability, or production readiness. All qualification flags
remain false and added consensus credit remains zero. Sixteen actual MU1 cost
points remain unknown.

[MANIFEST.json](MANIFEST.json) binds every retained package file except itself.
