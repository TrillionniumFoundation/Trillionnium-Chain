# Composition with the concurrent Cell transport continuation

The original integration branch advanced to `1f723bba961ec5f8d7e25e7b33db222dac7ef50c`
while this work was being validated. The source composition preserves that head
as its first parent and `038c063e48bf2f42884a44f62c65f22ac626595e` as its second
parent. It does not overwrite the three concurrent commits. Their complete
[evidence](../../cell-bt-composition-20261106/README.md), original failures and
35-second / 272,189,990-byte cold-cohort HOLD remain intact.

The concurrent custody-window fix and this work's owner fix use the same
`check_effects` call at the same boundary. The merge keeps one call in retain
and one in repair, together with both owner-generation and custody-window
explanations. It does not apply the guard twice. The native implementation,
without line comments, equals the incoming production implementation. Both
`height_window` and `replay_owner` regression modules remain registered.
The complete combined storage selector has 22 controls: 15 original, two
concurrent height-window controls and five owner-replay controls.

The source corpus is the union of both required-path/pin sets, recalculated
against the actual merged files. The generated native inventory includes all
new files from both branches. No signed domain, stored schema, budget, deadline
or readiness flag was changed to resolve the merge.

The 95 explicit V4 execution inputs still match their recorded bytes. M09 and
Node changed outside that limited closure, so the V4 measurements remain tied
to their original source and ELF; they are not a new binary performance run.
The earlier `validation/source-applicability.json` describes the first
candidate before this composition. Its storage input identity is not silently
reused for the combined source. The original 20/20 native result, the later
first-candidate 20/20 and nine sampler controls, and all other completed gates
are preserved in [the first-candidate archive](first-candidate-validation.tar.gz)
with [every member indexed](first-candidate-validation-index.json).

The combined source requires fresh M09 all-target/all-feature and documentation
controls, the 22-test storage selector, M12 native-budget controls, the sampler
unit controls, full strict Clippy, source integrity, graph, formatting and
repository-link checks. Those results must name their actual merged source;
older H2 or first-candidate success cannot supply them. None of these component
checks replaces the original public-service, History, externally funded task,
whole-Cell proof or independent adoption requirements. All six workpackages
remain HOLD / NO-GO.

## Final source-specific composition validation

The fresh combined-source commands below actually executed on committed source
`361825dd1f924770562705d7a68c78170f0375c3`, tree
`92f8fbdc5b722498ede9dd85040d4716aa6a182e`. Every native command has before/after
tracked-byte verification, a complete log, the actual command and exit status,
separate Cargo wait4 resource observations and post-command executable hashes.
The [machine-readable result](final-validation.json) preserves their precise
scope. Build time and test time are distinct; max single-process RSS is not
aggregate host or process-tree peak memory.

| Actual native command | Passed | Failed | Ignored |
| --- | ---: | ---: | ---: |
| `01-m09-all-targets-all-features` | 387 | 0 | 0 |
| `02-m09-doc-all-features` | 10 | 0 | 0 |
| `03-node-storage-all-features` | 22 | 0 | 0 |
| `04-settlement-native-budget-all-features` | 35 | 0 | 0 |
| `05-v4-sampler-release` | 9 | 0 | 0 |

Full-workspace/all-target/all-feature strict Clippy, Rust formatting, both
locked/offline Cargo graphs, corpus/inventory, repository/Markdown checks and
the source-specific negative controls also completed. The source-control
receipt preserves every suite's actual count; this is not an assertion that
all workspace unit tests ran. The Cargo.lock bytes remain unchanged.

The release sampler log retains `trnm SQLite I/O boundary UNQUALIFIED: RUSTC
must be absolute`. The native archive's `qualification-note.json` records the
observed execution environment and the separate cached-build qualification
scope. Nine sampler controls do not qualify this SQLite boundary; this
warning is not discarded or converted to a pass by the successful command.

Complete original receipts are losslessly retained in
[native validation](native-validation.tar.gz) with its
[member index](native-validation-index.json), and
[source validation](source-validation.tar.gz) with its
[member index](source-validation-index.json). Both archives were round-tripped
and every uncompressed member byte/hash verified before publication.

The separate Hepta candidate was published at
`fa1c0592e7d1dea60cd8d8459a4e2b18fdfbab61`. That is not a composition with
Chain's runtime or another Hepta branch. Its exact-head hosted CI is a separate
gate; a successful canary or pending job does not mean complete CI acceptance.

This evidence publication changes documentation and retained records only.
The [publication scope](publication-source-applicability.json) checks that the
native sources, scripts, workflows, manifests, lockfile and configs are still
the tested bytes. It does not rename the original V4 ELF/performance campaign,
the historical proof, H2 results, or original service failures as new runs.
Hosted validation of a later publication commit must identify its own head.

The complete prior PR description is retained
[byte-for-byte](pr688-preserved-before-full-workpackages.txt); no earlier
failure, unknown attempt or acceptance limit was removed to fit the PR body.
All six workpackages remain **HOLD / NO-GO, 0 of 6 closed**.
