# Node-local Cell adoption: source-bound validation

The final runtime source is **`b9a38fd6d245e20849c7edd848dbbe18298cad7e`**.
Its original-profile, locked/offline data-availability run passed **786 tests**
with zero failures, ignored or filtered cases. Full strict all-targets Clippy
and workspace formatting also passed. Earlier failures, intermediate sources
and the separate debug=0 diagnostic remain in this package; their outcomes are
not rewritten as successful runs.

## Final acceptance and separate supporting runs

| Observation | Actual source/profile | Result |
| --- | --- | --- |
| Data availability, all targets/features, `-j1`, one test thread | `b9a38fd6`, original repository profile, no overrides | Exit 0; 234.619 seconds; 741 library + 45 integration = **786 PASS**. |
| Strict Clippy, all targets/features, `-D warnings` | `b9a38fd6`, original profile | Exit 0; 51.206 seconds. |
| Workspace `cargo fmt --all --check` | `b9a38fd6` | Exit 0; 23.768 seconds; closes the separately retained formatting failure at `95a2a147`. |
| Release-bundle/PQ authority boundaries relevant to M15 | `95a2a147`, original profile; package and dependency source unchanged at `b9a38fd6` | **55 PASS**, exit 0; separate from the DA total. |
| Source-integrity and learning-reader Python suites | `95a2a147`; scripts unchanged at `b9a38fd6` | **43 + 25 + 13 + 13 = 94 PASS**. |
| Repository, CI contracts and locked/offline metadata | `95a2a147`; relevant input objects unchanged at `b9a38fd6` | 26 workspace members; 177 resolved packages; 1,480 Rust files, 27 normal dependency edges, 6,617 local links. CI inventory declarations are not executed tests. |

The new 16 owner, six model-boundary and four selected-resident tests total
**26 library controls**. The new **11 CLI controls** are included in the 45
integration tests. Both are subsets of 786, not additional tests. Earlier
11-test CLI repeats and the 741-test debug=0 diagnostic are retained separately
and are not added to the final total.

Original evidence: [native summary](raw/validation/frozen-b9a38fd6d2/native-test-summary.json),
[final commands and exits](raw/validation/frozen-b9a38fd6d2/results.json),
[native log](raw/validation/frozen-b9a38fd6d2/native-all-targets.log.gz),
[95a2 supporting runs](raw/validation/frozen-95a2a14771/native-and-lint-results.json).

## Failed and intermediate attempts retained

| Attempt | Recorded outcome and correction |
| --- | --- |
| Initial unfrozen libtest build | `rustc` SIGKILL 9 before tests ran. Its cause and missing overall Cargo exit/source receipt are not inferred from later runs. |
| Initial CLI compilation | Exit 101, E0624: fixture used private `CellManifestV1::new`. The fixture was corrected to import actual payload bytes through public `CellStoreV1::pack_file`; production visibility stayed private. |
| Frozen `4668fd87` CLI | Exit 101, **0 PASS / 11 FAIL**: fixture directories lacked required private permissions. Canonical, test-owned `0700` parents and private files fixed the fixture. The retained unchanged dirty patch then passed 11 tests. |
| Static round starting at `4668fd87` | Static/Python checks passed; the final guard correctly refused the three authorized Rust fixture edits. Its original `all_passed=false` remains intact. |
| Original-profile native at `68595a9` | Exit 101 after 1,215.568 seconds; libtest compilation ended with SIGKILL 9 and no test result. |
| Strict Clippy at `68595a9` | Exit 101 after 178.709 seconds for `manual_is_multiple_of`. After the equivalent fix, the retained dirty-patch round still failed with libtest metadata SIGKILL after 81.084 seconds. |
| Static round at `95a2a147` | Source identity and 94 Python tests passed; fmt exited 1 for one `cell.rs` residency re-export ordering difference. The original false aggregate is preserved; the subsequent format-only commit and original-profile passes are separate observations. |

The `95a2a147` diagnostic explicitly used
`profile.test.package.trnm-data-availability.debug=0`: 741 tests passed in that
profile. Original-profile CLI, production `--lib --bins` Clippy and release
checks also completed there. The final `b9a38fd6` run independently restored the
original full test/Clippy gates; it does not borrow qualification from the
changed-profile diagnostic. See [rounds.json](rounds.json) for source and profile
labels, commands' original records and per-round outcomes.

## Source identity and evidence-only continuation

The `95a2a147` static round performed its full source guard once: **27,867
tracked entries / 2,551,682,835 bytes**, tree
`3fba36baa1682fd5b4cbd5e49e07204464c26ed4`. HEAD, clean status and 29 related file
hashes matched before and after. The earlier `4668fd87` before/after records,
including the dirty-source refusal, are retained separately.

[Code binding](code-binding.json) and the [code-path inventory](code-path-hashes.json.gz)
record actual worktree SHA-256 values and matching `b9a38fd6` Git blobs for
`trillionnium`, `scripts`, `config`, workflows and `AGENTS.md`. The only
`95a2a147` to `b9a38fd6` change is the formatting order in `cell.rs`; scripts,
the release-bundle subtree, workspace manifest and lock objects are unchanged.
The evidence-only continuation is confined to this directory and the sole
development plan; it does not change the tested runtime.

Lock SHA-256 remains
`759c42c62d7b9a72d93c533039b5bf47f3508efabf1f1ee63f5eee59b9b9e55f`.
After terminal validation, the task-owned regenerable DA target was removed to
free build space. [Cache-release evidence](raw/validation/frozen-b9a38fd6d2/cache-release.json)
retains four tested binary SHA-256 values and the cleanup outcome. Source,
evidence, shared Cargo registry and Hepta target were retained; binary hashes
are identity records, not newly executed tests or retained binaries.

## Meaning and publication boundary

These tests cover explicit Adopt/Defer/Retain/Rollback, immutable policy and
model-only boundaries, monotone recovery and selected-byte consumption. They do
not authenticate external evaluation, chain inclusion, settlement, deployment
custody or model benefit. Current release and FinalUse owners remain separate.
The existing learning readers accept HEPLCP02 and refuse HEPLCP03/04 or tag 9
under an old header. New-format negative controls are hostile mutations, not
successful native HEPLCP04 exports; local defer/retain is not upstream NoUpdate.

The [original H probe](raw/validation/h-channel-probes.json) and
[same-key reconciliation](raw/validation/h-channel-recheck.json) failed at their
recorded times with MCP `Internal error`, unknown launch status and no job ID.
Their no-Git-write statements apply to those probe actions. A separate
read-only connector identity check established `ProfHepta`; **root plans
connector publication under existing user authorization; actual remote
commit/tree will be recorded in PR/readback**. This package does not claim that
publication has occurred or that H recovered.

## Archive integrity

[index.json](index.json) records every original and archived path, byte length,
SHA-256 and source-round label. JSON retains its exact bytes. Logs, patches and diffs use gzip with timestamp zero and no embedded source filename. Decompression
reproduces the original bytes. [archive-check.json](archive-check.json) records
archive checks, not execution or production acceptance. Historical absolute
paths inside original receipts are unchanged. All source states, failures,
repeats and changed-profile observations remain individually inspectable.
