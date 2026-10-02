# Development overhead audit, 2026-10-02

## Scope and source

The reviewed candidate starts at `47864b93461c783e684454b24358e23eed6dba1c`
(PR #204), after checking remote `main` at
`9fedf7ecbbe07177069c030592b4e03dcffebb81`. This is an audit record, not a
replacement for the [canonical development plan](TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md).

Inventory: 25 Cargo packages, 286 Cargo targets, 701 Rust files / 207,478
Rust lines, 77 documentation files, 46 scripts, 93 formal/reference files,
and 2,315 retained evidence files. Evidence occupies approximately 585 MiB.
The inventory includes disconnected source candidates; file counts are not
proof of compiled functionality or test execution.

The review covered CI command ownership, filesystem traversal, source-analysis
work, mutation-fixture construction, Cargo targets and source/module reachability,
explicit source bindings, generated inventory, and retained evidence boundaries.
It is not independent cryptographic, economic, model-efficacy or production
acceptance, and does not claim that every possible runtime optimization is exhausted.

## Implemented, behavior-preserving reductions

1. `check_repository.all_files` prunes the existing excluded directory set before
   descending. Previously `rglob` traversed all build, Git and cache trees before
   filtering their files. The included files remain identical, including regular
   file symlinks; directory symlinks are not followed. Regression tests compare
   old/new selection and observe that excluded directories are never scanned.
2. Pure Python/Rust lexical analysis is cached by exact source content, with
   32-entry bounds. Callers still reread files, so same-path mutations cannot
   reuse stale answers. Cached symbol collections are immutable. No validation,
   receipt, signature or source-hash check is bypassed.
3. Three source-binding-only mutation suites copy all ordinary source plus the
   exact declared evidence manifests and qualification metadata. They no longer
   copy unrelated campaign artifact bodies. Original bytes are copied into
   independent files, not synthesized or hardlinked. Missing, escaping or
   external-symlink metadata fails. Complete repository mutation and historical
   campaign replay suites retain their original complete fixtures.
4. The redundant complete repository mutation invocation is removed from
   `fuzz-smoke`. Its identical 50 tests remain in required `repository-truth`.
   A standalone `fuzz-smoke` invocation now intentionally covers only its
   reference/hash smoke checks. The workflow still declares all five required
   jobs from `config/repository-policy-v1.json`; every job checks out and verifies
   the same global `TRNM_EXPECTED_SOURCE_SHA`. No required check, test timeout,
   cryptographic parameter or acceptance threshold was removed or relaxed.

5. Removed 14 disconnected executor source/test copies (4,068 lines), after
   reviewing Cargo targets/features, every module and platform guard, compiler
   dependency output and all tracked text references. The active library and its
   `hot_bucket_tests` module retain identical SHA-256 hashes; all 262 actual tests
   pass before and after, with identical compiler dependency files. The canonical
   distributed-source inventory was regenerated and its owning
   `distributed_pipeline` example compiles. All 31 historical receipt files
   referencing the removed paths remain unchanged. Current source identity
   necessarily changes; historical qualification is not transferred to it.

6. The same bounded review removed 44 disconnected `trnm-types` files
   (6,609 lines) and 10 disconnected `trnm-oracle` files (1,343 lines).
   Actual Cargo targets include the types integration tests, whose live nested
   modules remain. All 380 tests across 19 targets pass before/after; all 39
   active source files and compiler dependency files are byte-identical.
   Both crates have no features, build scripts or platform-dependent module
   loading. The distributed example checks again after inventory regeneration.

7. Replaced the reference work test's self-comparison and parameter-name
   inspection with actual rejection of supplied digest arguments. An injected
   `**kwargs`-accepting implementation passed the old test and fails the new
   test. All 28 reference tests pass with the actual implementation. This is a
   caller-boundary regression test, not work-hardness acceptance.

## Measurements

Measurements are local observations, not hosted-CI timing promises. Other
validation work was running on the same machine.

- Fresh-process repository checker, three runs per implementation over identical
  input files before the executor cleanup: baseline 4.892 / 4.839 / 5.154 seconds; optimized
  3.489 / 3.427 / 3.558 seconds. Median falls from 4.892 to 3.489 seconds
  (28.7%). All six reports are identical: 25 packages, 701 Rust files,
  618 local links, 17 normal dependency edges, no activation.
- Separate single cProfile runs: 24,435,801 to 11,689,908 calls;
  9.399 to 5.391 seconds. Rust lexical transformation calls fall from 95 to 12.
  Profile overhead means these timings must not be mixed with unprofiled ones.
- Each source-binding fixture falls from approximately 616,087,893 to
  10,880,047 bytes. Three suites avoid approximately 1.82 GB of redundant
  copying while retaining their exact input metadata and negative mutations.
- Removing the second complete repository mutation invocation avoids one
  additional full source/evidence copy and one 50-test run per workflow.
  The retained optimized local run took 49.890 seconds.

## Deliberately retained work and follow-up boundaries

- Historical evidence bodies, failed observations, Git identities and original
  collectors remain intact. Their size alone is not a reason to delete them.
- Python contract tests repeated with reference, native executor and native
  session backends exercise different implementations; they are not duplicates.
- Rust package-specific versus workspace runs may have different feature
  unification. They were not removed based solely on matching test names.
- Source-binding checks explicitly do not execute the named tests or establish
  acceptance. Replacing them with fabricated pass receipts would weaken the
  project boundary rather than improve development speed.
- Cargo formatting traversal leaves 288 Rust files unvisited across six crates.
  This is a lead, not a deletion proof. The six peer-lease parts are explicitly
  `include!`d by the active recovery module and were therefore retained; they
  were false positives of formatter-only discovery. Some source/data inclusion
  patterns are outside formatter traversal. Candidate removals require target, feature,
  platform, module, generated-inventory and explicit-reference review, plus
  compiler/test evidence. No mass deletion is justified by this count.

## Verification record

- Eight new traversal/cache/fixture negative tests pass.
- Existing 50 repository mutants, 12 invariant bindings, 35 responsibility
  checks and 18 applicability checks pass.
- Full `repository-truth` passes with an explicit real GNU time observer.
  The first local attempt failed because `/usr/bin/time` is absent in this
  container; setting the supported `TRNM_GNU_TIME` to the existing official
  extracted binary passed all 12 qualification-runtime subprocess tests.
  That environmental failure is preserved and was not replaced by a stub.
- Locked offline Cargo metadata, `cargo fmt --all -- --check`, generated
  distributed-source inventory verification, Bash syntax and `git diff --check`
  pass.
- Bounded executor baseline: locked offline all-target/all-feature tests pass
  262/262 with one build job, incremental compilation disabled and debug info
  disabled. This is not a full-workspace Rust validation.
- The complete unchanged `external-evidence-contract` job passes before dead-file
  cleanup. It verifies original artifact bodies and recomputes historical
  semantics, including negative receipt/hash/source mutation tests. A final
  rerun after cleanup and committed-source/hosted checks remain to be recorded.
- An intermediate historical-cost check rejected a deleted file still present
  in the unstaged Git index. Staging the reviewed removals made the existing
  current-input inventory accurate and all historical-cost checks pass with
  `current_measured_inputs_match: false`. No evidence validation was weakened.
- Targeted `cargo check --offline --locked -p trnm-pon-node --example
  distributed_pipeline --all-features` passes after inventory regeneration.
