# Final validation scope review

Review date: 2026-11-11 UTC. This is a read-only review of source, existing raw
logs, and receipts. No Cargo command, remote job, source edit, threshold change,
or rerun was performed for this review. It grants no CI, release, production,
or whole-chain PQ qualification.

## 1. Decision and source identity

The evidence-only child commit can preserve and explain the implementation and
the observed outcomes. It must continue to report the original full Rust
baseline as **FAIL**. Successful focused tests, source checks, Clippy, and a
separate Node package run cannot turn that original command into PASS.

| Role | Identity |
| --- | --- |
| Base candidate | `df927b6ffaecff293b9e9428e3ba516f47cd101a` |
| Earlier observation cohort, Y | `90ee47159e32e9014410a1823bed05d84c17b858` |
| Current implementation/source cohort, Z | `cdd984808a088e6c2e13b1e1ae6630a94d500c89` |
| Z tree | `1ed39b6ebe55cb00c238f26f6bfc9361ab93faec` |
| Planned evidence child | E: a new identity, not yet assigned by this review |

The local checkout was still clean at Z during this review. Its path is
`/workspace/scratch/a4188f5c86b5/chain-pq-profile-boundary`.

The proof that Z and E have identical runtime/build inputs is a source relation.
It is not evidence that a command previously executed on Z also executed on E.
New E receipts must name E, while all imported Y/Z observations retain their
original source, host, command, environment, timestamps, and outcome.

## 2. Governing rules read

The root `AGENTS.md` requires preflight before edits, builds, commits, and
pushes; preservation of failed observations; and exact committed-source checks
of Cargo graphs/lockfiles, retained tests, strict Clippy, formatting, negative
source-integrity tests, and Markdown links. It contains no evidence-only waiver.
This review does not invent one. A bounded evidence-validation set must be
described as that set, without a statement that every exact-head retained-test
or CI requirement has been satisfied.

`config/repository-policy-v1.json` still names five required checks:
`repository-truth`, `protocol-contract`, `fuzz-smoke`, `rust-baseline`, and
`external-evidence-contract`. It keeps `production_candidate` and
`release_ready` false. The evidence commit must not change those requirements,
their thresholds, test rosters, source identities, or acceptance meaning.

`docs/architecture/CI_EXECUTION_CONTRACT.md` distinguishes actual exact-head
execution from source inspection and prospective-merge execution. The current
executable workflow and recipes are the source of precise shard/test counts;
older narrative counts in that document must not replace the current recipe.
In particular, the current native release block contains four controls.

## 3. Receipts actually available at this review snapshot

`final-validation-receipts-readonly.json` records the initial locally available
54 terminal wrapper receipts. Every corresponding stdout/stderr SHA-256 matched
its wrapper result. Its distribution is:

| Host and source | PASS records | FAIL records | Total |
| --- | ---: | ---: | ---: |
| Local-cloud Y | 11 | 5 | 16 |
| Local-cloud Z | 25 | 5 | 30 |
| Desktop Z, primary plus repository-truth packages | 7 | 1 | 8 |
| Snapshot total | 43 | 11 | 54 |

These are command-record counts, not native test counts. The original snapshot
was created before the final full-Rust archive was extracted locally. That
snapshot has not been modified. The complete full-Rust archive then arrived
during this review and received a separate additive verification in
`final-validation-full-rust-readonly.json`:

| Added desktop Z receipt | Actual outcome |
| --- | --- |
| `baseline-preflight` | PASS, return code zero |
| `rust-baseline` | FAIL, return code 101 |
| `pq-feature-off` | PASS, return code zero; one native test actually passed |
| `source-after` | PASS, return code zero; raw-byte source verification, not a test execution |

All 47 archive members (46 original files plus the export manifest) matched
their received/extracted bytes, names, types, modes, and manifest hashes. All
four result/context hashes and eight raw-log hashes matched. Every new wrapper
record bound clean Z before/after. The earlier 54 receipts' raw-log hashes were
also rechecked without modifying the original snapshot. The now-reviewed
combined scope is therefore **58 records: 46 PASS and 12 FAIL**. Node remains
pending and is not represented in that total. Recompute the final index after
its actual import rather than treating either 54 or 58 as an immutable final
package total.

| Actual observation | Scope supported by its command and raw output |
| --- | --- |
| Y `m06-new-tests` | Five new M06 tests passed. The separate `m06-test-build` receipt is compilation with `--no-run`, not another test execution. |
| Z local-cloud `m06-retained-tests` | `-p trnm-mvcc-fee --all-features --tests`: 18 executed test binaries/suites, 272 passed, zero failed, nine ignored, zero filtered. The five new tests are already included in 272. This is not an examples/doc-test invocation. |
| Z desktop `node-new-tests` | `--lib store::account_profile_scope_tests::`: four passed, zero failed/ignored, 1,398 filtered. This is a focused native run, not the retained Node package. |
| Z desktop `strict-workspace-clippy` | Workspace, all targets, all features, `-D warnings`, successful real execution. It is separate from the unexecuted Clippy tail of the failed full baseline. |
| Z formatting and Cargo graphs | Actual formatting and locked main/all-feature plus fuzz graph checks passed. Metadata resolution is not fuzz execution or a native test pass. |
| Z PQ integration and source integrity | 59 integration tests, including negative controls, and 43 source-integrity tests, including valid-source positive controls, passed. Neither suite consists solely of negative cases. |
| Z W1 consistency | 19 tests, seven real report-generation commands, and seven complete byte comparisons passed. These establish source/report consistency, not native W1 qualification. |
| Z desktop `repository-truth-runtime-python` | Complete original lane passed: return code zero, 1,085.246 seconds, clean Z before/after. The existing `TRNM_RUNTIME_RELEASE_PYTHON` selector selected an isolated environment containing the original hash-pinned `packaging==26.3`. |
| Z original full `rust-baseline` | Actual return code 101 after 2,841.481 seconds. DA library result: 713 passed, two failed, zero ignored/filtered; whole DA suite 735.20 seconds. Full lane remains FAIL. |
| Z independent PQ feature-off control | Actual `-p trnm-pon-node --no-default-features --test pq_application_local_feature_off`: one passed, zero failed/ignored/filtered. The formal raw archive and final source guard were verified. All-features runs cannot substitute for this configuration. |
| Z independent retained Node package | Job `1a1c8980187-135c4-111` was pending at assignment. Do not give it PASS or a test total until its actual terminal result and full raw output have been inspected. |

The successful repository-truth raw log includes CI contract 177 tests, CI
execution contract 77 tests, runtime-release 25 tests, and the final qualification
runtime 32 tests. These are constituent groups of that lane, not additional
independent full-lane passes. Its source checker is an actual invocation of
`check_repository.py`, including the CI contract validator and Markdown links.

Preserved failures include missing offline fuzz metadata, missing cargo-deny,
the old-source W1 report mismatch, EXDEV, missing GNU time, ENOSPC, compilation
SIGKILLs, and the original desktop Python dependency failure. No test execution
is claimed where compilation was killed; SIGKILL alone does not establish OOM.
The tool-preparation assertion failure is also preserved, separately from the
later actual successful supply-chain policy execution.

## 4. What the original full Rust lane did and did not execute

The original command was `bash scripts/ci/ci_job.sh rust-baseline`. Its actual
argv supplied isolated per-task Cargo and CI-tool directories. The recorder's
base `environment.CARGO_HOME` was overridden by the explicit `env CARGO_HOME=...`
argument; descriptions must use the effective argv rather than call it a
shared-cache run.

The complete stdout begins with the actual supply-chain PASS and records test
compilation finishing in 31 minutes 51 seconds. The DA executable was
`trnm_data_availability-206231ff342af726`. The two failures terminate the
workspace command at `scripts/ci/ci_job.sh:345`. The script uses
`set -euo pipefail`, so the tee does not hide Cargo's nonzero exit.

| Original full-lane region | Actual status |
| --- | --- |
| Formatting and supply-chain policy, lines 298-299 | Completed before workspace execution. |
| Workspace `--all-targets --all-features`, line 345 | Ran preceding test executables and DA; failed in the 715-test DA library. Subsequent workspace executables were not run. Full-workspace compilation is not full-workspace test execution. |
| DAA schedule readers and tests, branch-work-schedule readers/tests for both backends, and both joint-DAA readers/tests | Not reached. |
| Prefix export readback, model oracle/tests, authenticated-state SQLite readback, native authenticated backend/migration oracles, account multiproof, and obligation-range consumers | Not reached. Partial or empty export directories do not establish successful producer/consumer validation. |
| Four explicit ignored release controls and their exact-log checks/readbacks | Not reached. |
| Workspace all-feature doctests, line 406 | Not reached. |
| Workspace all-target/all-feature strict Clippy, line 407 | Not reached within this lane; the separate desktop command did pass. |

The four unexecuted release tests are:

1. `account_archive_prototype::native_store::batch_tests::native_authenticated_full_capacity_refund_entry_and_pending_reorganization_recover`
2. `store::growth_reference::tests::native_growth_reference_65537_signed_accounts_and_cold_reopen`
3. `store::growth::tests::native_growth_v2_signed_cross_65536_bounded_io_zero_nonce_and_reopen`
4. `account_archive_prototype::native_primitive_tests::native_complete_account_verification_cost`

A successful independent Node `--all-targets --all-features` invocation can
establish the normal tests that it actually executes. It does not run
doctests, automatically execute ignored release controls, or supply the
unexecuted full-lane export/oracle consumers. Preserve its exact ignored,
filtered, zero-test, and failure counts instead of treating its package name
as complete coverage of these different recipes.

## 5. Hosted Rust shards have a distinct acceptance contract

The executable mapping in `scripts/ci/rust_baseline_shards.py:25-50` is:

| Hosted shard | Unchanged commands extracted from the sole local recipe |
| --- | --- |
| `runtime` | Workspace native tests plus the complete export/oracle block. |
| `quality` | Formatting, supply chain, doctests, strict Clippy, then the four native release controls and their retained readbacks. |

The hosted quality shard is independent of the runtime shard. A failed desktop
full-lane command does not establish that a hosted quality shard failed or
stopped. This review claims no hosted shard execution at all.

The workflow's required `rust-baseline` job is a fan-in, not an alias for the
desktop full lane. The checker requires exactly the runtime and quality
artifacts, both successful, for the same current GitHub run ID and run attempt,
with exact command bytes, expected source identity, and equal before/after raw
source proofs. A local Clippy pass, a historical shard, a different run/attempt,
or a subset of these commands cannot satisfy it.

The workflow also retains separate prospective-merge shards/fan-in that bind
the exact candidate, base, and tested merge source. Exact-head observations do
not stand in for those prospective-merge observations. Relevant anchors are
`.github/workflows/trnm-required-baseline.yml:326-524` and
`scripts/ci/rust_baseline_shards.py:61-99,138-167`.

## 6. DA failure isolation and the limit of the conclusion

Both DA tests and their complete in-repository dependency closure have the same
Git tree/blob identities in base and Z:

| Path | Equal base/Z Git object |
| --- | --- |
| `trillionnium/crates/trnm-data-availability` | `1345ba7ede9d5e08d26ecc2f7f8c6a3474ff6158` |
| `trillionnium/crates/trnm-crypto-primitives` | `3bff846e9d6278d8f9bbad25aa71b66c0b9e7a00` |
| `trillionnium/crates/trnm-protocol` | `7b15f61b2c6c195dc7f35ab3180cc7f74f939f67` |
| `trillionnium/Cargo.toml` | `44df8f8d5eec880d10da42c12a903c03658cfc65` |
| `trillionnium/Cargo.lock` | `def80fa394ebb1ae6ce7d1d62ed77524152a2d04` |

DA's path dependencies are crypto and protocol; crypto's only path dependency
is protocol. Neither changed M06 nor Node is in this dependency closure.
This is evidence of source/dependency isolation from the account-boundary
patch. **There was no actual base execution for comparison.** It does not prove
a historical reproduction, flakiness, a passing base, an environment-only
cause, or the safety of disregarding the failed tests.

The TCP failure has an actual one-connection, 16-request-attempt,
100,144-response-byte, three-completed-manifest, nine-downloaded-chunk record.
The full fixture target is 20 frames and 165,736 response bytes. PersistentV2's
fixed two-second connection lifetime, one-connection budget, and lower-level
error erasure provide a concrete possible expiry/redial failure chain. The
existing log lacks phase clocks and the server's final report, so this is not
a demonstrated root cause. Request attempts need not equal wire exchanges.

The RS46 fixture creates a fresh ten-second absolute deadline for each 65- or
128-chunk case, shared across that complete shard-plan `create` operation.
The error can arise at one of three reachable local cache checks in
`cell/erasure/provider.rs:170,173,180`, before CRP1 file creation or physical
provider publication. It proves that deadline expired, not which case/chunk/
slot/check did so or whether CPU versus I/O consumed it. Partial CAS writes
may already exist. The two CAS transactions per shard and complete-case
counts are static work bounds, not observed completion counts.

The 735.20-second value is the whole 715-test DA suite, not either failing
test's elapsed time. Wrapper cumulative CPU/RSS are not an individual test's
peak measurements. This review makes no OOM claim and no inference that the
simultaneous repository-truth run caused the DA failures; the recovered timing
places repository-truth completion before the earliest possible Rust test
phase. No deadline, quota, optimization flag, ignored status, or acceptance
threshold was changed.

Detailed static references and evidence limits are in
`diagnostic_da_baseline_readonly.json` and
`diagnostic_da_rs46_readonly.json`. They are diagnoses, not additional native
test receipts.

## 7. Minimum meaningful validation for the evidence-only child E

This is a proposal for the root agent's next steps, not a claim that these
steps have already run. It preserves the original failed lane and does not
recommend repeating that large lane merely to seek a green outcome.

1. **Complete and verify the inputs.** Wait for each declared imported job to
   reach its actual terminal state. Pin each final archive and manifest hash;
   check every member's name, type, mode where recorded, byte length, and hash.
   Recheck each wrapper's stdout/stderr hashes, source identity, argv, and
   outcome. Keep original FAIL and interrupted/incomplete records visible.
   Rebuild the final index from actual imported receipts and compare it to the
   planned record roster. A pending Node placeholder cannot become a final PASS.
2. **Freeze the payload outside source first.** Review the actual staged bytes,
   the assembly helper and plan, and the derived record/binary indexes. Bind
   all payload files in the payload manifest. Keep the manifest and its own
   checksum sidecar outside that manifest's file list to avoid a self-hash
   cycle. Preserve original raw files without normalization or rewritten
   source labels. Measurements of a binary after a run retain that timing
   limitation; they are not execution-time signed attestations.
3. **Prove the evidence-only diff.** After the required preflight and actual
   child commit, record E and its exact parent Z. Exhaustively verify that all
   changed paths are the reviewed evidence payload, with no runtime source,
   manifests, lockfiles, compiler configuration, PQ parameters, scripts, CI
   recipes, ownership rules, or thresholds changed. Prove all existing paths
   outside the allowed payload have identical object identities and modes;
   reject unexpected additions as well as modifications/deletions. The new
   evidence tree changes E's whole-source identity even when runtime bytes match.
4. **Run exact-E source and evidence checks.** Use the existing strict raw-byte
   source guard before and after the E checks, with output outside the source
   tree. Run `check_repository.py` for current inventories, claim flags, CI
   contract and all Markdown links, the existing CI contract/execution tests
   needed for receipt semantics, and the original 43-test source-integrity
   suite. Revalidate the PQ corpus and its 59-test suite when confirming the
   new source inventory; keep HOLD/NO-GO unchanged. Do not substitute a clean
   Git status for the raw guard. Check W1 report bindings if the E diff changes
   any input they survey; do not rewrite historical numerical claims or goldens.
5. **Record bounded exact-E build/native observations precisely.** The root's
   proposed cached formatting, locked main/all-feature and fuzz graphs,
   workspace all-target/all-feature strict Clippy, M06 five-test target and Node
   four-test filter are useful real E observations. Use unchanged command
   flags, original tool/provider identities, and complete raw output. Count
   executed/ignored/filtered tests exactly. Focused 5+4 tests do not become
   all retained tests, metadata does not become fuzz execution, and Clippy does
   not become the hosted quality shard. If the root runs the retained M06/Node
   packages on E, report their actual broader scope separately.
6. **State the remaining qualification boundary.** E validation is evidence
   integrity plus the commands actually executed on E. It does not satisfy the
   original failed Z full lane, unexecuted tail, or missing exact-head and
   prospective-merge required hosted checks. The absence of an AGENTS waiver
   means there must be no blanket claim of all retained-test/CI requirements
   being met by a focused set. Preserve full-CI, production, release, and
   whole-chain PQ acceptance as false. Commit/push operations remain on the
   existing candidate and authorized channel without protection bypass.

The new evidence commit's own execution receipts should remain outside that
commit while the exact-head checks run. Rewriting E to embed its later
execution logs creates another source identity; it must not be silently
called the already-tested E. A later evidence child can preserve those logs
with their original E source binding if needed.

## 8. Review of the root README draft

The reviewed draft correctly preserved the full Rust FAIL, separate Clippy
scope, development-only account boundary, no silent Ed25519 retry finding,
unexecuted full-lane tail, no actual base comparison, and unresolved DA root
cause. No source or README edit was made by this reviewer.

The following precision changes were sent to the root and accepted there:

- Call the 59 tests integration tests including negative controls, not 59
  exclusively negative tests; the suite has a valid offline-fixture positive.
- Call the 43 tests source-integrity tests including negative controls; that
  suite also contains valid source and prospective-merge positives.
- Explain the actual hosted runtime/quality division, including the four
  release controls in quality, without assigning hosted outcomes from the
  stopped desktop lane.
- Make the RS46 deadline fresh per 65/128 case and shared by that entire create.

The retained-Node placeholder remains appropriate until its terminal raw
receipt is available. Before final staging, replace it only with the outcome
and counts actually in that receipt, and confirm the final record index
includes the full-Rust failure and all earlier failures.

## 9. Evidence references for final-stage review

All paths below are read inputs in the coordination/evidence area, not claimed
new execution receipts:

| Input | Verified SHA-256 or scope |
| --- | --- |
| `full-rust-baseline-observed-complete-stdout.log` | `91f4595a10c116306297e2acf061a1449e45ce26d524fe05645b21a13cf19d92`, 134,555 bytes |
| `full-rust-baseline-context-read.json` | Contains the original context bytes; inner context SHA-256 `3d42e81bde9d9a825b0ed8fb869ec4904e15b690485edcd3fe26743ceafb39a4` |
| `full-rust-wrapper-read-0305.json` | Original wrapper readback containing the baseline result; the complete frozen package below is now available as the final-stage raw source |
| `desktop-full-rust-evidence-v1.tar.gz` | `096cb2d208ad92dff1b2c39ec04da7579e9f06edba5e44451809ab6e11b66456`; 1,100,360 bytes, 47 members, four terminal records: three PASS and one FAIL |
| `full-rust-transfer-verification.json` | `79d0fc647623b4018c9a0bee4fc4cc0f3ed099e1abd9113ce72ad03edb07447d` |
| Formal full-Rust `result.json` | `9a8b556ee56c48e08feb58c887d3317943a1395faf825228cac8ca0104773310`; return code 101 and `pass:false` unchanged |
| `diagnostic_da_baseline_readonly.json` | `ac8d2d019cffc36eb55837180818d203b390c752642cb42db1224ead7033870e` |
| `diagnostic_da_rs46_readonly.json` | `3913eacb20711ad19c9ed27fb098c0d25a94eb344f3b5952e0324bfb2417174b` |
| `final-validation-receipts-readonly.json` | The explicitly bounded 54-record snapshot, 43 PASS / 11 FAIL; raw log hashes matched |
| `final-validation-full-rust-readonly.json` | `361e6b1cb4c8c788efc86eaa6ef3a262e4dfcdb85c3a4a2a37ca6cd5653f0301`; additive verification of four records and complete archive, combined 58 records / 46 PASS / 12 FAIL |
| `repository-truth-evidence-v1.tar.gz` | `f0499cffadc88c4377305e7b453090a638d513f4859e59cbb93b7a4c57fdc9ba`; original failure, pinned environment setup, targeted test, and full successful lane preserved |

The pending Node outcome and new E executions require fresh additive review.
They must not silently change the meaning or source cohort of this read-only
snapshot.
