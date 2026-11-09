# Chain source convergence and qualification evidence

**Status: HOLD / NO-GO for all seven qualification gates.**
This package records completed engineering checks, actual selected native executions, and retained failures on a fixed Chain source.

## Tested code and real ancestry

- Repository: `TrillionniumFoundation/Trillionnium-Chain`.
- Tested code commit: [`75dc7ec3973ce3661c27c895418efd5c6cc8b4a8`](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/75dc7ec3973ce3661c27c895418efd5c6cc8b4a8).
- Tested tree: `a58d215f954c1dee99ab7a031ff496e089499ba0`.
- Complete tracked source observations cover **26,153 files / 2,496,904,943 bytes**, with clean status and matching raw Git blobs and executable modes before and after validation.

The candidate has real merge ancestry for [#824](https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/824), [#825](https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/825), and [#827](https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/827), stacked on [#821](https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/821).
Merge `409e4e89afb0bd5203c5e50c6e6f1f1462d94a5c` combines the #824 and #825 heads; merge `e8e2fcb8d811638eb5fa757d28590fbe8e408e61` then includes #827.
The tested commit adds the executable observer, command/source bindings, current W1 mapping, and associated controls to that combined source.

The commit publishing this README and its archives is an **evidence publication commit**, distinct from the tested code commit above.
Adding evidence does not retrospectively execute a different commit or tree; use each receipt's explicit tested identity.
Previous PASS records, branch-local runs, and historical fixtures do not transfer qualification to this candidate or a later head.

## Raw records

| Archive | Contents and interpretation |
| --- | --- |
| [local-controls.tar.gz](local-controls.tar.gz) | The final 404-method local Python control set, exact-source records, current mapping, and retained initial failures/corrected summaries. |
| [native-records.tar.gz](native-records.tar.gz) | Native preparation attempts, strict Clippy, compiler-artifact records, real libtest registries, 12 exact executions, ELF observations, provider/toolchain observations, and recovery records. |
| [repository-controls.tar.gz](repository-controls.tar.gz) | The original 50-method repository suite, one-copy execution, preflight, and complete source observations before and after it. |
| [desktop-recovery.tar.gz](desktop-recovery.tar.gz) | Git checkout/materialization attempts and their failures; these records do not supply a successful desktop Chain execution. |
| [supporting-records.tar.gz](supporting-records.tar.gz) | Independent source/manifest review and original publication preflight/transport records identified by the accompanying manifest. |

The accompanying manifest provides archive digests and exact member inventories; individual records retain their own byte counts and hashes.
The two large libtest ELF payloads are **excluded from the published raw-record archive**.
Their observed build paths, retained local copy paths, sizes, and SHA-256 values remain indexed; a local-directory manifest is not an archive-member list.

## Completed validation, counted once

| Observation | Result | Scope |
| --- | ---: | --- |
| Final local Python control set | 404 distinct passing methods | Nine final passing suites; reruns and initial failed attempts are not added again. |
| Original repository control suite | 50/50 passing methods | Original entry point, one complete temporary copy; zero failures, errors, or skips. |
| Combined Python total | **454 distinct passing methods** | `404 + 50`; native tests and dependency file comparisons are separate. |
| Strict Clippy | Exit 0 | Complete workspace, all targets, all features, `-D warnings`, locked offline graph, complete source-bound receipt. |
| Normal native libtest build | Exit 0 | Original all-feature library build for the two selected packages; original profile and debug settings retained. |
| Selected normal native tests | **12/12 passed** | Every full name discovered exactly once; every exact named-execution checker exited 0. |
| Actual executable observations | **12/12 PINNED_AND_OBSERVED** | Every selected native execution used the explicitly pinned build artifact. |

The native registry contained 186 Crypto and 1,385 Node tests; this package executed the selected 12 controls, not the entire registry.
The 50-method repository run completed in 175.674 seconds; build/collector durations are operational records, not qualified throughput or latency measurements.

## Native build, provider, and executable identity

The successful build used the standard **rustup entry selecting Rust 1.95.0**, one Cargo build job, and `CARGO_INCREMENTAL=0`.
Original compiler flags, optimization levels, debug information, feature selection, and native test semantics were preserved.
Actual `rustc -vV`, `cargo -vV`, and Clippy versions, selected compiler/Cargo/driver executable hashes, and effective loader/build settings are retained.
The same local static **OpenSSL 3.5.9** provider was selected throughout; the CLI, two configuration headers, `libcrypto.a`, and `libssl.a` were byte-pinned.
All five provider inputs match across build-before, tests-before, and tests-after observations; selected tool executable hashes also match after execution.

| Actual libtest artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| `trnm_crypto_primitives` | 67,930,472 | `440866eec44f30e544035dad0d5d8d4f172ca38d0c3c1bbaa0b9aba3a3619f48` |
| `trnm_pon_node` | 509,454,416 | `741a76ae299273509fa9d4098ce430ce31e5ce1e0eaeae8d07505e5cd308ee64` |

The observer pins one open Linux ELF file object before dispatch, executes that descriptor, and observes the owned direct child's kernel executable object.
It checks the live process identity and executable file object, retains the real exit, reaps the child, and checks the dispatch object afterward.
Its evidence concerns an executable **file object at an observed instant**; process memory, loaded libraries/models, descendants, later `exec`, and complete build provenance remain outside that claim.
The observation mode is opt-in through `--native-executable-sha256`; it has not been enabled across every CI command or workflow.
The selected 12 runs explicitly used it. Missing observation remains incomplete even when a child exits 0; a recorded command success is not production or PQ acceptance.
Exact ELF copies were hash-checked before the task-owned temporary build directories were removed; retained copies have distinct filesystem identities.

## Dependency and current W1 source closure

The locked workspace registry graph contains **155 registry packages**; every retained crate archive matches its Cargo.lock checksum.
An independent byte comparison checked **11,130 archive-member files / 247,219,629 bytes** against the actual extracted source directories, with zero missing, extra, different, or changing members and zero package errors.
Cargo-generated marker files are reported separately. This is an observed input-byte audit, not proof of every historical compiler read or a hermetic build.
The current W1 mapping separately fixes **134 files across six reachable local path crates and eight literal include inputs**, with explicit build-input absence checks.
It reports `CURRENT_MAPPING_REPRODUCED_SECURITY_HOLD`; its reviewed runtime base is `e8e2fcb8d811638eb5fa757d28590fbe8e408e61`, while this execution's full-source receipts bind the tested commit above.
The retained historical V1 reader still reports `INPUT_REJECTED`; its historical named roster and failed workflow are not relabelled as passed.
All **15 cryptographic obligations remain UNRESOLVED**; lifetime budgets remain null/unadopted and existing security/production qualification flags remain false.
The mapping does not perform fresh cryptographic proof verification or establish complete external implementation/provider identity, QROM soundness, or quantum work hardness.

## Retained failures and recovery

| Retained event | Treatment in this package |
| --- | --- |
| Direct-Cargo preparation | The unchanged SQLite build guard reported `UNQUALIFIED` because the normal Rustup toolchain library directory was absent. The interrupted parent session exited 130; its original receipt remained incomplete with no invented child exit or PASS. |
| Standard-entry recovery | A separate attempt used the actual normal Rustup loader environment. The unchanged build guard emitted its layout-witness configuration, and strict Clippy plus the original native build completed with source-bound exit 0. |
| Canonical module typo | The prepared selector used `pq_identity_tests` instead of the actual `pq_identity::tests` module path. Real registry checking refused it before any selected native dispatch: zero tests executed in that attempt. |
| Exact continuation | A separate continuation corrected only that uniquely observed canonical prefix, verified all 12 full names, and bound the same build receipt and the same two ELF hashes. No source/test semantics changed and no rebuild supplied substitute results. |
| Git recovery | Failed desktop checkout and incomplete materialization records remain retained. The successful Chain observations came from the complete, fixed local checkout; failed desktop recovery is not treated as a completed source or test run. |
| Code publication recovery | The first push failed on a missing historical promisor blob and did not create the remote branch. A second ordinary push used a self-contained pack with delta reuse disabled and succeeded at the fixed code commit. Both raw attempts remain retained; no force push or hook bypass was used. |
| GNU Time readiness failure | The initial readiness run retained three errors from the unavailable default time-tool path. Explicit selection of the available GNU Time executable allowed the same original 71-method suite to pass; the failed run remains separate. |
| Summary correction | Two false `terminal_ok` fields came from an end-of-file heuristic after successful unittest summaries. Raw logs and recorded exit 0 support the correction; the original summary and every raw log were retained. |

Failures, incomplete receipts, filtered/unexecuted registry entries, and environment corrections remain visible; they are not erased or counted as additional passing tests.

## Seven qualification gates

| Gate | Required delivery and condition for changing HOLD | Remaining gap in this package |
| --- | --- | --- |
| **Source convergence — HOLD** | Fix both repository commits, dependencies, crypto providers, builds, and actual executed/loaded artifacts; obtain native results for that same complete source pair without importing side-branch PASS. | Chain source, selected input bytes, and 12 executions are recorded; a complete paired production build/load and native acceptance closure is still absent. |
| **Consensus safety — HOLD** | Define lawful cost classes, preparation reuse, task selection, quantum resources, time/DAA/credit in one explicit-assumption model; supply a joint argument, old-trajectory regression, and real Node migration. | Selected implementation controls do not establish the joint theorem, all-algorithm cost bound, complete old-trajectory campaign, or migration acceptance. |
| **Authority and effects — HOLD** | Enforce pre-admission refusal, current revocation, real byte binding, independent recovery anchors, and stable operation IDs; verify entry through final effect, including reorganization and Unknown without duplicate execution. | Local controls and record consistency leave the complete native authority-to-effect path and independent recovery contract open. |
| **Hepta closed loop — HOLD** | Retain one real iteration covering training, independent evaluation, NoUpdate, payment, cold retrieval, installation, next-task adoption, and failure recovery. | Separate owner-side observations do not supply that complete same-iteration Chain/Hepta closure. |
| **Cell network — HOLD** | Demonstrate independent placement, renewal, challenge, repair, WAN cold recovery, and real-device loading; recover the complete version after the author and some providers go offline. | This package contains no independent WAN/custody/offline-provider campaign satisfying the complete-version recovery contract. |
| **Performance — HOLD** | Measure the complete honest/hostile workload at the same resources and security; satisfy the original confirmation/resource contract and report qualified goodput and tail latency. | No qualifying end-to-end performance campaign is claimed; compiler timings and selected test passes do not close this gate. |
| **Whole-chain PQ — HOLD** | Exercise all eight real domains under a fixed crypto profile; close critical unknowns with full-lifetime budgets, composition arguments, and independent cryptographic and implementation review. | The 15 W1 obligations, lifetime/composition bounds, complete domain paths, and independent qualification reviews remain open. |

The original **4-second, 0.25-CPU, 2-GiB, zero-swap, 256-PID** contract remains unchanged, together with its original confirmation and honest/hostile workload requirements.
The temporary build resources and observer overhead do not replace that contract, extend its deadline, or establish qualified goodput.
No resource threshold, confirmation requirement, or security condition is lowered by this evidence publication.

## Private owner coordination

- Fixed private code commit: `756968dba94e969a1ee9bc151683682b6fb4da31`.
- Fixed private code tree: `1348a43f8ced85980b39df46d2e995eca73f9f6f`.
- Owner coordination: [private PR #5432](https://github.com/TrillionniumFoundation/hepta-private-ci/pull/5432).

Independent owner-side validation is recorded against that same fixed private code; its review and raw records remain with the private repository.
Private test names and raw data are not reproduced in this public Chain README; private results are not added to the Chain counts above.
Paired integration, production activation, and complete learning-loop acceptance remain subject to their own unchanged closure conditions.

## Interpretation

Read the raw command, source, provider, compiler-artifact, registry, and process-observation records together with the manifests.
A later source, dependency, provider, build, or loader change requires matching new evidence; an evidence-only publication does not move the tested identity.
All seven gates remain **HOLD / NO-GO**, with production, performance, and whole-chain quantum-security qualification ungranted.
