# PoN Problem 1 — implementation evidence

This bundle preserves two concrete accounting corrections, their original failing controls, independent review, and validation of the frozen implementation. **The result remains HOLD.** The retained actual-cost audit still has sixteen unknown cost points. The work does not establish real customer demand, a physical resource lower bound, quantum cost parity, or task-supply liveness.

The implementation identity is:

| Identity | Value |
| --- | --- |
| Implementation commit | 187b880048e30196407960f48b10c379859d1396 |
| Implementation tree | ad3b3f541edf816d5e0f44605d8ba29472b3b63c |
| Parent / original baseline | e798d7125724d4b9f98c24d00cc80031f2eab4a9 |
| Archive status | IMPLEMENTATION_VALIDATION_COMPLETE |
| Native build and retained unit controls | PASS; 33 retained tests; two resource stops preserved |
| Whole-source after-check | PASS; byte-identical to both source-before records |
| Publication preparation | ProfHepta sender verified; actual publication is attested by subsequent GitHub PR/ref metadata |

[summary.json](summary.json) contains the machine-readable index. [implementation-source-map.json](implementation-source-map.json) pins every changed implementation file. The [source-before record](validation/implementation-source-before.json) verified 26,119 tracked entries and 2,485,338,994 bytes against the frozen commit; that identity check itself executed no tests. Later source or native observations are not inferred from this record.

## Corrections and retained counterexamples

### Fixed-packet metering

The existing fanout campaign uses two producer packets. A valid reception and its whitespace-only carrier replay belong to the first packet; a discarded response belongs to the second. Those packet identities must remain the same across receivers and topologies. The reader now binds each accepted case to its fixed slot, requires distinct slot identities, and, when the producer roster is supplied, checks that exact roster. Explicit malformed expectations fail rather than becoming an unpinned check.

The [unchanged probe](metering/fixed_packet_identity_probe.py) and its [original](metering/legacy-counterexamples.json) and [fixed](metering/fixed-v1-counterexamples.json) records retain the same probe hash and the same six input hashes:

| Synthetic inconsistency | Original reader | Fixed reader |
| --- | --- | --- |
| Carrier replay relabelled as a third work ID | PASS | FAIL |
| One receiver swaps the two packet IDs while the global set stays size two | PASS | FAIL |
| Distinct nonce slots reuse one ID | PASS | FAIL |
| One topology coherently renames the original IDs | PASS | FAIL |
| All topologies swap the original packet slots | PASS | FAIL |
| Original producer roster is absent | PASS | FAIL |

PASS and FAIL in this table describe report acceptance, so rejecting these malformed inputs is the intended correction. A failed binding leaves the complete distinct count null while retaining partial observed IDs, costs, bytes, failed attempts, and denominators. It awards no chainwork. These are synthetic report-integrity controls, with no claim of a native consensus exploit.

The original five pinned source files are retained under metering/baseline; they are a small source subset, not a standalone old checkout. The six canonical synthetic inputs are under metering/inputs. They were reconstructed from the unchanged probe's input construction and checked against both retained records' SHA-256 values; they are not new measurements.

The produced accounting report uses pon-grouped-fresh-deployment-cost-v1, and reanalysis uses pon-grouped-fanout-reanalysis-v2. Historical input remains pon-grouped-fresh-fanout-campaign-v0. Native work-profile and signed-domain identities are unchanged.

### Service outcomes and branch reconciliation

The original service owner could lose the distinction between a retained terminal business outcome and a later branch monetary state. Three unchanged regression methods fail against the original implementation and pass after the correction: completed service cannot become cancelled, cancelled service cannot become complete, and completed service cannot become unknown after reorganization.

The [original red receipt](owner/baseline-red.json), [raw failure log](owner/baseline-red.stderr), [retained regression source](owner/baseline-control-tests.py), and [original owner source](owner/baseline-service_work_settlement_v1.py) preserve that result. The [first green record](owner/green-01.json) and [post-review green record](owner/green-02.json) remain separate. The final targeted result is 38 service tests plus the original 23 budget tests, already included in the 327-test committed-source campaign below. The budget implementation is unchanged. [Owner summary](owner/SUMMARY.json).

Independent review found one additional case in the first patch: completion followed by reorganization and an ordinary generic budget close left the local outcome complete while branch lane outcomes were unknown, yet no reconciliation was reported. The [before record](review/independent-review-before-owner-correction.json) deliberately retains its false requirement result and the [reviewed source snapshot](review/service_work_reviewed_snapshot.py). The [after record](review/independent-review-after-owner-correction.json) requires reconciliation and preserves all non-promotion flags.

The same [independent script](review/independent_review.py) enumerated **729 assignments** of three labels across six successful reception rows. Anchored checking accepted exactly one original assignment; structural checking without a producer roster accepted exactly six consistent injective assignments. Costs, attempts, and zero chainwork were preserved across the enumeration. The [review notes](review/README.md) describe reproduction and limits.

These red/green and review records were made against identified working-tree bytes before the implementation commit. Their original HEAD fields and timestamps remain untouched. They are not relabelled as full-checkout execution of the later commit.

## Validation on the frozen implementation

The [formal campaign](validation/formal/summary.json) ran the following eleven existing suites on commit 187b880. Its 327 successful test IDs are distinct:

| Existing suite | Tests |
| --- | ---: |
| test_grouped_fresh_deployment_cost_v0 | 50 |
| test_grouped_fanout_reanalysis_v1 | 21 |
| test_service_work_settlement_v1 | 38 |
| test_reward_budget_oracle | 23 |
| test_fixed_probability_contract | 16 |
| test_credit_feasibility | 31 |
| test_credit_envelope_contract | 40 |
| test_normalized_search_cost | 37 |
| test_amortized_cost_potential | 34 |
| test_amortized_cost_potential_independent | 6 |
| test_lifecycle_cost_v1 | 31 |
| **Distinct total** | **327** |

There were zero failures, errors, skips, expected failures, unexpected successes, timeouts, empty suites, or missing observations. Each suite retains argv, timestamps, exit code, stdout, stderr, test IDs, and imported-module hashes before and after. All recorded prior module bytes remained unchanged. [Runtime and exact suite plan](validation/formal/plan.json) records Python 3.12.14, numpy 2.3.5, cryptography 50.0.0, executable identity, and selected environment values. No missing dependency was silently installed or replaced for this run.

The [source/CI campaign](validation/source-ci/summary.json) separately passed ten original checks. Its reported test-suite counts are **overlapping per-suite counts** and must not be summed into a distinct total or added to 327:

| Source/CI suite | Reported count |
| --- | ---: |
| Source integrity | 43 |
| Project boundary | 16 |
| CI execution | 77 |
| CI contract | 164 |
| PQ integration | 57 |

The other checks were preflight, repository consistency, CI contract check, PQ integration check, and distributed inventory. Their complete command receipts and raw streams remain in validation/source-ci.

An earlier [source-pin preparation refusal](validation/preparation-source-pin.json) is retained with its [raw stderr](validation/preparation-source-pin.stderr): the PQ integration check returned exit 1 because the development-plan source had changed before its corpus pin was refreshed. The later passing result does not erase this preparation failure.

## Native validation and final implementation source

The [native summary](validation/native/SUMMARY.json) and its [file manifest](validation/native/file-manifest.json) retain the original locked default/all-feature/fuzz dependency graphs, workspace formatting, strict all-workspace/all-target/all-feature Clippy with `-D warnings`, and the existing `pon_work::tests::` suite. All requested final gates passed on the exact implementation commit. The native suite passed **33 tests, zero failed and zero ignored**, with 146 unrelated library tests filtered by the declared selector; this is not the full native or hosted CI matrix.

The metadata graphs ran with `--locked` and fetched the required original dependencies. Clippy and the retained native tests subsequently ran with `--offline --locked`. Rust 1.95.0, one compiler job, disabled incremental compilation and DEV/TEST debug information zero are recorded. Original package optimization levels, assertions, overflow checks, features and warning policy remain unchanged. These are validation settings, not a matched performance or energy experiment.

Both interrupted Clippy attempts remain failures to complete: the [first record](validation/native/rust-clippy.json) stopped when the evidence volume ran out of space; the [second record](validation/native/rust-clippy-attempt2.json) stopped when shared temporary storage fell below its reserve. Both exited via SIGTERM -15 without a compiler diagnostic error. Byte-identical task-owned caches, target and logs were relocated outside the repository; [storage identities](validation/native/storage-relocation.json) and [guarded realpaths](validation/native/guarded-storage.json) are retained. The [third attempt](validation/native/rust-clippy-attempt3.json) completed the same strict command. No interrupted attempt is counted as a pass.

The [whole-source after record](validation/implementation-source-after.json) and [actual invocation receipt](validation/implementation-source-after.receipt.json) were made after all implementation validation. They exactly match the [initial before record](validation/implementation-source-before.json) and [native before record](validation/implementation-source-native-before.json): 26,119 tracked entries, 2,485,338,994 bytes, implementation tree ad3b3f541edf816d5e0f44605d8ba29472b3b63c. Whole-source identity verification itself executes no tests and establishes no computational lower bound.

## Historical reanalysis and actual cost

The [historical input](metering/inputs/historical-fanout-report.json) is the exact 402,979-byte report with SHA-256 915485a66d8b9ee4d1aadece413edb928274640a1830a840f818571b3042df96. The [updated offline reanalysis](metering/historical-fanout-reanalysis-v2.json) reports:

| Receiver topology | Completed transport attempts | Verified receptions | Distinct original work IDs | Independent full Cell checks |
| --- | ---: | ---: | ---: | ---: |
| 1 | 6 | 3 | 2 | 4 |
| 2 | 12 | 6 | 2 | 8 |
| 4 | 24 | 12 | 2 | 16 |
| **Campaign observations** | **42** | **21** | **The same 2 IDs recur** | **28** |

The identity count is not summed across topologies. This is reanalysis of retained observations, **not a new native campaign**, 42 necessary inferences, or 21 new useful applications. Original transport files were not re-read and original source/binary checks were not re-executed. Actual external consumer uses and demand remain unestablished.

The [actual-cost audit](validation/actual-cost-contract-audit.json), with its [invocation metadata](validation/actual-cost-contract-audit.metadata.json), retains **HOLD_NO_GO**. Eight classical and eight quantum cost points remain unknown. Binding validation covers four relation source files; it does not turn a finite-model certificate into an actual W1 lower bound. Complete legal-strategy simulation, amortized lower bounds, initial advice/potential, cross-scale and cross-fork composition, actual-hash reduction, resource/time/network assumptions, mixed-miner chain properties, native identity/weight integration, and real Cell adoption remain unclosed.

The implementation also extends section 6 of formal/pon-nakamoto-v1/CREDIT_FEASIBILITY_V1.md. Its exact file identity is in the source map. The contract fixes work, resource, and success context; counts unconditional lifecycle cost including failed attempts; keeps task selection, cache, and shared state inside allowed strategies; separates application savings from matched joint-execution savings; and qualifies quantum/variable-time comparisons. This is a clarified research contract, not a new physical cost theorem or a claim that common credit removes same-scale hardware advantage.

## Integrity, selection, and replay

[manifest.json](manifest.json) covers every regular file in this bundle except itself, with byte counts, SHA-256 values, and per-file provenance. Original files are copied byte-for-byte, including empty streams and old absolute-path metadata. New summary and input-reconstruction artifacts are explicitly marked as generated.

[Selection notes](assembly/selection.json) identify omitted duplicate passed schema-stage outputs, redundant publication preparation source packs, and large source snapshots. All selected original red controls, the independently found correction, and the preparation source-pin refusal are retained. [Sensitive-output review](assembly/sensitive-output-review.json) records the closed selection and credential-pattern inspection; no authentication command outputs or secret values are included.

The [first assembly attempt](assembly/assembly-first-attempt.json) also remains recorded: a draft link check ran before manifest.json was written and returned exit 1. Correcting that ordering completed the bundle. This packaging check executed no protocol test and changed no repository source.

Verify the bundle from any location:

~~~bash
python3 verify_manifest.py /absolute/path/to/pon-problem-one-20261108
~~~

For fixed metering replay, use a separate checkout of the implementation commit as the working directory and run the unchanged metering/fixed_packet_identity_probe.py with argument fixed. For original replay, use a separate checkout of the parent commit and argument legacy. Both require the original repository dependencies. The five archived baseline files bind the old source bytes; they do not replace that complete dependency checkout.

The six input files can be independently reconstructed into a fresh directory:

~~~bash
python3 -B metering/materialize_inputs.py --root /absolute/implementation-checkout --out /absolute/new-input-directory
~~~

The independent review reproduction commands are in review/README.md. Existing formal and source/CI runner scripts and their exact argv remain beside their receipts; replay must use new output directories rather than overwrite the original records.

## Publication and delivery identity

The [prepared sender receipt](publication/prepared-sender-187.json) and [transport audit](publication/transport-audit-187.json) retain effective ProfHepta identity and original preflight results. The remote sender intentionally contains only the exact 33-file preflight closure; it is not a full checkout and ran no native or whole-source gate. Complete source and validation belong to the separate checkout identified above. Failed preparation attempts, unusable old source cache and missing-source manifest identity remain recorded. The archive download was removed only after the complete source and Git objects were preserved; its [disposition receipt](validation/source-archive-disposition.json) and [baseline identity](validation/source-baseline.json) are retained.

This archive predates its own evidence commit and push. Actual publication and the evidence child's own source/static check results are reported by the associated GitHub PR and ref metadata. The child adds evidence only; it does not relabel the implementation's native execution or the historical campaign as a new execution on that child. No merge or activation is performed by this archive.

