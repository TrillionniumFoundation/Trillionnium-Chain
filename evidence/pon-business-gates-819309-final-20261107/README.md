# Final 819 readback and ordinary Legacy admission-root continuation

**Status: HOLD.** The real 819309 push did not close the original four-second pressure or 4,105-block History gates. Its complete local Node package also failed. This record preserves those complete attempts and introduces a narrowly scoped ordinary-admission root calculation change. No earlier result certifies the new source.

## 1. Identity and publication authority

| Identity | Exact value |
| --- | --- |
| Published H | 819309fd312298e099642e1253b1d4ba07113e98 |
| Resolver-observed main B | dd6e1c3cbeacbdc532b0679297835b3a0aac78f0 |
| Ordered-parent prospective merge M | 28df21f965e0348690836c9c854dab645827a03d |
| H and M tree | f9d63abb9e2931fd78e26ccb87e3a7955068f267 |
| Priority workflow, attempt 1 | [42402618518](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42402618518) |
| W1 workflow, attempt 1 | [42402618462](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42402618462) |

The [publication receipt](publication-819/receipt.json) binds the normal push to the existing integration branch and actual GitHub administrator **ProfHepta**, user ID 102159240. Both workflow actor fields were ProfHepta. Main remained B. The project-local Git identity is ProfHepta with its ID-bound GitHub noreply address; [AGENTS.md](../../AGENTS.md) requires this administrator and the HeptaRuntime local GitHub channel for assistant-operated publication.

No replacement remote branch, force push, protected-main bypass, self-approval or runtime activation follows from these observations. Earlier e70 and d26 captures remain separate, including e70 baseline 3.098539910 seconds, x64 2,362 returns and ARM cursor 3,404.

## 2. Complete real CI denominator

The [fixed gate core](ci-819/GATE_CORE.json) and original paginated metadata retain:

| Denominator | Success | Failure |
| --- | ---: | ---: |
| 37 workflow jobs | 26 | 11 |
| 34 native lanes | 24 | 10 |
| 136 materialize / before / after / context steps | 136 | 0 |

The ten native failures were four ordinary service lanes, two fresh-challenge lanes and four History lanes. Four State lanes and twenty W1 component jobs succeeded. The additional failed workflow job could not recover historical artifact 11531476198; its cause remains UNKNOWN.

The original Host contract remains cpu.max = 25000 100000, burst 0, memory 2 GiB, swap 0 and pids 256. The service window remains four seconds, with sixteen hostile workers, seven honest submissions and independent depth-six confirmation. History retains 4,105 planned imports, a 1,800-second server lifetime and thirty-second request deadline. These developer-harness conditions do not change the ten-second target block interval or establish production finality.

### Ordinary service

All four lanes completed their five native invocations with exit 0 and returned seven successful honest Submit responses. The original strict reader nevertheless rejected CONFIRMATION_TARGET.

| Lane | Baseline / target | Baseline seconds | Pressure / target | Attack calls | Pressure History RPCs |
| --- | --- | ---: | --- | ---: | ---: |
| x64 H | 1/1 | 2.998398221 | 0/1 | 334 | 3 |
| x64 M | 1/1 | 2.379932989 | 0/1 | 457 | 6 |
| ARM H | 1/1 | 1.810381926 | 0/1 | 428 | 6 |
| ARM M | 1/1 | 1.781689543 | 0/1 | 427 | 7 |

The final independent replay retained PUBLIC_REQUEST_DEADLINE. A successful Submit, accepted intermediate page, completed native process or valid Host receipt is not transaction confirmation. Pressure confirmation latency remains null.

### Fresh challenge

Each x64 job contains two separate cohorts. Original-proof cohorts failed CONFIRMATION_TARGET; fresh-proof cohorts failed FRESH_BUSINESS_TARGET and their native processes exited 101.

| Source / cohort | Baseline seconds, 1/1 | Pressure / target | Attack calls | Native exit |
| --- | ---: | --- | ---: | ---: |
| H / original | 3.013527913 | 0/1 | 321 | 0 |
| H / fresh | 3.104824911 | 0/1 | 214 | 101 |
| M / original | 2.682595039 | 0/1 | 386 | 0 |
| M / fresh | 2.680975825 | 0/1 | 244 | 101 |

Every cohort returned seven successful honest Submit responses. Fresh-cache path checks passed with zero exact-fact hits; actual pressure full replays were H 206 and M 239. Original-cohort cached rejections were 260 and 314, with 57 and 65 full replays. These distinct denominators do not establish business success. Host checks before and after the runs reported no errors.

## 3. History returns, rows and activation

All four History native invocations exited 101, each with zero passed / one failed. Validators reached height 4,105; independent confirmers did not activate that history.

| Lane | Successful imports / 4,105 | Non-genesis packets | Active height / generation / slot | Cancelled cursor | Observed failure stage |
| --- | --- | ---: | --- | ---: | --- |
| x64 H | 2,791/4,105 | 2,791 | 0 / 0 / 0 | none | Server lifetime, then Connection refused |
| x64 M | 3,386/4,105 | 3,386 | 0 / 0 / 0 | none | Server lifetime, then Connection refused |
| ARM H | 4,104/4,105 | 4,105 | 0 / 0 / 0 | 3,782 | Final import / activation deadline |
| ARM M | 4,104/4,105 | 4,105 | 0 / 0 / 0 | 3,701 | Final import / activation deadline |

Including genesis, ARM has 4,106 block rows. Reorg rows have done = 2 and cancelled lifecycle records; active remained genesis. Durability of the final packet does not establish a successful return or atomic activation.

x64 servers reached the original 1,800-second lifetime. ARM final calls reached the thirty-second deadline; their servers recorded stop_requested before lifetime expiry. All eight databases were inspected with immutable, read-only, query-only SQLite, without opening a Node or running recovery. SHA256 values matched before/after. Original database bytes remain inside the fourteen original CI ZIPs described by the [fixed core package](ci-819/README.md).

The e70, d26 and 819 values are separate captures, not paired performance measurements. All four State lanes passed six named controls and the main forty-test migration suite. Their two successful one-test FIFO subprocess summaries are not two additional main tests. Release-profile State controls and unoptimized local budget failures remain separate observations.

## 4. Complete local validation on 819

The [source-control attempt](source-819/summary.json) executed seventeen suites and **666 named methods**, including 202 Cell and 79 Host controls, with no failure, error or skip. The frozen runner and name/hash roster are retained in source-driver. Exact graph/lock, source-integrity, inventory, repository/links and formatting checks passed.

The [prepush manifest](native-819/runs/819309fd312298e099642e1253b1d4ba07113e98/prepush/manifest.json) passed strict workspace/all-target/all-feature Clippy and complete linked inventory. Compilation is distinct from test-body execution.

The single original complete invocation was:

    cargo +1.95.0 test --locked --offline --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --all-features --no-fail-fast -- --nocapture --test-threads=1

The [final per-target readback](native-819/runs/819309fd312298e099642e1253b1d4ba07113e98/full-node/final-readback-v1.json) accounts for every native harness and the separate doc-test section:

| Part | Programs | Passed | Failed | Ignored |
| --- | ---: | ---: | ---: | ---: |
| Library | 1 | 1,169 | 2 | 33 |
| Binary unit | 1 | 14 | 0 | 0 |
| Integration | 65 | 321 | 10 | 24 |
| Native total | 67 | 1,504 | 12 | 57 |
| Doc-tests, separate | 1 | 4 | 0 | 0 |

Cargo exited 101 after 6,656.162724 seconds; the external driver exited 1 without a timeout. The [complete original log](native-819/runs/819309fd312298e099642e1253b1d4ba07113e98/full-node/records/node-full.log) retains every failure. Both actual 65K State tests and all twelve native Cell tests passed. Child summaries were not added to outer counts.

Complete source-before/source-after matched across 12,639 tracked entries and 1,277,471,450 bytes, with shared SHA256 5759d06c351357aa4d7b24e1b56c03607da60870788f30139a8e10460744c6b6. Every registered executable and ordinary CLI binary also matched. Eight live-captured excerpts were later checked against their exact byte ranges and prefixes in the final EOF log.

### All twelve retained failures

Three tests directly report PUBLIC_MUTATION_CPU_BUDGET:

- Library: admitted_custom_genesis_over_eight_mib_keeps_original_held_schedule_and_cpu_owner, Legacy arm.
- Library: native_inactive_page_parents_use_checked_material_without_early_activation, AuthenticatedV1 final page.
- native_node: test_full_transaction_pages_use_byte_limits_and_recover_all_native_state, Legacy complete History page.

Eight tests directly report PUBLIC_HOST_KERNEL_PARENT:

- architecture_delivery_compare: signed_dag_delivery_comparison_uses_same_native_business_and_confirmation_contract.
- evaluation_sync_observation: actual_public_full_sync_query_partial_refusals_reorg_and_retirement.
- mining_service_budget: mining_runtime_ends_before_service_and_fresh_native_follower_confirms_last_chain.
- native_node: test_authenticated_cli_push_and_sync_share_one_durable_outbox_owner.
- public_cli: actual_public_cli_pins_server_denials_fail_and_sync_verifies_native_history.
- public_intake_v2: one_packet_history_preserves_partial_progress_and_independent_validation.
- public_intake_v2: unknown_caller_cannot_override_ledger_and_full_sync_independently_verifies_actual_work.
- public_pool_cli: actual_v3_cli_unknown_guest_funding_and_atomic_renewal_reach_native_receiver.

One failure remains differently classified: public_pool_cli::actual_pinned_peer_cli_follows_native_blocks_and_closes_shared_owner first has an anonymous-thread Option::unwrap(None), then named-test Disconnected. A Host cause is not established.

The >8 MiB Legacy case consumed 3,241,575,336 ns of paid CPU against 2,000,000,000 ns initial credit plus 809,635,077 ns credited refill, leaving -431,940,259 ns. Both workers completed and active remained unchanged after refusal. The original loop stopped before its Authenticated arm. A separately named supplementary Authenticated test passed with 2,086,613,567 ns CPU; it does not replace that unexecuted arm.

The Authenticated inactive-page failure is outside the new Legacy selector. Its later positive credit does not disprove an earlier real-time refusal. The Legacy full-transaction failure uses twelve blocks with 256 signed transfers each. Its complete-page call includes ordinary admission and final activation; the old log does not localize the refusal to the last root fence.

## 5. Narrow change in this follow-up source

The [ordinary admission tail](../../trillionnium/crates/trnm-pon-node/src/store.rs) now passes the existing classical Legacy full-input root arithmetic to its final check of current active State. The selector is renamed from legacy_reorg_root_arithmetic to legacy_persisted_root_arithmetic; existing reorg call sites and test selectors retain their behavior.

This does not retain a successful validation or prior SQL rows. Complete current SQL State is still read, canonical grammar and bounds checked, the actual current stored root compared, and all original active/slot/ancestry, writer/schema/no-write-epoch, cancellation and commit boundaries retained. The generic readback wrapper still passes no optional Legacy arithmetic. PQ, Growth and Authenticated relations retain their existing checks.

Existing mathematical material is bounded to 2 MiB and consumes complete current input. Reuse requires matching actual leaf input, with original error/collision checks; contention, poison or arithmetic error falls back to the original root calculation. Parent/child/active use can change cache churn. No final-fence cost or end-to-end gain is inferred from old aggregate CPU totals.

The [new regression](../../trillionnium/crates/trnm-pon-node/src/store/legacy_admission_root_tests.rs) requires two warmed-cache fault subcases to reject with original ROOT/local-integrity/owner-stop semantics: an untouched active cell changes from alpha to bravo, or the active block's stored root claim changes. A matched successful trigger control supplies the complete callback reference. Failure must preserve that trace up to the final commit callback, roll back every durable table, leave the child absent and survive cold reopening with the original State.

New-source verification requires sixteen named library exact invocations, one separately declared affected Legacy History integration exact, strict Clippy, actual linked inventory and the unchanged 666 source controls. These are requirements for the frozen follow-up commit, not passes inherited from 819. All original Authenticated and other failures remain independently recorded.

## 6. Cost findings and remaining architectural scope

The [native import analysis](analysis-native-import/README-v1.md) retains all 21 original replay rows: twenty successful and one deadline refusal.

| Original segment | Caller replay CPU ms | Nested Host checkpoint CPU ms | Nested PacketWork CPU ms |
| --- | ---: | ---: | ---: |
| Fresh H baseline, seven replays | 534.997037 | 474.142861 | 432.661929 |
| Fresh H pressure, one replay | 85.559084 | 78.222604 | 75.300652 |
| Service x64 M baseline, seven replays | 413.636870 | 368.123867 | 333.344715 |
| Service x64 M pressure, six replays | 326.423472 | 297.271034 | 279.826748 |

Columns overlap and must not be added. M06's root metric is not the final active-State fence. The last pressure failure stopped in Work before admission and did not execute the newly changed call site. No owner-wait phase entered; wall minus caller CPU is not measured lock wait.

The [Host and scope review](candidate/read-only-review-v1/README.md) separates the receiver's warm scalar account from the verifier's cold account. Receiver, sixteen attack clients, Head and independent verifier share the original Host parent in this harness. Both observed receivers had zero mutation-CPU refusals; their credit is not the cgroup's total CPU usage. The verifier's original 100 ms initial reserve/refill produces a separate cold wait and is reused on later pages. No credit or resource ceiling changes.

Host checks already read live boot identity, current-thread membership, parent identity and all five limits without duplicate same-file reads inside a check. Retained-directory-descriptor reuse was rejected because it would change fresh absolute-path semantics after replacement/rename. No Host checkpoint, full PNW1 validation, failed attempt, cancellation or late rejection is removed.

Full SQL State traversal remains. Touched-set execution needs the separate parent/root relation, complete mandatory obligations, COW atomic writer, source-preserving migration and untouched-corruption/audit rules in [State recovery](../../docs/protocol/pon-nakamoto-v1/details/STATE_RECOVERY.md). This change does not complete that migration or qualify WAN behavior, production activation, confirmed TPS or p95/p99 guarantees.

## 7. Retention and observation limits

[RETAINED_COPY.json](RETAINED_COPY.json) binds the first 1,527 copied files and 339,017,508 bytes: fourteen original core CI ZIPs, every 666-control output, complete native attempt and excerpts, publication receipts, analysis and reviewed patches. Copied originals were read-only and destination bytes were verified. New evidence is written only in the isolated follow-up worktree. Executable copies, Cargo targets/caches and provider trees remain separately retained with identities in [the native whitelist](native-819/ARCHIVE_WHITELIST.json).

The [sealed W1 v1](w1-v1/W1_CORE.json) independently verified fourteen of twenty artifacts, eighteen native manifests and 452 campaign commands. Six 240-second download timeouts retained partial ZIPs and UNKNOWN coverage. GitHub job success and independent archive/reader coverage are separate denominators. Later bounded transport addenda retain their own identities, preserve v1, and execute no new native campaign. Larger text metadata is losslessly compressed with raw/compressed byte and hash mappings; large complete/partial W1 ZIPs remain separately retained.

The [fixed v2 transport package](w1-v2/W1_COVERAGE.json) recovered five of those six original artifacts, reaching nineteen independent readbacks. The final [Range v3 coverage](w1-v3/W1_FINAL_COVERAGE.json) completes **20/20 original W1 artifacts, 24 native manifests, 632 campaign commands and 724 process records including identity/build**. It retrieved only the missing 3,208,816-byte tail of artifact 13586509176 with HTTP 206 and the exact Content-Range. The new full 174,175,856-byte copy matched the original GitHub SHA256; the prior 170,967,040-byte partial remained unchanged. The same pure reader passed. All six v1 240-second timeouts and the one v2 900-second timeout remain recorded. No CI or native producer was rerun, and the original business qualification remains HOLD.

The [History / SQL / COW addendum](candidate/history-sql-cow-addendum-v1/README.md) records the existing snapshot tail, full active-State and final activation obligations separately. Most hot SQL already uses bounded prepared statements. Remaining statement-compile candidates have no measured benefit and are not included in this source change. The addendum binds nine individually read source/evidence files to 819; it is not a new complete source verification.

[ADDITIONAL_COPY.json](ADDITIONAL_COPY.json) retains the separate v2/preparation copy manifest. [FINAL_ADDITIONS.json](FINAL_ADDITIONS.json) binds the final v3, static review and original copy/check receipts. The initial 1,527-file count belongs only to RETAINED_COPY.json, not to the sum of these later independent additions.

Earlier [d26 and combined-source evidence](../pon-business-gates-readback-20261107/README.md), the failed 93277 controls, old resource failures and the missing historical artifact remain intact. Locator/read, observer and packaging errors are identified separately from native failures. Original four-second, sixteen-worker, 4,105-import and cold-activation requirements stay open until actual new-source results establish otherwise.

## 8. First frozen candidate source-control failure retained

Candidate fa6388d06195711b5d72217b2b7f10b03756e886 (tree 4bb21bcd9a931eac6d56aa4ef472a97f435444f9) completed its single original seventeen-suite invocation. All **666/666 named methods passed**, but the overall source-control attempt failed because the separate PQ integration checker rejected the workflow source binding. Complete source-before/source-after matched. No native build or body ran on this candidate.

The [entire original source attempt](candidate/source-attempt-fa6388d06195711b5d72217b2b7f10b03756e886/summary.json), original error log and authoritative failed/exit-1 terminal remain intact. [WORKFLOW_BINDING_FIX.json](WORKFLOW_BINDING_FIX.json) records the concrete correction: the workflow's internal store.rs pin had been updated, but the corpus still named the workflow's previous Git blob. All 576 existing manifest entries were compared with the frozen candidate tree: 575 matched, one differed, none was missing.

The follow-up changes only that corpus field to actual workflow blob 3468dab27c330c086ac8b05f59675d7afe88445a. It does not change the workflow, checker, production Rust, test budget or original failure. The follow-up commit requires its own complete source-control invocation and the declared native validation; the failed candidate's 666 method passes are not an overall green result.
