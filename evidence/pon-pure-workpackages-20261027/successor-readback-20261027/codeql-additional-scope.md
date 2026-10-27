# Additional finite scope inventory: 316 exposed Rust results

Source `0c804e9f5bcf6e972bbb4524c744d4b3c8801c34`, Rust analysis `2035397981`. This is a complete directory of the API-exposed 316 results, with limited production-risk screening. It is not a 307-alert semantic audit, clearance, new scan or gate pass. The frozen nine-alert report/archive remain unchanged.

## Counts

| Scope | Results |
|---|---:|
| example | 5 |
| unit-test | 279 |
| integration-test | 23 |
| fuzz-target | 8 |
| production-or-unknown | 1 |

Queries: {'rust/cleartext-logging': 27, 'rust/hard-coded-cryptographic-value': 289}. Hard-coded rule reported kinds: {'nonce': 284, 'salt': 5}. There are 39 distinct sink files. These result counts contain no key/IV/password-labeled finding from this query, but absence of that label is not proof those risks are absent.

## Production candidate retained: alert 1024

`trillionnium/crates/trnm-pon-node/src/main.rs:2641`, normal `println!("{value}")` after `run()` succeeds. This sink is outside the test module and must not be filtered away as a fixture.

All four API-exposed paths start at account data or permanent-account-growth settings in growth_cli/native_store and reach run()->Ok(value)->println. Related locations additionally name three real secret_identity calls; their full flow paths are not included in this subset.

secret_identity reads an owner-controlled file and returns DevelopmentIdentity with private secret_hex and public_hex fields. It must not be dismissed as only a public fixture merely from the DevelopmentIdentity type name.

growth-account intentionally emits public owner and Account(balance,nonce); growth-witness emits public proof bytes. Authentication setup takes secret_identity into client/server objects, while the examined listening JSON obtains public_key(). The identity type exposes public_key and internal signing methods, not a serializer. No raw secret->Value emission was established by these inspected paths.

**Disposition:** No immediate key/IV/password disclosure was established by this bounded inspection. The alert remains open/unresolved. Obtain the full original path evidence or add focused secret-canary output tests for normal authenticated CLI/error paths before considering closure. Neither the four displayed flow paths nor the query-name heuristic clears all twelve source relations.

## Full query/path directory

| Query | Scope | Count | Path |
|---|---|---:|---|
| rust/cleartext-logging | example | 1 | `trillionnium/crates/trnm-pon-node/examples/lifecycle_atomic_continuity.rs` |
| rust/cleartext-logging | example | 2 | `trillionnium/crates/trnm-pon-node/examples/support/state_witness_artifact.rs` |
| rust/cleartext-logging | fuzz-target | 8 | `tests/fuzz/fuzz_targets/authenticated_state.rs` |
| rust/cleartext-logging | integration-test | 2 | `trillionnium/crates/trnm-pon-node/tests/account_archive_execution.rs` |
| rust/cleartext-logging | integration-test | 1 | `trillionnium/crates/trnm-pon-node/tests/account_obligation_ranges.rs` |
| rust/cleartext-logging | integration-test | 2 | `trillionnium/crates/trnm-pon-node/tests/model_composition_v4.rs` |
| rust/cleartext-logging | integration-test | 2 | `trillionnium/crates/trnm-pon-node/tests/model_evidence_v3.rs` |
| rust/cleartext-logging | integration-test | 1 | `trillionnium/crates/trnm-pon-node/tests/release_finality_v2.rs` |
| rust/cleartext-logging | production-or-unknown | 1 | `trillionnium/crates/trnm-pon-node/src/main.rs` |
| rust/cleartext-logging | unit-test | 1 | `trillionnium/crates/trnm-pon-node/src/account_archive_prototype/multiproof_tests.rs` |
| rust/cleartext-logging | unit-test | 1 | `trillionnium/crates/trnm-pon-node/src/account_archive_prototype/native_store_batch_tests.rs` |
| rust/cleartext-logging | unit-test | 1 | `trillionnium/crates/trnm-pon-node/src/ingress.rs` |
| rust/cleartext-logging | unit-test | 2 | `trillionnium/crates/trnm-pon-node/src/ingress/public_v3/scalar_cpu_completion_tests.rs` |
| rust/cleartext-logging | unit-test | 1 | `trillionnium/crates/trnm-pon-node/src/store/growth/mandatory_capacity_tests.rs` |
| rust/cleartext-logging | unit-test | 1 | `trillionnium/crates/trnm-pon-node/src/store/root_rejection_cache_tests.rs` |
| rust/hard-coded-cryptographic-value | example | 1 | `trillionnium/crates/trnm-pon-node/examples/llm_zero_gain_round.rs` |
| rust/hard-coded-cryptographic-value | example | 1 | `trillionnium/crates/trnm-pon-node/examples/pon_w1_budget_report.rs` |
| rust/hard-coded-cryptographic-value | integration-test | 9 | `trillionnium/crates/trnm-pon-node/tests/native_compact_execution.rs` |
| rust/hard-coded-cryptographic-value | integration-test | 2 | `trillionnium/crates/trnm-pon-node/tests/native_growth_cli.rs` |
| rust/hard-coded-cryptographic-value | integration-test | 1 | `trillionnium/crates/trnm-pon-node/tests/public_v3_from_zero.rs` |
| rust/hard-coded-cryptographic-value | integration-test | 1 | `trillionnium/crates/trnm-pon-node/tests/public_v3_multiprocess.rs` |
| rust/hard-coded-cryptographic-value | integration-test | 2 | `trillionnium/crates/trnm-research-protocol/tests/protocol_v1.rs` |
| rust/hard-coded-cryptographic-value | unit-test | 4 | `trillionnium/crates/trnm-pon-node/src/ancestry_index.rs` |
| rust/hard-coded-cryptographic-value | unit-test | 3 | `trillionnium/crates/trnm-pon-node/src/ingress.rs` |
| rust/hard-coded-cryptographic-value | unit-test | 11 | `trillionnium/crates/trnm-pon-node/src/operator_pool_policy_tests.rs` |
| rust/hard-coded-cryptographic-value | unit-test | 4 | `trillionnium/crates/trnm-pon-node/src/operator_task_store_tests.rs` |
| rust/hard-coded-cryptographic-value | unit-test | 6 | `trillionnium/crates/trnm-pon-node/src/store/admission_parent_tests.rs` |
| rust/hard-coded-cryptographic-value | unit-test | 3 | `trillionnium/crates/trnm-pon-node/src/store/authenticated_migration_tests.rs` |
| rust/hard-coded-cryptographic-value | unit-test | 16 | `trillionnium/crates/trnm-pon-node/src/store/funding/tests.rs` |
| rust/hard-coded-cryptographic-value | unit-test | 1 | `trillionnium/crates/trnm-pon-node/src/store/growth/mandatory_capacity_tests.rs` |
| rust/hard-coded-cryptographic-value | unit-test | 20 | `trillionnium/crates/trnm-pon-node/src/store/growth/tests.rs` |
| rust/hard-coded-cryptographic-value | unit-test | 5 | `trillionnium/crates/trnm-pon-node/src/store/growth/work_checked_tests.rs` |
| rust/hard-coded-cryptographic-value | unit-test | 7 | `trillionnium/crates/trnm-pon-node/src/store/growth_reference_tests.rs` |
| rust/hard-coded-cryptographic-value | unit-test | 3 | `trillionnium/crates/trnm-pon-node/src/store/native_budget_tests.rs` |
| rust/hard-coded-cryptographic-value | unit-test | 2 | `trillionnium/crates/trnm-pon-node/src/store/root_rejection_cache_tests.rs` |
| rust/hard-coded-cryptographic-value | unit-test | 88 | `trillionnium/crates/trnm-task-kernel/src/tests.rs` |
| rust/hard-coded-cryptographic-value | unit-test | 12 | `trillionnium/crates/trnm-transport/src/lib.rs` |
| rust/hard-coded-cryptographic-value | unit-test | 43 | `trillionnium/crates/trnm-types/src/relay.rs` |
| rust/hard-coded-cryptographic-value | unit-test | 19 | `trillionnium/crates/trnm-types/src/transcript/mod.rs` |
| rust/hard-coded-cryptographic-value | unit-test | 20 | `trillionnium/crates/trnm-worker-agent/src/tests_commit_salt_security.rs` |
| rust/hard-coded-cryptographic-value | unit-test | 1 | `trillionnium/crates/trnm-worker-agent/src/tests_journal_security.rs` |
| rust/hard-coded-cryptographic-value | unit-test | 4 | `trillionnium/crates/trnm-worker-agent/src/workflow_ops.rs` |

## Classification evidence and limits

The JSON records every result index, alert number, source line, original message, reported source locations and the exposed flow origin/end summaries. Every sink file has its exact source blob/SHA-256. Unit-test classification cites the cfg(test) parent/module chain; fuzz targets are kept separate, and example code is not claimed to be cfg(test)-excluded. Integration-test path classification follows Cargo target conventions without a native build or exhaustive alternate-import audit.

Most hard-coded results refer to public nonce/sequence or test salt parameters, but this inventory does not individually certify their semantic use. No crypto implementation or test vector was renamed, no log or predicate was removed, and no policy exclusion was added.

The nine-report README, triage JSON and tar archive were SHA-256 checked before and after this work and preserved byte-for-byte.
