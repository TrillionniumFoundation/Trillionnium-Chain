# M07 Branch roots, schema and owner-controlled persistence

Revision: invariant-driven revision3. Selected target: `pon-nakamoto-v1`.
[Sole development plan](../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md); [exact invariant registry](../../config/pon/invariants-v2.json).

## Scope and ownership

Distinct fresh native-development and reference revision3 SQLite namespaces; each has one writer. Neither silently upgrades or writes the other namespace.

The claims below apply to their named component and tests, not to an independently accepted full native node.

## PoN State machine

### M07.OpenNamespace

Every owned initialization crash cut can recover; foreign incomplete databases and injected schema objects reject without writable mutation. Fsync exact initialization intent, create schema plus genesis in one transaction, remove marker after commit; compare exact schema projection on reopen.

**Atomic/commit boundary:** Fsync exact initialization intent, create schema plus genesis in one transaction, remove marker after commit; compare exact schema projection on reopen.

### M07.StageBranch

BEGIN IMMEDIATE, insert immutable block, insert changed-key deltas, COMMIT. Any failure rolls back the transaction. A restart reads complete old/new state, not partially visible rows.

**Atomic/commit boundary:** blocks+deltas one transaction; active pointer separate M08 publication.

## M07.OwnedInitialization

**Invariant:** Every owned initialization crash cut can recover; foreign incomplete databases and injected schema objects reject without writable mutation.

**Scope:** Distinct fresh native-development and reference revision3 SQLite namespaces; each has one writer. Neither silently upgrades or writes the other namespace.

**Atomic boundary:** Fsync exact initialization intent, create schema plus genesis in one transaction, remove marker after commit; compare exact schema projection on reopen.

**Failure schedule:** Intent persisted; Schema staged; Before initialization commit; After commit before marker removal; Unexpected trigger and unmarked empty database.

**Expected result:** Every owned initialization crash cut can recover; foreign incomplete databases and injected schema objects reject without writable mutation.

**Resource and retention rule:** Ordinary append writes only changed keys; one physical state slot, separate logical generation.

## Concrete regression selectors

`formal/pon-nakamoto-v1/test_invariants.py::InitializationTests.test_every_initialization_cut_recovers_only_our_exact_intent`

`formal/pon-nakamoto-v1/test_invariants.py::InitializationTests.test_unmarked_empty_database_is_not_reinitialized`

`formal/pon-nakamoto-v1/test_invariants.py::InitializationTests.test_injected_trigger_rejects_before_writable_open`

`formal/pon-nakamoto-v1/test_invariants.py::RestartForkTests.test_append_retains_one_physical_state_slot`

These exact functions contain executable assertions. The registry only checks binding; actual outcomes and source/input identities belong to the separate qualification report.

## Module-specific threat and residual work

Initialization gaps, trigger/schema substitution, disk full, path replacement and unbounded full-state copies.

Full descriptor/sidecar fencing and physical power-loss qualification remain pending.
The explicit authenticated native storage namespace below adds persistent account
updates while retaining complete native State verification.

## Current source and verification

- [`trillionnium/crates/trnm-pon-node/src/store.rs`](../../trillionnium/crates/trnm-pon-node/src/store.rs).
- [`formal/pon-nakamoto-v1/ledger.py`](../../formal/pon-nakamoto-v1/ledger.py).

No test binding or local campaign grants independent acceptance, ordinary Hepta execution or production activation. Preserve the exact source, profile and environment of every outcome.

## Executed evidence and scope

[Responsibility-level evidence navigation](README.md#responsibility-and-evidence) reads
measured commits from immutable receipts. The module's entries in
[module-maturity-v1.json](../../config/pon/module-maturity-v1.json) identify actual callable
owners, controlled entrypoints, backends, persistence and exact observed test selectors.
Run `python3 scripts/ci/report_module_evidence.py --module M07` from the repository
root to see subject-byte and complete recorded-runtime matches separately, plus scenarios
not observed in each package. A byte match is not a new test run or product acceptance.
Historical v1/v3/v4 results are never repinned. The sole plan selects further work.

## Native development continuation and remaining scope

Node is now a native single-writer fresh-namespace SQLite owner for blocks/deltas, staged KV, snapshots and active generation. Existing Python storage remains a separate oracle. Descriptor/sidecar races, physical power loss, long-run growth and incremental persistent roots remain unqualified.

The current callable mappings remain in `config/pon/module-maturity-v1.json`.
Exact native entry, storage and work behavior is specified by N3 in NETWORK_CLIENT,
the native continuation in STATE_RECOVERY and the prepared-producer section in WORK_PROFILE.
No historical receipt is relabelled as executing this source.

## Actual-state cancellation and statement reuse

The [history/state resource contract](../protocol/pon-nakamoto-v1/details/HISTORY_STATE_RESOURCE_BOUNDS_V1.md) preserves the actual KV/root check and adds cancellation every256 rows, a final tip/generation/slot check and reused delta statements. The SQLite schema and atomic transaction boundary remain unchanged. Complete root construction and retained history still have their stated growth costs.

The [authenticated account/state research companion](../protocol/pon-nakamoto-v1/details/ACCOUNT_ARCHIVE_PROTOTYPE_V1.md#authenticated-complete-state-companion)
computes a separate full-parent-bound commitment and checks proof-derived prologue
and successor aggregates. It never stores that commitment as the Node state root,
publishes an archive branch or changes this module's schema or atomic boundary.
The existing branch owner and complete native State root remain authoritative.
The separately selected native backend below supplies persistent account updates
and migration/recovery rules. Complete compact non-account obligations, retained
witness-data responsibility and growth pricing remain separate requirements.

## Explicit authenticated-state archive

The [durable research archive](../protocol/pon-nakamoto-v1/details/AUTHENTICATED_STATE_ARCHIVE_V1.md)
uses its own namespace and explicit caller operation. It imports actual native genesis,
reexecutes an admitted block through complete authenticated-state inputs and checks
full state/receipts before atomically publishing checkpoint, delta and optional selection.
CAS generations do not rewind when selecting an older branch. Missing data, altered
records, stale selection, quota exhaustion and cancellation refuse without partial
publication. Reads and reopen reconstruct complete states and compare actual native
branch data. This separate reference-backed store adds no ordinary startup selection,
installed state root, public proof service, pruning or rollback of local operation facts.

## Explicit native authenticated storage and migration

[Native authenticated storage v1](../protocol/pon-nakamoto-v1/details/NATIVE_AUTHENTICATED_STORAGE_V1.md)
is selected through `Node::open_with_authenticated_state` in a fresh storage
namespace. It keeps copy-on-write account nodes and complete state commitments in
the same `native.sqlite` transaction as admitted blocks and canonical deltas.
Genesis seeds the account tree; later actual account deltas update persistent roots
and sums, which are independently compared with the complete native State.
Active reads, historical reads, reorganization and recovery require the retained
authentication material; unavailable data does not use the legacy backend.
The ordinary opener, original DDL and consensus header root bytes retain their meaning.

Explicit migration holds a consistent source transaction and preserves the original
namespace. It copies every retained ordinary table, including local monotone facts,
and validates native branch execution before publishing a fresh destination. A
pending marker prevents either opener from accepting an incomplete destination.
External owner-journal modes require their own migration authority and are refused.
Logical equality, cancellation and process-loss tests do not establish physical
power-loss behavior or a general deployed-data migration service.

Both native storage modes now check actual block/delta/snapshot writes and the
persisted selected state before COMMIT. Selection also checks its expected
generation, event rows and reorganization state after the final write. A suppressed
write or a final write that damages the intended state cannot return a successful
publication. These checks add complete-state readback cost; no overall latency
improvement is inferred from the incremental account-node representation.


## 本轮来源绑定（Round 10）

本节补充 `M07.OwnedInitialization` 的原生后端来源绑定。
[原生认证存储](../protocol/pon-nakamoto-v1/details/NATIVE_AUTHENTICATED_STORAGE_V1.md)
按路径合并本次账户更新，在同一 owner 事务内保存最终子树。成功返回时，本次新增的
`archive_nodes` payload 均属于最终 successor；旧版本和侧分支继续保留。该承诺不覆盖
SQLite 物理页／WAL 大小或累计历史上界。取消和 SQL 拒绝可能发生在事务内部分写入之后，
由 owner 回滚；原始 parent 值、nonce 单调性及禁止账户删除的约束保持不变。

[原生 ancestry 索引](../protocol/pon-nakamoto-v1/details/NATIVE_ANCESTRY_INDEX.md)
的实际行在相关提交和恢复边界检查。独立 storage reader 从完整保留图的 parent walk
重建所有期望 jump 和 seal，包含 inactive forks；迁移两边相同的损坏不能仅凭 cell
相等通过。完整 State 校验和读取成本仍见
[状态与历史资源边界](../protocol/pon-nakamoto-v1/details/HISTORY_STATE_RESOURCE_BOUNDS_V1.md)。

完整 65,536-key 原生容量测试在普通 debug suite 中明确 ignored，必须以实际
`--release --exact --ignored` 专项执行建立证据；忽略记录及此处来源登记均不是通过。
以下绑定不授予物理断电保障、全历史保留资格或独立验收，`independent_accepted=false`。

对应完整回归 selector：

- `trillionnium/crates/trnm-pon-node/src/account_archive_prototype/native_store_batch_tests.rs::batched_paths_match_serial_versions_and_keep_every_insert_reachable`.
- `trillionnium/crates/trnm-pon-node/src/account_archive_prototype/native_store_batch_tests.rs::batched_paths_cancel_and_sql_refusal_roll_back_partial_writes_and_reopen`.
- `trillionnium/crates/trnm-pon-node/src/account_archive_prototype/native_store_batch_tests.rs::batched_paths_keep_original_parent_nonce_and_no_deletion_checks`.
- `trillionnium/crates/trnm-pon-node/src/account_archive_prototype/native_store_batch_tests.rs::native_authenticated_full_capacity_refund_entry_and_pending_reorganization_recover`.
- `trillionnium/crates/trnm-pon-node/src/native_ancestry_commit_tests.rs::real_signed_packets_reject_omitted_and_late_modified_ancestry_before_commit`.
- `trillionnium/crates/trnm-pon-node/src/native_ancestry_commit_tests.rs::restart_checks_exact_active_tip_row_set_including_genesis`.
- `trillionnium/crates/trnm-pon-node/src/native_ancestry_commit_tests.rs::activation_final_events_cannot_commit_missing_or_extra_active_ancestry`.
- `formal/pon-nakamoto-v1/test_native_authenticated_storage_oracle.py::NativeAuthenticatedStorageOracle.test_all_retained_ancestry_rows_are_reconstructed_across_inactive_forks`.
- `formal/pon-nakamoto-v1/test_native_authenticated_storage_oracle.py::NativeAuthenticatedStorageOracle.test_ancestry_missing_extra_genesis_and_unknown_rows_are_refused`.
- `formal/pon-nakamoto-v1/test_native_authenticated_storage_oracle.py::NativeAuthenticatedStorageOracle.test_resealed_wrong_ancestor_height_and_component_seals_are_recomputed`.
- `formal/pon-nakamoto-v1/test_native_authenticated_storage_oracle.py::NativeAuthenticatedStorageOracle.test_ancestry_rows_require_exact_types_and_unique_keys`.
- `formal/pon-nakamoto-v1/test_native_authenticated_storage_oracle.py::MigrationPreservationOracle.test_identically_corrupt_migration_ancestry_is_not_qualified_by_cell_equality`.
