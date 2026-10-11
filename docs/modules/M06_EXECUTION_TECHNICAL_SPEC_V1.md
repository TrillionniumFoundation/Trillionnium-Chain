# M06 Deterministic application execution and reversible deltas

The pure [checked derived commitment contract](../protocol/pon-nakamoto-v1/details/DERIVED_STATE_COMMITMENT.md)
adds bounded root computation for complete actual states. It retains existing execution,
receipt and reversible-delta rules; the durable Node owner commits and publishes results.

Within one Node preparation or checked-admission operation, the first actual
`state_at(parent)` read may supply both execution and parent task eligibility.
This still reads complete canonical KV (or checked snapshot/deltas for an inactive
branch) and checks its admitted root. The private eligibility is dropped with that
operation; neither Node nor the unlocked proof search retains it as authority.
Registered preparation preserves lifecycle eligibility before source admission and
V1 registry eligibility after source admission. Output accounting uses that parent
eligibility against the separately executed successor, including maintenance,
renewal, revocation, slot/generation and product-conflict checks. It does not grant
a new registration authority over its containing block. Initial admission context
and checked-work re-entry remain independent checks; search completion still
rechecks the current parent/generation, exact pool batch and full native admission.
There is no new SQL isolation guarantee for writers outside the sole Node owner.
Actual selectors `trnm-pon-node --test operation_local_parent --test task_output_root_parity`
cover complete packet parity, active/inactive/reopened parents, independent later
KV corruption and the complete successor-root/output-accounting path. These local
checks do not establish a throughput improvement or public qualification.

Revision: invariant-driven revision3. Selected target: `pon-nakamoto-v1`.
[Sole development plan](../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md); [exact invariant registry](../../config/pon/invariants-v2.json).

## Scope and ownership

Native execution is owned by existing `trnm-mvcc-fee`. The separately coded Python
reference and twelve-command parity below cover the historical default core; they do
not establish general reference execution of every gated native extension.

The claims below apply to their named component and tests, not to an independently accepted full native node.

## PoN State machine

### M06.ExecuteCandidate

Run deterministic due expiry and maturity before txs; execute the closed command set enabled by the exact context; transfer exact fees, stage subsidy; verify global conservation and size bounds. Remote calls, floats and evaluator programs never run inside state transition.

The12-command equivalence claim below applies to the historical default context.
Explicit successors additionally gate signed task registration, renewable requester
leases and native frozen evaluation transitions by committed profile. Their exact
interfaces, payloads, errors, windows and retention bounds are in
[LEDGER_WIRE](../protocol/pon-nakamoto-v1/details/LEDGER_WIRE.md),
[QUALIFIED_TASK_LIFECYCLE_V2](../protocol/pon-nakamoto-v1/details/QUALIFIED_TASK_LIFECYCLE_V2.md),
[V3 atomic renewal](../protocol/pon-nakamoto-v1/details/QUALIFIED_TASK_LIFECYCLE_V3.md),
[V4 signed overlap](../protocol/pon-nakamoto-v1/details/QUALIFIED_TASK_LIFECYCLE_V4.md)
[PUBLIC_EVALUATION_LIFECYCLE](../protocol/pon-nakamoto-v1/details/PUBLIC_EVALUATION_LIFECYCLE.md)
and the explicit revision11 [integer factor candidate](../protocol/pon-nakamoto-v1/details/NATIVE_INTEGER_FACTOR_CANDIDATE_V2.md).
The latter loads the complete actual ILM2 parent from State, recomputes771 BA
coordinates and the complete candidate model, and persists context-bound duplicate
rows through the existing staged State/deltas. It neither reinterprets old tag6
nor proves general model-function equivalence or useful quality.
Lifecycle18 OPEN/20 REVOKE/21 REGISTER retain their selected contract; standalone19
RENEW is V2-only, and atomic22 is V3/V4-only. V3/V4 refuse19; V4 selects revision9.
Native selectors `trnm-pon-node --test task_lifecycle --test task_lifecycle_v3 --test task_lifecycle_v4 --test public_evaluation` exercise
their actual signed execution, material-bound work, persistence/reopen and heavier-fork
behavior. Controlled scores and public development authorities do not qualify objective
ML quality, task demand or evaluator independence.

**Atomic/commit boundary:** Return complete state/delta intent; caller M07 owns persistence.

### M06.DeriveBranchDelta

For sorted union of keys compare canonical values; emit only changed entries, encode absence as NULL and empty value as real bytes. Detach verifies after then restores before; attach checks before then writes after.

**Atomic/commit boundary:** Same atomic commit as admitted block row.

## M06.TwelveCommandEquivalence

**Invariant:** The historical twelve core commands produce identical state, receipts, fees and root at one, two, four and eight workers.

**Scope:** Historical default-context native/Python parity. Signed task13, native
evaluation14..17, selected lifecycle18..22 and revision11 factor23 have separate native contracts and tests;
this invariant does not claim full Python transition parity for those extensions.

**Atomic boundary:** Mandatory transitions first, parallel local proposals, canonical read-set validation, one re-execution on conflict, then final conservation and subsidy.

**Failure schedule:** Tasks, cancel, receipt and accept; Contribute, evaluate, publish and claim; Quota reserve/use and work registration; Missing native backend.

**Expected result:** All twelve commands produce identical state, receipts, fees and root at one, two, four and eight workers.

**Resource and retention rule:** 256 transactions; tracked prefix reads detect phantoms; explicit native bridge is bounded to16MiB and30 seconds.

## Concrete regression selectors

`formal/pon-nakamoto-v1/test_native_execution.py::NativeExecutionTests.test_all_twelve_tags_match_for_1_2_4_8_workers`

`formal/pon-nakamoto-v1/test_native_execution.py::NativeExecutionTests.test_missing_native_binary_is_not_reference_fallback`

These exact functions contain executable assertions. The registry only checks binding; actual outcomes and source/input identities belong to the separate qualification report.

## Module-specific threat and residual work

Incorrect conflict sets, receipt order changes, unbounded retries and successful fallback masking missing implementation.

A native application engine is not a complete native consensus/persistence/Hepta host.

## Current source and verification

- [`trillionnium/crates/trnm-mvcc-fee/src/pon_executor.rs`](../../trillionnium/crates/trnm-mvcc-fee/src/pon_executor.rs).
- [`formal/pon-nakamoto-v1/native_execution.py`](../../formal/pon-nakamoto-v1/native_execution.py).
- [`formal/pon-nakamoto-v1/ledger.py`](../../formal/pon-nakamoto-v1/ledger.py).

No test binding or local campaign grants independent acceptance, ordinary Hepta execution or production activation. Preserve the exact source, profile and environment of every outcome.

## Executed evidence and scope

[Responsibility-level evidence navigation](README.md#responsibility-and-evidence) reads
measured commits from immutable receipts. The module's entries in
[module-maturity-v1.json](../../config/pon/module-maturity-v1.json) identify actual callable
owners, controlled entrypoints, backends, persistence and exact observed test selectors.
Run `python3 scripts/ci/report_module_evidence.py --module M06` from the repository
root to see subject-byte and complete recorded-runtime matches separately, plus scenarios
not observed in each package. A byte match is not a new test run or product acceptance.
Historical v1/v3/v4 results are never repinned. The sole plan selects further work.

## Block-scoped execution continuation

The existing native executor now bounds thread creation per block and preserves a private
verified main envelope across canonical state replay. This is a computational fact, not
work validity or local permission. Capacity/range state transitions remain ordered and
consumer signatures still bind actual quota state. See the exact algorithm, errors and
counterexamples in [EXECUTION_PARALLEL](../protocol/pon-nakamoto-v1/details/EXECUTION_PARALLEL.md).
Complete-state root construction, full native node assembly and Hepta ownership remain
separate work; worker counts do not establish throughput or independent acceptance.

Exact continuation selectors (each must appear as actually executed in a current receipt):

- `formal/pon-nakamoto-v1/test_native_execution.py::NativeExecutionTests.test_block_scoped_workers_and_no_duplicate_main_signature_on_conflict`
- `formal/pon-nakamoto-v1/test_native_execution.py::NativeExecutionTests.test_funding_dependency_replays_state_not_main_signature`
- `formal/pon-nakamoto-v1/test_native_execution.py::NativeExecutionTests.test_capacity_prefix_commands_do_not_speculate_unbounded_snapshots`
- `formal/pon-nakamoto-v1/test_native_execution.py::NativeExecutionTests.test_later_invalid_signature_does_not_change_canonical_error`
- `formal/pon-nakamoto-v1/test_native_execution.py::NativeExecutionTests.test_single_signature_context_cannot_be_reused_for_another_payload`

## Native cache / receiver continuation

The exact continuation is specified in [native execution](../protocol/pon-nakamoto-v1/details/EXECUTION_PARALLEL.md), [admission](../protocol/pon-nakamoto-v1/details/ADMISSION_SECURITY.md) and [client/recovery](../protocol/pon-nakamoto-v1/details/NETWORK_CLIENT.md). It does not promote native persistence, independent acceptance or public-network capacity. Exact additional counterexamples:

- `formal/pon-nakamoto-v1/test_native_session.py::NativeSessionTests.test_all_twelve_tags_run_in_1_2_4_8_worker_persistent_sessions`.
- `formal/pon-nakamoto-v1/test_native_session.py::SessionBoundaryTests.test_boolean_before_value_does_not_alias_integer_zero`.
- `formal/pon-nakamoto-v1/test_native_session.py::SessionBoundaryTests.test_lost_reply_discards_advanced_cache_and_retries_same_input`.
- `formal/pon-nakamoto-v1/test_native_session.py::SessionBoundaryTests.test_exact_predecessor_memo_does_not_skip_returned_root_verification`.


The explicit [operator actor context](../protocol/pon-nakamoto-v1/details/OPERATOR_ACTORS_V1.md)
uses the existing module owner and fresh public descriptor/signature-bound N/P/G.
This changes development bootstrap custody and role pins only; native admission,
execution and confirmation remain required, and no independent/public flag is accepted.

The optional [derived state commitment](../protocol/pon-nakamoto-v1/details/DERIVED_STATE_COMMITMENT.md)
uses an allocation-free ordered difference preflight, complete canonical root fallback
and unchanged public delta bytes. A disjoint pair of valid65536-key states can produce
131072 changes; the delta budget selects fallback before cloning that change vector.
Cache accounting and implementation-conditioned workspace bounds are not protocol
payload limits, hard allocation/RSS limits or proof of a reachable native workload.

The independent [checkpoint tile material replay](../protocol/pon-nakamoto-v1/details/CHECKPOINT_TILE_MATERIAL_V1.md)
checks a complete pinned safetensors file, exact tensor coordinates, original input
bits and integer quantization against all A/B bytes. Its private checked result can
bind a source-signature/context-checked QWT1 manifest. It neither replaces actual
parent eligibility nor proves model forward, genuine demand, hardware cost, useful
contribution or a qualified consensus cost class. The separate explicit revision10
[checkpoint tile task selector](../protocol/pon-nakamoto-v1/details/CHECKPOINT_TILE_TASK_V1.md)
requires full original replay in Settings construction and every Node open, binds a fresh
operator/policy N/P/G and only admits the installed Maintenance/output0 relation.
Its material replay does not replace actual parent/source eligibility or native execution.

## Mandatory capacity and native model evidence

[Continuity v1](../protocol/pon-nakamoto-v1/details/CONTINUITY_V1.md) checks mandatory future key liabilities in both accepted parent and successor state. [Model evidence v3](../protocol/pon-nakamoto-v1/details/NATIVE_MODEL_EVIDENCE_V3.md) adds native frozen-task inference, strongest-control-positive scoring, exact reveal binding and known-source budgets. These are explicit new contexts under the existing executor and branch owner; earlier profile vectors and authority limits remain.

## Incremental prefixes within one owner operation

[Same-block prefix execution](../protocol/pon-nakamoto-v1/details/LOCAL_MEMPOOL_LIFECYCLE.md#same-block-incremental-m06-prefix)
uses CheckedTransactionPrefix, constructed from the checked immutable original
parent and a fixed height/miner/parent-id/configuration. Mandatory actions run
once. Every append compares the previously accepted raw prefix and prepares and
applies only the new suffix. Each returned result still includes complete ordered
receipts, finalized reward, conservation/capacity checks, full state/root and the
original-parent-to-output delta. Changed-key scratch rollback includes rejection,
cancellation and unwind; a previous completed block is never a new prefix parent.

Node may move that builder from reconciliation to submission within the same
operation. A new operation rereads actual KV and root. M05 and owner permissions
still check complete prefixes, and every accepted group still pays full state
encoding/root/output costs. This removes repeated M06 transaction execution,
without granting persistent state authority or an end-to-end throughput bound.

The explicit [model composition V4](../protocol/pon-nakamoto-v1/details/NATIVE_MODEL_COMPOSITION_V4.md)
successor validates the full bundle as the exact sum of bounded common-parent
component deltas, rejects exactly cancelling component subsets, requires
superiority over each included component and computes
positive leave-one-out weights before an existing funded release is admitted. Its
fresh context and embedded release record preserve V3 semantics. Public fixed-task
ablation does not establish training causality, future efficacy or fair universal
attribution; a perfect25/25 parent saturates this finite development objective.

Independent Python oracles now compute complete small continuity expiry/archive
transitions and complete revision14 integer composition/release/claim expectations.
Their native bridges export actual executor outcomes; exact case sets, canonical
State/receipt bytes and run identities are checked without accepting native scores
as expected answers. The seeded continuity inputs do not claim signed reachability,
and the composition oracle does not independently verify signatures, roster closure
or ILF2 witnesses. The separate full-capacity Node fixture covers real quota expiry,
new-account reentry, two heavier reorganizations and three cold reopens.

## Checked parent sharing and local capacity observations

`CheckedExecutionParent::bind` checks every canonical actual State value and the
expected snapshot/root before sharing the opaque map. It avoids one additional
complete parent map in the warm path; actual state scanning, cold roots, complete
successor execution and all protocol bounds remain. The copying control and error
order are specified by [derived commitment](../protocol/pon-nakamoto-v1/details/DERIVED_STATE_COMMITMENT.md).

The Node's local `capacity-observe` reads actual KV/root and the one current
revision12 capacity algorithm. Its generation/slot-bound report separates retained
accounts from future obligations and never promises next-block admission. This is
diagnostic ownership, with unchanged M06 capacity and reward semantics; see
[continuity](../protocol/pon-nakamoto-v1/details/CONTINUITY_V1.md).

## Shadow account-archive research boundary

[Account archive prototype](../protocol/pon-nakamoto-v1/details/ACCOUNT_ARCHIVE_PROTOTYPE_V1.md)
projects complete actual State into a separate, fresh-domain SQLite COW account
archive. Immutable branches retain balance and nonce, and missing records refuse
as unavailable data rather than proving absence. Checked views require complete
root/branch-bound membership or nonmembership proofs before account lookup. They
are never fed to current M06 as a partial State.

The explicit `account_archive_execution::execute_with_progress` research wrapper
binds immutable Settings, the original parent checkpoint, complete State and account
roots/counts, and a complete execution-specific proof bound before calling M06 with one
worker. Every semantic account point read must have its original-parent witness;
current ordered values still come from full State and the transaction write overlay.
Enabled continuity rules also gate their mandatory-recipient existence reads.
Missing or unused witnesses refuse, as do account changes without a checked access,
deletion and parent-child nonce decrease. The shared M06 callback hook authenticates
no callback by itself; the research wrapper owns those checks.

Full aggregate account/non-account scans, funds, fees, subsidy, conservation,
capacity and complete successor roots remain. The returned native Output and
`pon-checked-account-execution-v1` observation do not admit a block or publish an
archive successor; ordinary Node admission and archive activation stay separate.
Default execution entrypoints, production capacity, full-state commitments and
consensus selection remain unchanged. A large synthetic archive, signed Node
projection and proof-gated complete-State execution have separate observation
contracts; none declares unbounded new-account admission or independent DA.

The separate [authenticated complete-state companion](../protocol/pon-nakamoto-v1/details/ACCOUNT_ARCHIVE_PROTOTYPE_V1.md#authenticated-complete-state-companion)
binds account root/count/balance and a complete ordered non-account partition with
its aggregate funds to the checked full parent. Those non-account rows are actual
mandatory-execution input, so an omitted due obligation cannot become an absent
one. Combined original-parent account proofs derive the mandatory-prologue and
final changed-account roots and aggregate deltas; both are compared with complete
State rebuilding. The complete native M06 relation and its existing errors remain
the execution authority. The new commitment/observation domains grant no ordinary
Node admission, durable root or bounded partial-State execution. Full non-account
input and reference scans remain. Whole-block account witnesses are bounded by
checked parent keys plus twice the actual transaction count plus one miner, using
the current transaction-access contract; the standalone point-query limit remains32.
A sorted proof frontier combines changed paths with O(P) auxiliary references and
a depth256 stack, while the original AAW1 proof bytes remain O(256P). The separate
[durable archive](../protocol/pon-nakamoto-v1/details/AUTHENTICATED_STATE_ARCHIVE_V1.md)
reexecutes actual admitted Node transitions before its own atomic publication;
installed Node state and consensus selection remain separate.

The explicit AAM1 companion now constructs a canonical shared account frontier
directly from persistent Patricia nodes. `prepare_compact` and
`execute_with_compact_state_witness` bind the same complete parent, non-account
partition, actual obligation set and transaction/miner access bound. They never
expand one 256-sibling witness per queried account. Canonical decoding rejects
duplicate, overlapping, non-maximal, empty or unnecessary boundary nodes. Original
parent accounts and changed paths are checked once and reused for mandatory and
successor updates; all ordinary M06 gates and complete reference comparisons remain.
The actual three-block signed fixture uses41 queried accounts and80 transactions;
independent Python application replay checks exact AAM1 bytes and both phase roots.
The measured1,611/2,251-byte encodings and conservative7,561,821-byte global bound
are proof-size observations, not full execution latency or proof-availability claims.

The [native authenticated storage backend](../protocol/pon-nakamoto-v1/details/NATIVE_AUTHENTICATED_STORAGE_V1.md)
now installs authenticated account nodes and state records in the actual Node
writer transaction under a fresh explicitly selected schema. Its commitments use
the complete final State after M06 and qualified task output accounting; the
independent full-State comparison therefore includes records created after ordinary
application execution. This does not replace the complete input relation above.


## 本轮来源绑定（Round 10）

本节补充 `M06.TwelveCommandEquivalence` 的显式研究入口绑定。
[货币义务完整范围关系](../protocol/pon-nakamoto-v1/details/MONETARY_OBLIGATION_RANGES_V1.md)
从已检查的完整 parent 建立独立有序非账户索引，认证 quota、release、reward、task
四个完整前缀范围及相邻边界。未来与零金额记录也必须披露，合法的子集 membership
不能代替完整范围。`execute_with_monetary_state_witness` 只在私有 checked 范围建立后
把这些行用于父状态货币义务发现；其他非账户规则、successor capacity 与完整 State
参照继续执行，默认 Node admission 仍使用完整状态路径。

原生 fixture 定义了 21 个块、37 笔签名交易、16 加 2 笔到期退款，以及原本不存在的
奖励接收者在成熟块内消费的路径；独立 reader 从安装 genesis 和签名应用交易重建
parent、AAM1、完整范围、两个执行阶段和 packet 应用承诺。该 reader 不重新证明 W1
或 fork choice。精确 JSON 字节计数针对完整 parent 已接受的 canonical Value 值域，
UTF-8 支持涉及顶层 State key。测试定义与实际执行分别记录；以下 selector 不授予
partial-State、数据可用性或独立验收，`independent_accepted=false`。

对应完整回归 selector：

- `trillionnium/crates/trnm-pon-node/src/account_archive_execution/obligation_ranges.rs::complete_ranges_cover_empty_edges_shared_neighbors_and_retained_unknown_namespaces`.
- `trillionnium/crates/trnm-pon-node/src/account_archive_execution/obligation_ranges.rs::valid_subset_membership_cannot_omit_due_future_zero_or_neighbor_rows`.
- `trillionnium/crates/trnm-pon-node/src/account_archive_execution/obligation_ranges.rs::range_frontier_is_maximal_and_extra_authenticated_rows_are_refused`.
- `trillionnium/crates/trnm-pon-node/tests/account_obligation_ranges.rs::monetary_ranges_execute_signed_expiry_future_capacity_and_reward_maturity_against_native_node`.
- `trillionnium/crates/trnm-pon-node/tests/account_obligation_ranges.rs::monetary_ranges_preserve_nonmonetary_cleanup_and_refuse_raw_m06_projection_omission`.
- `formal/pon-nakamoto-v1/test_obligation_range_oracle.py::MonetaryRangeOracle.test_full_sorted_source_includes_future_and_zero_amount_rows`.
- `formal/pon-nakamoto-v1/test_obligation_range_oracle.py::MonetaryRangeOracle.test_empty_partition_and_single_edge_rows_are_canonical`.
- `formal/pon-nakamoto-v1/test_obligation_range_oracle.py::MonetaryRangeOracle.test_empty_ranges_share_nearest_boundaries_once`.
- `formal/pon-nakamoto-v1/test_obligation_range_oracle.py::MonetaryRangeOracle.test_lexical_endpoints_unicode_keys_and_arbitrary_suffixes`.
- `formal/pon-nakamoto-v1/test_obligation_range_oracle.py::MonetaryRangeOracle.test_authentic_subset_cannot_omit_any_due_future_or_zero_obligation`.
- `formal/pon-nakamoto-v1/test_obligation_range_oracle.py::MonetaryRangeOracle.test_authentic_subset_cannot_omit_immediate_boundary`.
- `formal/pon-nakamoto-v1/test_obligation_range_oracle.py::MonetaryRangeOracle.test_authentic_extra_non_boundary_leaf_is_noncanonical`.
- `formal/pon-nakamoto-v1/test_obligation_range_oracle.py::MonetaryRangeOracle.test_split_hidden_subtree_is_valid_membership_but_noncanonical_frontier`.
- `formal/pon-nakamoto-v1/test_obligation_range_oracle.py::MonetaryRangeOracle.test_parent_and_count_roots_require_exact_external_anchor`.
- `formal/pon-nakamoto-v1/test_obligation_range_oracle.py::MonetaryRangeOracle.test_order_duplicates_rank_and_value_types_are_not_coerced`.
- `formal/pon-nakamoto-v1/test_obligation_range_oracle.py::MonetaryRangeOracle.test_frontier_zero_overlap_duplicate_reorder_and_digest_changes_fail`.
- `formal/pon-nakamoto-v1/test_obligation_range_oracle.py::MonetaryRangeOracle.test_exact_json_shape_dimensions_and_byte_bounds`.
- `formal/pon-nakamoto-v1/test_obligation_range_oracle.py::MonetaryRangeOracle.test_serde_struct_bytes_are_canonical_independent_of_json_map_input_order`.
