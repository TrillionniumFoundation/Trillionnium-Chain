# M15 Single host composition and bounded lifecycle

Revision: invariant-driven revision3. Selected target: `pon-nakamoto-v1`.
[Sole development plan](../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md); [exact invariant registry](../../config/pon/invariants-v2.json).

## Scope and ownership

Native development CLI composition, including loopback and explicit allowlisted signed private transport, plus a separate reference ledger with explicit native compute bridge. These development invariants are not a claim of a complete native public host.

The claims below apply to their named component and tests, not to an independently accepted full native node.

## PoN State machine

### M15.StartExecutableSpecPeer

Acquire the exclusive store owner, verify parameters, and recover unfinished branch, replay and outbox state before binding. Plain service may bind loopback only. The private signed profile additionally requires the explicit authenticated flag, a no-follow single-link owner-private key, an exact allowlist and a positive session generation for a non-loopback bind. Separately selected public V2/V3 development profiles use their resource-ticket contracts and grant guests no ledger, source or evaluator authority. No network admission precedes recovery.

**Atomic/commit boundary:** One Node owns branch state, inbound replay and outbound exact-wire state in a private current-schema namespace.

### M15.SendDurableAuthenticatedRequest

Create and sign one canonical request under the exact expected server identity and session generation. Commit its payload, wire and digests before connect/write. If the process or network loses the response, reopen and retry only the stored wire. Clear pending bytes and advance the nonce only after a context-matching strict server signature with `terminal=true`; a different request while pending rejects.

**Atomic/commit boundary:** `peer_outbox` reservation commits before network I/O. Verified terminal acknowledgement advances `highest_ack` and clears every pending field in one transaction.

### M15.StopAndReconcile

Stop admission, requestchild stop, wait bounded5seconds, kill+reap ifunresponsive; retain DB intent and local effect identity. No global service or external credentials are touched.

**Atomic/commit boundary:** Child owner acquired immediately; finally paths clean startedchildren.

## M15.ExplicitBackend

**Invariant:** A host selecting native execution either uses that binary or fails; it does not silently substitute a reference success path.

**Scope:** Native development CLI composition, including loopback and explicit allowlisted signed private transport, plus a separate reference ledger with explicit native compute bridge. These development invariants are not a claim of a complete native public host.

**Atomic boundary:** Backend choice before execution; bounded subprocess response; independently recompute returned root.

**Failure schedule:** Missing or inaccessible binary; Failed native transaction; Restart with persisted higher-work tip; Stderr fills before stdin is consumed; Stdout exceeds32MiB configured boundary; Child times out while holding pipes.

**Expected result:** A host selecting native execution either uses that binary or fails; it does not silently substitute a reference success path.

**Resource and retention rule:** 16MiB bridge input,32MiB stdout,64KiB stderr,30-second deadline; both pipes drained while writing; only the owned child session is terminated.

## M15.DurableOutbox

**Invariant:** A native authenticated client commits one exact signed wire before network I/O, retries only those bytes after restart and advances its nonce only after a verified terminal response.

**Scope:** Caller-owned private development Node namespace; not a wallet, production key service or remote physical-effect exactly-once protocol.

**Atomic boundary:** `peer_outbox` stores payload, wire and digests before connect/write; verified terminal acknowledgement atomically advances `highest_ack` and clears every pending field.

**Failure schedule:** Connection refused after reservation; Response lost after server commit; Client restart with pending bytes; Different request attempted while pending; Wrong server signature or session; Symlink, hard-link or group-readable secret file.

**Expected result:** Restart preserves one exact request. Retry cannot change its bytes, server or context, and no retryable/nonterminal response consumes the nonce.

**Resource and retention rule:** One pending request per session,2MiB wire,positive signed generation/nonce and descriptor-checked single-link private secret input.

## Concrete regression selectors

`formal/pon-nakamoto-v1/test_native_execution.py::NativeExecutionTests.test_missing_native_binary_is_not_reference_fallback`

`formal/pon-nakamoto-v1/test_invariants.py::RestartForkTests.test_admitted_before_activation_is_selected_on_restart`

`formal/pon-nakamoto-v1/test_native_execution.py::NativeExecutionTests.test_wrong_native_context_rejects_even_an_empty_block`

`formal/pon-nakamoto-v1/test_bounded_process.py::BoundedProcessTests.test_concurrent_pipe_drain_before_large_input`

`formal/pon-nakamoto-v1/test_bounded_process.py::BoundedProcessTests.test_stdout_flood_is_killed_and_reaped`

`formal/pon-nakamoto-v1/test_bounded_process.py::BoundedProcessTests.test_timeout_reaps_own_child`

`trillionnium/crates/trnm-pon-node/src/ingress.rs::test_durable_client_outbox_survives_network_loss_and_rejects_changed_request`

`trillionnium/crates/trnm-pon-node/src/ingress.rs::test_durable_client_retries_exact_wire_after_lost_server_response`

`trillionnium/crates/trnm-pon-node/src/main.rs::test_authentication_configuration_uses_the_opened_file_identity`

`trillionnium/crates/trnm-pon-node/tests/native_node.rs::test_authentication_options_are_scoped_to_network_commands`

`trillionnium/crates/trnm-pon-node/tests/native_node.rs::test_authenticated_cli_push_and_sync_share_one_durable_outbox_owner`

These exact functions contain executable assertions. The registry only checks binding; actual outcomes and source/input identities belong to the separate qualification report.

## Public development queue revision r3

[Public V3](../protocol/pon-nakamoto-v1/details/PUBLIC_POOL_INTAKE_V3.md) retains
its existing64 connections,8 mutation/8 read grants,2 proof/1 read workers and
2+2 queue slots. A paid canonical body may remain in the original connection's
`Enqueue` stage while its original10s work and30s total deadlines run; finite
connection-ID polling does not add an unbounded queue, owner or authority.
EOF/expiry/shutdown cancel pending tasks, with full native stage fences retained.
`queue_backpressure_events` counts Full polls, not failed requests; elapsed metrics
include scheduling and waits and are not CPU or mutex-held time. New resource
profile digests refuse old r1/r2 cookies. Local honest service controls do not grant
WAN/SLA or anonymous Sybil fairness. The ordinary CLI can also select the explicit
[revision11 factor model](../protocol/pon-nakamoto-v1/details/NATIVE_INTEGER_FACTOR_CANDIDATE_V2.md);
old task/model/actor contexts do not silently select it.

## Module-specific threat and residual work

Fallback masking missing modules, startup before recovery, task starvation and authority conflation.

The exact private-development request path is integrated, but same-operator allowlisted peers are not independent public operators. Open discovery/gossip, encrypted transport, ordinary Hepta entry, persistent miner/mempool scheduling and signed production owner resources are not claimed.

## Current source and verification

- [`trillionnium/crates/trnm-pon-node/src/main.rs`](../../trillionnium/crates/trnm-pon-node/src/main.rs).
- [`trillionnium/crates/trnm-pon-node/src/ingress.rs`](../../trillionnium/crates/trnm-pon-node/src/ingress.rs).
- [`trillionnium/crates/trnm-pon-node/src/store.rs`](../../trillionnium/crates/trnm-pon-node/src/store.rs).
- [`formal/pon-nakamoto-v1/native_execution.py`](../../formal/pon-nakamoto-v1/native_execution.py).
- [`formal/pon-nakamoto-v1/ledger.py`](../../formal/pon-nakamoto-v1/ledger.py).
- [`formal/pon-nakamoto-v1/bounded_process.py`](../../formal/pon-nakamoto-v1/bounded_process.py).

No test binding or local campaign grants independent acceptance, ordinary Hepta execution or production activation. Preserve the exact source, profile and environment of every outcome.

## Executed evidence and scope

[Responsibility-level evidence navigation](README.md#responsibility-and-evidence) reads
measured commits from immutable receipts. The module's entries in
[module-maturity-v1.json](../../config/pon/module-maturity-v1.json) identify actual callable
owners, controlled entrypoints, backends, persistence and exact observed test selectors.
Run `python3 scripts/ci/report_module_evidence.py --module M15` from the repository
root to see subject-byte and complete recorded-runtime matches separately, plus scenarios
not observed in each package. A byte match is not a new test run or product acceptance.
Historical v1/v3/v4 results are never repinned. The sole plan selects further work.

## Native cache / receiver continuation

The exact continuation is specified in [native execution](../protocol/pon-nakamoto-v1/details/EXECUTION_PARALLEL.md), [admission](../protocol/pon-nakamoto-v1/details/ADMISSION_SECURITY.md) and [client/recovery](../protocol/pon-nakamoto-v1/details/NETWORK_CLIENT.md). It does not promote native persistence, independent acceptance or public-network capacity. Exact additional counterexamples:

- `formal/pon-nakamoto-v1/test_native_session.py::SessionBoundaryTests.test_multiple_selected_backends_reject_before_starting_cache`.
- `formal/pon-nakamoto-v1/test_native_session.py::SessionBoundaryTests.test_changed_selected_binary_cannot_reuse_previous_success`.

## Native development continuation and remaining scope

The M15 composition binary `trnm-pon-node` starts/recover/admit/mine/export/sync/confirm/serve without Python fallback. It reuses M00/M01/M05/M06 and owns one fresh native branch namespace. `push` and `sync` can use the same durable signed client outbox; `serve` can use the matching allowlisted signed private-development ingress or explicitly selected resource-ticket public development intake. The separately versioned V3 public contract adds signed transaction bundles and a read-only pool snapshot. Its optional `serve --mine` shares one native owner with the wall-clock miner and persistent local pool. Authentication options are command-scoped and do not turn local status/mining commands into key consumers. Open peer discovery/gossip, confidentiality, sustained hostile-WAN service and ordinary Hepta/resource integration remain unaccepted.

The current callable mappings remain in `config/pon/module-maturity-v1.json`.
Exact native entry, storage and work behavior is specified by N3 in NETWORK_CLIENT,
the native continuation in STATE_RECOVERY and the prepared-producer section in WORK_PROFILE.
No historical receipt is relabelled as executing this source.

## Explicit evaluation-profile selection

The ordinary `trnm-pon-node` development CLI accepts `--evaluation-policy closed-round-all-eligible-min-v1` on a fresh namespace. Omission keeps revision3;
unknown values reject. The network, parameters, plan and genesis are bound before store
open. A node never opens an old namespace under successor semantics, and cross-network
packets reject. The actual CLI regression also mines a heavier fork, reopens storage and
replays the original signed candidate under the surviving state.

Selector: `formal/pon-nakamoto-v1/test_evaluation_round.py::ClosedRoundTests.test_ordinary_native_cli_uses_successor_and_reopens_only_its_namespace`.
This is a bounded native development path, not authenticated public P2P, ordinary Hepta
resource ownership or production activation.

## Native bounded queued owner continuation

The existing Node SQLite owner now provides explicitly enabled local PNX1 queue/group
submission, M05 typed metadata, exact M06 prefix preview, fenced mining batches and
branch-relative reconciliation. Queue success is not execution, inclusion, confirmation
or external permission. All pending and archived rows/bytes plus local removal digests
are bounded; local removal history is not rewound by reorg. See the exact interfaces,
limits and actual native selectors in
[LOCAL_MEMPOOL_LIFECYCLE](../protocol/pon-nakamoto-v1/details/LOCAL_MEMPOOL_LIFECYCLE.md).
The explicit V2 local profile adds admission-triggered wholly terminal cache eviction;
operator removal digests remain monotonic and separately finite. See
[LOCAL_MEMPOOL_CACHE_V2](../protocol/pon-nakamoto-v1/details/LOCAL_MEMPOOL_CACHE_V2.md).
Public-v2 transport operations and acceptance flags are unchanged by this local owner.

For public V3 `serve --mine`, `--mining-seconds N` optionally selects1..259200 seconds no greater than service `--seconds`; omission uses the service budget. This choice is checked before store creation. Successful miner runtime or block-limit completion leaves ingress serving retained Head/History until the service budget ends; mining failure or service completion stops the shared runtime. Native stages remain nonpreemptive, so neither budget guarantees an exact stop or successful peer catch-up.

The integrated current entrypoints, cooperative stop/failure behavior and actual tests
are [CONTINUOUS_MINING_V1](../protocol/pon-nakamoto-v1/details/CONTINUOUS_MINING_V1.md)
and [PUBLIC_POOL_INTAKE_V3](../protocol/pon-nakamoto-v1/details/PUBLIC_POOL_INTAKE_V3.md).
The executable tests submit a guest signed funding/renewal bundle, actually mine it,
and sync another full native owner. This finite local behavior is not independent
WAN acceptance or a durable service guarantee.

The explicitly configured `serve --peers FILE` composition uses the same owner
for paid pinned Head/History following, full native packet verification and
observed-work branch selection; see
[PINNED_PEER_POLLING](../protocol/pon-nakamoto-v1/details/PINNED_PEER_POLLING.md).
It retains a fixed target/cursor through network errors, and allows one labelled
genesis fallback for an initial signed cursor refusal. Open discovery/gossip,
eclipse resistance, public fairness and independent operators remain unaccepted.
Renewable mining supports the separate
[V4 overlap contract](../protocol/pon-nakamoto-v1/details/QUALIFIED_TASK_LIFECYCLE_V4.md),
without changing V3 signed heights or inventing source/requester authorization.


The explicit [operator actor context](../protocol/pon-nakamoto-v1/details/OPERATOR_ACTORS_V1.md)
uses the existing module owner and fresh public descriptor/signature-bound N/P/G.
This changes development bootstrap custody and role pins only; native admission,
execution and confirmation remain required, and no independent/public flag is accepted.
The separate explicit revision10 [checkpoint tile task selector](../protocol/pon-nakamoto-v1/details/CHECKPOINT_TILE_TASK_V1.md)
adds full original material replay before store creation and on reopen, with a fresh
operator/policy N/P/G and unchanged source/lease wire codecs. Config policy construction
alone performs no file replay; only Maintenance/output0 is selected and all public,
model-quality, useful-contribution and hardness acceptances remain false.

## Checked derived state-root calculation

The existing native SQLite owner may retain one optional M06-derived commitment,
fenced by active block, generation and state slot. Actual KV/canonical values remain
the input on every read; preview, mining and admission do not publish speculative
successors. Direct activation publishes only after its database COMMIT; reorganization
and recovery discard unrelated context. Historical reconstruction checks actual delta
before bytes and every intermediate root. Exceeding the optional cache budget takes
the complete-root path without reducing protocol state limits.

The interfaces, software accounting, fallback/error rules and exact parity controls
are specified in
[DERIVED_STATE_COMMITMENT](../protocol/pon-nakamoto-v1/details/DERIVED_STATE_COMMITMENT.md).
This calculation changes no durable owner, state namespace or signed domain. A new
performance result requires its own committed source and binary binding.

## Bounded local evaluation observations

The [complete-history V1 observer](../protocol/pon-nakamoto-v1/details/EVALUATION_CONFIRMED_OBSERVATION_V1.md)
and [round-window V2 observer](../protocol/pon-nakamoto-v1/details/EVALUATION_CONFIRMED_ROUND_OBSERVATION_V2.md)
have explicit CLI queries and private native result construction. They check actual
membership, branch/generation, frozen evaluation records and installed confirmation
policy. V1 refuses histories exceeding4096 blocks; V2 can assess a complete bounded
round window later in history while explicitly leaving its predecessor and earlier
global confirmation/clock history unevaluated. Original State/root ownership remains
necessary. These unsigned local observations grant no transaction, execution,
adoption, reward, independent evaluator or public-network authority.

The optional [sync evaluation query](../protocol/pon-nakamoto-v1/details/SYNC_EVALUATION_OBSERVATION_V1.md)
performs the bounded V2 observation on that same exclusive Node only after complete
public V2/V3 synchronization. Partial sync never produces a phase result. A later
observation refusal reports the completed sync fact without rewinding admitted blocks
or printing a success phase. Omission preserves the original sync result. This local
composition adds no remote evaluation operation or economic permission.

Its retirement fixture uses explicit64+64+64+49 page-budget commands and durable
cursor/ancestry checks, with an original120-second listener owned and joined by each
phase. It preserves all241 real successor blocks and the final archive refusal,
without certifying uninterrupted241-block delivery within one listener lease. The
historical single-transfer timeout remains outside this resumed-fixture scope.

## Typed owner failures and explicit continuity

[Typed error identity](../protocol/pon-nakamoto-v1/details/INTERNAL_ERROR_IDENTITY.md) preserves display/wire text while separating stable local cause from signed remote refusal. [Continuity v1](../protocol/pon-nakamoto-v1/details/CONTINUITY_V1.md) adds an explicit maintenance choice under a fresh context; all local owner/revocation gates remain. Neither change authorizes a deployment.

## Bounded history projection and same-operation prefix execution

[History resource bounds](../protocol/pon-nakamoto-v1/details/HISTORY_STATE_RESOURCE_BOUNDS_V1.md)
use at most64 ancestry rows per SQL statement for complete clock and confirmation
scans. Every header and recorded parent remains checked; cancellation runs between
queries and the final active identity is rechecked. The scan remains linear in
history, and evaluation observers retain their own explicit work/round boundaries.
[Pool prefix execution](../protocol/pon-nakamoto-v1/details/LOCAL_MEMPOOL_LIFECYCLE.md#same-block-incremental-m06-prefix)
reuses one checked original parent and only same-block scratch within an operation.
Neither optimization changes wire results, durable single-writer ownership,
reorganization rules or permission for retained groups.

Retained local header/KV/reorg/replay integrity failures now preserve their concrete
local origin and typed source through polling and recovery. Matching remote text,
ordinary unknown locators, callback cancellation and clock deferral cannot acquire
owner-stop authority. The history growth example separately checks a complete
reference root and records actual derived-cache methods/software charges after read
and confirmation operations; these observations do not measure concurrent lock cost,
process RSS or persistent authenticated state performance.

## Local capacity and client recovery identities

`capacity-observe` is a local CLI/Node observation with its own JSON schema. It
retains ordinary Node open/recovery behavior, rejects incompatible task profiles
before opening, checks actual committed KV/root and final generation/slot, and
does not extend peer Head or signed responses. The [continuity contract](../protocol/pon-nakamoto-v1/details/CONTINUITY_V1.md)
defines every reported obligation and the remaining permanent-account boundary.

Public V3 client phases use `PublicClientStage` for recovery and failed-phase
accounting. The `failed_stage` JSON labels and null remain the same; unknown
diagnostic labels never acquire native phase identity. This explicitly refines
the public Rust field type and leaves signed wire messages and retry/deadline
limits unchanged; see [internal errors](../protocol/pon-nakamoto-v1/details/INTERNAL_ERROR_IDENTITY.md).

## Research account storage and bounded History pages

`account_archive_prototype` owns a separate SQLite namespace and explicit caller
context; it is not opened or consulted by ordinary Node startup, admission,
activation or recovery. Complete before/after State projections, real signed
Node transitions and synthetic large-space fixtures are distinguished in
[its contract](../protocol/pon-nakamoto-v1/details/ACCOUNT_ARCHIVE_PROTOTYPE_V1.md).

The same explicit research module exposes full-parent state-witness construction
and checked execution under fresh observation/commitment domains. This combines
account proofs with all non-account rows for actual mandatory execution and checks
prologue/final roots and aggregate funds against full State. It adds no startup
option, admission shortcut, archive activation or new stored Node root. Existing
Settings, branch selection and durable single-writer boundaries remain required.

Ordinary History page service retains its existing input, output, wire, errors
and cancellation order while using bounded actual-record batches and at most16
Hash candidates. The full H-edge path remains verified. Native whole-call timing
and exported complete packet frames are specified in
[resource bounds](../protocol/pon-nakamoto-v1/details/HISTORY_STATE_RESOURCE_BOUNDS_V1.md).
The Hash payload counter is not an RSS or physical SQL allocation measurement.

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

## Explicit native authenticated storage selection

Actual local Node commands accept `--state-backend authenticated-v1` for the fresh
`native-authenticated-branch-schema-v1` implementation. No option, or explicit
`legacy-v2`, selects the original backend. Wrong schema selection fails before
database mutation. Unknown choices and options on unrelated commands fail before
opening a store; external owner configuration combined with the new backend is
explicitly unsupported and fails before loading that configuration.

The selected backend participates in real status/recovery, mining, submission,
confirmation, pool, sync and serving paths. It stores authenticated account nodes
with native branch data in one transaction and exposes a checked AAM1 account query
from that same database. The CLI test mines a real maintenance block, cold reopens
the new namespace and binds capacity observations to its exact active state.

`Node::migrate_to_authenticated_state` is a separate explicit local API on an
already owned legacy Node. It preserves the source and all retained local facts,
validates inactive branches and pending reorganization, and publishes only a fully
checked fresh target. It is not an implicit startup conversion. The original
account/archive research APIs keep their separate namespaces and meanings.

See [native authenticated storage](../protocol/pon-nakamoto-v1/details/NATIVE_AUTHENTICATED_STORAGE_V1.md)
for publication, migration and refusal rules. Complete-State work, non-account
scans, global physical storage responsibility, external owner migration and public
proof availability remain separate constraints; the option grants no release or
production activation.


## 本轮来源绑定（Round 10）

本节补充 `M15.ExplicitBackend` 的实际接口来源绑定。
[原生认证存储](../protocol/pon-nakamoto-v1/details/NATIVE_AUTHENTICATED_STORAGE_V1.md)
的账户查询先检查请求维度，再读取 snapshot／重放状态；取消贯穿原生状态准备和
AAM1 构造，并保留实际取消错误。回调改变已观察存储时须拒绝和回滚相关事务，成功
重试仍与真实节点字节绑定，不从缓存中的旧成功结果推断权限。

借用账户解码、缓存 SQL statement 与单次 leaf 解码保留完整原始 grammar、实际行读回、
错误和 progress 检查。组件成本测试 `native_complete_account_verification_cost` 在普通
debug suite 中 ignored，必须以实际 `--release --exact --ignored` 执行记录其范围；
完整容量专项具有相同的实际 release 执行要求。组件观测不等于整 Node 验块、锁等待、
磁盘或公开 proof 服务成本，剩余边界见
[状态与历史资源边界](../protocol/pon-nakamoto-v1/details/HISTORY_STATE_RESOURCE_BOUNDS_V1.md)。

以下仅为实际函数和测试定义绑定；后端显式选择、迁移、普通产品入口与验收继续分离，
不写入当前 CI 通过或部署资格，`independent_accepted=false`。

对应完整回归 selector：

- `trillionnium/crates/trnm-pon-node/src/native_account_query_tests.rs::native_account_query_dimensions_precede_any_snapshot_or_state_read`.
- `trillionnium/crates/trnm-pon-node/src/native_account_query_tests.rs::native_account_query_cancellation_preserves_error_snapshot_and_exact_retry_bytes`.
- `trillionnium/crates/trnm-pon-node/src/native_account_query_tests.rs::native_account_query_reads_real_nodes_and_rolls_back_callback_mutations`.
- `trillionnium/crates/trnm-pon-node/src/account_archive_prototype/native_primitive_tests.rs::native_leaf_decoder_preserves_complete_original_grammar`.
- `trillionnium/crates/trnm-pon-node/src/account_archive_prototype/native_primitive_tests.rs::native_borrowed_accounts_preserve_arrays_numbers_and_field_failures`.
- `trillionnium/crates/trnm-pon-node/src/account_archive_prototype/native_primitive_tests.rs::native_cached_node_statements_read_actual_rows_and_trigger_effects`.
- `trillionnium/crates/trnm-pon-node/src/account_archive_prototype/native_primitive_tests.rs::native_complete_account_checks_keep_branch_bytes_errors_and_progress`.
- `trillionnium/crates/trnm-pon-node/src/account_archive_prototype/native_primitive_tests.rs::native_complete_account_verification_cost`.
