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
