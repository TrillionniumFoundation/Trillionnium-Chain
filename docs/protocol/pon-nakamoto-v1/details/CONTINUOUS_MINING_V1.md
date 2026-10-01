# Wall-clock mining under the native Node owner

This development API is `trnm-pon-node::mining::run_pool_mining`. The existing
M15 `Node` remains the SQLite, branch and activation owner. The M05 typed queue
and M06 execution preview are used by the [native local pool](LOCAL_MEMPOOL_LIFECYCLE.md).
No additional global scheduler or execution ledger is introduced. Public deployment,
work-class hardness and model efficacy remain unqualified.

## Inputs and finite limits

`MiningConfig` carries `miner`, `material`, `max_transactions`,
`max_transaction_bytes`, `search_attempts`, `pace`, `runtime`, `max_blocks`.
The miner must exactly equal the immutable local pool policy's `preview_miner`.
Limits are1..256 transactions,159..524288 transaction bytes,1..4096 work attempts
per search,1..60 seconds of minimum pause after a completed attempt, positive
runtime no greater than72 hours, and1..100000 activated blocks. These are upper
engineering limits, not a72-hour measurement or a service guarantee.

`MiningMaterial::Registered` supplies exact16384-byte model and input artifacts.
Each attempt derives the actual matrices and finds its source statement in the
parent state. For renewable V2/V3/V4 the owner reads the current slot's canonical
684-byte signed statement and exact lease, checks the native eligible-task
relation and independently invokes cryptographic material/source admission. For
signed-task-dev-v1 it reads the canonical652-byte registration and its genesis
context. Source bytes are never synthesized or automatically signed. A queued
registration/renewal cannot authorize its own containing block. The next block
uses the actually admitted successor, which allows an atomic V3 renewal to keep
the same material usable without retaining an obsolete bootstrap signature.
[V4](QUALIFIED_TASK_LIFECYCLE_V4.md) separately permits inclusion during the signed
overlap. V3 keeps its exact containing-height restriction; local preview reserves
no height for either profile.

`MiningMaterial::LegacyDevelopment` requires the explicit historical task profile.
The CLI `--task-bootstrap` selects the fixed maintenance material; it does not
extend its lease or credit a useful output. A genuine source/requester must submit
any renewal. The task window and bounded retained-pool policy can stop a campaign
before its requested runtime or block limit; neither is an indefinite liveness claim.

## Actual sequence and ownership

1. Check the monotonic runtime/stop budget and wait for the configured pause.
2. Acquire the shared Node owner without indefinitely blocking shutdown. Read the
   actual active parent/generation and local wall-clock seconds. If the parent
   timestamp is not earlier than the current clock, wait for the real clock.
3. Reconcile and select complete retained queue groups with actual M05 admission
   and M06 execution. Bind the exact parent/generation, pool context and miner.
4. Under the owner, verify current task/source/material, execute the candidate
   state, bind transaction/state/receipt roots, target and task, and prepare the
   actual arithmetic work. This creates no block or pool-consumption certificate.
5. Release the Node/SQLite lock before proof search. Check stop/deadline before
   each nonce attempt. A single transcript calculation is not preemptible; search
   does not hold a lock that prevents public status or new pool submission.
6. On a winning proof, reacquire the owner cooperatively and check the remaining
   budget, actual parent/generation and exact retained batch. A changed active
   branch discards the candidate as `stale-search`, without storing/activating it.
   Check stop/deadline again after the nonpreemptive native batch revalidation.
7. Native `admit` completely verifies work and execution; `activate_observed`
   applies the existing branch policy using the actual wall clock. Reconcile the
   local pool against that actual branch, release the owner and emit diagnostics.

State preparation, a single transcript, native admission, activation and SQLite
commit remain nonpreemptive. A requested duration cannot interrupt those operations
and is not a strict deadline. Long state preparation/commit and public workers
still share the single write owner. Public saturation, processing fairness, signed
transaction authority, fork validity and confirmation policy are separate issues.

## Diagnostics and errors

`native-wall-pool-mining-event-v1` records the observed wall time, parent/generation,
height, optional actual block id, selected transaction count/bytes, completed proof
trials, make/admit/activate/reconcile elapsed nanoseconds and failure. Kinds include
`activated`, `search-exhausted`, `search-stopped`, `stopped-before-admission`,
`stale-search`, `failed`. `make_ns` includes preparation and proof search; it is
elapsed time including scheduling, not CPU cycles. Search errors before a proof
completes do not invent a partial trial count. Selected transactions in a failed
or discarded candidate are not counted as included.

The report records attempted/exhausted/stale searches, actually activated blocks,
transactions in those actual blocks, observed work trials, elapsed duration and
`stop_reason` (`block-limit`, `runtime`, `stop-request`). Diagnostics are unsigned
local observations. Exact packets and state remain in the native durable store;
confirmation requires the existing native chain observation and depth/work policy.
A failed diagnostic sink stops future work but cannot rewind a committed block.
Events distinguish `admitted` and `activated`, retain the actual block id as soon
as admission succeeds, and identify `failure_stage`. A postactivation cache
reconciliation failure emits `failed` with the already activated block and stops
future mining; it does not erase the durable inclusion fact. Reopen and operator
reconciliation can recover the stale cache. The synchronous observation sink and
CLI stdout flush have no enforced deadline; a blocked sink can delay shutdown.
`public_network_ready`, `production_activation` remain false.

Important refusals include `MINING_LIMITS`, `POOL_MINER`, `MINING_OWNER`,
`EXPLICIT_TASK_REQUIRED`, `SIGNED_TASK_PROFILE_REQUIRED`, source/material/lease
admission errors, pool batch/context errors, and ordinary native storage/branch
errors. Exhausted search budget is recorded and retried after the configured pause;
invalid task material or execution is a visible failure, without fallback mining.

## Additive elapsed observations

Events and normally returned reports retain existing make/admit/activate/reconcile
fields and add `initial_owner_wait_ns`, `pool_batch_ns`,
`pre_search_batch_validation_ns`, `prepare_ns`, `search_ns`,
`post_search_owner_wait_ns` and `post_search_batch_validation_ns`. Reports aggregate
these elapsed stages; existing event stage aggregates are also returned. `make_ns`
includes preparation and search and must not be added again to those two sub-stages.
Owner-wait fields measure polling acquisition attempts and their retry sleeps, not
synchronous native execution. Actual run time also includes pace, initial metadata
reads, context fences, observer calls and other uninstrumented overhead. Aggregate
wait may include unsuccessful iterations with no candidate event, such as a held
owner through runtime expiry or waiting for the next wall-clock timestamp.

Pool-batch and pre-search validation failures emit scoped failed events retaining
completed elapsed stages. Post-search revalidation retains its time on failure;
an already activated block remains reported if later reconciliation fails. Errors
return an error rather than a successful aggregate report. These are local elapsed
observations, not process CPU time, an adversarial cost lower bound, service fairness,
a throughput guarantee or hard deadline. Synchronous native stages remain
nonpreemptive. No signature, execution, task or chain validation is skipped.
Reconciliation continues to re-execute growing complete prefixes, and observed
activation continues to check retained timestamps through the ancestor history.
The binding optimization and added timers remove neither cost. A future history
summary must preserve branch identity and check the caller's actual observed time;
there is no cached reusable clock approval in this change.

## CLI and acceptance scope

`pool-submit --transactions FILE --pool-policy FILE` admits one canonical lowercase
hex bundle of1..16 signed PNX1 transactions into the explicitly configured local
pool. It creates no block. `pool-status` reads the local pool's branch classifications;
these are queued/sequence-consumed/expired/blocked facts rather than finality.
`mine-loop --pool-policy FILE --seconds N --blocks N --pace-ms N` runs the above
wall-clock path. Select the matching task/evaluation/model profiles and exact
`--genesis-time`; signed mining requires explicit `--task-bootstrap` or both
`--task-model` and `--task-input`. `--logical-now` is refused for this command.
The policy file is opened with no-follow and must be a regular, singly linked,
non-group/world-writable bounded JSON file. A different stored policy/context
refuses rather than resetting or importing queue history.

Local CLI operations require the existing exclusive Node lock; a separate CLI
cannot alter a running owner's queue. A shared public service must use the same
`Arc<Mutex<Node>>` and a separately versioned, explicitly selected bounded
transaction protocol. Guest identities must not enable, reset, prune or change
operator policy. Standalone `mine-loop` provides neither gossip nor automatic WAN
propagation. The explicit V3 CLI composition is
`serve --admission-profile public-protected-development-v3 --public-development-network
--pool-policy FILE --mine --task-bootstrap`. Both service and optional miner share
one Node, owner mutex and stop signal. Optional `--mining-seconds N` selects the miner's
runtime independently of service `--seconds`:1..259200 seconds and no greater than the
service budget, checked before creating a store. Omission retains the service runtime.
Service completion or a mining failure stops and joins both workers. A successful miner
runtime or block-limit completion leaves ingress available until the service budget
expires, so other nodes can request the final retained blocks. Native stages remain
nonpreemptive; the interval is an opportunity for catch-up, not a guarantee of it or an
exact stopping deadline. Without `--mine`, mining-only options
refuse. V2 refuses these V3-specific options. `pool-push` and
`pool-status-remote` use the separate [public pool contract](PUBLIC_POOL_INTAKE_V3.md).

Actual tests in `tests/pool_mining.rs` execute signed funding dependencies and
native proofs, check exact retained raw bundles and durable reopen, renew the
sole task with one tag22 and mine the next block using its new source signature,
exercise stop/runtime and invalid material without consuming queued transactions,
and invoke the real CLI including its logical-clock refusal. Existing native packet,
task and fork regressions must also pass after the preparation refactor. These finite
local tests do not replace sustained WAN, state-growth, attack-budget, independent
operator or genuine task/model acceptance.

`tests/mining_service_budget.rs` additionally waits for actual runtime-ended mining,
then exercises paid Head/History and a fresh full-native follower, checks complete state,
sender nonce and installed confirmation, and verifies natural service shutdown. Invalid,
unused and non-V3 `--mining-seconds` choices reject before a namespace is created.
