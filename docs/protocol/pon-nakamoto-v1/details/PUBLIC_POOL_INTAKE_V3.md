# Public development intake V3 and the native local pool

This is a fresh, explicitly selected development profile. It connects paid guest
transport requests to the Node's actual persistent pool. It does not certify public
readiness, independence, fair access under saturation, exact transaction inclusion,
confirmation, model efficacy, or economic work. V2 retains its separate signed domains
and one-hour service bound. Both modules bind the current derived ancestry index
with at most1024 SQL lookups in a fresh resource-policy digest; see
[NATIVE_ANCESTRY_INDEX](NATIVE_ANCESTRY_INDEX.md). V3 resource revision r5 retains the r4 paid body/output partitions, disconnect
fences and paid enqueue waits, and retains bounded pre-Challenge/pre-Ready waits
inside the same connections while original resource capacity is unavailable. It adds
local measured mutation CPU reservation/accounting under the r5 digest. V2 retains its
own resource digest; these changes do not silently alter its contract. Security
fixes still require review of both modules.

An operator can select the bounded local
[request resource observer](PUBLIC_REQUEST_RESOURCE_OBSERVATION.md) to capture
actual worker-thread CPU intervals and application-frame byte progress. This
optional API preserves the selected signed r5 policy and native request rules; its nested
CPU intervals and stream bytes are not energy or physical network measurements.

## Exact boundary

`ingress::public_v3::serve_public_protected_v3` accepts the **existing**
`Arc<Mutex<Node>>` and `Arc<AtomicBool>`. The operator enables and fixes the local
pool before serving. The continuous miner and the public worker share that owner
and stop signal. The reactor does not create a second Node, a second database
owner, another mempool, or a miner. Shutdown requests stop and joins workers; it
cannot forcibly interrupt an already executing native stage.

The explicit finite service lifetime is greater than zero and at most 72 hours.
That is an operator-selected maximum, not evidence of a 72-hour run. Per-connection
phase deadlines, 64 active connections, the 8 MiB paid-body budget, 32 MiB output
budget, two native/proof workers with a two-entry queue, and one read worker with
a two-entry queue remain bounded. Scalar responses reserve 16 KiB capacity before
serialization; history retains its separate larger limit. Native stages are
nonpreemptive: the 10-second work deadline bounds admission/lock waiting and socket
phases; it is not a hard interruption guarantee for a running M06 preview. A
successful durable pool reservation can outlive the requesting socket or response.

Resource revision r5 binds these limits and finite readiness/enqueue behavior in `PublicPolicy::id()`. It reserves
131,072 bytes of the existing 8 MiB body pool and 524,288 bytes of the existing
32 MiB output pool for Head/PoolStatus control responses. Mutation body permits
and non-control output permits cannot exhaust these reserves.
After a valid ticket and caller signature, before sending Ready, the server grants
at most eight mutation requests and eight read requests. Each grant remains held
through body collection, queue/work execution and output cleanup. Rotating caller
keys cannot increase these global lane limits. Eight challenge tokens are reserved
from the existing global bucket for reads. These reservations introduce no extra
worker, queue, Node owner, ledger authorization or retained guest identity.

The r5 receiver retains pre-Challenge and pre-Ready waiters in the same at-most64
Connections. `WaitChallenge` holds a complete validated fixed Hello;
`WaitGrant` holds its immutable Cookie after the original complete Solution
context/expiry, ticket, strict caller signature and **single** spent reservation.
Four logical FIFO heads split Challenge/read, Challenge/mutation, Grant/read and
Grant/mutation. A checked readiness ordinal and four head IDs are obtained by
scanning the existing bounded Connection map; no pending socket collection,
canonical body queue, worker, channel capacity, Node owner or durable guest identity
is added. Small stage/scalar metadata is bounded memory, not a zero-allocation or
hard RSS assertion. Incomplete prefixes and unsolved earlier accepts have no FIFO
order and cannot block an already validated waiter.

`WaitChallenge` keeps the original accept-based2-second Hello and30-second total
deadlines. No cookie or token is held before issuance. Only the eligible FIFO head
uses the existing global challenge bucket; mutation cannot consume its last eight
read tokens. One Cookie is then issued with the original signed lifetime interval.
After Challenge output the Solution deadline remains the original absolute Cookie
expiry. `WaitGrant` never renews that expiry or total deadline and never repeats
Solution signature/ticket/spent checks on polling. The original expiry is checked
again before granting Ready. Temporary fullness is a typed waiting result; a
poisoned resource pool remains an error. A waiter takes both the original lane and
body permits or rolls back a temporary lane immediately, with no body Vec or Task
allocated before Ready. Strict within-lane FIFO can intentionally block a smaller
body behind a larger head; read reservation remains separate.

EOF, original expiry and stop close a waiter. Unissued Challenge consumes no token;
a previously issued token is not refunded. A paid waiter's spent id remains
single-use until original expiry cleanup and is never refunded or live-evicted.
Ready2s, Body5s, body-complete Work10s, Output5s and accept-based Total30s are the
existing limits. Client frame reads also keep their original absolute deadlines:
`read_exact_deadline` sets each socket timeout from the same remaining duration,
not a fresh5-second budget. Original nonpreemptive native stages can still cross
an admission deadline. Eight slow granted bodies can outlive another Cookie2s;
64 incomplete or unpaid Connections can still deny a new caller. This change is
finite readiness scheduling, not a guarantee that any honest request completes.

`pending_challenge_*` and `pending_grant_*` record entries, grants, closures,
wait elapsed and peak pending counts. `spent_reservations` counts each successful
original single-use reservation, including a request that later waits or expires. Each entry ends in one grant or closure;
polling does not count as a new failed request. Pending terminal phases remain
Hello/Solution, never Body/Work. A pending request has no Task or full-work CPU;
CPU remains absent rather than a fabricated zero. Wait elapsed is not CPU. Closed
shutdown requires zero original lane/body/output reservations and actual worker
joins. The legacy r3 refusal counters are retained fields; r5 resource fullness
waits and can expire instead of immediately incrementing a refusal counter.

A full worker channel retains its canonical Task in `Stage::Enqueue` on the same
bounded Connection, body and lane permit. The reactor attempts pending enqueue in
connection-ID order without adding workers or channel entries. It preserves the
original body-ready10-second work and accept-based30-second total deadlines;
polling never renews either deadline. EOF is checked before dispatch, and dropping
a pending connection releases its task/permits. This is finite local scheduling,
not FIFO completion or a fairness guarantee under identity churn.

The reactor cancels an Enqueue/Await task on disconnect, expiry or shutdown. Workers check
its cancellation and original deadline when taking a queued task, while waiting
for the owner, and between context checking, complete work verification and native
admission. An already running transcript, M06 preview or SQLite operation remains
nonpreemptive; cancellation cannot erase a committed fact. A fresh profile digest
is mandatory: correctly signed r1/r2/r3/r4 cookies and old client pins refuse r5, without fallback.
For bits8/lifetime2000ms the digest is
`6f7b5a6018a8f78044c932b9559af21a3a02808c2773447ba96de0935816a41e`;
for default bits16/lifetime2000ms it is `bcc5e234fe15a83f3e1921d810acf1e64f8c53350d5c211c9f879c9544854a48`.
The V3 magic, cookie/caller signature domains and canonical request/response wires
remain unchanged. The initial shared connection cap and pre-ticket processing can
still be exhausted; lane isolation does not establish anonymous honest fairness.

The retained r4 client contract keeps both TCP halves open until receiving the response.
An EOF while awaiting native work cancels the task; TCP does not distinguish a
peer's full close from `shutdown(Write)` at this point. A client that half-closes
its write side after sending a body therefore forfeits the response. Ordinary V3
clients already keep both halves open. The signed localhost control preserves a
half-closed client's read side, observes cancellation without work/admission, then
submits the identical valid packet normally through complete native verification.

V3 uses `PPH3` and `PPS3`, `public-protected-development-v3`, and fresh signed cookie,
caller, ticket, body, response, peer-binding and profile domains. There is no
version negotiation or fallback. V2/V3 cross-version requests are rejected before
paid request-body allocation. Every operation, including reads, must pay its own
connection-local resource ticket and sign the exact cookie/nonce. The random guest
transport identity confers no ledger key, source authorization, model ownership,
chain work, voting power, or reward claim. Guest identities/replay operations are
not stored durably; **valid signed transaction facts** are stored in the operator's
actual pool.

## Local paid mutation CPU reserve

Resource revision r5 adds one volatile account to each PublicServer epoch, shared
by its two mutation workers and all caller identities. It starts with two CPU
seconds of credit, refills at250 million CPU nanoseconds per wall second up to
a ceiling reduced by outstanding start reservations, and reserves100 million CPU nanoseconds before each actual mutation
dispatch. These are explicit local service parameters, committed as numeric
fields in the policy digest. They are not a ticket difficulty, attacker cost
floor, hardware-independent price or hardness calibration. Reads use their
existing separate worker and permits and do not debit this account.

Linux uses the existing checked thread clock. Unsupported/unavailable clocks,
invalid subtraction and poisoned accounting refuse future mutations with
`PUBLIC_MUTATION_CPU_UNAVAILABLE`; insufficient credit or the two in-flight
limit returns `PUBLIC_MUTATION_CPU_BUDGET`. Refusal occurs after the original
paid protocol and canonical body/queue checks but before starting native
dispatch or full proof verification. No new queue, worker, Node owner, State
cache or durable caller row is added. Key rotation cannot reset the account.
Restart begins a new explicit volatile service epoch; this is not a host-global
CPU quota across listeners, private ingress, miner threads or service restarts.

The outer actual worker-thread dispatch interval is charged exactly once. When
Submit executes full work verification, its measured subset is reported
separately and subtracted from the outer interval to report the remaining
native dispatch CPU. The full-work subset and remainder sum to charged CPU;
the optional observer's nested full-work and total fields still must not be
added. Actual failed proofs and native refusals consume their measured CPU.
Context/signature/State checks inside dispatch are included; reactor parsing,
caller/ticket authentication, response signing/output and other threads are
excluded. A completed mutation's accounting failure disables future starts
without replacing its actual native outcome or signed success. No completed
fact is undone, and no failed measurement is refunded as zero.

A call may exceed its start reservation. Its actual CPU becomes debt, which
blocks new starts until refill repays it. At most two existing calls may still
be executing, because the original two mutation workers are unchanged. This
bounds the number of nonpreemptive overshoots, not each call's CPU or duration.
SQLite/M06 execution, lock occupancy and read latency remain nonpreemptive;
the account does not promise a hard process CPU limit, honest Submit fairness,
Head SLA or public readiness. A dropped running permit disables further starts
rather than silently refunding an unknown charge. Budget exhaustion can deny
honest mutation callers as well as expensive invalid work.

`mutation_cpu_*` counters expose reservations, refusals, unavailable clocks,
actual charged CPU and shutdown credit/debt/in-flight status.
`mutation_full_work_cpu_ns` and `mutation_dispatch_excluding_work_cpu_ns` are
disjoint aggregates. They do not identify individual remote attackers or
establish physical host CPU attribution. The source control checks actual
signed native admission, post-success clock failure, read availability under
controlled debt, rotated callers, debt/refill arithmetic and missing clocks.
Fresh runtime evidence is required for any new source or resource digest;
historical r4 loopback and Tailnet results retain their original scope.

## Closed operations

| Op | Canonical request | Owner action |
| --- | --- | --- |
| 1 | `submit` with the existing block packet hex | Existing real work verification and native block admission |
| 2 | `head` | Existing bounded native head metadata |
| 3 | `history` with tip/after | Existing bounded native history page |
| 4 | `pool_submit_bundle` with `pool_context`, `transactions` | Exact signed PNX1 bytes through Node M05/M06 and durable reservation |
| 5 | `pool_status` | Read-only native pool snapshot, scalar public projection |

Op 4 requires an exact 64-character lowercase hex `pool_context` matching the
operator's stored pool policy under the same Node mutex. This pins existing
configuration; it does not let the guest select the miner or alter limits. The
canonical body scanner checks **before** serde vector allocation: 1–16 members,
each 159–2048 decoded bytes, no escapes or non-lowercase hex, at most 32,768 total
decoded bytes, and a raw JSON body of at most 66,048 bytes. All fields/cardinality,
wire op and canonical serialization must match. Operator limits can be stricter.

Actual Node admission verifies canonical encoding/network/selected profile,
strict main signature, expiry, fee/resource limits, nonce and full retained pending
prefix through the real M05 typed gate and M06 preview. The preview and admission
remain one bounded native stage under the existing Node owner. A malformed,
conflicting, unfunded or otherwise invalid bundle gets no partial new reservation.
The native receipt's typed-gate counts concern the **whole reconstructed pending
prefix**, not only the newly submitted members. `duplicate` means the same local
bundle facts were retained; it does not prove that the bundle was mined. Local
bundle grouping does not make unrelated signed transactions consensus-atomic;
atomic renewal uses the actual V3 renewal command.

Op 5 calls only `Node::pool_status_snapshot()`. It cannot call `pool_reconcile()`,
prune, reset, enable the pool, change configuration or select a miner. The native
snapshot validates bounded retained metadata/bytes but does not run a new M06
preview. The public response omits per-group digests/reasons/raw wires and returns
bounded counts, the actual active parent/generation, the last checked
parent/generation, `classification_current`, and four scalar native V2 cache-GC
observations. GC counters/hash describe local cache eviction, not exact inclusion,
finality or an operator deletion certificate; see
[LOCAL_MEMPOOL_CACHE_V2](LOCAL_MEMPOOL_CACHE_V2.md). It exposes stale classification
explicitly after an active-chain change until an **operator/miner** reconciles.
Counts for queued/blocked/expired/sequence-consumed groups refer to that last
classification. `SequenceConsumed` only says an active nonce is used; it does not
prove that these exact bytes were included. Receipt and status explicitly set
inclusion/adoption/reward/public-readiness authority to false. Normal chain
observation and confirmation remain separate.

## Cost, fairness and verification

Block PoN work counters and pool preview counters are separate. V3 reports actual
pool submit starts/finishes/failures and native elapsed time. Reads and transport
solution costs are recorded separately. Queued transaction fees are checked in
preview and charged by actual block execution; admission does not silently debit
ledger funds or invent a new economic payment. Duplicate submissions still incur
all transport and native verification costs.

The finite worker/row/body/output bounds do not prove honest service under a
saturated queue or a cheap adversarial hash farm. The shared mutex can delay reads
while a bounded native preview runs. Persisted pool growth, source renewal,
reorganization/finality recovery, cold restart and external WAN operation still
need actual integrated campaigns. A resource ticket is not a Sybil theorem.

## Ordinary CLI composition and executed acceptance

`serve --admission-profile public-protected-development-v3
--public-development-network --auth-secret FILE --pool-policy FILE` fixes the
operator's bounded local pool before listening. Add `--mine` and explicit
`--task-bootstrap` or model/input files to run the existing wall-clock miner on
the same owner and stop signal. Service completion or either failure stops and joins both. A successful finite
miner block limit leaves ingress serving the retained chain until the configured
service budget expires. Mining-only options without `--mine`
refuse; V2 refuses the pool/miner options. See
[CONTINUOUS_MINING_V1](CONTINUOUS_MINING_V1.md) for finite limits and failure facts.

`pool-push --transactions FILE --pool-context HEX --peer ADDRESS` and
`pool-status-remote --peer ADDRESS` require the exact V3 profile, server public-key
pin and caller identity file. They do not open a second local store. A signed
business denial remains structured stdout with `ok=false` and CLI exit status2.
Unknown profiles, private-session mixing and network logical clocks refuse without
fallback. Head/History/block push/full sync accept explicitly selected V3 alongside
their existing V2 contract.

`tests/public_pool_cli.rs` executes the actual CLI composition: an unknown guest
submits signed funding dependencies and a tag22 atomic renewal, a wall-clock miner
includes the exact three raws, and a different native receiver validates the chain
and new task statement. Its finite eight-block run and strict option refusals do
not certify public service. The first stale task-window fixture failures are retained
in work observations; task admission was not relaxed to make the run succeed.

Three native socket integration tests exercise actual guest signed transfer bundles,
funding/nonce dependency, same-bundle duplicates, wrong pool context and corrupted
signature rejection, no partial rows/no ledger nonce consumption, operator mining,
stale read-only snapshot, explicit operator reconcile and persistent reopen. Both
actual cross-version socket clients reject V2/V3 mixing and later honest requests
still succeed. Startup cannot enable an unconfigured pool; invalid lifetime bounds
are rejected. Legacy V3 unit controls exercise body guards, closed ops, profile/magic/
signature domains, cookie tampering/restart epochs, paid reservations, slow frames,
fragmented honest traffic, expired connections and cleanup. Resource revision r3
also exercises the actual signed Head under near-full mutation body occupancy,
grant retention across queued tasks and replies, disconnect/half-close cancellation,
and a ticket-passing Product rejection followed by valid native acceptance.
Finite queue controls hold four paid tasks beyond two occupied queue entries,
retain deadlines, accept eight actual submissions, and cancel four disconnected
pending requests without allocating new queue capacity. Six r4 controls add
real paid FIFO release followed by complete native admission, signed read service
under a48-Hello burst, exact readiness/expiry boundary selection, lane/body
reservation rollback with typed poison failure, correctly signed old/new profile
incompatibility, and paid EOF/expiry/stop closure with absent Body/Task/full-work CPU.
The original expiry and failure paths remain tested; waiting does not turn a
previous failure into a successful native admission by assertion.

These tests are local component evidence. The root integration must replay on the
final committed Cargo graph with the actual pool and continuous miner, complete
strict checks and resource campaigns, and preserve failures. No acceptance flag for
public readiness, source independence, task/model efficacy or production activation
is enabled by this document.

## Local request observations

`serve_public_protected_v3_with_metrics` accepts a trusted local shared metrics
mutex. It uses the same worker/queue/Node owner and returns a final snapshot after
shutdown; holding that observation mutex can delay this local process. These
counters neither authenticate a guest nor prove an economic cost bound.

`call_public_protected_v3_with_metrics` returns the ordinary result and separate
construction, challenge, solution-search, solution/body/response and total elapsed
nanoseconds. Failed calls retain their current stage, elapsed time and completed
ticket trials. A signed business refusal still completes transport; its failure
stage is null. Elapsed time includes scheduling/network waits and is not CPU time.
The ordinary API retains its wire and return behavior.

V3 client CLI commands can explicitly select `--client-observations` to emit this
unsigned local diagnostic as one stderr JSON line, also on a failed transport call.
The signed reply remains on stdout, and unsuccessful calls retain exit2. Parsing
or identity-file errors before constructing the observed call have no stage receipt.
V2 and other profiles refuse this option. Controller wall time includes process
startup too and must remain separate from the client's stage observations.

`queue_backpressure_events` counts repeated Full polls, not refusals or failed
requests. `enqueued_after_backpressure` counts eventual task dispatches;
`queue_wait_ns` measures body-ready to enqueue elapsed time, not CPU/owner-lock
occupancy. `peak_pending_enqueue` counts bounded existing connection stages.
Per-request transport, business refusal and complete native rejection denominators
remain separate from these scheduling observations.

The isolated r3 component observation preregistration
`1eb224ab08985bc97b690e2b90e1c1f4a8c292c908649be3cbf158ba407001ac`
used three10s localhost phases. All180 scheduled honest requests succeeded:
20 Submit/20 Head/20 History in each phase. Cached invalid traffic recorded800
attempts (8 Product,792 DUPLICATE_CONTENT); distinct-fork invalid traffic recorded800
(799 Product,1 paid-grant client refusal). Queue refusals were0;71 Full polls were
backpressure observations. Original independently coded scalar/State/ordered-
receipt replay accepted22 distinct valid packets: the anchor,20 linear successor
packets, and one independently constructed valid fork template. Each of the three
closed service stores instead contains genesis plus the21 linear packets (66 total
stored rows, including3 genesis rows). The valid fork was admitted only in its setup
Node and independently replayed; the three service stores did not admit it. Its
product-only mutation rejected as PRODUCT. This is same-operator loopback engineering evidence, not
800 full verifications of cached duplicates, live mining, new combined-source
qualification, WAN/SLA, task hardness or public acceptance. The prior1c mixed
observation accepted9 of20 honest Submit opportunities and recorded7 queue
refusals; these historical facts are not relabelled by this successor.

The three-phase observer used the historical legacy task context and precomputed
valid empty blocks, not revision10 checkpoint tasks or revision11 factor candidates.
For each phase's20 honest Submit opportunities, observed maximum/p95 elapsed
latencies in milliseconds were baseline47.16/36.27, cached139.07/41.06, and
distinct-fork31.71/30.94. These include observer scheduling/waits, are not CPU
measurements or TPS, and provide no p99 estimate (fewer than100 samples).
