# Public development intake V3 and the native local pool

This is a fresh, explicitly selected development profile. It connects paid guest
transport requests to the Node's actual persistent pool. It does not certify public
readiness, independence, fair access under saturation, exact transaction inclusion,
confirmation, model efficacy, or economic work. V2 retains its separate signed domains
and one-hour service bound. Both modules bind the current derived ancestry index
with at most1024 SQL lookups in a fresh resource-policy digest; see
[NATIVE_ANCESTRY_INDEX](NATIVE_ANCESTRY_INDEX.md). V3 resource revision r9 retains
the r5 paid body/output partitions, disconnect fences, paid enqueue waits and local
measured mutation CPU reservation/accounting. Bounded pre-Challenge/pre-Ready waits
remain inside the same connections while original resource capacity is unavailable.
It observes cancellation within complete M05 Work replay and at bounded M06
envelope preparation, canonical application and precommit boundaries. V2 retains its
own resource digest; these changes do not silently alter its contract. Security
fixes still require review of both modules.

An operator can select the bounded local
[request resource observer](PUBLIC_REQUEST_RESOURCE_OBSERVATION.md) to capture
actual worker-thread CPU intervals and application-frame byte progress. This
optional API preserves the selected signed r9 policy and native request rules; its nested
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
serialization; history retains its separate larger limit. The 10-second work deadline bounds admission/lock waiting and socket phases.
M05 full transcript replay and M06 envelope/application boundaries observe that
same deadline cooperatively; this does not interrupt an individual signature,
deep State operation, root/history computation or SQLite call. A
successful durable pool reservation can outlive the requesting socket or response.

Resource revision r9 binds these limits and finite readiness/enqueue behavior in `PublicPolicy::id()`. It reserves
131,072 bytes of the existing 8 MiB body pool and 524,288 bytes of the existing
32 MiB output pool for Head/PoolStatus control responses. Mutation body permits
and non-control output permits cannot exhaust these reserves.
After a valid ticket and caller signature, before sending Ready, the server grants
at most eight mutation requests and eight read requests. Each grant remains held
through body collection, queue/work execution and output cleanup. Rotating caller
keys cannot increase these global lane limits. Eight challenge tokens are reserved
from the existing global bucket for reads. These reservations introduce no extra
worker, queue, Node owner, ledger authorization or retained guest identity.

The r9 receiver retains pre-Challenge and pre-Ready waiters in the same at-most64
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
not a fresh5-second budget. M06 and SQLite stages can still cross
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
joins. The legacy r3 refusal counters are retained fields; r9 resource fullness
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
admission. During full Work replay, `verify_with_progress` also checks before
replay, every bounded noise hash, each matrix output row, each transcript tile,
product reconstruction and the final verified result. The public callback uses
the original task deadline, stop flag and connection cancellation flag; no new
TTL or CPU allowance is created. An error returns local `Cancelled(error)`,
separate from `WorkError`; it drops intermediates and cannot construct
`VerifiedWork` or `WorkCheckedPacket`. The ordinary `verify` wrapper uses an
infallible callback, retaining complete PNW1 bytes, arithmetic and cheap-error
precedence. A matching transcript still requires the whole product relation.

M06 uses a shared `Sync` observer before/after each envelope preparation and
canonical apply, and around mandatory work, reward and staged root/output. A local
`ExecutionError::Cancelled(error)` is distinct from a canonical relation error.
All started scoped workers are actually joined, including partial spawn/failure
paths, before returning; cancellation discards the preview State and staged
commitment. `CheckedExecutionParent` never retries or falls back on cancellation.
No-cancellation wrappers retain full State, ordered receipts, root, nonce rules
and canonical error precedence. Node checks before opening the write transaction,
at each delta boundary and immediately before durable commit. An error inside
that transaction drops it and rolls back uncommitted block/index/delta/snapshot
rows. No new fence runs after commit: original activation and native durable
success remain true even if cancellation then becomes visible.

These checkpoints bound work between observations, not CPU seconds or physical
preemption. A single signature, State clone/mandatory/apply operation, canonical
encoding/full root, task-output processing, history, lock wait and SQLite call
remain indivisible. The explicit public Pool bundle path also passes the request callback through
its original fixed-workers1 complete prefix execution. Ordinary pool callers
keep the no-cancellation wrapper and canonical behavior. Local cancellation
returns immediately instead of being classified as a Blocked relation error;
already committed reconciliation remains committed, and an uncommitted new
bundle rolls back at the original persistence boundaries. All observations reuse
the original immutable stop/cancellation flags and absolute task deadline; no
new TTL, CPU-second limit or resource allowance is introduced.
A fresh profile digest is mandatory: correctly signed r1/r2/r3/r4/r5/r6/r7/r8 cookies and
old client pins refuse r9, without fallback. For bits8/lifetime2000ms the
source-derived digest is
`947e9272b16ca79e339bda28b9c0c26e31d898ead9828bb5f1ca9e2e7c382bbd`;
for bits12 it is `ada335c79bef025337d8b551ce1365fde15637ba28b15c063880e923d63d7177`;
for default bits16 it is `31dd4c31841a1416a2ad7e0d8026e7acaa234cddd8f89e9b1bca3f2ad2a1f6bc`.
Actual CLI capture and qualification on the committed successor remain necessary;
these source-derived values do not relabel any historical r5/r6/r7/r8 result. Existing
`work_failed` observations include an abandoned replay as well as invalid relations;
the returned local cancellation error retains the actual reason. CPU spent before
cancellation remains included in measured full-work and outer mutation accounting.
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

Resource revision r5 introduced the volatile account retained by r9 in each PublicServer epoch, shared
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
limit returns `PUBLIC_MUTATION_CPU_BUDGET` from the scalar reservation primitive.
The public worker now retains the dequeued task's order while waiting for
recoverable shortage, as specified below. Start refusal occurs after the original
paid protocol and canonical body/queue checks but before native dispatch or full
proof verification. Revision r9 also
observes exhaustion during the request at the existing cooperative checkpoints. No new queue, worker, Node owner, State
cache or durable caller row is added. Key rotation cannot reset the account.
Restart begins a new explicit volatile service epoch; this is not a host-global
CPU quota across listeners, private ingress, miner threads or service restarts.

Historical revision r8 introduced the measured outer worker interval O plus the
checked sum C of every actual scoped M06 worker interval, exactly once. Guards
sample the existing thread clock on the same actual worker at entry and exit,
including canonical rejection, cancellation and panic unwind. All successfully
spawned workers join even after a partial spawn failure. Spawned, started,
finished and known interval counts must agree before C is usable; no absent
Output is mistaken for zero CPU. Every defensive preview retry shares this
request-local collector. PoolBundle forwards it through every full prefix
preview; its existing fixed workers1 path actually spawns no scoped workers.

Revision r9 samples newly consumed CPU on the actual current owner or scoped
worker at those existing progress callbacks. Each real worker retains a separate
same-thread stamp; its RAII exit samples the final tail even on panic or cancel.
One request-local collector spans sequential previews and every defensive retry.
It keeps only live thread identities/stamps and scalar debit, never State, packet
or admission authority. Entries are removed at actual scope exit, so sequential
scopes may exceed eight lifetime starts without inventing parallel capacity.
The available credit is debited immediately under a short global-account lock.
The unchanged100ms start reserve stays outstanding until final settlement;
available credit plus those reserves never gains another burst through refill.
Negative credit makes request cancellation sticky at its next observed progress,
while final tails still debit actual CPU. A missing/poisoned clock, registry or
checked sum makes the account unavailable immediately; it does not report zero.
Neither request-account nor budget locks span math, a worker join or SQLite.

After all started workers join, original full intervals remain authoritative.
Final settlement debits only `(O+C)-already_debited`, then returns the one original
start reserve. A partial sum greater than the measured full total is an accounting
failure. This subtraction prevents double charging W, scoped CPU and prior live
increments. No new cancellation fence follows durable commit; a final-tail clock
failure/debt disables future mutations while preserving the actual signed ACK.
A missing scoped-worker end clock before persistence cancels that request and
leaves active State, pool records and all typed SQLite table rows unchanged; it
cannot produce an ACK. These precommit and postcommit faults are separate tests.
The charged metrics remain the complete O+C total, not the residual alone. An
in-progress request has only the global credit/debt observation until it closes;
no per-request telemetry schema or physical hard CPU-second cap is added.

When Submit executes M05 verification, its measured W remains nested in O.
Charged CPU is O+C; the existing full-work and excluding-work counters report W
and O-W+C without adding a metrics field or changing State/Output schemas.
The optional observer's dispatch thread field still reports O, and its nested
full-work and total fields must not be added. Failed proofs and native refusals
consume their measured CPU. Unknown worker endpoints, mismatched closure counts
or checked arithmetic immediately disable further mutation starts and settle
without a fabricated zero or reserve refund. A completed native outcome and
signed success remain unchanged. These are worker execution intervals, not exact
OS thread lifetimes: startup, teardown and post-sample bookkeeping are excluded.
Reactor parsing, caller/ticket authentication, response signing/output and
unrelated service or miner threads remain outside this account. A completed mutation's accounting failure disables future starts
without replacing its actual native outcome or signed success. No completed
fact is undone, and no failed measurement is refunded as zero.

A call may exceed its start reservation. Its actual CPU becomes debt, which
blocks new starts until refill repays it. At most two existing calls may still
be executing, because the original two mutation workers are unchanged. This
bounds the number of nonpreemptive overshoots, not each call's CPU or duration.
Deep M06 State/root operations, SQLite calls, lock occupancy and read latency
remain nonpreemptive;
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

## Recoverable CPU shortage at the existing dequeue boundary

The public mutation worker holds its existing receiver/dequeue-order lock until
it acquires the original CPU start reservation or the original task becomes
ineligible. This prevents the other mutation worker from repeatedly taking later
queued tasks while the head is waiting for refill. No new queue, waiter registry,
worker, identity priority, CPU bucket or reservation is added. Already running
workers can settle, and the reactor and the separate read queue remain independent.
The dequeue lock is released **before** native dispatch and never covers a Node
lock, proof execution, M06 preview, worker join or SQLite transaction.

A short polling iteration checks the same cancellation/stop flags and the earlier
of the task deadline and service end. It briefly locks the original scalar
account, applies its original elapsed-time refill and releases the account before
sleeping for at most one millisecond. Polling does not count another reservation
or rejection. When a start is possible, the original acquire/stamp/reserve and
single settlement path is used. Cancellation is rechecked before that acquire.
There is no new TTL, fresh start credit or refund. Expiry while waiting cannot
close another worker's outstanding reservation. Unknown accounting is not a
recoverable shortage. With no live reservation and insufficient possible refill
before the original deadline, the original immediate budget refusal is retained.
A concurrent trusted non-public owner can still win the final reservation race;
its real refusal is not hidden or converted into an unowned permit.

Waiting is pre-dispatch scheduling. Its wall time remains in the client's original
operation interval, but scheduling/poll CPU is outside the existing O+C mutation
execution account, like reactor and response work. It must not be reported as
zero CPU or silently added twice to nested worker observations. This change does
not establish a complete process/energy cost, anonymous fairness before a task
has obtained its queue position, or a bound on indivisible native operations.

### Retained failure and regression scope

On PR227 head `5a2549eef8e74f0dcfc2f88181e84a7aeab49a8f`, run
`37562991474` / head Rust job `112604284070` failed the sustained service
assertion. Artifact `11459232018` (ZIP SHA256
`0b4e81e029cfbb04aa3ba7ff619be7b426d999a57cf898848de840ae91fd7fde`)
retains the complete report: both phases closed their actual accounting and
capture invariants, but all sixteen second-phase attempts of the honest block
returned `PUBLIC_MUTATION_CPU_BUDGET`. The report records 235 and 327 CPU
refusals in the two phases. This is an observed admission-budget starvation case,
not evidence that a fake work proof was accepted. The new wait does not replace
or weaken the original finite/sustained assertions, four attack workers, traffic
windows, request deadlines, byte/queue/CPU limits or complete-state comparison.

Six local reserve/wait regressions cover actual monotonic refill, impossible
refill, cancellation, original expiry, shared unknown state and preservation of
a different live reservation. Their controlled credit edits are mechanism tests,
not attack-cost measurements. The existing actual TCP from-zero test is the
separate traffic experiment; debug and release observations must retain their
own binary/source/profile identities. Neither a finite successful pressure run
nor an admission-budget shortfall changes production/public qualification flags.

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

## Shared settlement result and sustained local observation

The existing paid-dispatch and continuous-operation owners now consume the same
Boolean result from `PaidMutationCpuBudget::settle`. A successful mutex lock and
a known final thread sample do not prove that an outstanding reservation was
returned correctly or that the shared epoch remains available. A missing or
impossible reservation marks accounting unavailable, cannot mint credit, and is
reported by the public-dispatch clock-failure counter even when measured CPU is
known. Known CPU remains charged; an already completed native result or signed
reply is not rewritten. Known negative credit and unknown accounting remain
separate states. Resource r9, wire/profile identity and every resource constant
are unchanged.

`ServiceMutationCpuDomain::observe` is a read-only local API. It returns stored
credit, outstanding reservations, accounting availability and the existing
policy constants. It neither refills credit nor advances the time watermark;
reading it cannot return a reservation or authorize dispatch. Its result has no
remote or consensus authority. A poisoned mutex returns an error instead of a
fabricated zero balance. This volatile domain can be shared across same-process
Node reopen; a process restart still requires the existing owner arrangements.

The existing `public_v3_from_zero` service test retains its original two-phase
finite report, all eight reads per phase, CPU-clock tests and complete-state
checks. It additionally runs two four-second **arrival windows** on separate
native receiver/producer stores. Four joined senders rotate sixteen independently
constructed false-trace packets and transport identities. One honest reader
runs concurrently; an actual ordinary native block is submitted with its
original request deadline. Every failed attempt is retained. Outstanding calls
are joined after each arrival window; `traffic_and_join_wall_ns` includes that
drain, not just the requested four seconds. No request is restarted with a fresh
campaign window. Finite attempt and observer caps remain explicit failure gates.

The new `public-v3-sustained-local-from-zero-v1` report records every construction
trial/exhaustion, separate diagnostic verifier time, client/receiver CPU scopes,
raw requests or their retained packet reference, every observer connection and
actual stored-credit samples. Complete native state is compared, the Node is
closed/reopened, and the same shared CPU domain and its exact stored meter are
retained. The original queue, public tickets, CPU burst/refill/reserve and all
request deadlines are unchanged. The fixed genesis makes material context
reproducible, but actual scheduling and request streams differ across runs.

Sampled credit below the start reserve, sampled negative credit and CPU-budget
refusal counts are distinct observations. A run that never depletes its budget
remains a non-depletion result even when it records many late transcript
rejections. Passing requires all attempted honest reads on time, one on-time
honest submission per phase, complete accounting/capture and identical native
state. It does not require or invent a saturation result. The report never
qualifies public fairness, cheapest-adversary cost, strongest honest production,
independent WAN, ordinary Hepta export, future model benefit, physical power loss
or production activation. Honest build CPU is calling-thread only; total honest
worker CPU and client-confirmed transaction throughput remain null.

### Atomic FIFO CPU start reservation

A dequeued mutating task now performs the final shared-account refill decision
and acquisition of its existing `MUTATION_CPU_START_RESERVE_NS` under the same
CPU-budget mutex. Previously the waiter could observe enough refilled credit,
drop the account lock, and then lose that exact credit to another active
mutation worker before `acquire` relocked the account. Under sustained invalid
work this could repeatedly turn the oldest already-dequeued honest submission
into `PUBLIC_MUTATION_CPU_BUDGET` even though the original refill interval
made its start reserve available.

The corrected linearization retains the existing dequeue-order lock until this
single reservation is owned, and still releases both locks before native work.
It adds no queue, worker, caller preference, refill, burst, reserve, retry
budget, refreshed deadline or authority. Impossible refill, unavailable CPU
accounting, cancellation and the original absolute deadline remain failures.
Settlement and complete W1/M06 validation are unchanged. The exact-head and
prospective-merge sustained campaigns must retain their actual results; this
implementation change is not itself a saturation-fairness qualification.

### Current parent and pre-commit cancellation coverage

The existing shared Submit dispatcher now routes the same original request stop
and execution/CPU callback into admission-context parent reconstruction, before
starting W1 verification. Cancellation there cannot be interpreted as invalid
work or stored corruption and returns no verified packet. After full verification,
controlled native admission repeats all state-dependent checks under the original
owner and observes the same callback during parent acquisition and complete
pre-commit delta, parent/child-state and active-state readback. No separate
service budget, queue, admission profile or grant is added.

The final checks still execute in the existing single-writer transaction; a
pre-commit cancellation rolls back uncommitted block/delta/account records. After
successful COMMIT, the original activation/response path remains authoritative;
there is no new cancellation that retroactively turns durable success into failure.
Ordinary no-control callers retain no-op wrappers. Individual signatures, JSON
encodings, complete roots and SQLite calls remain nonpreemptive, so this is more
cooperative coverage, not a hard latency or CPU bound. External owner preparation,
activation and whole-host scheduling retain their separately documented limits.

The original exact three `public_v3_from_zero` tests, finite report, sustained
arrival windows and all r9 resource numbers remain unchanged. A fresh campaign
on changed source must retain its actual outcomes; the old non-depletion result
cannot be promoted to saturation fairness merely because callbacks were added.
The shared-dispatch regression
`context_cancellation_precedes_work_verifier_and_preserves_public_retry`
checks that an interrupted parent context calls no full-work verifier, writes no
block and permits a later complete ordinary retry.


## Consumed start reservations and the single shared CPU balance

The original 2,000,000,000ns burst, 250,000,000ns/second refill,
100,000,000ns start reservation and two-worker limit are unchanged. This is a
correction inside the existing volatile r9 scalar owner, not a new work profile,
caller identity lane, durable ledger, CPU grant or admission difficulty.

Let C be the original stored credit (which excludes every complete outstanding
start reservation), n the active request count, R the start quantum, and t_i the
actual cumulative owner-plus-scoped-worker CPU sampled for request i. The owner
now retains the bounded scalar S = sum_i min(R,t_i). The actual budget balance is
C+nR. Credit not promised to unfinished work is C+S; the still-unused promises
sum to nR-S. A new start requires C+S >= R and an available original worker slot.
A continuation requires C+S >= 0 after retaining its complete newly observed debit.
A consumed promise is not frozen a second time merely because t_i crossed R.
An unused promise of another request never becomes spendable by this request.

Each actual LiveRequestCpu owner supplies its checked monotonic cumulative sample;
remote payloads and observer JSON cannot supply t_i. A live or final sample m
increments S by min(R,t_i)-min(R,t_i-m), and subtracts all m from C. Refill still
caps C at burst-nR. Settlement joins the exact already-sampled total and original
residual O+C CPU, removes min(R,t_i) from S, returns R-residual to C and releases
one slot. It neither refunds sampled CPU nor counts nested Work twice. Missing
samples, impossible consumed-reserve sums, duplicate/unowned settlement, lost
owner count, poisoned locks and overflow remain unavailable; no such failure
can mint a start. Late known CPU still remains a debit, never a retroactive change
to an already committed Native outcome. The old observed stored_credit_ns is
still raw C, not a spend permission or a standalone proof of global exhaustion.

The existing scalar CPU regression inventory retains its original assertions and
adds the concrete post-quantum refusal counterexample, two-request isolation,
refill clipping, exact final/residual return, impossible sample joins and a
200,000-step independently represented remaining-promise comparison. The reference
tracks actual balance and per-request unused promises rather than reproducing the
C/S implementation. These are finite arithmetic/native owner controls; neither
physical minimum attack cost, public Sybil fairness, sustained independently
operated exhaustion, future-model efficacy, power-loss nor saturated WAN TPS follows.
The full existing network-only business, actual-depletion/recovery, source/head
and prospective-main-merge, capacity/history and paired Hepta gates remain required.
