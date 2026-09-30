# A2 — explicit attack budget, not an invented work-hardness proof

The exact matrix transcript relation is unchanged. It has measured cheap-forgery versus
full-recompute rejection asymmetry. No queue implementation resolves its cryptographic
cost hardness, input-instance fairness or permissionless Sybil problem.

## Implemented local capacity boundary

`trnm-transport::proof_admission` allocates three public permits and one recovery permit,
two permits per peer, with duplicate in-flight identities. The host receives a distinct
local RecoveryIngress capability; remote message fields cannot select it. Counts and
identity are updated under one mutex. Drop reclaims capacity on normal failure or unwind.
Stop changes generation; resumed service does not erase old live jobs or make their
permits current. Saturation returns Busy, not an invalid-block verdict.

This is an actual native component but not yet the production P2P host. A2000-identity
flood regression checks the local count and reserved capacity; it is not a measured
network attack nor proof an arbitrary public honest miner can always get a slot.

## Adversarial qualification matrix

| Attacker freedom | Required experiment | Current conclusion |
|---|---|---|
| invent trace that passes ticket | generation versus invalid verification cost at equal target | known amplification, unresolved |
| choose zero/low-rank/sparse task | compare fastest valid alternative transcript implementation | correctness can be checked; cost lower bound unqualified |
| reuse task or preprocessing | measure amortized cost over many challenges | no independence/hardness theorem inherited |
| change payout/body/parent | mutation and canonical transcript tests | binds context; not alone a work-cost proof |
| change proof representation | canonical output/block identity and malformed proof tests | no alternative serialization nonce accepted |
| vary peer identities | global cap and reserved recovery test | local resources bounded, public fairness unresolved |
| withhold bodies or old proof data | authenticated retrieval/cancel/timeout with bounded obligations | native network integration still missing |

A new succinct proof or admission mechanism requires its own exact statement, bytes,
security assumptions, verifier cost and invalid-input bounds. It cannot be substituted
silently, and normal hash tickets are not renamed useful work. Never alter chain validity
because one peer or receiver is overloaded. Busy and temporarily unavailable are local
observations; an actual cryptographically invalid proof is a separate fact.

## Executed work versus capacity, and cross-lane duplicates

Active duplicate keys include the local admission lane. A public sender holding a digest
cannot block the independently held recovery capability for that same digest. It still
cannot request recovery priority through a remote field. Each lane owns its own permit;
dropping a public permit cannot clear a recovery permit's identity or accounting.

`pon_admission_load` runs actual full verification during2048 local public attempts and
16 recovery verifications. It records before-work Busy decisions and expensive rejection
counts. This proves only the measured capacity/isolation behavior, not public honest-peer
fairness or a Sybil cost theorem. `pon_adversarial_cost` uses the actual half-range devnet
target with dense, zero, rank-one and sparse matrices, separating honest winning cost,
forgery hash trials, verification and rejection. Honest structured runs are not the
fastest adversarial implementation; measured cost does not supply a hardness theorem.

## Same-target resource model and public service obligations

A useful admission budget names the target, profile, task class, attacker preprocessing,
forged-ticket trials, honest work attempts, encoded bytes, verifier CPU time, queue delay,
cache state and actual hardware. Construction/rejection ratios use the same target and
units; ratios of process wall times must not be presented as cryptographic operation
lower bounds. Separately report cold and warm caches, invalid field/length/task checks,
failed ticket checks, ticket-passing false transcripts and duplicate valid retransmits.

For m public verifier slots, a measured isolated service approximation is
m / C_invalid requests per second when C_invalid is in seconds per request, not a safety theorem. Under an explicit
arrival model lambda_invalid*C_invalid + lambda_valid*C_valid must remain below the
usable public CPU budget for a stable queue; burst tails and honest waiting time still
need measurement. A recovery reservation protects only the locally authorized lane. It
does not prove that a new honest public miner can obtain service during identity churn.

The public qualification campaign must run the actual M04/M02 ordinary ingress path,
not acquire local permits by directly calling a library. Bind miner and attacker source,
identity churn policy, bounded queues, CPU scheduling, network loss/delay and independent
operator roles. Measure admitted, Busy, rejected-before-work, rejected-after-work, valid
accepted and honest wait-tail counters. Missing ordinary ingress is an integration gap,
not a passing fairness result. State whether the attack is controller-delivery withholding,
real network loss or genuine hostile peers; these observations are not interchangeable.

The controlled cost collector in `scripts/pon_work_cost_report.py` can re-run the existing
native cost binary and preserve raw output plus exact-source identities. It rejects
mixed targets, duplicate samples, Boolean counters and invented security flags, but
creates no public-admission qualification. It does not send traffic to any peer or host.

[The historical contract/tooling cost record](../../../../evidence/pon-contract-authority-v1/README.md)
binds its actual execution, raw samples, target, binary and original source, including
its retained failed environment setup. It is checked as historical after native-session
source changes. The newer collection below has its own current-input check; neither
record grants public admission or work-hardness acceptance.

## Early rejection before branch-state reconstruction

`work_oracle.precheck` is now reused by the existing Ledger admission path after bounded
header/transaction context checks and before potentially expensive `state_at(parent)`.
It checks certificate width/magic, field ranges, TaskId and ticket threshold. Malformed
fields, substituted task and bad ticket cannot force state replay or full transcript work.

A passing precheck is explicitly NOT `VerifiedWork`. A forged digest passing the ticket
still reaches the unchanged complete transcript verifier and rejects there. Parent-state
work eligibility, signatures, deterministic execution and roots remain mandatory before
persistence. This saves malformed-input replay cost; it does not solve a cheaply fabricated
passing ticket, structured-input shortcuts, fastest-adversary cost or public Sybil fairness.

## Current same-target measurements after native-session integration

[The new retained collection](../../../../evidence/pon-native-session-v1/work-cost/README.md)
binds the current native source inventory and exact binary to dense, zero, rank-one
and sparse tasks at one target. The old contract-authority collection is verified only
as historical observations. The current CI path still requires a matching current-cost
collection; it does not silence a stale-source failure by changing the old result.
These CPU timings do not bound the fastest adversary or guarantee honest public service.

## Native development ingress mixed-load boundary

The ordinary native entry now accepts closed socket confirmation batches while actual
false-transcript requests pass the ticket prefilter and fail full work verification.
The bounded regression verifies every honest result and exact rejected-request counts;
it neither bypasses the durable owner nor directly acquires fake library permits.
Loopback-only access, IP grouping, three socket workers and serialized proof/state work
remain explicit limitations. Read-only traversal checks stop/deadline cooperatively;
this does not solve fastest valid producer shortcuts, identity churn, slow-connection
starvation or sustained honest public admission. No public listener is enabled by tests.

## Native admission lock boundary

The existing native `serve` path performs context/duplicate checks under the one Node
owner, then drops that lock before full transcript replay. `WorkCheckedPacket` owns the
exact verified packet behind private fields; it cannot be a caller-supplied Boolean or
be rebound to another packet. Admission reacquires the same owner and reruns current
namespace, duplicate, parent, target and clock checks before application/state/receipt
validation and atomic persistence. Cancellation after verification leaves no new block.
Owner-lock waiting checks the request deadline rather than blocking indefinitely.

Deterministic scheduling regressions execute a status read while work is outstanding,
change the best branch during that interval, and exercise cancellation, wrong destination
context, stale clock and exact retransmission. The real socket regression continues to
reject 32 ticket-passing false transcripts while serving 16 four-query batches. These
are controlled loopback observations, not a Sybil/public fairness bound. Full valid
application execution, recovery and noninterruptible SQLite calls still use the owner.

## Alternative valid producer versus unchanged invalid rejection

The same-relation PreparedTask kernel in W1 is an implemented lower-cost candidate,
not a changed proof system or a separate admission ticket. Its transposed arithmetic,
exact bounded reduction and tile-batched hashing must be compared at the same tasks and
targets as the unchanged full verifier. Keep setup, successful and unsuccessful attempts,
full rejection and network arrival budgets separate. A better valid producer can reduce
the security cost per credited unit even while every existing invalid-proof test passes.

The ordinary native node remains a bounded development loopback endpoint. Its local
read/verification concurrency is not authenticated permissionless public fairness.
No filter, queue budget or measured median may set work_profile_qualified or public
activation. Sustained identity-churn delivery through the future authenticated public
owner, fastest implemented structural attacks, clock/target changes and honest service
under saturation remain explicit acceptance work.

## Explicit transport admission challenge v1

`ingress::serve_protected` and `serve_authenticated_protected` are distinct opt-in
development listeners. Historical `serve` and `serve_authenticated` retain their
named development scope. A protected Submit connection must complete the new
`trnm-pon-admission-challenge-v1` / `trnm-pon-admission-solution-v1` exchange before
obtaining a public proof permit or calling the PoN verifier. Read-only requests do
not perform this search. Ordinary protected client helpers require a challenge for
Submit and refuse a legacy terminal response as `ADMISSION_REQUIRED`. A protected
client first sends the closed `trnm-pon-admission-hello-v1` frame and verifies the
matching `trnm-pon-admission-ready-v1` response before transmitting the original
Submit bytes. The subsequent challenge must name the exact profile announced by
Ready before the client performs any search. The hello commits to those exact bytes. A legacy listener rejects the
hello without receiving a mutating request. A protected listener rejects an
unnegotiated Submit before work; signed durable request bytes are never rewritten.

The challenge binds the admission profile, network, parameters, genesis, a fresh
32-byte OS-entropy nonce, the hash of the EXACT received request frame, the selected
leading-zero bit count, lifetime and Unix-millisecond expiration. The admission
profile commits to both cost parameters and the connection-local SHA-256 protocol.
An authenticated listener additionally signs the challenge in the independent
`native-transport-admission-server-sign-v1` domain; the client checks the expected
server key before searching. Existing authenticated request/outbox bytes and their
ledger meaning do not change. There is no bearer authorization or alternate work
statement in these messages.

The solution names the complete canonical challenge digest and a u64 search nonce.
The server checks the corresponding SHA-256 leading-zero predicate once. It accepts
exactly one solution on that same connection and then discards that challenge;
reconnecting, retrying after restart or changing any request needs fresh entropy and
a fresh solution. Cross-connection replay cannot select a previous nonce. A solution
frame is at most 512 bytes and must use the exact closed serialization. Challenge
write and solution read share one monotonic absolute deadline; partial bytes cannot
extend it. Unix expiry is checked by the client as a bounded search aid, while the
server's monotonic deadline decides acceptance. Entropy failure refuses intake.

`AdmissionPolicy::new` accepts 8..20 leading-zero bits and 100..2000 milliseconds.
The explicit development default is 16 bits and 2000 milliseconds; these are measured
experimental resource parameters, not approved public deployment values. Clients
refuse out-of-cap policies, wrong context/request/server, expired challenges and
searches exceeding 1,048,576 trials. Protected listeners retain three fixed socket
workers, the existing frame/connection limits and local recovery permit isolation.
Two workers may process negotiated proof requests; the third refuses proof hellos
as `ADMISSION_BUSY_READ_ONLY_RESERVED` before receiving their bodies and remains
eligible for read-only frames. After sending this refusal it yields for 2 ms before
accepting another connection, bounded by the server lifetime. This avoids an
immediate refusal/accept loop outpacing the two proof workers' idle polling; it does
not guarantee that an idle proof worker wins every accept race. The profile commits
to this policy as `reserved-hello-yield2ms`. Its nominal local backoff is 2 ms;
operating-system scheduling may extend observed wakeup delay. Protected read-only requests do not consume proof
permits. Every protected initial frame and Hello/body exchange shares a 100 ms
absolute preface deadline. Slow fragments cannot renew that budget. The profile
hash commits to this allocation and deadline as well as the puzzle parameters.
Frame helpers recheck the absolute deadline after the final successful syscall;
late final bytes cannot turn an expired read/write into a completed frame. Protected
untrusted preface, request-decoding and authentication errors return at most 128 Unicode
characters under a separate 100 ms write budget. Both limits are profile committed.
A huge malformed operation therefore cannot select a huge echoed error response.
Clients may reconnect to the identical destination after the nonterminal reserved
lane refusal, at most 256 attempts, with 10 ms backoff and one five-second absolute
negotiation deadline. Retries transmit only the nonmutating Hello before acceptance;
they never replace the durable signed request, advance its nonce or downgrade the
protocol. Raw Busy negotiation responses convey no authentication authority.
No puzzle holds a proof or recovery permit. Slow initial frames can still occupy
all three workers for the short preface budget, and repeated anonymous connections
can still compete for socket acceptance. Slow links may fail the experimental
100 ms budget. This separation does not guarantee anonymous honest scheduling.

The admission predicate is independent of a parent block's PoN target. Historical
easy-target or low-work side-branch submissions must also pass it, without declaring
those branches consensus-invalid. Paying the transport puzzle never bypasses full
transcript, parent eligibility, application, root, replay or clock verification.
An attacker that pays this budget can still send a ticket-passing false transcript;
the original verifier must reject it. The hash search neither adds chainwork nor
proves useful computation, task hardness, public Sybil resistance or model utility.

The returned `Metrics` separates issued challenges, accepted solutions, rejections
before work, unnegotiated submissions, work-verifier invocation counts and measured
check/replay durations. Malformed hellos remain separate malformed-frame counters.
Socket accepts, protected preface refusals and reserved read-only worker refusals
are counted separately from solved or rejected admission challenges. A retry can
create multiple socket accepts for one ultimately submitted request.
Nanosecond durations use the monotonic elapsed clock and include actual scheduling;
they are not CPU-cycle lower bounds or sustained request-rate estimates. Reporting
must include bits, TTL, hash trials, request bytes, hardware, operator identities,
valid/invalid arrival schedules, expired/slow connections, Busy and honest wait
samples. Under identity rotation, any fairness assumption must name the scheduler,
connection budget and anonymous admission model; changing keys does not magically
add resource cost beyond the actual performed search. Sustained independent public
attack/service and hardware-asymmetry acceptance remain separate work.

`tests/protected_ingress.rs` uses real sockets, original ticket-passing false
transcripts, real valid work blocks, expiry, exact-wire context/replay substitution,
authenticated durable retransmission and a bounded mixed load. Its raw sample
output is new execution evidence only when actually run on the identified source;
test existence and local passes do not promote public activation or work hardness.
The explicitly ignored `sustained_protected_socket_cost_campaign` is a release
measurement with separate baseline, unpaid false-transcript and paid false-transcript
phases. The false-transcript phases have two sequential anonymous loopback streams
for a requested ten seconds each. It changes false transcript digests for each request, uses a
known easy genesis parent, and records actual elapsed duration, performed hash trials,
Busy responses, server checks, honest Submit/Head attempts, successes and failures.
The `slow_hello_occupancy` phase adds three rotating TCP streams for ten seconds.
Each alternates between a half-written initial Hello and a complete Hello with
its promised request body withheld, holds that socket for 150 ms and then opens
a fresh one. Partial initial Hellos can occupy all three socket workers until the
preface deadline; complete Hellos test the two proof slots and reserved read-only
worker. Honest Submit and Head calls continue throughout the phase. Slow connections
and failed attack negotiation attempts retain their own denominators.
Its `transport-admission-sustained-cost-v2` report names the fixed encoded body
length `request_template_bytes`. `attacker_body_bytes_successfully_written` sums
only complete attack request-body writes confirmed by the actual protected client
helper, before reading a challenge or terminal response. It excludes frame prefixes,
Hello, solutions, responses and unknown partial writes; it is not total network
traffic. `attacker_body_write_success_count` counts these completions.
`attacker_body_write_outcome_unknown_count` counts helper failures, including failures
before a body starts or after a partial write; `attacker_body_not_started_count`
counts connection/setup failures before calling the helper. The three counts sum
to false-transcript attack attempts. Baseline and slow-Hello phases have zero body
counts because those streams do not send attack request bodies. A later response
failure retains the already completed body bytes and its transport-error observation.
The observed honest sample denominator must survive any failed or starved requests.
These local streams do not establish fairness under independent or rotating
public identities, and elapsed hash rate is not an adversarial cost lower bound.

## Explicit public development transport successor

The [public-v2 contract](PUBLIC_INTAKE_V2.md) replaces the connection-work-v1
shared short Hello/body deadline only when explicitly selected. It assigns fixed
phase deadlines and connection/body/output/queue budgets, resource tickets to
all public operations, bounded metadata/one-packet history reads, and no durable
guest identity table. These are transport changes. The full experimental PNW1
verifier, source admission, deterministic execution, branch rules and chainwork
remain authoritative. Native calls already in execution are not preempted by a
connection deadline. Saturation and serialized persistence can still deny honest
service; physical deployment and a predeclared attack/service budget remain
required. Local conformance does not remove the experimental work-profile gate.
