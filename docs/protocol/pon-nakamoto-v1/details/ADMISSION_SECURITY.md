# A2 — explicit attack budget, not an invented work-hardness proof

The exact matrix transcript relation is unchanged. It has measured cheap-forgery versus
full-recompute rejection asymmetry. No queue implementation resolves its cryptographic
cost hardness, input-instance fairness or permissionless Sybil problem.

## PN1 shared-operation admission target

This amendment specifies I02 of the
[sole plan](../../../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md).
Later sections retain the existing and historical implementation boundaries;
this target does not claim they already supply public fairness. Work hardness
is qualified separately under [neural work](../NEURAL_WORK.md).

The ordinary M15 host must bind every public/paid mutation and its actual scoped
workers to one enclosing operation. Before expensive decoding, task acquisition
or state reconstruction, reserve bounded ingress bytes, queue entries, worker
capacity, start CPU credit and an absolute deadline. The operation identity,
lane capability and original resource/deadline context survive duplicate calls,
cancel requests and lost ACK. Only the existing local capability may choose the
recovery lane. Caller identities or fees alone do not establish honest public
fairness or exempt any path from shared resource accounting.

| Boundary | Required behavior and measurement |
| --- | --- |
| Intake | Bounded framing/parser, duplicate detection and cheap canonical/ticket checks; measure rejected-before-work separately. No caller-supplied Boolean constructs verified work. |
| Scheduled work | Charge actual decode, task/state acquisition, proof checking, execution, durable commit and all scoped worker CPU. Join or retain ownership of late workers before final settlement. Record CPU, wall wait and queue occupancy separately. |
| Cancellation/Unknown | Stop at defined safe boundaries, retain spent credit and exact operation identity, and reconcile the original outcome. A timeout does not prove cancellation, non-dispatch or block invalidity. |
| Confirmation | Client history import and depth/work checks retain their own measured budget and deadline. Receiver ACK is not a completed honest business round. |
| Restart | Durable effects, revocations and acknowledged obligations remain fenced. A restart must not mint fresh resource credit for an unresolved operation or release capacity still owned by work. |

Do not remove integrity fences, expand budgets or shorten the confirmation
policy to pass the existing regression. Instrument nested stage costs first;
charge each interval once to its enclosing operation. Separate a resource
bound from a fairness objective: the public test must declare honest offered
load, attacker bandwidth/CPU/identity churn, scheduling, network assumptions,
maximum pending work and required honest completion/tails. Unbounded attacker
arrivals have no implied service guarantee. Paid/public isolation is accepted
only for the tested envelope and shared bottlenecks, including disk and State.

The first exit test is the original native campaign with 1,024 signed seed
transfers, four seed blocks, 21 business blocks, three 30-second rounds per
baseline/from-zero/late-product mode, 0/24/24 attackers, two workers,
2 CPU-second burst, 0.25 CPU-second/second refill and 100 ms start reserve.
Require 3/3 timely, independently imported confirmations per mode in each of
three complete runs. Keep all offered honest requests, Busy, timeout, invalid,
unknown, cancelled and reorged outcomes. Missing a planned confirmation fails
that run; extending its window creates a different experiment. Source494 and
df6 failures remain retained; the latest 9bd optimization still needs this run.

After that finite regression, PN5 independently operated WAN service additionally
requires the preregistered attack/load and completion objectives. Record sustained
credit depletion/debt, expensive rejection rate, paid and recovery lane progress,
state/SQL time, actual worker CPU, memory/disk high water and p95/p99 with sample
counts. If the no-attack baseline fails, repair and measure it before attributing
the whole deficit to adversarial W1. A local passing test cannot close the
independent or computational-security gates.

### PN1 identity-capacity and sustained-pressure acceptance target

This supplements, and never changes, the original campaign and the fixed-seed
ROOT cohort below. M03/M04/M15 own I02 scheduling and actual resource settlement;
M17 owns the frozen offered workload and complete result denominator. The
current completion-work table has 4,096 identities per live owner epoch. Full
capacity removes new-identity promotion while ordinary paid validation remains
available. The existing full-table component control is not a sustained-service
qualification and the table is not a durable operation/replay journal.

Preregister an additional cohort that really constructs at least 4,097 distinct
complete-W1 packets, including the relevant changed-root rejection cases, and
continues distinct-nonce traffic after the table fills. Retain every attempted
construction, failed search, packet digest and actual CPU cost. Run matched
replay-only, new-identity and honest-only controls on fresh namespaces with the
same fixed initial state and original resource policy. The honest schedule,
duration, arrival/byte rates and finite actor budgets are fixed before execution.
If generation cannot supply the declared rate, record producer limitation; do
not call an underoffered receiver saturated or reduce the workload afterward.

| Boundary | Required supplement evidence |
| --- | --- |
| Capacity | Observe occupancy reaching 4,096 through real work, attempts beyond it, promotion/fallback/repeat counts and bounded retained memory; direct fixture filling cannot satisfy this row. |
| Pressure | Every planned honest confirmation round overlaps an exact hostile rejection and observed actual paid depletion. Retain coverage duration and maximum nondepleted gap against their preregistered thresholds; reservations and global averages are not spent CPU. |
| Honest service | Every planned round satisfies its original absolute deadline and depth/work policy, including rounds after capacity exhaustion. Retain Busy/timeouts/missing rounds; cold reopen cannot supply timely confirmation. |
| Accounting | Actual owner and all scoped-worker CPU settle once; measured cleanup, in-flight bytes/workers and unresolved owner costs reconcile. Unknown samples remain unknown. |
| Integrity and recovery | No invalid block or partial state enters live/cold history; legal traffic after pressure, listener reconstruction and process restart preserve their stated accounting/recovery semantics without fresh credit for an unresolved effect. |

A cohort fails its supplemental service claim if any required row is absent
or a frozen threshold fails. Preserve the original campaign's own PASS/FAIL
unchanged. In particular, the audited source `ef2a6958` original run
[40120511847](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/40120511847)
passed 27 confirmation rounds, but only seven of eighteen hostile rounds
overlapped observed depletion and its prepared business set had three distinct
transactions per run. It did not execute this capacity/churn supplement.

If measurements motivate epoch rotation or a different bounded fair queue,
specify its owner lifecycle, replay/identity retention and recovery behavior
before implementation. TTL eviction or restart must not let a repeated hostile
packet repeatedly regain priority or replenish the original operation budget.
Changing scheduling cannot weaken complete W1, current-parent/state rechecks,
original deadlines or M07 atomic commit. Qualify this service change jointly
with PN2 state/history cost; computational hardness remains a separate I01 gate.

### Fixed-seed ROOT rejection component cost

The opt-in `signed_seed_state_root_replay_component_cost` in
`trnm-pon-node/tests/public_v3_multiprocess.rs` shares the existing
`valid_work_state_root_replays_are_paid_without_admission` runner. The original
eight signed transactions on genesis and two M06 workers still require known
positive scoped-worker CPU. The new fixture uses the same seed builder as the
original campaign: four legally admitted blocks with 256 signed transfers each,
then its first business transaction (nonce 1025) on the fixed h4 parent, with
one M06 worker. State is never injected or enlarged adaptively.

After changing only the reference State root, the producer performs a fresh
legal W1 search. Its actual prepared-producer/search CPU and wall cost and all
ticket attempts are retained, including failed attempts before the winner;
Node-owned seed/reference searches retain aggregate cost with their unexposed
attempt counts explicitly unavailable. Separate preparation, independent W1
verification, encoding and client-thread costs are retained. Process preparation
totals enclose their component measurements and must not be added to them.
The shared-process `support::call` CPU includes receiver work; its separate
`client_thread_cost` is the isolated client observation.

Three sequential, identical bodies use fresh ordinary public handshakes. Each
must finish Work successfully, execute M06 and refuse `ROOT`, with exact body
digest/connection coverage, positive known owner CPU and a settled paid debit.
For one transaction/one M06 worker, known scoped CPU must be zero; unknown is
not converted to zero. The first request follows real seed replay and is not an
OS-cache-cold claim; the next two expose warm replay costs. Stored block/event
counts, active state and cold readback must remain unchanged; the false packet
must stay absent before and after a separate legal reference acceptance epoch.
Repeated expensive rejection is established by these assertions, not inferred
from a successful admission's commit cost or a presumed negative cache.

Run this selector explicitly with `--ignored --exact --test-threads=1`, in
release mode, with a fresh `TRNM_CI_RECEIPT_DIR`. Retain exact source/binary,
command, real hardware, affinity and cgroup/resource limits alongside the raw
JSON. A local host different from the original 4-CPU/16-GiB CI is only a
controlled component-cost observation. The fixture changes no production
limits, protocol, 2 CPU-second burst, 0.25 refill or 100 ms depletion threshold.
It cannot qualify a sustained-load campaign, PN1 fairness or work hardness.
The original source `8d56f2f` campaign's three FAIL results remain: all 189
submission observations/27 confirmation rounds succeeded, but all six hostile
phases lacked genuine paid depletion. A full supplemental saturation cohort
and independent honest windows remain unexecuted by this test.

### Fixed-seed ROOT supplemental cohort

The separate ignored selector
`separate_process_root_rejection_and_signed_confirmation_supplement` reuses the
same phase and actor owners for one 30-second baseline followed by one 30-second
`valid-work-root` pressure phase. It retains the h4/1,024 signed seed and nonce
1025 one-transaction body. Each of 24 actors independently prepares the selected
generic producer, searches W1 on its own changed-root/header-nonce instance, checks
the winner and replays its fixed body through fresh ordinary signed handshakes.
All actual attempts and known positive acquisition/diagnostic costs are required.
The original from-zero/late-product campaign, three runs and six hostile FAIL
results remain separate and unchanged.

The 480-call cap, t=1/5/9 signed business schedule, seven blocks per round,
three independent-client confirmations at depth six, 2-second CPU burst,
0.25-second/second refill and original strict credit <100 ms / paid debit >1.9 s
depletion predicate remain. Each round needs exact-hostile-body receiver Work
acceptance followed by Admission refusal with CPU progress, and at least one
actual signature-verified client ROOT refusal wholly within that round. The
observer has no error text; its Admission refusals are not all labeled ROOT.
CPU-budget refusal, deadline/Unknown and overlapping-only calls cannot supply
the ROOT response. Live observer snapshots are non-atomic; the ROOT evidence
interval closes after the last snapshot and must remain inside the fixed phase.

All 24 reports must complete without reaching the cap or forced kill. After
service joins, reconcile the whole paid/settled/Submit-owner/service CPU domain;
concurrent per-request paid deltas are not ownership evidence. One M06 worker
requires known zero scoped CPU, not an invented zero for missing telemetry.
All 24 distinct hostile packet IDs remain absent live and after cold reopen;
the receiver/client must equal the producer's exact 21-business-block State and
expected block/event counts. Cold reopen occurs after the window and contributes
no timely confirmation.

`scripts/run_pon_root_supplement.py prepare` freezes one clean source and a
read-only release test binary without running that selector. `execute` requires
the exact prepared-manifest SHA and binary, one new `trnm-pn1-root-*.service`
systemd user service with aggregate CPUQuota=400%, CPUQuotaPeriodSec=100ms,
MemoryMax=16G, Nice=10, KillMode=control-group and RuntimeMaxSec=600. Controller,
verifier, actors and descendants share that service; actual limits and actor
readiness membership are checked. An exclusive claim prevents rerunning the
same prepared cohort after failure. Existing bounded-process/source/resource
owners retain commands, streams, source/binary hashes and failed observations.
The initial source freeze retained **NOT_RUN** until a separate authorization.
One authorized 30-second baseline plus 30-second ROOT phase then ran on
`c61e2112de67f9295258246b42d3c3ebf652d445`, with immutable release binary SHA256
`7c036d081c7b92cfb933633c26ca6e9bcdcb0fa09302209865bb2dd5f5e9c2bd`, inside one
actual aggregate 400%/100-ms/16-GiB/Nice-10 systemd user service. It **FAILED**.
The baseline completed all three depth-six confirmations. Under ROOT pressure,
the first two confirmed, but the third had no confirmation at 30.007524305 s.
Twenty of 21 honest submissions succeeded; the final h25 submission ended with
`FRAME_DEADLINE`. The receiver stopped at h24, 24 events and 25 stored blocks;
the client retained its h18 confirmed tip. Final producer equality therefore
failed. No after-window recovery was counted as timely progress.

The retained pressure input produced 617 hostile calls: 593 signed ROOT replies
and 24 client I/O/deadline failures. All 24 actors completed below their cap,
without forced kill; exact-body Work/Admission CPU progressed in each observed
round. The original numeric depletion relation and whole-sample containment
were independently read back from the retained samples. Final paid CPU was
9,396,951,692 ns, equal to settled full/Submit-owner/service CPU, with known
zero scoped CPU. All 24 hostile packet IDs stayed absent live and cold; cold
reopen matched the incomplete live receiver. These facts do not repair the
missing third business confirmation or pass the supplemental cohort.

The failed native step exited 101 and the launcher failed without retry. The
exclusive cohort claim, original streams, all actor reports, numeric samples,
source/binary pins and service properties remain retained privately. The unit
and all 26 observed original processes were gone at cleanup. A measurement
limitation also remains: the runner's failure path did not emit its planned
within-service source/resource-after records. An independent raw source check
after failure confirmed the frozen source, and the immutable binary hash was
unchanged; a removed cgroup's final counters cannot be reconstructed. No PN1,
original-campaign, hardness, independent-operator, WAN or production flag changes.

The subsequent `pon-root-supplement-execution-v2` launcher attempts the frozen
binary hash, exact source and live-service resource readbacks independently after
an ordinary measured-run failure as well as success. Each unavailable observation
is recorded without suppressing the others or replacing the original failure.
Any failed after-check prevents success. The one-use claim and all original
native inputs, deadlines and acceptance criteria remain unchanged. This records
live after-observations, not final counters after unit deletion, and supplies no
missing observation for the earlier failed c61 cohort. Launcher fault controls
use mocked native execution and real small file hashes, not a new pressure run.

A later, separately frozen current-source cohort on
`f7795a3d72bb59d9f0625186d301fc3ce0dc028e` (tree
`c09f6946bb2cb0b40e7489d6ca57e4aaecec3bb7`) **passed these supplemental
criteria only**. Its release binary SHA256 is
`07d34e50e289135e652f04c50cdbe8fce17ab7399273889cc1abf2d32c706ab4`;
report SHA256 is `d049d54ef1670a576098ab71ab1f95bf9af1efcb86fad19cce2eab7941dee346`.
The original inputs, caps, deadlines and aggregate service limits were unchanged;
the optional ROOT rejection cache stayed **off**. Current scheduling and native
arithmetic differ from c61; this is not an isolated causal comparison of one
optimization. One malformed launcher command was rejected before service creation
or cohort claim, retained, and corrected; exactly one native cohort was executed.

All 24 actors completed below the cap without forced kill. All 21 business blocks
and three depth-six confirmations completed, at 5.967304544, 16.120909061 and
26.006862713 seconds; each round contained genuine numeric depletion and 151,
152 and 152 signature-verified ROOT replies respectively. Of 595 samples, 541
met the original depletion predicate; minimum remaining paid credit was
67,817,742 ns. Whole paid/settled owner CPU reconciled to 9,403,286,579 ns with
known zero scoped CPU. The scheduling owner retained 45 of 4,096 fixed identities
and observed 662 repeat skips; this does not qualify capacity exhaustion or
distinct-nonce churn. The generic phase's `finite_phase_criteria_met` remains
false; only the separately frozen valid-Work/ROOT supplemental predicate passed.

All 152 captured files / 57,416,786 bytes were hash-verified. Independent SQL
readback of closed snapshot copies matched both full current key/value sets,
tip/root, height 25, 25 events and 26 stored blocks; all 24 hostile IDs were
absent. Local activation generations legitimately differ (receiver 25, client 7)
and are not chain heights. A prior read-only Python inspection created empty WAL
and reader SHM sidecars after capture; these are retained separately, with all
original captured bytes unchanged. Binary/source/live-resource after-checks
passed; all 26 observed processes and the original cgroup were gone at cleanup.
This is not final raw accounting of a deleted unit. The earlier c61 and original
three-run failures remain failed; no PN1, hardness, independent-operator, WAN,
model-loop or production qualification changes.

### Optional bounded final-ROOT rejection component

`Node::enable_local_root_rejection_cache` explicitly enables one volatile cache
in the existing M15 Node's M06 execution path. Default open, cold reopen and every current
CLI/service constructor leave it off. This is a local component API, not a
public resource profile, admission capability or activation. Growth-reference
execution is excluded. Existing raw/scoped cost fixtures retain their default
uncached execution.

Only admission's final State/receipts comparison, after successful real M06 and
qualified task-output derivation, constructs a private mismatch fact. The key
contains the full encoded packet, actual checked parent ID/root and local
network/parameters/genesis/backend/task-profile context. A fact cannot be
serialized, imported, shared or survive the owning process/source instance.
Retention receives the same binding scope returned by the checked executor;
an earlier SQL Record is not that scope. An A→B→A SQL fault regression checks
that a refusal derived from B cannot reject the restored valid A packet.
Current full W1 verification still precedes the private checked-packet type.
Each hit follows fresh header/task/time checks, actual State restoration,
canonical parent-root and account-graph checks, owner permits/journal rechecks,
mining/continuous gates and both original parent-binding cancellation points.
Only deterministic execution/output derivation is omitted. A final progress
checkpoint precedes returning cached ROOT or retaining a new fact. Generic
ROOT errors, accepted packets, cancellation, Unknown and local integrity failures
never become facts. A changed actual SQL root, State or account graph remains a
fresh integrity failure, even with an identical packet.

The fixed array has at most 32 entries. Its 2-MiB retention cap includes fixed
cache/Node-field metadata and exact boxed packet lengths; this is not an RSS or
allocator-overhead bound. Oldest facts are evicted as necessary. TTL is 30
seconds from creation, never renewed by a hit/duplicate. A failed, out-of-range
or backward monotonic sample clears facts and disables reuse for that owner;
reenabling does not reset it. There is no new durable journal, lane, identity
whitelist, CPU credit, wire domain, State cap or namespace. Actual owner/worker
CPU continues through the existing paid accounting; no saved cost is charged as
executed CPU.

Component tests exercise true cold execution then skipped replay execution,
fresh full Work and signed public ROOT replies with positive actual settled
CPU, nonmatching bytes/context/parent/root, changed storage, cancellation,
generic-error exclusion, cold reopen, eviction, exact-byte/slot limits and
clock/TTL failure. They are not a new pressure campaign or a throughput proof.
No full campaign is run for this component. Nonce/body churn can miss every
entry, and fresh full Work/State/context costs remain. Original PN1 and the
`c61e2112` supplemental failures, arithmetic-profile research boundaries and
all production/qualification flags remain unchanged.

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

## Native fixed-wire rejection before task State

The native Node calls `pon_work::precheck_proof_statement` before
`eligible_work_task_with_progress` can reconstruct the parent State. This bounded,
allocation-free check accepts only the exact PNW1 width and magic and canonical
little-endian A/B/C fields, derives TaskId from the exact A/B bytes, and rejects a
claimed transcript digest whose challenge-bound ticket exceeds the header target.
The transcript digest remains unverified. Success returns only `()` and cannot
construct `VerifiedWork`. Parent-state task eligibility, complete transcript
replay, product verification and final commit validation remain mandatory. The
encoding-only helper remains available; the statement filter composes it without
changing the standalone full verifier's original validation order.

Common admission retains its existing owner, exact-duplicate, header, parent,
target, clock and transaction-root checks before the statement check. The
continuous public owner additionally checks the statement after its declared packet
parent/task binding and before its earlier task-State lookup. Existing bounded
header/ancestry reads can still occur; this is not a zero-database-read claim.
The helper distinguishes length, version, field, task and target errors; native
malformed magic/fields and mismatched task/bad ticket report their `WORK:` error
before task-State errors.
Existing packet-grammar length errors still reject earlier where applicable.
The standalone full verifier's original error order, including zero target
before field rejection, is unchanged.

Regression selectors `proof_encoding_precheck_`, `proof_statement_precheck_`,
`mode4_packet_encoding_precheck_precedes_actual_parent_task_lookup` and
`paid_malformed_work_encoding_settles_without_starting_full_verification`
cover encoding/statement boundaries, no parent-State entry or work replay on
malformed input, substituted task or bad ticket, valid retry and exact duplicate behavior, and the original paid CPU
settlement when work never starts. The private continuous-owner fixture checks
only ordering and grants no execution authority. These source regressions do
not measure hostile network saturation or qualify work hardness; canonical
ticket-passing false transcripts can still reach expensive rejection.

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
Two workers may process negotiated proof requests; the third remains eligible for
read-only frames. Each proof worker first waits at most 2 ms for a connection on
its own zero-capacity rendezvous channel, then tries the existing listener. After
the read-only worker reads a canonical, request-digest-bound Hello, it tries to transfer
that exact socket and already-read frame to either proof worker. The first
`try_send` remains immediate. If neither receiver is ready, the same worker sleeps
for at most100 microseconds between opportunities for up to2 ms, bounded by the
original request and preface deadlines. Actual scheduling can overshoot the
requested sleep; the next opportunity first checks the original absolute expiry.
The zero-capacity channels retain no pending sockets. A successful
transfer reuses the original 10-second request deadline and 100 ms preface deadline;
it neither repeats accept/frame reading nor increments socket accepts again. The
three workers still own at most three sockets in total. The read-only worker does
not receive a proof body, solve/verify the puzzle or acquire a proof permit. This
bounded transfer opportunity still holds its original accepted socket. If no proof
worker takes ownership within that original budget, the existing
`ADMISSION_BUSY_READ_ONLY_RESERVED` refusal and bounded 2 ms yield remain. This
reduces repeated wrong-lane acceptance without guaranteeing anonymous scheduling,
an operating-system wakeup bound or public fairness.

The profile hash explicitly commits to `hello-rendezvous0`,
`handoff-opportunity2ms`, `poll100us`, `proof-recv-before-accept2ms`,
`original-deadlines` and `socket-ceiling3`, alongside
`reserved-hello-yield2ms`. This changes the protected transport profile digest;
same-profile peers and fresh transport contexts must use the new digest. Old
protected peers cannot silently negotiate a fallback. It changes no PoN work,
chain weight, ledger schema or signed transaction domain. Protected read-only
requests do not consume proof permits. Every protected initial frame and Hello/body exchange shares a 100 ms
absolute preface deadline. Slow fragments cannot renew that budget. The profile
hash commits to this allocation and deadline as well as the puzzle parameters.
Frame helpers recheck the absolute deadline after the final successful syscall;
late final bytes cannot turn an expired read/write into a completed frame. Protected
untrusted preface, request-decoding and authentication errors return at most 128 Unicode
characters under a separate 100 ms write budget. Both limits are profile committed.
A huge malformed operation therefore cannot select a huge echoed error response.
Clients may reconnect to the identical destination after the nonterminal reserved
lane refusal, at most512 total Hello attempts, with10 ms backoff and one five-second absolute
negotiation deadline. Retries transmit only the nonmutating Hello before acceptance;
they never replace the durable signed request, advance its nonce or downgrade the
protocol. The larger finite retry ceiling can cover the original five-second budget;
it never renews that budget. Both the retry ceiling and handoff opportunity are
committed by the new profile digest; an old profile rejects with `ADMISSION_PROFILE`.
Raw Busy negotiation responses convey no authentication authority.
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
`admission_hello_handoffs` counts successful zero-capacity ownership transfers;
it is a subset of accepted connections, not a new request or another socket accept.
The controlled real-socket rendezvous regression forces the reserved-side first
accept and runs actual native work/admission. A separate production-listener test
replays serial 250-member read-only bursts before subsequent protected submissions;
its repeated observations are not new independent confirmations. The existing
occupied-proof-worker Head, expiry, replay and authentication controls remain
required. These finite regressions do not accept a public availability gate.
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

Public V2 r2 and [V3 r3](PUBLIC_POOL_INTAKE_V3.md) resource policies partition their
existing body/output totals, retain per-lane grants through socket/task completion
and cancel disconnected requests between native stages. Each uses its own new
pinned resource digest while preserving its separate wire and signing domains.
The signed socket controls fill paid mutation budgets with different callers,
preserve Head service, cancel two owner-waiting and one queued request, and then
fully verify the original valid packet. A changed product with the original trace
is still rejected by the complete verifier. These component controls neither
certify sustained attacker budgets nor repair the separate connection-work-v1
26/27 short unpaid-phase observation. Shared pre-ticket/connection resources and
the single native owner remain relevant to public availability.

V3 r3 additionally retains a paid canonical request in the original bounded
connection's Enqueue stage when its unchanged two-entry worker channel is Full.
Connection-ID polling preserves original work/total deadlines and paid permits;
EOF/expiry/shutdown cancels before dispatch. The64 connection cap,8/8 grants,
2 proof/1 read workers,2+2 queues and body/output totals do not increase.
New policy digests reject r1/r2 cookies. Full polls are scheduling observations,
not request refusal counts. The finite localhost three-phase control accepted all
180 honest Submit/Head/History requests while cached and distinct-fork Product
mutations were refused; it does not establish unknown-caller Sybil fairness or
restore the separately unexecuted remote mixed-hostile qualification.


## Four from-zero W1 transcripts: executable P0 boundary

The existing public V3 from-zero attack and CPU-domain regressions are retained.
An additional P0 case now constructs **four different** ticket-valid false traces
under one challenge, canonical A/B, task and target, without calling a real W1
producer or training. These test inputs are not asserted to be the user's earlier
four unprovided raw payloads.

* The independent Python oracle method
  'FourFromZeroTicketRegression.test_four_ticket_hits_replay_and_reject' in
  'formal/pon-nakamoto-v1/test_work_precheck.py' fixes challenge bytes 00..1f
  and target 7f followed by 31 ff bytes. Its four winning trial nonces are
  0, 1, 2, 3. Each must pass the cheap filter, perform one actual arithmetic
  replay and fail with TRANSCRIPT.
* The native method
  'four_from_zero_w1_traces_keep_native_state_and_chainwork_unchanged' in
  'trillionnium/crates/trnm-pon-node/tests/public_v3_from_zero.rs' selects
  a real Node genesis maintenance context, then searches four distinct trace
  claims under **that exact same native header challenge and target**.
  Each is fully rejected by the reference, default and limb verifiers;
  the reference path must visit all 512 transcript tiles, reach neither
  product nor VerifiedWork, and Node admission must return WORK:Transcript
  with no block, active-head, stats or cold-reopen change.
* The existing 'scripts/ci/run_from_zero_native.py' owner now requires this
  fifth named native test, while preserving its original four test selectors.
  The native test prints a source-scoped report with per-case CPU and wall-clock
  times. 'TRNM_W1_FOUR_NATIVE_REPORT' optionally saves a new create-only
  raw JSON file; clocks that are unavailable remain null. Those are newly
  observed costs, not fabricated historical CPU measurements.

A mathematical negative test and a correctly rejected invalid block are not
proof of public denial-of-service resistance.

## P1–P6 remaining acceptance, without new authorities

| Phase | Existing owner | Required evidence (not conferred by this patch) |
| --- | --- | --- |
| P1 | M04/M15 | Enumerate all externally reachable complete W1 verification callers and bind an actual shared host/process CPU and memory owner. Key rotation, different listener process, process restart and cancellation cannot mint fresh unaudited mutation capacity. |
| P2 | M04/M17 | Freeze W1 target, V3 Cookie bits and expiry, full actor/source identities and CPU/GPU/hash rates. Measure whole false-trace producer, all misses, honest Cookie cost, receive/decode/W1/M06 costs and tail latency under identical resource limits; estimate no hardware-independent minimum from a single CPU. A signed Cookie revision needs a fresh versioned profile. |
| P3 | M04/M15/M17 | Cross-connection cookie replay, caller-key rotation, distinct false traces, valid-work/false-StateRoot, benign requests and branch recovery share one real budget. Busy/Deferred/local cancellation never imply Invalid or negative chainwork. |
| P4 | M17/A03 | In **three runs per each of three attack modes**, demonstrate 3/3 timely client-confirmed honest rounds per run under preregistered attacker and host budgets; include all failures, Busy and censored requests, unchanged task/challenge and complete raw receipts. Local/same-admin runs are not independent WAN acceptance. |
| P5 | M01/M02/M17 | Compare W2-A Merkle intermediate-commitment sampling, W2-B complete cryptographic computation proof and W2-C explicitly separated anti-Sybil PoW. Bind complete original statement, unique lottery ticket, replay/fork choice and total generation plus validation cost. Freivalds product checks alone do not authenticate the false transcript. |
| P6 | M01/M02/M17 | An independent reviewer implements a third verifier from a frozen new version's statement and byte grammar, tests hidden bad/valid witnesses and grinding/replay, and signs an environment/source-bound opinion. No internal vector or single assistant review can supply independence. |

All existing W1 signed domain, 49,188-byte proof, challenge, ticket formula,
fork choice and protocol acceptance remain unchanged. Admitting public work
is a *resource* decision; only complete verification confers the existing
VerifiedWork result. New W2 logic must use a separately governed version,
consensus context and external review, not an implicit fallback.


### P1 initial concrete W1 caller inventory (source audit, not an acceptance claim)

This static inspection is pinned to source parent
'630f871293e48588e0a1ceae7ceb64973d3ec31d'.
It names concrete native callers; a complete public reachability graph and
verified host-wide budgets remain pending.

| Entry | Actual W1 call | Existing cost owner and gap |
| --- | --- | --- |
| M15 native Node 'store.rs:Node::admit' | 'WorkCheckedPacket::verify' followed by checked native admission | Context/owner checked; not itself a host-wide public CPU scheduler. All remotely influenced callers need upstream resource ownership. |
| M04 native ingress 'ingress.rs:measured_work_verify' | Full 'WorkCheckedPacket::verify' | Timed wall duration and admission permits; wall milliseconds are not actual calling-thread CPU or a host-wide hard budget. |
| M04 V2 'ingress/public_v2.rs:public_dispatch' | Full 'WorkCheckedPacket::verify' | Bounded public worker and phase deadline; records wall time but no V3-style actual CPU debit. This is an explicitly unresolved P1 exposure if externally enabled. |
| M04 V3 'ingress/public_v3.rs:public_dispatch' | 'verify_with_progress' / arithmetic-fact variant | Actual thread CPU charged by 'PaidMutationCpuPermit' in original finite service domain; per-process/host-wide and physical multi-CPU isolation remain separate obligations. |
| M05 opt-in 'ingress/metered_work_facts.rs' | Private verified-work fact cache plus metered source | Requires caller-supplied 'ServiceMutationCpuDomain'; does not replace V2/V3 network listeners. |
| Native mining 'mining.rs' | Local producer proof self-check through 'pon_work::verify' | Local mining producer, not by itself remote mutation admission. |

Before closing P1, audit *every* exported CLI/listener/gossip/sync path
including these wrappers, test externally reachable bad-work input on all
selected profiles, retain true CPU/memory/process-owner evidence, and ensure
all processes share the same physical capacity cap. Introducing new
accounting without these readbacks is not a completed fix.


### Reproduction of bounded P0 and P2 research paths

Run the original project preflight and the existing source-bound CI owner
before treating any output as an exact-source runtime observation. New output
files must not already exist. The Python oracle has no native chain authority:

    TRNM_W1_FOUR_PY_REPORT=/absolute/new-p0-oracle.json \
      python3 formal/pon-nakamoto-v1/test_work_precheck.py -v

The native Node test is included in the required original
'run_from_zero_native.py' selector list. A directly targeted development run
can use the original native test target with the unchanged W1 proof profile:

    TRNM_W1_FOUR_NATIVE_REPORT=/absolute/new-p0-native.json \
      cargo test --locked --manifest-path trillionnium/Cargo.toml \
      -p trnm-pon-node --test public_v3_from_zero \
      four_from_zero_w1_traces_keep_native_state_and_chainwork_unchanged \
      -- --exact --nocapture --test-threads=1

The optional P2 sample tool computes the same SHA-256 framing and big-endian
ticket leading-zero predicate as V3, **but on synthetic Cookie ID bytes**:

    python3 scripts/ci/test_pon_v3_cookie_cpu_study.py
    python3 scripts/pon_v3_cookie_cpu_study.py \
      --bits 8 12 16 --samples 2 --max-attempts 262144 \
      --out /absolute/new-cookie-cpu-proxy.json

It records all misses, limited searches, actual Python process CPU and wall
clock, capped output and missing GPU/native observations as null. This is
not an authenticated V3 transport session, a real GPU hash-rate measurement,
a client cost bound across devices, or evidence of affordable honest access.
No P2 production admission parameter is selected by the results.


### P1 interim network boundary (current candidate after the first fix)

Legacy 'public_v2::serve_public_protected_v2' and its private owner
composition now reject non-loopback bind addresses with
'PUBLIC_V2_LOOPBACK_ONLY' before accepting any proof. An explicit native
regression binds '0.0.0.0:0' and checks refusal without starting a service.
This intentionally narrows a legacy development transport that has no
V3-equivalent measured mutation-CPU account. It does **not** make trusted
loopback clients Sybil-resistant and does not close P1. Legacy V2 signed
payloads and W1 proof verification remain unchanged on permitted loopback
listeners; migration to the V3 CPU-metered interface must be explicit.
Other native authenticated/protected entrypoints still require independent
host-budget evaluation and P1 remains OPEN.


### P1/P3 additive defense and original resource-owner integration

The original CPU-domain implementation (V3 'scalar_cpu') is reused by a new
plain-W1 Submit-only native seam 'ingress::dispatch_shared_with_metered_w1'.
It retains all known Node context/owner checks and one actual
'ServiceMutationCpuDomain' for both complete W1 verification and M06 execution
and its scoped worker intervals. Results preserve the **original native
outcome** and return CPU settlement separately. An invalid Transcript/Product
cost still debits the owner; if live accounting becomes Unknown, no fabricated
credit or success is issued. The Node pins its first original CPU-domain
identity and rejects a later newly created domain for the same owner.

This seam is **opt-in**, and was not silently wired into other independently
versioned network profiles. It is tested for valid and invalid statements,
shared cloned budget, new-domain refusal and unchanged prior state; no cross-
process host owner, physical hard preemption or independently operated WAN
review has been executed. It does not close P1.

A separate optional direct-mapped math-only cache in
'trnm-crypto-primitives/src/pon_work/rejection_cache.rs' stores only
fully replayed immutable 'Transcript' or 'Product' failures. Bounds: 1..256
slots and positive TTL at most 30 seconds, with complete profile, challenge,
task, target and proof bytes bound in the key. Expired/poisoned/evicted entries
fall back to unchanged full verification. A hit invokes the caller's
cancellation checkpoint and can return **only a WorkError**, never
VerifiedWork, block application, task authority or chainwork. Present parent,
time, eligibility, and application context must still be verified by the
existing Node owner. Different bogus traces miss and still cost one full
replay each; a fresh false trace can still starve the original CPU budget.

The V3 'PublicServer::with_w1_rejection_cache' builder selects this option
explicitly. Its default is **off**; signed V3 policy identity, task wire,
W1/PNW1 proof bytes, target, W1 ticket/chainwork and runtime activation
remain unchanged. This is a bounded local optimization for repeated invalid
bytes, **not** a remedy for cheap novel false transcripts, Sybil identities,
or host-wide CPU fairness. Public rollout needs a separate reviewed
configuration/evidence scope.

### P5 W2-A concrete research outcome

See [the 512-leaf W2-A sampled Merkle prototype](W2_A_RESEARCH.md).
A real one-leaf-corrupted committed transcript escapes a small deterministic
sample, with normal-looking authenticated sampled openings. Hence this
scheme is not an accepted succinct proof, and no passing filtered statement
may grant consensus authority. W2-B/W2-C/P6 independent acceptance stay OPEN.
