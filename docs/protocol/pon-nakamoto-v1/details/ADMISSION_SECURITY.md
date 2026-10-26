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

#### Identity supplement implementation and preregistration draft

The new `public_v3_identity_churn` test target begins this existing PN1/I02
obligation; it does not replace either historical campaign. Its ordinary control
really constructs three different complete W1 packets, submits them through the
signed public TCP path and observes paid Work acceptance followed by `ROOT`.
Three proofs do not exercise capacity. The ignored
`real_paid_w1_identity_capacity_prefix` instead requests 4,097 actual distinct
packets through the same code, retaining the real owner observations. It is a
serial same-host capacity component, **not** the full sustained-service campaign.
The ignored selector has not been executed by adding or compiling this code.

Both use the original four legally executed seed blocks/1,024 signed transfers
and the next signed transfer (nonce 1,025) on h4. Only the reference State root
is changed. Each candidate receives a disjoint 4,096-nonce range starting at
`2,000,000 + index*4096`. The real generic producer is prepared once, then creates
each challenge's complete proof. Every target miss and producer error, actual
thread CPU or unknown sample, winner packet, ordinary/scalar-reference checks
and exact complete-packet identity remain in new create-only files. Changing the
client signing key is not a new work identity. Existing registry fields are
observed, never fixture-filled, evicted or reset by this test.

Local receipt namespace `public-v3-real-identity-prefix-v1` has these files:

| File | Required retained content and validation |
| --- | --- |
| `seed.json` | Actual encoded seed/template packets and aggregate preparation CPU; Node's unexposed preparation-search count stays null. |
| `plan.json` | Requested count, original policy ID, actual initially empty owner, one producer setup and component scope. |
| `NNNNN-started.json` | Index/template/nonce range, synced before search, so an interrupted construction cannot disappear. |
| `NNNNN-construction.json` | Every attempted nonce/ticket/trace/hit and actual CPU, including errors/exhaustion; complete winner bytes and identity, separately timed construction and verifier/encoding. Missing/mismatched indices, bytes, attempts or known CPU cannot pass construction validation. |
| `NNNNN-call.json` | Exact body digest/packet identity, real signed reply/error and client metrics/CPU, plus actual same-owner occupancy. Busy, timeout and refused calls remain in the denominator. |
| `report.json` | Joined receiver observations, real completion counters, closed CPU balance, live/cold integrity and component verdict. All service/hardness/WAN/activation qualifications remain false. |

The prefix alone supplies no source/binary collection wrapper or complete
campaign qualification. Its local files are not exact-commit qualification receipts.
The prefix's 1,800-second outer collection cap grants no additional per-request
deadline, start reserve or paid credit. Do not run a capacity experiment until
the enclosing clean-source/binary/resource collector and full preregistration
are reviewed. Existing native campaigns and historical failures remain intact.

The complete matched-cohort protocol is the next implementation slice within
this same obligation. These **draft** values must be reviewed and frozen before
any qualifying run; they are engineering budgets, not measured achievable rates:

- Retain 24 actors, two paid workers, 2 CPU-second burst, 0.25 CPU-second/second
  refill, 100 ms reserve, 2-second calls, 4-CPU/16-GiB host envelope and at most
  480 calls per actor across prefix and pressure. Proposed allocation is at most
  192 prefix calls plus 288 pressure calls per actor; 24*192 allows 4,608 offered
  prefix packets, not an invented count of verified identities.
- Every fresh namespace has the same real seed and prefix workload. Record the
  prefix's actual occupancy, credit/debt and elapsed time; at least 4,096 real
  full-work identities must be observed. Failure to fill within the proposed
  1,800-second cap fails capacity, with all partial work retained.
- After the prefix, retain the same live owner/credit. Run separate honest-only,
  replay-only and fresh-identity 30-second windows; replay actors reuse their
  actual prefix packets, while fresh actors construct a new packet for every
  offered call. Scheduling is closed-loop, with at most one unresolved call per
  actor and at most 288 pressure calls in 30 seconds. The 9.6 Hz arithmetic is
  only a mean cap, not an offered fixed arrival rate. There are no catch-up
  bursts or extra workers; every unoffered remainder and construction error is
  retained. Separate producer limitation from time waiting for an earlier call.
  Neither establishes receiver saturation without actual paid-depletion evidence.
- Retain t=1/5/9, three rounds, 21 real business blocks and independently imported
  depth-six confirmations within the original absolute window. Proposed pressure
  coverage is at least 90% in every honest round, with no nondepleted gap over
  one second; each round must additionally contain exact-body signed `ROOT` and
  Work/Admission rejection observations plus actual paid depletion. Sampling
  cannot impute depletion between missing samples.
- The full reader must reject direct table fixtures, repeated packets labeled
  fresh, missing/mutated attempts, source/binary/policy mismatch, credit resets,
  unknown or double-counted CPU, omitted honest failures, absent post-capacity
  rounds and inadequate offered pressure. It must compare hostile absence in
  live/cold history and join every original scoped worker before reconciliation.

The next source slice adds the independent `public_v3_identity_campaign` target:
24 actual test-binary subprocesses, matched namespaces/prefixes, the closed-loop
pressure controller, and ordinary t=1/5/9 history import/confirmation. Its raw
namespace is `native-public-v3-identity-churn-supplement-v1`; each phase retains
actor job/readiness/exit records, every slot disposition and construction/call
file, 50 ms read-only owner samples, before/prefix/pressure/closed CPU flows,
and hostile packet absence in live/cold history. Source/tree and actual executable
digests bind each actor; a parent-held owner prevents an epoch reset at the
prefix/pressure boundary. Actor and sample owners join even on error/unwind.

The full native selector is opt-in and has not run. Its separate two-process,
two-second control has zero honest rounds and cannot qualify capacity or service.
An independent collector/reader must check the complete raw record and conservative
credit-freshness bounds; point samples alone do not certify an intervening depleted
interval. Failed searches retain trace/ticket/CPU records, but not every complete
attempt's proof bytes: complete construction-cost qualification stays **UNKNOWN**.
Even a later finite service PASS cannot close that cost gate, restart/reconstruction
cohorts, independent operators or WAN acceptance. The current full supplemental
service verdict remains NOT_RUN/NO_GO; small controls cannot promote it.

The next local receipt profile, `public-v3-real-identity-prefix-v2`, additionally
retains all 49,188 proof bytes for **every** successful `prove`, including target
misses, inside the existing construction JSON. It reserves a complete 100-KiB
attempt and 128-KiB terminal/winner frame before performing another proof. A
construction is capped at 8 MiB; its stage bucket includes started, construction
and call files. A cap after a construction starts stops proof work and preserves
that started file, prior full attempts and an `evidence-cap` terminal; it cannot
pass. An actor must record not-started indices in a separately reserved stage
terminal if insufficient budget remains even to start; that full-owner route is
not yet implemented. Any I/O error poisons the byte owner, forbidding reuse.
The v2 writer counts
serialized bytes before streaming one temporary file, syncing once and publishing
it. It adds no per-attempt files or sync calls. The 32-MiB retained-data envelope
does not claim an observed total-process heap or VM limit.

The explicit three-proof v2 control has no capacity or service qualification.
The original v1 schemas, selectors, time limits and retained failure remain.
Full v2 collection stays closed until its remaining owned-process limits and
whole-artifact ledger are implemented and reviewed: 64-MiB prefix buckets for
all 72 actors, 96-MiB fresh-pressure buckets for 24 actors and 8-MiB replay-pressure
buckets for 24 actors total 7,104 MiB. The original **8-GiB total artifact** and
4-CPU/16-GiB resource boundaries remain; the other 1,088 MiB must cover the binary,
all SQLite sidecars, samples, metadata, logs and the inventory itself. These caps
are stricter local collection constraints; cap failures establish no work-hardness
result. Full raw proof replay also cannot prove global cheapest cost or a bound
on specialized hardware advantage.

The next v2 slice declares the complete 8-GiB ledger and separate owned-process
limits: 512-MiB actor address space from exec, 3-GiB native parent address space,
and 8/16-MiB per-file limits. The 24 actor envelopes plus native parent total
15 GiB, leaving the original 16-GiB cgroup authoritative for the whole run.
Seven fixed Node roots additionally reserve 1 MiB for zero-byte locks and bounded
initialization markers; a failed marker is preserved. A separate small native
probe can exercise file-cap errors, VM denial and real child reap. The full-v2
selector remains closed while actor/log/sample writers and the complete resource
receipt chain are unfinished. These are evidence collection limits, not a change
to the original PN1 workload, its retained failures or service acceptance.

The explicit short owned-process probe has exercised a real 8-MiB file-cap
failure, virtual-address denial and normal child reap in the original resource
envelope. A separate native initialization trace also observed the transient
`native.sqlite-journal` before WAL mode; a final three-file snapshot is therefore
insufficient to certify the complete SQLite I/O bound. Rollback/temporary-file
coverage is still required before full-v2 collection can open.

The separate v2 sample writer preserves complete rows in at most twelve 8-MiB
chunks per phase. It retains the original per-sample data sync and one final full
sync, with attempts and successes recorded separately. Rotation adds no sync;
cap, collision and I/O failure poison the owner and retain the first unpersisted
observation for a failed terminal. Its small negative controls are component
evidence only: the writer is not yet connected to the 24-actor controller, and
the 50-ms sampling schedule and original windows remain unchanged.

The separate v2 log owner caps combined actor stdout/stderr at 64 KiB and binds
termination to the actual child pidfd. A cap or I/O failure records observed and
retained byte counts, stops that child and joins both pipe readers; no log sync
is added. Small real-subprocess controls exercise normal dual streams and a
128-byte cap/termination/reap. This owner is still awaiting the full v2 actor
and controller connection. The original v1 direct logs and failed controls remain.

The v2 actor owner now connects the real h4 template, generic prepared producer,
full-attempt acquisition and original signed TCP calls to those byte owners.
It charges existing job bytes against a 448-KiB metadata budget and reserves a
separate 64-KiB failed-terminal slot inside the same 512-KiB actor total. A
construction cap, I/O failure or budget refusal stops future work/calls, records
the started or not-started index, and retains every planned slot disposition.
Producer setup, nested CPU clocks, replay of an actual prefix packet and the
original deadlines remain. Its metadata-failure control is not a real capacity
run; controller connection and the complete SQLite I/O boundary remain pending.

The new v2 controller source connects that actor to its exec-time limits, real
protected receiver, bounded dual pipes and chunked samples. It preserves the
original owner epoch, 50-ms schedule, 30-second pressure, two-second calls,
ordinary three rounds and live/cold hostile absence checks. Its phase owner
reserves 64 KiB for a failure terminal inside each combined 16-MiB phase bucket;
markers and the single unsplit report share the remainder. A cap/I/O failure
retains its first terminal, poisons that writer and cannot qualify. Sample errors
retain their first unpersisted observation; every child and pipe reader is joined.
This source connection has not executed a v2 actor campaign.

Before freezing or executing the full v2 plan, the three phase buckets were
reallocated from 8 to 16 MiB each. The unchanged 8-GiB artifact ledger now reserves
8,177.5 MiB and leaves 14.5 MiB unassigned. Earlier source descriptors and hashes
remain historical records; no observed cap failure was converted into a pass.
The parent per-file limit remains 16 MiB, so an oversized report still fails
rather than being split or given extra syncs. The full selector remains closed:
the top-level collector owner chain and complete transient SQLite file boundary
still need implementation/review. Neither component tests nor a new I/O profile
can close the original disk-backed control failure or claim full qualification.

The top-level v2 campaign source now installs the owned parent VM/file limits
before opening the first Node, charges preparation against its separate 8-MiB
bucket, and owns plan, process-limit, final Node inventory and report files. The
32-MiB root bucket is further partitioned into 1 MiB for those raw JSON files
(including a reserved 64-KiB failure terminal) and 31 MiB for the outer inventory;
the total ledger is unchanged. A failed phase stops later phases and preserves
their not-started dispositions. The v2 two-actor selector retains the original
control plan and assertions in a fresh namespace. Its separate local debug /
source-overlay execution completed in 28.751043894 seconds: two real actors
made six paid calls, all returned ROOT, and the identity owner grew from zero
to two after the prefix and six after pressure. An independent reader rebuilt
all nine complete attempted proofs (including three misses), reconciled
519891843 ns of paid receiver CPU, and checked cold SQLite copies and actual
parent/child termination. This is a finite component observation; the retained
v1 two-actor failure is still open. It proves neither capacity exhaustion at
4096 identities nor sustained post-capacity pressure, exact committed-source
qualification, minimum work cost, hardware fairness or service improvement.
Neither v2 campaign source nor these component observations enable full collection.
The independent outer writer limits and complete transient SQLite I/O boundary
remain unqualified, and the full selector still refuses to start.

The subsequent fresh `pn1-owned-sqlite-real-inode-v1` implementation has a
[finite native evidence index](../../../../evidence/pon-native-io-pn1-20261025/README.md).
It preserves two actual Node failures: trusted pool setup was missing first;
after correcting that prerequisite, ordinary cold reopen still latched xLock
3850. Error 10 in that later result is the subsequent sticky admission refusal.
A separately frozen reproduction observed a read-only descriptor's write-lock
attempt returning EBADF; that errno is not retroactively inserted into either
original log. Only actual read-only connections now configure and verify
NO_CKPT_ON_CLOSE before SQL access. Writer WAL/FULL and every lower error latch
remain unchanged. Final finite controls passed: ten VFS cases/89 receipt rows,
and actual Node writing, two public reads, real service termination and same-root
AuthV1 cold readback with 20 required files/27 complete healthy receipts.
They do not open the full campaign guard, qualify the private test reader,
produce 4,097 new identities or discharge the original service failure.

The same review found a separate known persistence dependency issue in bundled
SQLite 3.46.0: the official
[WAL-reset defect](https://www.sqlite.org/wal.html#walreset) affects concurrent
write/checkpoint connections. The generic safe factory permits that capability;
scoped single-writer/serialization arrangements do not certify all consumers.
A reviewed patched dependency and fresh ABI/native evidence are required.
Neither successful finite cold readback nor FULL synchronization disposes of
this race, and no historical corruption has been established here.

### 2026-10-26 source overlay and evidence boundary

The [dated compact evidence addendum](../../../../evidence/pon-native-io-pn1-20261026-addon/README.md)
preserves the earlier index, all original failures and the original PN1/I02
acceptance targets. Its 3.46 normal-C witnesses and finite PASS results qualify
only their frozen overlays; a later dependency graph needs its own evidence.

| Recorded scope | Actual retained observation | Boundary still open |
| --- | --- | --- |
| Held-directory native002 | Four actual Linux children/43 metadata/18 RootReceipt locations, with double rename/replacement and same-lease cold readback. Original001 is overall FAIL after MemoryError and missing final receipts; the 8,192-byte bucket-label defect remains explicit. | Logical byte/lifetime accounting is not a physical-block quota, original three-FD caller, full writer or public campaign. |
| Original VFS004 and Node005 | Ten VFS children/89 locations = 86 healthy + three original expected SQLite 13 cap refusals; the cap case remains 64 KiB. Ordinary Node 20/27 retains 4 KiB/WAL/FULL, two-second calls, single actual join and same-lease cold AuthV1 state. | Original Node 6b4 preparation failure is separate from actual 6b9 success; all results are on the old graph. |
| Six-file original harness bridge | Private held-output capability, exact seven role leases and four authenticated open sites; first-pass reservation plus fail-closed second-pass serialization. Strict-Clippy002, normal compilation, 13 units (11 retained + two stateful) and final formatting pass. | Strict-Clippy001 exit 101 and 13 ignored remain; native libtest child PID/birth is not separately retained, so collector identity cannot stand in for original caller qualification. Two copies of this diagnostic opt-level 3/debug 2 ELF do not fit the existing 192 MiB binary bucket; this is not a measurement of the original full selector's `--release` ELF. |
| SQLite source/graph admission and fresh failures | Seven exact rusqlite 0.39.0 pins, sys 0.37.0/SQLite 3.51.3, v2 normal-C fence and 155 resolved nodes. Actual normal001 exit 101/28.262877 s and normal002 exit 101/4.054297 s remain. After equivalent API adaptations, normal003 compiles with exit 0/6.614984 s; its sealed receipt binds actual cfg/v2 fence, four defined globals, 19 independently read-back static layout values and the 19,130,200-byte VFS ELF (opt-level 0/debug 2). | Normal compilation and read-only C witness inspection do not establish runtime ABI/control qualification. No actual new-engine native control has passed. Earlier 3.46 PASS does not transfer; release/security closure remains open. |

Keep these interfaces inside the existing I02 owner. The caller may pass only
its private, actually inherited output File and checked identity; public
receipt JSON cannot manufacture that authority. The held owner creates the
seven fresh roots relative to the original directory capability. It retains
their actual PID/dev/ino, slot/lifetime limits and one-use phase ownership;
no canonicalized path, receipt inode, fallback backend or reset substitutes
for those held objects. Miner, receiver, verifier and cold reopen consume the
correct original role lease. Actual service finish/join and connection close
precede terminal receipts and same-lease cold reopen.

The generic evidence writer must charge the full checked reservation before
second-pass File writes, bound each chunk, and preserve the first write/flush
error even if Serialize swallows it. A size mismatch or failed write cannot
sync/publish a successful result, refund partial bytes or unpoison subsequent
writes. Two stateful unit controls are finite evidence, not exhaustive panic,
I/O-fault or whole-campaign accounting qualification. Missing actual child
identity, terminal records, complete root receipts or source/fence binding
continues to reject the corresponding qualification.

The earlier 178,353,576-byte ELF was a diagnostic build with debug 2 and
assertions/overflow checks enabled. Retain its exact bytes, duplicate-copy
accounting and failed budget observations. The unchanged original full caller
instead requires an actual `--release` no-run build with opt-level 3/debug 0,
assertions/overflow checks disabled and test true, followed by exact compiler
profile and source-binding review. Its ELF size is not yet measured. This is
the existing caller preparation, without stripping/deleting diagnostic evidence,
relaxing a cap, enabling the full guard or bypassing clean-source admission.

The next gate is the new engine's actual normal-C ABI witness and unchanged
three finite control families. Then qualify every outer writer, the legitimate
original three-FD caller and the independent strict reader before any full
selector. Only after those gates may the frozen 4,097 complete identities
crossing the 4,096-entry paid boundary and fresh 24-actor pressure/service
profiles execute for acceptance. Preserve the original 8 GiB and every bucket,
3 GiB AS/16 MiB FSIZE, 4 CPU/16 GiB, two-second calls, three 30-second pressure
windows, proof/CPU/depletion/confirmation assertions and all failed/ignored
observations. Full guards remain false.

The original LAN setup3 stopped at 00:04:53Z with
`FAIL_UNRESOLVED_CHILD_TERMINAL`, not a completed 72-hour observation. Its final
elapsed time is 6.586268785 hours; seven samples/14 cold hops are only the last
successful checkpoint. Missing listen/terminal receipt plus SSH 255 retains
the original unknown 1 GiB ledger charge and unknown remote native termination.
Later reachability over the existing Tailscale alias and an unavailable old
temporary root do not establish reboot or resolve that original terminal.
This failure closes no independent-administrator WAN, goodput, model-loading,
release/custody/repair, ordinary three-upgrade or Windows isolation obligation.

### Controlled 3.51.3 SHM compatibility and finite readback

The [three-family source-bound increment](../../../../evidence/pon-native-io-pn1-20261026-addon/sqlite3513-compat-three-finite.json)
preserves the original new-engine VFS failure (10 real terminals, three
5386/SHMMAP failures, 80/89 required receipts). The pinned upstream's WAL
recovery can pass state 2 directly as the extension argument. The wrapper's
admitted state domain is now exactly 0/1/2; both nonzero states reserve all
rounded bytes before delegation. Unknown and negative states, oversize growth
and extra objects retain their original refusal and sticky-error behavior.
No direct runtime argument trace is claimed.

After that two-predicate fix, original VFS 10/89, Node 20/27 and held 4/43/18
finite controls actually passed with real terminal and complete source/build/
executed-image readback. The original three expected SQLite 13 cap refusals
remain in VFS's denominator; Node keeps the original two-second calls,
256 transfers, one retained proof, zero new W1, single join and cold AuthV1
readback. The independently reviewed results qualify only those local Linux
controls. Workspace/all-targets compilation and seven-consumer strict Clippy
also pass. All original failed artifacts remain; the held database's 8,192
bytes are still charged to the stricter provenance bucket rather than the
SQLite label. Full writer/caller/reader, original release-profile preparation,
full paid-identity attack, Windows, model/release/custody and WAN gates stay open.

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

The original release-profile no-run build now actually passes (2026-10-26T03:18Z): exit 0 in 268.031 seconds, exact opt-level 3/debug 0/assertions false/overflow checks false/test true, and an actual 10,134,904-byte ELF. Its two-copy arithmetic is 20,269,808 bytes, within the unchanged 192 MiB bucket. The root independently rechecked the ELF, both original streams, the actual durable terminal and all 22 before/after source pins; no monitor violation or owner error occurred. The separately documented 178,353,576-byte diagnostic ELF and every failed build remain historical evidence. This new result removes only the release-build/profile/size preparation blocker: no lawful prepared bundle or execution copy was created, and the original three-FD caller, whole writer, strict reader and full 4,097-identity acceptance remain unqualified. No full guard, deadline, assertion or budget changed. See the [original release-build compact receipt](../../../../evidence/pon-native-io-pn1-20261026-addon/sqlite3513-original-release-build.json).


### PN1 / I02: public finite three-FD preparation and readback candidate

The existing PN1/I02 sequence gains a separately named finite component entry.
It does not enable or change the original V1/V2 full route, Plan, assertions,
deadlines, Windows groups, pair steps or resource and evidence limits. The new
profile and prepared/inventory/claim/dispatch/execution/readback domains use
`pn1-native-io-three-fd-component-v1` and the corresponding
`pon-native-io-three-fd-component-...-v1` names.

| Interface | Contract and next owner |
| --- | --- |
| [Public collector](../../../../scripts/run_pon_native_io_component.py) `prepare` | On the ROG-integrated clean committed source, require exact head/tree, original Nice 10 / four CPU / 16 GiB, a fresh disjoint held build target and output. Actually run the locked offline original release no-run build, capture the compiled executable through the same held target FD, and seal original streams, source/resources, origin identity and inventory. No supplied success flag or old ELF can substitute. |
| Same collector `execute` | Consume that real preparation once. Bind its original parent/root/leaf identity and stable claim key, retain both physical binary copies under the original 192 MiB aggregate, and pass exactly executable/output/source-cwd FDs. Run the new exact ignored selector through the existing native-I/O `Plan::control()` path; record actual parent PID/birth/wait and original descendant FD/terminal evidence. |
| [Independent component reader](../../../../scripts/ci/check_pon_native_io_component.py) | Require pinned preparation and execution inventories plus the retained original claim; reject unknown/missing/partial/cap/error outcomes. Reconstruct all retained complete W1 attempts, actual calls/CPU balances, two actors and their FD bindings, three actually used healthy closed roots and private-copy SQLite cold history. It does not open producer databases for repair. |
| [Counterexamples](../../../../scripts/ci/test_pon_native_io_component.py) | Retain real rename/copy/replacement, unreadable-tree, inherited-input, actual birth/wait, failed-start pipe cleanup, terminal-write and held-artifact controls. Synthetic byte fixtures only exercise capture; they are never executed or used as public preparation. |

Implementation order remains PN1/I02: ROG reviews and commits the complete
collector/selector/reader/tests delta on the existing branch, then a caller
actually invokes public `prepare`, pins its returned documents, invokes
`execute` once, and runs the independent reader. Only those actual results can
close this finite mechanism prerequisite. An isolated compilation, a passed
mechanism unit test or an internally consistent fabricated bundle cannot do so.
The trusted local operator, chosen toolchain and pinned input receipts remain
explicit assumptions; hashes and local process records are not host attestation.

Acceptance keeps the original control Plan: two actors, one prefix plus two
pressure calls each, prefix 30 seconds, pressure two seconds, call two seconds,
readiness 180 seconds and cleanup five seconds. The outer finite collector is
fixed at 180 seconds and its build child at 1,200 seconds. The original AS/FSIZE,
three physical-domain eight-GiB ledger, all bucket limits, synchronization and
first-error accounting remain. The separate six-GiB build target with 512 MiB
reserve is conservatively monitored, not a physical block quota or instantaneous
peak proof. Directory replacement or unknown scans fail; limits are not raised
and charged partials are not refunded.

The finite reader must prove two prefix and six final unique paid work identities,
not a 4,096-entry exhaustion result. It actually uses roles 0/5/6: miner, fresh
receiver and independent client. Seven registrations are not seven exercised
Nodes. All full-writer/full-caller/full-reader/full-4,097, model, Windows, WAN and
merge qualifications remain false. The next original acceptance still requires
the complete whole writer, original caller and strict reader, followed by the
unchanged 4,096 plus fresh sustained 24-actor workload.

At this source admission, twelve finite mechanism counterexamples pass locally
under a repository-portable loader. The Rust selector format check passes.
Public prepare/execute/readback, compilation of the added selector on a clean
committed source and exact-head required CI are **not yet run or qualified**.
The original warning-bearing attempt and all earlier failures remain retained.
Nice-19 mechanism controls do not qualify the Nice-10 public resource contract.


2026-10-26 PN1/I02 review follow-up (V15 → V17; original acceptance unchanged):
ROG review found that the new component owner's stream loops overwrote the step label;
a real child/writer counterexample recorded the erroneous member name
`build.stderr.log.step.json` in the retained RED log and failed the required
`build.step.json` lookup. Its temporary fixture files were not preserved. Keep the step label separate from
stream member names for both build and component execution. An independent review
also found that the component reader called the original full-reader limit validator,
although the actual native installer honestly writes `full_ledger_implemented=false`.
Use a separate finite-component validator that requires that exact false value and
preserves every original schema, role, typed PID, cgroup, address-space and file-size
assertion. Do not mutate receipts, set a full flag true, weaken the full reader, or
claim the false full-ledger field as full qualification. The unchanged twelve mechanism
cases plus two new counterexamples passed after correction; the original RED and all
prior receipts remain retained. These Nice19/AS1GiB mechanism observations are not
public Nice10 preparation/execution/readback, full-writer/strict-reader, 4096+fresh,
Windows, model-upgrade, WAN, or merge acceptance. A clean committed corrected source
and its actual public preparation → execution → independent readback are still required.


2026-10-26 PN1/I02 complete-review follow-up (V18; original acceptance unchanged):
The revised ROG V15 ACK identifies four findings. V17 addressed R01 (step label)
and R04 (finite/full resource discriminator); its local resource-fix label must
not be confused with the ACK's R02. V18 addresses that R02 by retaining bounded
failure context when real stream or step publication fails after a child has
terminated: original child error, actual return code, PID/birth/parent/wait record,
observed stream lengths/hashes and the publication error remain distinct. Error
prefixes are bounded by their ASCII JSON representation, with explicit truncation.
The original terminal reservation, first writer failure and partial charges remain;
no physical ENOSPC guarantee is added. Claim termination uses an actual step or the
same component/profile failure context only after the original owner validator
accepts the recorded terminal; missing, aliased or unknown ownership stays unknown,
and native success and full qualification are never promoted by a publication error.
Actual read-only reserved descriptors produced kernel EBADF in the real ComponentIO
write path after a nonzero child and a timed-out/reaped child. Both original RED
observations and corrected finite passes remain retained; these are controlled
storage faults, not a real disk-full or public claim execution qualification.

ACK R03 restores the original finite actor schema/worker/source/tree/binary,
setup_calls=1/prepared-generic producer and typed metadata checks, and the original
completion-work domain/capacity/epoch/counter validation before finite 0/2/6 checks.
A separate test module serializes and rehashes the same 61 synthetic fixtures;
its original 60 negative assertions failed before correction and are rejected after
correction. Its positive fixture reaches only the unrelated FD replay sentinel:
these are predicate controls, not native, complete-bundle or signed authenticity proof.
The combined four-module check passed nineteen mechanism/predicate tests with all
fourteen preceding test bodies unchanged. Nice19/AS1GiB diagnostics, rehashed
fixtures and retained failure context do not qualify public Nice10 preparation,
execution and readback, whole writer/strict reader, seven actual roots, the original
4096+fresh workload, Windows, three model rounds, independent WAN, or merge readiness.
A clean committed corrected source and all original required executions remain due.


2026-10-26 PN1/I02 first real public preparation failure and bounded monitor correction (V19):
The first actual clean-source public prepare on ec0acdff5717b8f584b26f30f1162bd9bf1cc888
(tree 49de9450a7738b15f3dc63b808f957ce49804df2) failed. The real Cargo child
PID 1404396 / birth 8179665 / parent 1379349 was reaped with wait -9 after
62.971600613 seconds; the complete owner used 88.91997036199609 seconds.
The original 1200-second build bound did not expire. Actual source and Nice10,
400% CPU, 16GiB and four-CPU observations were retained. No prepared document,
execution or independent readback was produced. Original stdout/stderr, step and
terminal records remain failures. The sender and cause of SIGKILL are UNKNOWN:
normal compiler-progress logs and the limited journal/kernel lookup do not prove
or exclude OOM, an external stop, or a monitor stop.

An independent controlled reproduction against immutable ec0 source found that
real unlink and rmdir between enumeration and stat/descent abort the original
monitor with ENOENT; the same watch fault kills a real owned child. Those three
original RED observations establish a defect, not the cause of the earlier build.
The correction restarts the entire held-tree scan only for internal ENOENT, under
the same single five-second deadline and cumulative 200,000-entry bound, retaining
partial observed logical peaks. It does not skip a disappeared entry and accept
an incomplete scan. Missing or replaced top roots, permission errors, symlinks,
FIFOs, other unknown objects, persistent churn and cap overruns remain refusals.
The original 6GiB target / 512MiB reserve and watch interval are unchanged.

The monitor retains its first bounded typed error, observed retries, actual owned
child wait and kill attempts alongside the original first writer error. A later
NONZERO or terminal-publication refusal cannot promote success or erase these
observations. The mandatory prepared monitor record uses fresh stored schema
`pon-native-io-three-fd-component-prepared-v2`; build-specific failure diagnostics
use `pon-native-io-component-owned-build-step-failure-v2`. The profile, claim domain,
original execution failure schema, selector, native/full acceptance and all caps
remain unchanged. Logical sampling is not a physical or instantaneous quota.
New tests exercise actual filesystem changes and owned child termination; they
cannot qualify Cargo preparation, one-shot execution, complete-bundle readback,
full-writer/strict-reader, seven roots, 4096+fresh, Windows or model/WAN acceptance.
A new clean committed source and the actual public prepare → execute → independent
readback remain required. Any new-source attempt must retain the first failed
owner's spent budget; no unchanged-head retry, fake prepared record, old binary,
fresh budget reset or discarded failed target is allowed. Full guards and merge
readiness remain false, and the existing PN0–PN6 acceptance stays in force.

On the fixed V19 source, all seven added controls passed in 6.050 seconds.
The final combined five-module run passed all twenty-six tests in 6.578 seconds
(owner 7.094219090 seconds); the two original test files and all original nineteen
test bodies remained byte-for-byte unchanged. All five actual ec0 helper sources
and every current candidate Python pin were checked before and after. These are
bounded Nice19/AS1GiB controls, not a successful public build or any full acceptance.


### PN3/I09–I10 cold runtime namespace and authority boundary (2026-10-26; OPEN)

The existing selected-release path must receive a complete, explicitly versioned
runtime identity and an owner-admitted private held runtime/material namespace.
The current fixed eleven-material verifier authenticates its stated bytes; it does
not attest the interpreter/stdlib/native dependency graph, preserve every ancestor
until the HF path reopens it, or mint CURRENT/FinalUse/installation authority.
Keep the old eleven-role/300MiB base limits and all existing permissions unchanged;
new stored or signed runtime contracts require fresh namespaces and exact checks.

The same owner must reserve and retain every overlapping cache, DB/WAL/SHM,
installed/staging tree, archive/extraction scratch, old/new version, metadata and
held/unknown object inside its original controlled-root budget. A separate pathname,
unlink, failed SSH connection or hash verification cannot create a refund. The old
923MB observation is a RECORD pathname sum; the432MB shared library is already in
it, the512MiB cache bound is a different measure, and the300MiB bound applies only
to fixed base roles. Pocket's original UNKNOWN1GiB is NETWORK reservation, not disk.
Preserve its charge and the original failed/frozen LAN admission; no replacement
provider, new budget or disk-free claim follows from this clarification.

The actual interpreter/import/HF opens must stay bound to the admitted identity and
namespace. Refuse missing libraries/wheels, undeclared ambient or online imports,
ancestor replacement, premature eviction, permission/full-disk/crash failures and
unknown terminal. Keep original resource, selector/CURRENT, FinalUse, Ready,
cancellation, shutdown/actual-child and reconciliation checks. Data download or
forward completion never substitutes for install authority or OS-child terminal.
The ordinary I10/next-task route and three actual parent/train/evaluate/download/
install/readback rounds, with a separate benefit decision, remain required.

The original eleven-object SQLite I09 and signed native case retain their limited
preinstalled-runtime PASS while the overall I10 handoff remains FAIL/UNVERIFIED.
The original35-second material cohort does not certify full cold runtime acquisition.
Do not extend any original timer, role, quota or assertion to obtain green output.
Keep original three-replica custody/repair/version retention and independent
three-administrator/fault-domain72hWAN acceptance. Same-administrator LAN cannot
prove these. Full cold runtime and production/merge readiness remain false.
See [cold-release evidence](../../../../evidence/pon-upgrade-implementation-20261018/native-rounds/cold-release-contract-20261026/REPORT.md) for exact source, original raw scopes, units and pending interfaces.

Retained V19 [original failed preparation and integrated bounded controls](../../../../evidence/pon-native-io-pn1-20261026-v19/README.md)
include the additional source-check diagnostic timeouts; none closes public or full qualification.

PN1 / I02 opt-in component-v2 [real-Header 64-reuse source diagnostics](../../../../evidence/pon-w1-real-header-64reuse-source-20261026/README.md)
retain original failures and all fixed limits. One fixed setup precedes64 sibling
Headers under one real parent; this does not qualify64 parent advances, public
work hardness, all kernels, hardware parity or the4097 paid denominator. Unknown
EOF/descendants and any original/cleanup failure remain refusals. The final
first-error correction has a partial injected control only; strict Rust Clippy0
is not a qualifying native/source-to-binary/whole-owner execution receipt.
