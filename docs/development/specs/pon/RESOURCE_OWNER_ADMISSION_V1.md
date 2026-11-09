# Local resource owner admission V1

## Status and scope

This is an explicit local resource-accounting candidate. It does not change
the signed `public-protected-development-v3` r14 contract, PNW1, packet
validity, ledger authority, or the original host/service acceptance profile.
Production qualification remains **HOLD_NO_GO**.

The first implementation scope is a durable hash-chained append journal, a
guarded native observer API, and an opt-in observer CLI integration. Legacy entry
points remain separately identified below. An optional wrapper does not prove
that every public, local, or concurrent caller is covered.

The original source reviewed for this work is PR #812 at
`7e044b65454f4c9ea505591727332acffb33e7e5`. PR #802's observer envelope at
`cc09d6dc311596a9d9a45c64e9392caff4a75c0b` is a separate reference, not an
assumed ancestor or an execution result for this candidate.

## Owner and authority

One original Node path selects `resource-owner-v1.journal` and the explicit
`pon-local-resource-owner-v1` profile. Process IDs, listeners, connections,
caller keys, and operation
IDs do not select fresh accounts. Concurrent cooperating processes must use
the same locked journal and durable admission transition. Opening it again preserves
spent amounts, reservations, unknown outcomes, profile identity and record
capacity. A process restart grants neither a new initial allowance nor refill.

The profile is trusted local configuration. Selecting a lane is accounting,
not proof of task funding, caller authority, economic independence or honest
behaviour. A future network integration must derive committed and recovery
entitlement from its original authenticated operation; an untrusted request
must not select those lanes merely by naming them. Cookie possession, a valid
PQ signature, and complete W1 each establish different facts and do not alone
establish that entitlement.

`ResourceOwnerV1::initialize` is explicit trusted local provisioning. It
requires an existing private owned Node directory and holds its original
`owner.lock` exclusively during adoption. Existing, partial or corrupt journals
are not overwritten. `ResourceOwnerV1::open` never creates or replenishes one.
The framed journal retains sequence numbers, previous-frame digests and exact
canonical bytes, with a fixed size/record cap. A malformed or torn suffix
refuses further use; it is not silently truncated into a fresh account.

Canonical path aliases resolve to the same owner and principal. Journal and
native-database symlinks/hard links are rejected. This is a trusted same-UID
local API; it does not claim to exclude every hostile directory-renaming race
or to authenticate an arbitrary writer who controls the whole directory.

This first scope controls cooperating entry points on the same original Node.
Copying or replacing the entire Node directory, reverting all local durable
state, or running outside the guarded API is not prevented by the local
journal. Host-wide coverage requires the original fixed resource tree and
enforced entry-point ownership. Freshness against complete local rollback
requires an independent state anchor. No such qualification is inferred here.

### Separate namespaces

The local profile and stored schema have fresh versioned identities. They must
never reuse an r14 signed domain, reinterpret an old account, or silently
migrate an existing database. A profile mismatch refuses before dispatch.
Changing capacities, lane semantics, deadline interpretation or settlement
rules requires an explicit successor or authorised migration contract.

The existing public profile is preserved byte-for-byte. Receiver binding stays
in local admission tickets; it must not be added to the global consensus work
challenge.

## Finite resource classes

| Lane | Purpose | Required boundary |
| --- | --- | --- |
| Bootstrap | Untrusted or newly admitted work | One finite aggregate allocation across identities and listeners; no fixed free share per new identity. |
| Committed | Previously authorised, reserved service work | Finite dedicated CPU and byte allocation; future network callers require an independently verified entitlement. |
| Recovery | Reconciliation, settlement and cleanup of an original operation | Finite dedicated capacity that ordinary bootstrap work cannot consume. Recovery preserves the original operation binding. |

The first owner accounts CPU nanoseconds and cumulative charged bytes.
Retained memory, socket count, output buffering, PID count and worker count
remain separate physical limits; cumulative byte accounting is not a proof of
resident-memory bounds. Explicit dispatch and cleanup reservations protect
capacity before work starts. No lane can borrow another lane's allocation by
changing caller identity or reopening the owner. V1 has no automatic refill or
manual top-up operation; authorised replenishment `F` is zero throughout V1.

Finite record capacity is part of the contract. The owner must refuse a new
operation when its durable capacity is exhausted rather than silently evicting
unsettled or replay-relevant rows. Expiry alone does not make an unknown cost
known. This refusal is a service failure, not evidence of liveness.

## Immutable operation and lifecycle

Admission binds the following original values:

```text
owner/profile identity
operation ID
request digest
parent state
absolute deadline
lane and dispatch/cleanup reservation
```

The concrete structures are `ResourceProfileV1`, `ResourceRequestV1`,
`OperationBindingV1` and the non-cloneable `ResourceReservationV1`. The request
also binds `recovery_of`: a recovery reservation must name an original
unsettled operation. Class-local CPU/byte grants, maximum in-flight counts and
retained-record capacities are independently fixed by the profile.

The tuple is fixed before dispatch. Reusing an operation ID with changed
values refuses; an identical retry must not dispatch twice or refund twice.
Caller-supplied identifiers do not establish native request correctness: the
guarded caller must derive the request digest and parent from the actual
request it will execute, and preserve the original deadline.

| Transition | Required durable/resource behaviour |
| --- | --- |
| Admit | `reserve` checks profile, tuple, capacity and remaining allowance under the journal lock; persists dispatch and cleanup reservations before returning `AdmissionV1::Fresh`. Identical retries return `AdmissionV1::Existing`, which grants no dispatch. |
| Dispatch | `claim` or `claim_existing` durably changes `Reserved` to `Running` once. A retry or concurrent process cannot obtain another execution grant. Native validation also requires the particular returned handle to have claimed the operation. |
| Progress | Keep original CPU/byte accounting. Nested phase observations must not be charged again on top of the full owner plus worker interval. |
| Cancel or crash | Preserve the unsettled reservation or unknown outcome. A cancellation request is not proof that workers stopped. |
| Settle | `CompletionV1` requires worker termination, effect readback, cleanup completion and a nonzero receipt digest. `ChargeV1::Measured` records the complete supplied measurement; `Conservative` consumes the full original reservation. Preserve actual native outcome independently of accounting success. |
| Reopen | Retain all prior charges, reservations and unknown outcomes. Do not reset allowances, record limits or original deadlines. |

Reserve and claim events retain a nondecreasing `clock_floor_unix_ms`.
Backwards supplied timestamps refuse fresh work; reopening does not reset the
floor. Existing-status reads and conservative reconciliation grant no fresh
deadline or refill. This detects local observed rollback; it does not prove
that caller-supplied wall time is authentic or that all durable state is fresh.

Unresolved `Reserved` and `Running` records retain their entire principal;
there is no fabricated terminal success on Drop. Conservative reconciliation
can close either state after independently establishing the completion facts.
A reserved operation cannot obtain a measured refund before it was claimed.

Settlement must not label an unmeasured interval as zero. Failed clocks,
missing worker intervals or failed durable settlement keep the operation
unresolved. A representable measured overrun is retained as charged debt and
fences new admission in every lane, including recovery; original conservative
reconciliation remains callable. The overrun is not discarded or converted to
spendable overshoot. A committed native effect
with unknown accounting remains committed with unknown accounting; it must
not become a clean rejection that encourages an unsafe fresh-ID retry.

The local API's settlement facts are supplied by its trusted integration.
Their presence in a receipt does not independently prove that all workers
were stopped or an effect was read back. Each integrated native path must
obtain these facts from its actual execution owner. Whole-process termination,
scoped-worker joins, authoritative effect inspection and cleanup checks cannot
be replaced by an untrusted caller's assertions.

## Accounting invariant and overshoot

For each supported resource, sum the lanes' settled charges `C`, outstanding
execution reservations `R`, cleanup reservations `K`, and original allocations
`G`. Let `F` be replenishment, which is zero in V1. The intended bound is:

```text
C + R + K <= G + F + bounded overshoot
```

Admission is a durable accounting check. It does not by itself enforce the
physical cost of arbitrary Rust code after dispatch. The first finite profile
does not infer replenishment from a process restart or wall-clock advance.
Any later refill mechanism must preserve one authoritative watermark and
accounting identity, including crashes and clock rollback.

Every new admission must fit its own lane's original allocation without using
overshoot. V1 retains full outstanding reservations until terminal settlement;
it does not sample or incrementally meter CPU itself. A trusted adapter either
supplies a complete terminal measurement or conservatively consumes the whole
reservation. `within_declared_accounting_bound` compares the aggregate ledger
amount against total grants plus one declared overshoot allowance. It is a
diagnostic accounting flag, not a physical cost certificate. Both
`physical_resource_bound_qualified` and `honest_service_bound_qualified` remain
false.

There are three distinct quantities: initial allocation, maximum retained
credit, and overshoot. An unused reservation is not additional credit. When
measured CPU is charged against an operation, its unconsumed reservation must
decrease consistently; live charges and terminal residuals must not count the
same CPU twice. Likewise, phase timings are diagnostic subdivisions, not new
billable intervals added to the outer owner and its actual scoped workers.

A physical overshoot argument must include all concurrently running workers,
the largest nonpreemptible section after a check, measurement resolution and
the final control/cleanup work. A conditional engineering expression is:

```text
overshoot <= sum(worker nonpreemptible work + measurement gap)
             + control tail + cleanup tail
```

Every term requires a bound for the actual implementation. W1 progress
callbacks are cooperative observation points; deep State/root and SQLite
operations are not made preemptible by this ledger. An unknown cost does not
become bounded merely because a reservation remains held.

The fixed cgroup parent can impose an aggregate CPU upper limit on its actual
descendants. Its quota period, scheduler behaviour, memory/PID limits and
coverage must be retained when interpreting short-window observations. The
nominal 0.25 CPU rate is not a zero-overshoot theorem. No new physical bound is
claimed without measurements and justified maximum sections under the
original resource profile.

## Honest service: conditional lower bound

A resource cap alone supplies no positive honest-service lower bound. Three
reserved lanes prevent one kind of accounting interference, but do not alone
implement a scheduler or guarantee that the host will provide CPU on time.

A future cost-based scheduler may use DRR-style deficits in CPU/byte units.
Its accounting must charge actual cost and retain debt. Request counts and
per-key queues are insufficient: one sender can use many identities, and
different requests have different costs. RFC 8290 provides a byte-scheduling
precedent, not a proof for this CPU service.

For a defensible conditional contract, assume an already admitted committed
operation has maximum complete cost `c`, preceding admitted work `W`, and
actual committed-class service supply at least `r * max(0, t - L)` while
backlogged. A FIFO cost-service bound is then:

```text
completion delay <= L + (W + c) / r
```

Input/output transfer and external dependency delays require their own bounds.
The premise needs positive actual host service, bounded nonpreemptible
interference, bounded admitted queue depth and a total cost envelope covering
verification failure, native State, output and cleanup. It also needs bounded
recognition/authentication of committed service: a reserved execution lane
cannot help a request stuck indefinitely behind bootstrap authentication.

This is a conditional statement, not an achieved lower bound for the first
integration. An enum label or valid W1 does not identify an honest request.
Current completion priority after full W1 can include work that later fails
State verification. No unconditional open-network newcomer service guarantee
or Sybil-resistance result follows from this profile.

## Entry-point coverage

The following table records the first integration boundary. Native execution
results belong in the evidence record for the tested commit; this contract
does not infer a passing run from source inspection.

| Entry or stage | First candidate scope | Outstanding qualification |
| --- | --- | --- |
| Guarded native resource-owner API | `ResourceOwnerV1::{reserve, claim_existing, observe, snapshot, reconcile_conservatively}` and non-cloneable `ResourceReservationV1`. | Callers must provide actual immutable request bindings, total measurements and trustworthy termination/readback/cleanup facts. |
| Native packet observer | `observe_existing_packet_owned` consumes the exact claimed reservation, verifies packet bytes/contract and actual active parent, then reads the original bounded private snapshot. | Direct library callers still need a process envelope; the API leaves terminal settlement to the supervisor. |
| Opt-in observer CLI | `resource-owner-init` provisions explicitly; `packet-status` with the complete `--observation-resource-*`/operation/parent/deadline/packet bindings reserves before reading packet bytes and spawning the bounded child. The adapter uses Bootstrap only. | Aggregate invocation, crash, cost and honest-service observations remain separate evidence. Failed/unknown child results keep the original reservation. |
| Cookie issuance, PQ handshake/signing | Existing public path; no all-path successor integration claimed. | Charge preparation, verification/signing and output under the common owner. |
| Length parsing and body reception | Existing public connection/body bounds remain. | Common durable CPU/bytes admission before expensive stages; bounded admission overhead. |
| Complete W1 and native State | Existing native checks remain unchanged. A local guard can surround a participating call only. | Enforce the same owner at all public/library entry points, with worker and nonpreemptible cost coverage. |
| History, Growth and snapshot readers | Only the explicitly integrated observer entry is in first scope. | Route all readers through the same account; retain original byte/work/deadline limits. |
| Concurrent listeners, CLI and direct local calls | Durable account coordinates cooperating callers of the guarded API. Adopted stores reject the ordinary cold packet-observer entry and unbound `packet-status`; adoption shares the original Node lock. | Other public/History/Growth/library paths and copied Node directories are not all covered by this observer adoption. |
| Output, cancellation and cleanup | Reservation and terminal conditions are represented by the local contract. | Actual integration must measure all work, prove worker termination and read back effects before refund. |
| Host resource tree | Existing fixed parent requirements remain. | Demonstrate actual membership and total consumption across all processes and ingress paths. |

Journal open/validation, hashing, admission parsing and journal writes also
consume resources. A per-operation reservation does not retrospectively pay
unbounded work performed to reach admission. Their enclosing host/bootstrap
budget and maximum work remain part of the full integration obligation.

### Observer selection and settlement

The owned `packet-status` selection requires all of:

- `--observation-resource-profile-sha256`;
- `--observation-operation-id`;
- `--observation-parent-state`;
- `--observation-deadline-unix-ms`;
- `--observation-packet-sha256`.

The contract also binds backend, worker count, snapshot-byte limit, process CPU
limit, wall limit, optional logical time and the actual native context. The
first adapter accepts bounded packet files in the supported local development
contexts, not an implicit fallback for unsupported owners or input modes.
The parent verifies and freezes the actual packet after admission; the child
and native entry verify the same complete digest. The original deadline is
preserved. A direct internal worker invocation must claim a previously reserved
operation and still installs the same process CPU ceiling.

After a successful bounded child result, the supervisor requires child exit,
private-directory cleanup and exact native receipt bindings, then uses
`ChargeV1::Conservative`. It does not infer a measured refund from low elapsed
time. A failed child, missing receipt, timeout or uncertain cleanup leaves the
original hold. Its declared byte principal is not a measurement of every
SQLite reread, and its process CPU envelope does not prove coverage of all
supervisor/admission work or the entire host resource tree.

## Rejection-cost measurement matrix

Keep the original W1 relation and target. Include a legal native control and
distinguish repeated packets from novel packets for every applicable arm.

| Input class | Required native outcome | What it measures |
| --- | --- | --- |
| True transcript, false canonical product | Product rejection; no State effect | Product-screen opportunity and the cost still paid before rejection. |
| True nonzero product, false transcript digest | Transcript rejection; no State effect | Full transcript replay cost that a product-only screen cannot remove. |
| True W1, false State root | Complete work verification followed by root rejection; no invalid effect | Downstream rejection, settlement and cleanup after W1 success. |
| Novel bad-packet stream | Original account retains cumulative costs and refuses further dispatch when exhausted | Cache-miss workload dimension, not a separate mathematical failure relation. |
| Legal control | Actual expected native outcome | Honest delay, original deadline, resource use and effect readback under the same workload. |

Changing a header State root changes its work challenge. The third arm needs
a freshly valid W1 for that changed header; mutating a previously valid packet
without recomputing work does not test downstream State rejection. Preserve
preparation/acquisition costs and unsuccessful ticket searches when comparing
attacker and receiver costs.

Record source/profile/provider/executable identity, lane, packet novelty,
precheck result, replay count, cache hits/misses, owner-plus-worker CPU, bytes,
wall time, memory, reservation state, unknown costs, actual effect readback,
worker termination, cleanup, and honest queue/deadline/outcome. Phase timing
must not be added a second time to its enclosing CPU interval.

The existing primitive rejection benchmark, native State-root regression and
PR #802's distinct-product campaign are prior evidence with their own scopes.
They must not be renamed as results of this candidate. Failed observations,
timeouts, cancellations, missing samples and exhausted searches stay in the
record. Original 0.25 CPU / 2 GiB / zero swap / 256 PID / 4-second / 16-hostile
acceptance is unchanged; a separate longer pressure experiment cannot replace
it.

## Screening and proof backend boundaries

For fixed nonzero `D = AB - C` over the actual finite field, a uniform
independent receiver vector sampled after the complete packet is fixed gives
`Pr[D r = 0] = q^(-rank D) <= 1/q`. Independent repetitions multiply the
probabilities. If `C = AB`, every vector passes even with a false transcript.
RNG cost and failure are themselves bounded admission work. Public
hash-derived vectors need a separate grinding and quantum-search analysis.
No product screen replaces full W1 or proves PQ128.

For 512 committed tiles, one wrong tile and 64 distinct uniform samples leave
miss probability `448/512 = 87.5%`. Original PNW1 does not supply a locally
openable tile commitment. A new tree must bind the ordered tiles, their
dependencies and the original ticket's final digest; independent commitments
do not establish their relationship. Sampling needs a distance/robustness
argument or a complete proof before it can replace replay.

WHIR's published 360-microsecond / 63-KiB example concerns a particular
100-bit polynomial commitment. It is not a complete W1, PQ128, restricted-host
or latest-failure result. Compare complete statement-equivalent backends using
prover total cost, post-win delay, verifier CPU/memory, cold/warm conditions,
late failures, State/commit/cleanup and actual security parameters. WHIR-based
QROM results exist; the project's exact field, program, transcript, recursion
and lifetime query budget still require a concrete mapping.

Verde-style deterministic verification requires its honest-participant and
availability/dispute premises. It can help faithful execution of a declared
training/evaluation program; it does not establish the minimum physical cost
of every legal PoN strategy.

## Preparatory validation observations

Local preparatory work used the cached Rust 1.95.0 toolchain, offline locked
dependencies and the repository's unchanged test optimisation profile. It did
not execute the new native tests and supplies no acceptance result:

| Attempt | Actual observation | Qualification |
| --- | --- | --- |
| Initial scoped node test build | Refused because the partial staging checkout lacked the baseline `consensus-arithmetic-v1.json` compile-time fixture. | No test result. The exact #812 fixture was subsequently recovered and its Git blob SHA verified as `c3a86442e0b2d0b57fbdd5d0954288b5e92e6dc2`. |
| Scoped node test build after exact fixture recovery | `rustc` reached node test code generation and was terminated by SIGKILL; Cargo exited 101. | Cause remains unconfirmed. Do not relabel this as a proved out-of-memory event, a test failure in a specific function, or a successful test run. |
| Preparatory metadata check already started before local validation stopped | Refused on another absent baseline fixture, `tests/fuzz/fuzz_targets/support/work_certificate.rs`. | No overall Cargo-check PASS and no native test result. No replacement fixture or relaxed build profile was used. |

The original logs also retain the SQLite I/O-boundary loader-directory warning
marking this preparatory environment **UNQUALIFIED**. Formatting of the two
new owner files completed, but formatting is not native execution. Authoritative
source, build and test gates require the complete original checkout on the
selected execution host; results must stay bound to that actual source.

## Primary references

- [RFC 9000, address validation and computational attacks](https://www.rfc-editor.org/rfc/rfc9000.html): sections 8 and 21.9 distinguish address/byte-amplification limits from computational exhaustion.
- [RFC 8290, FQ-CoDel](https://www.rfc-editor.org/rfc/rfc8290.html): cost-based byte scheduling and the limitations of per-flow fairness.
- [WHIR paper](https://eprint.iacr.org/2024/1586) and [author implementation](https://github.com/worldfnd/whir): freeze resolved implementation parameters before comparison.
- [SWIRL, a WHIR-based STARK analysis](https://openvm.dev/swirl.pdf): construction and QROM/RBR premises are separate from this Node's numerical security qualification.
- [Verde paper](https://arxiv.org/html/2502.19405v1): deterministic verification under its explicit honest-provider assumptions.
- [Original public_v3 source](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/7e044b65454f4c9ea505591727332acffb33e7e5/trillionnium/crates/trnm-pon-node/src/ingress/public_v3.rs) and [PR #802 remaining boundary](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/cc09d6dc311596a9d9a45c64e9392caff4a75c0b/evidence/pon-cpu-observer-budget-20261108/README.md).
