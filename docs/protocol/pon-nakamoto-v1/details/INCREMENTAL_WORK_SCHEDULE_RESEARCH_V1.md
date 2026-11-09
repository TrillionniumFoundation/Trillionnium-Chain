# Incremental full-W1 research prefixes

Status: **bounded research; no native activation or production qualification**.

This component extends the
[branch work schedule research](BRANCH_WORK_SCHEDULE_RESEARCH_V1.md).
The implementation and controls are in
[research_work_schedule.rs](../../../../trillionnium/crates/trnm-pon-node/src/research_work_schedule.rs)
and its
[integration tests](../../../../trillionnium/crates/trnm-pon-node/tests/research_work_schedule.rs).
It changes no existing packet domain, settings identity, stored schema,
admission policy, fork choice or business deadline.

## Construction and evidence boundary

`IncrementalWorkSchedule::new` starts from an independently fixed `Profile`
and its genesis. The prefix has private fields. Its only public advancement
methods accept a complete PNH1 or PGH2 packet and execute the existing full W1
verifier in that packet's actual challenge domain.

There is no constructor from caller-provided headers, a
`CheckedBranchSchedule`, a `FullWorkCheck`, peer cumulative work, an anchor
hint, a checkpoint or a serialized prefix. The old arithmetic constructor
remains useful for independent reconstruction but supplies no full-work
authority to the incremental object.

Successful advancement checks the network/parameter namespace, parent,
height, exact required target, historical time, transaction commitment,
encoding and complete candidate W1. The target comes from the existing
prefix and fixed profile. The candidate's timestamp and the local wall clock
do not choose it. Anchor identity and the exact checked 512-bit work sum
follow the same branch as the prefix.

This is a local proof-and-schedule observation. It does not reexecute
application State, validate growth account-witness semantics, authorize
tasks or payments, authenticate native storage, establish minimum work cost,
or create an admission capability. Full W1 validity is not any of those
additional predicates.

## One candidate replay and atomic publication

Appending replays the current candidate once. Previously checked complete
proofs are not replayed by `next_context` or by a later append. Each object
retains bounded chronological points, a set of seen block identifiers,
cumulative work, its derived anchor and the maximum ancestor timestamp.
Median time uses at most eleven points, and the required target uses the
fixed legacy interval or the actual activation ancestor. The seen-ID lookup
is logarithmic in prefix length.

All fallible checks and a final cancellation callback complete before any
prefix field changes. A wrong product, namespace, parent or wire, a
historical-time refusal, and either early or final cancellation leave the
object equal to its prior value. A retry of a cancelled packet can succeed;
redelivery of an already appended packet refuses without additional work
credit or another proof replay.

A `Clone` creates a separate research branch with the checked common prefix.
Advancing one clone does not mutate another. Its anchor is derived from that
branch's actual activation block. Cloning does not reset accumulated credit
or turn shared preparation into newly paid physical work.

The bound remains 4096 non-genesis blocks. A valid block at height 4096 can be
appended and its resulting work retained. The terminal object refuses a
successor context instead of failing the valid terminal append by attempting
to compute height 4097. Per-object memory is bounded; this component supplies
no global limit on the number of caller-created branches.

## Candidate time and branch time

Existing `HistoricalCheck::clock_eligibility` remains a **candidate-only**
clock query. It has never established eligibility of all ancestors.
The new `branch_clock_eligibility` evaluates the maximum timestamp of the
whole checked prefix, including genesis and the candidate where applicable.

This distinction matters before C1 activation because old-policy historical
timestamps may be nonmonotone. For example, the valid arithmetic prefix
1010, 1020, 1100, 1021, 1022 and candidate 1023 has a greatest timestamp of
1100. With skew 120 and current time 903, the candidate alone is eligible,
while the whole branch is deferred until 980. The context preserves that
maximum even after the high ancestor leaves the MTP window.

Clock movement only changes the current eligibility result. It cannot
recalculate historical target, anchor, work or the packet-bound statement.
These clock methods do not restart a task deadline or grant execution time.

## Controls and their limits

Both existing native campaigns now compare incremental and full retained-path
reconstruction using actual complete PNH1 and PGH2 packets. Their controls
cover current-packet replay counts, namespace/wire/parent refusal, wrong
product, early cancellation, cancellation after complete verification,
successful retry, duplicate refusal, cloned forks, cross-fork anchors,
old-policy nonmonotone clock eligibility, and cold packet reconstruction.

The horizon unit control uses an explicitly synthetic arithmetic prefix of
4095 points and one genuinely generated and completely verified terminal W1
packet. It verifies terminal acceptance, successor refusal and no mutation
on refusal. It is **not** an execution of 4096 full proofs. The integration
campaigns remain the complete-proof evidence for public construction.

Cold recovery of this ephemeral object starts at genesis and replays complete
retained packets. There is no persistent-cache import. The original
`inspect_retained_branch` adapter retains its complete proof replay.

## Remaining native integration

The original Node DAA already reads bounded recent history; the genesis
replay belongs to the research adapter. This change therefore does not claim
to repair a deployed native DAA denial of service.

A production cached branch context still needs the original Node owner's
coherent transaction and storage-epoch boundary, a complete accepted-state
predicate, controlled cache capacity, reorganization/cold-recovery
reconciliation, and a versioned parameter/wire/storage transition for any
new consensus policy. A block ID alone does not authenticate mutable full
proof bytes. None of these obligations is supplied by an in-memory research
prefix.

C1 target credit and MU1's fixed-probability `16u` research credit remain
different models. There is no native MU1 credit bridge, physical-cost lower
bound, lifetime quantum-credit theorem, production admission or activation
in this component.
