# G1-R4B application finality v1

Status: **BLOCKED_UPSTREAM / candidate-only / no gate promotion**

Outcome: the local queue/readback contract is a reviewable candidate slice;
the package cannot close because the A03 permit/body/JMT carrier and the
cross-store application-finalization callback have not been accepted.

This package is the A04-owned application-side slice of G1-R4.  It is bound to
the candidate source below and never changes production, activation,
release-readiness, or normative-freeze truth.

## 1. Authority and exact source

```text
repository = TrillionniumFoundation/Trillionnium-Chain
base_ref  = feature/chain-g1-r4c-full-gap-closure-20260829
base_sha  = 6e0189e351015ef3230f217ca7ff86149baedcf0
base_tree = efea864cb2fbc4835a59a089b3dbab8934e71231
plan      = docs/chain-poco-bft-mainline-20260825@8198fea0307eb368df34ff77ffc272a6b0e655ec
stage     = G1-native-host-incomplete
authority = candidate
classification = candidate-non-normative
```

The assessed plan, machine truth, protocol manifest, and release-readiness
documents remain immutable inputs.  The candidate flags remain
`production_candidate=false` and `production_consensus_activation=false`.

## 2. Objective and non-claims

The local slice makes an application-owned finalization queue explicit.  It
requires a proof/body/overlay/JMT identity for each successor, accepts only
contiguous ascending ancestors, and acknowledges a front only together with
an exact committed-head readback.  It also gives retry and losing-fork
retention/reclamation a typed, testable boundary.

It does **not** claim any of the following:

```text
Core/Safety/signing/checkpoint authority
authenticated proposal-body or runtime-profile retrieval
production/effect-driver/process wiring
cross-store atomicity with Core or Safety
physical power-loss, disk-full, torn-write, or independent-process evidence
G1-R4 exit, release readiness, or validator activation
```

## 3. Ownership

Owned paths:

```text
trillionnium/crates/trnm-native-application/**
trillionnium/crates/trnm-native-application-sqlite/**
finalization queue and application-finalization modules
application-finalization focused tests and gates
docs/development/packages/**/*R4B*
```

Forbidden paths/surfaces:

```text
SafetyStore, signer, checkpoint and anti-rollback authority (A05)
fault harness and independent process campaigns (A06, except approved hooks)
ordinary proposal validation and execution owner (A03)
production/activation/release/normative truth
```

## 4. Typed gap ledger

| ID | Severity | Status | Local disposition |
|---|---:|---|---|
| R4B-QUEUE-001 | P0 | CANDIDATE_SLICE | Queue rejects skipped, reordered, or conflicting successors; independent Rust execution is still required. |
| R4B-APPLY-002 | P0 | BLOCKED_UPSTREAM | Needs an accepted Core permit plus authenticated body/overlay/JMT source. |
| R4B-READBACK-003 | P0 | BLOCKED_UPSTREAM | App readback exists in a candidate archive, but Core receipt/ack is a separate store transition. |
| R4B-MULTI-004 | P0 | CANDIDATE_SLICE | Three-successor queue ordering is covered; durable multi-block apply remains open. |
| R4B-DUP-005 | P1 | CANDIDATE_SLICE | Exact queue replay is idempotent and conflicting readback is rejected; source cardinality remains open. |
| R4B-FORK-006 | P0 | CANDIDATE_SLICE | Referenced/child fork evidence is retained and unreferenced leaves are reclaimed; cross-store GC remains open. |
| R4B-RESPONSE-007 | P0 | BLOCKED_UPSTREAM | A local retry disposition is possible; process-boundary proof is not. |
| R4B-SOURCE-008 | P1 | BLOCKED_UPSTREAM | Exact-one source cardinality and authenticated route/generation binding require the A03 carrier. |
| R4B-FAULT-009 | P0 | BLOCKED_UPSTREAM | Disk/torn/power-loss matrix belongs to the A06 harness after A03/A04 interfaces. |

No existing PR closes these A04 queue/app gaps.  PRs #6/#7/#8 and the R4A
marker package are intentionally not duplicated.

The machine-readable ledger for this run is:

```yaml
package: G1_R4_APPLICATION_FINALITY_V1
slice: G1_R4B_APPLICATION_FINALITY_V1
outcome: BLOCKED_UPSTREAM
authority: candidate
classification: candidate-non-normative
gaps:
  - id: R4B-QUEUE-001
    severity: P0
    status: CANDIDATE_SLICE
    owner: A04
    evidence: native queue state machine plus multi-successor unit tests
  - id: R4B-APPLY-002
    severity: P0
    status: BLOCKED_UPSTREAM
    owner: A03
    request: A04-R4B-001
  - id: R4B-READBACK-003
    severity: P0
    status: BLOCKED_UPSTREAM
    owner: A03
    request: A04-R4B-001
  - id: R4B-MULTI-004
    severity: P0
    status: CANDIDATE_SLICE
    owner: A04
    evidence: h0-to-h1-to-h2-to-h3 contiguous queue vector
  - id: R4B-DUP-005
    severity: P1
    status: CANDIDATE_SLICE
    owner: A04
    evidence: exact replay and conflicting identity negatives
  - id: R4B-FORK-006
    severity: P0
    status: CANDIDATE_SLICE
    owner: A04
    evidence: reference and child protected fork reclamation vector
  - id: R4B-RESPONSE-007
    severity: P0
    status: BLOCKED_UPSTREAM
    owner: A03
    request: A04-R4B-001
  - id: R4B-SOURCE-008
    severity: P1
    status: BLOCKED_UPSTREAM
    owner: A03
    request: A04-R4B-001
    blocker: source loader is outside this package's accepted application boundary
  - id: R4B-FAULT-009
    severity: P0
    status: BLOCKED_UPSTREAM
    owner: A06
    blocker: approved process/fault hooks and A03 carrier are absent
interface_requests:
  - request_id: A04-R4B-001
    requester_agent: A04
    owner_agent: A03
    current_interface_digest: none
    proposed_interface: permit-bound application body/overlay/JMT read plus fresh readback
    safety_rationale: prevent skipped ancestors, root drift, source ambiguity, and fork replay
    version_impact: additive candidate interface; production flags unchanged
    required_vectors: [one, ascending_2_plus, skip, reorder, duplicate, sibling, response_loss, tamper]
    downstream_invalidation: [A04, A05, A06, G1]
    status: BLOCKED_UPSTREAM
    reviewer: independent A03/A04 review required
```

## 5. Frozen candidate interface

The application boundary adds candidate-only, host-neutral values and a queue
state machine in the existing native-application source inventory:

```text
NativeFinalizationIntentV0
  parent head + target head + proof/body/overlay/JMT digests
NativeFinalizationApplyReadbackV0
  exact intent + committed target head + JMT root + durable sequence
NativeFinalizationQueueV0
  contiguous pending front, committed history, retained fork evidence
```

The constructor rejects zero identities and non-successor heights.  Queue
acknowledgement checks the complete identity before mutating head/history.
`reconcile` distinguishes an exact pending source from an exact committed
target after a lost response.  The queue never issues a Core/Safety capability.

The required A04→A03 interface-change request is frozen as:

```text
request_id = A04-R4B-001
requester_agent = A04
owner_agent = A03
current_interface_digest = none (no accepted A03 interface digest)
proposed_interface = Core-issued non-cloneable finalization permit carrying exact
  authenticated parent, target header/body, overlay identity, JMT plan/runtime
  profile binding, and a fresh application readback consumed by Core
safety rationale = prevent skipped ancestors, root drift, source ambiguity and
  replay of a competing fork
version impact = additive candidate interface; no production flag change
required vectors = one block; 2/3/10+ ascending; skipped/reordered; duplicate;
  same-root sibling; response loss; stale head; parent/overlay/root tamper
downstream invalidation = A04 SQLite/process tests, A05 tag-3/checkpoint join,
  A06 fault/replay matrix and G1 review
status = BLOCKED_UPSTREAM pending A03 owner/reviewer acceptance
reviewer = independent A03/A04 review required
```

## 6. State machine and invariants

```text
enqueue exact successor -> Pending(front)
Pending(front) + exact durable readback -> Committed(head/history)
Committed + same identity -> ExactReplay (no write)
non-front / skipped / conflicting identity -> reject (state unchanged)
losing sibling -> RetainedFork -> reclaim only with zero references
```

Required invariants:

1. every canonical target is the exact height-one successor of the preceding
   committed/pending head;
2. a receipt binds parent, target, proof, overlay, body and JMT identities;
3. a duplicate identity never creates a second history entry or head advance;
4. a failed validation mutates no queue, head, history, or fork evidence;
5. a fork is not reclaimed while its explicit evidence reference or a pending
   child still names it;
6. committed durable sequences increase strictly along the retained history;
7. retry classification is only `Pending` or exact `Committed`; an ambiguous
   third state is an error requiring fail-stop/recovery.

The local bound is `MAX_FINALIZATION_QUEUE_ENTRIES_V0`; callers must apply a
batch in ascending order and must not treat this candidate queue as a durable
cross-store acknowledgement.

The retained in-memory history is intentionally bounded as well.  It is a
candidate replay window, not the 100,000-block G1-S04 evidence ledger; a real
adapter must externalize durable receipts before any history compaction and
must preserve an exact source/target decision for older retries.

## 7. Vectors and negative mutants

Positive vectors include h0→h1, h1→h2→h3, exact replay after response loss,
and a retained h1 sibling whose reference is released before reclamation.

Retained negative mutants include:

```text
apply h3 before h2; omit h2; reorder h2/h3
change parent BlockId/height/root or target JMT root
change proof/body/overlay digest while retaining the target BlockId
re-submit an exact receipt and a same-target conflicting receipt
reclaim a fork while its reference or pending child remains
return an unknown/mixed readback after the application write
```

Every mutant must leave the pre-state unchanged, or be retained as a
`PersistedStateMismatch`/`CommitUncertain` candidate outcome.  No mutant is
silently converted into a pass.

The tests in this slice do not exercise SQLite reopen, JMT writes, Core receipt
CAS, Safety/checkpoint joins, or independent processes.  Those are deliberately
open/blocked rather than inferred from this pure state machine.

## 8. Evidence and commands

Evidence scope is `crate`/`candidate`, classification
`candidate-non-normative`.  The required commands on an authorized clean
Rust runner are:

```sh
bash scripts/project-preflight.sh
cargo test --locked -p trnm-native-application --all-targets
cargo test --locked -p trnm-native-application-sqlite --all-targets
cargo clippy --locked -p trnm-native-application --all-targets --no-deps -- -D warnings
cargo clippy --locked -p trnm-native-application-sqlite --all-targets --no-deps -- -D warnings
```

In this run the source and static preflight were revalidated, but `cargo` is
not installed in the execution environment.  Therefore no test or clippy
command is reported as passing; the failed tool invocation is retained as an
environment limitation.

Observed command results for this run:

```text
bash scripts/project-preflight.sh --audit                         PASS (0 errors)
bash scripts/ci/check_canonical_development_plan.sh                PASS
git diff --check                                                    PASS
bash scripts/ci/check_trnm_native_application_boundary.sh          BLOCKED (cargo not found)
bash scripts/ci/check_trnm_native_application_sqlite_boundary.sh   BLOCKED (cargo not found)
bash scripts/ci/check_poco_bft_mainline_truth.sh                   BLOCKED (cargo not found)
cargo test/clippy for both owned crates                               NOT RUN (cargo not found)
```

## 9. Exit, rollback and invalidation

`MODULE_CLOSED_CANDIDATE` is not available until an independent clean-clone
replay verifies the queue vectors and the accepted A03 carrier.  This run
terminates as `BLOCKED_UPSTREAM` after the local queue contract slice.

Rollback is a branch-local revert of the candidate files; production truth is
never edited.  Any change to the queued identity, readback semantics, or
source digest invalidates R4B queue/readback tests and downstream A05/A06
joins.  The deterministic next action is to obtain the A03 interface response,
then bind the queue front to a real authenticated application/JMT owner and
run the full fault/replay matrix.  Downstream A05 tag-3/checkpoint joins and
A06 fault/replay evidence are invalidated until that response is accepted.
