# G1-R4B application finality v1

Status: **BLOCKED_UPSTREAM / candidate-only / no gate promotion**

Package: `G1_R4_APPLICATION_FINALITY_V1`
Gate: `G1`
Agent: `A04`
Package branch: `feature/chain-g1-r4-application-finality-v1-20260829`

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
plan_id   = trnm-ai-native-blockchain-development-plan-v1
plan      = docs/chain-poco-bft-mainline-20260825@8198fea0307eb368df34ff77ffc272a6b0e655ec
plan_sha256 = aba99ae6be2ff8a4aac4d6355e1f778e49a7075a80b09453f16984f85bb0b6cd
machine_truth_sha256 = 19baef8a393d235b4f87a1351e2b8cdf2e7bb1f2eea8770ecc67d3e18966c6be
protocol_manifest_sha256 = ca41347d4559934e706aea13d242625e905b99d956b6187f7df449c1c27299aa
toolchain_lock_sha256 = ee1e9a8382092a397f1b041107cf6b86e468d521af3aa7963e5f6e714e6c3382
canonical_plan_ref_observed_tip = 92449b8e101642f39d644d863db7bb60dea488f7
canonical_plan_ref_observed_tree = cf8f1ab4f5065cb0551a30ec0e036cd44cb31766
branch_tip_at_package_start = 6e0189e351015ef3230f217ca7ff86149baedcf0
stage     = G1-native-host-incomplete
authority = candidate
classification = candidate-non-normative
```

The assessed plan, machine truth, protocol manifest, and release-readiness
documents remain immutable inputs.  The candidate flags remain
`production_candidate=false` and `production_consensus_activation=false`.
The observed canonical-plan tip is a descendant of the manifest-assessed
commit/tree and is recorded without substitution; the canonical-plan gate
therefore remains a pass and this run has no `BASE_DRIFT`.

## 2. Objective and non-claims

The local slice makes an application-owned finalization queue explicit.  It
requires a proof/body/overlay/JMT identity for each successor, accepts only
contiguous ascending ancestors, and acknowledges a front only together with
an exact committed-head readback.  It also gives retry and losing-fork
retention/reclamation a typed, testable boundary.

It does **not** claim any of the following:

```text
Core/Safety/signing/checkpoint authority
authenticated proposal-body, header-context, or runtime-profile retrieval
chain/genesis/route/generation scope binding for the opaque heads
cryptographic receipt binding or an external anti-rollback sequence watermark
production/effect-driver/process wiring
cross-store atomicity with Core, Safety, or checkpoint
durable reopen/decode/receipt compaction or an authenticated live-reference inventory
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
| R4B-READBACK-003 | P0 | BLOCKED_UPSTREAM | App readback exists in a candidate archive, but the Core/Safety receipt/ack is a separate A05-owned transition (downstream handoff). |
| R4B-MULTI-004 | P0 | CANDIDATE_SLICE | Three-successor queue ordering is covered; durable multi-block apply remains open. |
| R4B-DUP-005 | P1 | CANDIDATE_SLICE | Exact queue replay is idempotent, target/proof collisions and aliased overlay tuples are rejected, and repeated body/JMT digests with a distinct target-bound overlay remain orderable; durable source cardinality remains open. |
| R4B-FORK-006 | P0 | CANDIDATE_SLICE | Referenced/child fork evidence is retained and unreferenced leaves are reclaimed; cross-store GC remains open. |
| R4B-RESPONSE-007 | P0 | BLOCKED_UPSTREAM | A local retry disposition is possible; the A05/A06 process-boundary proof is not (downstream handoff). |
| R4B-SOURCE-008 | P0 | BLOCKED_UPSTREAM | Exact-one source cardinality and authenticated route/generation binding require the A03 carrier; otherwise application commit can precede a Core rejection. |
| R4B-FAULT-009 | P0 | BLOCKED_UPSTREAM | Disk/torn/power-loss matrix belongs to the A06 harness after A03/A04 interfaces. |
| R4B-SQLITE-010 | P0 | BLOCKED_UPSTREAM | The owned SQLite crate is a validation journal with no finalization queue/intent/head/JMT/receipt/fork schema; A03/A05 seams must be accepted before persistence is added. |
| R4B-HISTORY-011 | P0 | BLOCKED_UPSTREAM | The bounded replay history rejects the 1025th successor; authenticated durable receipt externalization/compaction and an exact old-retry anchor are still unaccepted. |
| R4B-SCOPE-012 | P0 | BLOCKED_UPSTREAM | Intent values lack authenticated chain/genesis/route/generation/runtime-profile scope; this belongs in the accepted carrier. |
| R4B-RECEIPT-013 | P0 | BLOCKED_UPSTREAM | Readback currently requires only a non-zero receipt digest and local sequence; cryptographic receipt binding and an external anti-rollback floor are absent. |
| R4B-GC-014 | P0 | BLOCKED_UPSTREAM | Fork GC receives an opaque caller list; authenticated live-reference inventory and cross-store retention authority are absent. |

No existing PR closes these A04 queue/app gaps.  PRs #6/#7/#8 and the R4A
marker package are intentionally not duplicated.

The A05/A06 entries use the governed `BLOCKED_UPSTREAM` status for the package
ledger even though their dependency kind is a downstream handoff (A05 follows
A04).  This is not permission to edit A05/A06.  The package terminal outcome is
`BLOCKED_UPSTREAM` because the A03 carrier is still missing.

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
    owner: A05
    request: A04-R4B-002
    dependency_kind: downstream_handoff
  - id: R4B-MULTI-004
    severity: P0
    status: CANDIDATE_SLICE
    owner: A04
    evidence: h0-to-h1-to-h2-to-h3 contiguous queue vector
  - id: R4B-DUP-005
    severity: P1
    status: CANDIDATE_SLICE
    owner: A04
    evidence: exact replay, target/proof/aliased-overlay conflicts, and repeated body/JMT digest vector with distinct overlays
  - id: R4B-FORK-006
    severity: P0
    status: CANDIDATE_SLICE
    owner: A04
    evidence: reference and child protected fork reclamation vector
  - id: R4B-RESPONSE-007
    severity: P0
    status: BLOCKED_UPSTREAM
    owner: A05
    request: A04-R4B-002
    dependency_kind: downstream_handoff
  - id: R4B-SOURCE-008
    severity: P0
    status: BLOCKED_UPSTREAM
    owner: A03
    request: A04-R4B-001
    blocker: source loader is outside this package's accepted application boundary
  - id: R4B-FAULT-009
    severity: P0
    status: BLOCKED_UPSTREAM
    owner: A06
    blocker: approved process/fault hooks and A03 carrier are absent
    request: A04-R4B-003
  - id: R4B-SQLITE-010
    severity: P0
    status: BLOCKED_UPSTREAM
    owner: A04
    blocker: SQLite is validation-only; A03 carrier and A05 cross-store CAS/readback are not accepted
    requests: [A04-R4B-001, A04-R4B-002]
  - id: R4B-HISTORY-011
    severity: P0
    status: BLOCKED_UPSTREAM
    owner: A04
    blocker: candidate replay history is hard-bounded at 1024; safe compaction needs an authenticated durable receipt/sequence anchor
    requests: [A04-R4B-001, A04-R4B-002]
  - id: R4B-SCOPE-012
    severity: P0
    status: BLOCKED_UPSTREAM
    owner: A03
    request: A04-R4B-001
    blocker: chain/genesis/route/generation/runtime-profile scope is not carried by the local host-neutral intent
  - id: R4B-RECEIPT-013
    severity: P0
    status: BLOCKED_UPSTREAM
    owner: A05
    request: A04-R4B-002
    dependency_kind: downstream_handoff
    blocker: receipt digest is structurally non-zero only; cryptographic binding and external sequence floor are unaccepted
  - id: R4B-GC-014
    severity: P0
    status: BLOCKED_UPSTREAM
    owner: A05
    request: A04-R4B-002
    dependency_kind: downstream_handoff
    blocker: live-reference inventory is caller-supplied and not cross-store authenticated
interface_requests:
  - request_id: A04-R4B-001
    requester_agent: A04
    owner_agent: A03
    current_interface_digest: none
    proposed_interface: A03-provided permit-bound application body/header-context/overlay/JMT read plus fresh readback (using the existing Core permit; no new Core capability)
    safety_rationale: prevent skipped ancestors, root drift, source ambiguity, and fork replay
    version_impact: additive candidate interface; production flags unchanged
    required_vectors: [one, ascending_2_plus, skip, reorder, duplicate, sibling, response_loss, tamper]
    downstream_invalidation: [A04, A05, A06, G1]
    status: BLOCKED_UPSTREAM
    reviewer: independent A03/A04 review required
  - request_id: A04-R4B-002
    requester_agent: A04
    owner_agent: A05
    current_interface_digest: none
    proposed_interface: Core validates the A04 application readback; A05 consumes only the resulting Core-issued tag-3 transition and performs Safety/checkpoint CAS plus fresh cross-store readback
    safety_rationale: resolve commit/ack response loss to exact source or target without deleting referenced evidence
    version_impact: additive candidate interface; production flags unchanged
    required_vectors: [ack_loss, response_loss, store_skew, rollback, referenced_fork, restart]
    downstream_invalidation: [A04, A05, A06, G1]
    status: BLOCKED_UPSTREAM
    dependency_kind: downstream_handoff (A05 depends on A04)
    reviewer: independent A04/A05 review required
  - request_id: A04-R4B-003
    requester_agent: A04
    owner_agent: A06
    current_interface_digest: none (no accepted A06 application-finalization hook digest)
    proposed_interface: test-only process/fault hook that can cut application commit/readback, Core receipt, Safety tag-3, checkpoint CAS, queue acknowledgement, and fork-GC boundaries without minting production authority
    safety_rationale: make response-loss, power-loss, partial-write, and referenced-fork retention outcomes independently replayable
    version_impact: additive candidate test hook; production flags unchanged
    required_vectors: [response_loss, commit_ack_loss, torn_write, power_loss, restart, referenced_fork, history_full_after_commit]
    downstream_invalidation: [A04, A05, A06, G1]
    status: BLOCKED_UPSTREAM
    dependency_kind: test_hook_handoff
    reviewer: independent A04/A06 review required
```

A03 PR #21 (`1b9543b3b22cc959d0ea2b3123c349761adada32`, tree
`3c0ae054f358b45f5801ee8111d1833aee40dbd0`) is a separate Draft
`BLOCKED_UPSTREAM` proposal.  It has no review or accepted A04 interface
digest, so it is recorded as a pending response and is not treated as the
source carrier for this package.

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
`acknowledge_front` is only an application-local cache transition after a
durable application readback; it is not a Core queue pop, a Safety transition,
or a checkpoint commit.  The integrated ordering remains:

```text
application commit/readback
 -> Core validates and emits its application-finalization receipt
 -> A05 persists/reads back the Core-issued tag-3 Safety transition
 -> A05 performs successor checkpoint CAS/readback
 -> Core acknowledges the queue front and only then allows fork GC
```

A05 must consume the Core-issued tag-3 transition and must never treat a raw
application receipt as Safety authority.

The required A04→A03 interface-change request is frozen as:

```text
request_id = A04-R4B-001
requester_agent = A04
owner_agent = A03
current_interface_digest = none (no accepted A03 interface digest)
proposed_interface = A03-provided permit-bound application execution carrier
  (using the existing Core-issued non-cloneable permit) carrying exact
  authenticated parent, target header/body/context, overlay identity, JMT
  plan/runtime profile and chain/genesis/route/generation scope binding, plus a
  fresh application readback consumed by Core
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

The separate A04→A05 cross-store request is frozen as:

```text
request_id = A04-R4B-002
requester_agent = A04
owner_agent = A05
current_interface_digest = none (no accepted A05 receipt/checkpoint digest)
proposed_interface = A04 application readback is first validated by Core; A05
  consumes only the resulting Core-issued tag-3 transition and performs the
  successor-checkpoint CAS/readback with an exact source/target response-loss rule
safety rationale = prevent ack-before-commit, cross-store skew and reclamation
  of evidence still referenced by Safety/checkpoint recovery
version impact = additive candidate interface; no production flag change
required vectors = ack loss; response loss; store skew; rollback; referenced
  fork; fresh-process restart
downstream invalidation = A04 process/SQLite tests, A05 tag-3/checkpoint
  vectors and owner acceptance, A06 fault/replay matrix and G1 review
status = BLOCKED_UPSTREAM pending A05 owner/reviewer acceptance; dependency_kind
  = downstream_handoff; A05 follows A04 and this package does not edit its surface
reviewer = independent A04/A05 review required
```

The A04→A06 test-hook request is frozen as:

```text
request_id = A04-R4B-003
requester_agent = A04
owner_agent = A06
current_interface_digest = none (no accepted A06 application-finalization hook digest)
proposed_interface = test-only process/fault cuts around application
  commit/readback, Core receipt, Safety tag-3, checkpoint CAS, queue ack and
  fork GC; the hook cannot mint production authority
safety rationale = independently replay response-loss, torn-write, power-loss,
  restart, and referenced-fork retention outcomes
version impact = additive candidate test hook; production flags unchanged
required vectors = response loss; commit/ack loss; torn write; power loss;
  restart; referenced fork; history-full-after-commit
downstream invalidation = A04 application tests, A05 tag-3/checkpoint joins,
  A06 fault/replay matrix and G1 review
status = BLOCKED_UPSTREAM pending A06 owner/reviewer acceptance
dependency_kind = test_hook_handoff
reviewer = independent A04/A06 review required
```

## 6. State machine and invariants

```text
enqueue exact successor -> Pending(front)
Pending(front) + exact durable application readback -> AppCommitted(head/history cache)
AppCommitted + Core receipt + A05 tag-3/checkpoint readback -> CoreAckEligible
AppCommitted + same identity -> ExactReplay (no write)
non-front / skipped / conflicting identity -> reject (state unchanged)
losing sibling -> RetainedFork -> reclaim only with zero references
```

Required invariants:

1. every canonical target is the exact height-one successor of the preceding
   committed/pending head;
2. an application readback carries and checks the exact parent, target, proof,
   overlay, body and JMT intent structurally; cryptographic receipt binding is
   still an open upstream requirement;
3. a duplicate identity never creates a second history entry or head advance;
4. a failed validation mutates no queue, head, history, or fork evidence;
5. a fork is not reclaimed while its explicit evidence reference or a pending
   child still names it;
6. committed durable sequences increase strictly along the retained history;
7. retry classification is only `Pending` or exact `Committed`; an ambiguous
   third state is an error requiring fail-stop/recovery.

The local bound is `MAX_FINALIZATION_QUEUE_ENTRIES_V0`; callers must apply a
batch in ascending order and must not treat this candidate queue as a durable
cross-store acknowledgement.  `AppCommitted` is not `CoreAckEligible` until
the Core receipt and A05 tag-3/checkpoint barriers above have succeeded.

The retained in-memory history is intentionally bounded as well.  It is a
candidate replay window, not the 100,000-block G1-S04 evidence ledger; a real
adapter must externalize durable receipts before any history compaction and
must preserve an exact source/target decision for older retries.

The readback constructor currently checks only a non-zero receipt digest and a
positive local sequence.  It does not authenticate the receipt checksum,
anchor the first sequence to an external watermark, or decode/revalidate a
persisted row after restart.  Likewise, fork reclamation accepts an opaque
caller-supplied live-reference list.  These are deliberate candidate seams;
the A05 receipt/checkpoint contract and A06 process/fault evidence must supply
the authority before any of them can support a closure claim.

## 7. Vectors and negative mutants

Positive vectors include h0→h1, h1→h2→h3, exact replay after response loss,
and a retained h1 sibling whose reference is released before reclamation.

Retained negative mutants include:

```text
apply h3 before h2; omit h2; reorder h2/h3
change parent BlockId/height/root or target JMT root
change proof/body/overlay digest while retaining the target BlockId
reuse an overlay/body/JMT tuple with a distinct proof on the next successor
re-submit an exact receipt and a same-target conflicting receipt
reclaim a fork while its reference or pending child remains
return an unknown/mixed readback after the application write
fill the retained history and attempt the 1025th commit (`history_full_after_commit`)
```

Every mutant must leave the pre-state unchanged, or be retained as a
`PersistedStateMismatch`/`CommitUncertain` candidate outcome.  No mutant is
silently converted into a pass.

The `history_full_after_commit` mutant is specifically retained: once the
1024-entry replay window is full, an external application commit can succeed
while queue acknowledgement rejects the next history entry, leaving the
target pending and requiring an authenticated receipt/compaction anchor before
retry.  This is a P0 liveness gap, not a successful long-run finalization.

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

The SQLite boundary script also contains a pre-existing gate-hygiene mismatch:
its metadata probe expects `terminal_k_whole_node_cas_integration=false` while
the final informational printf says `true` (`R4B-GATE-011`).  With Cargo
unavailable the integration probe never runs; this mismatch is retained as a
known gap and is not evidence of closure.

## 9. Exit, rollback and invalidation

`MODULE_CLOSED_CANDIDATE` is not available until an independent clean-clone
replay verifies the queue vectors, the accepted A03 carrier, the durable
history-compaction anchor, and the A06 fault cuts.  This run terminates as
`BLOCKED_UPSTREAM` after the local queue contract slice.

Rollback is a branch-local revert of the candidate files; production truth is
never edited.  Any change to the queued identity, readback semantics, source
digest, history-compaction anchor, or test-hook cut invalidates R4B
queue/readback tests and downstream A05/A06 joins.  The deterministic next
action is to obtain A03 interface request `A04-R4B-001`, then obtain the A05
receipt/checkpoint response and A06 test-hook response, bind the queue front to
a real authenticated application/JMT owner, and run the full fault/replay
matrix.  Downstream A05 tag-3/checkpoint joins and A06 fault/replay evidence
are invalidated until those responses are accepted.
