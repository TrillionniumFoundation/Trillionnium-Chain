# Fixed Host F0: authenticated client import and the next native observation

## Status and evidence boundary

The retained F0 campaign still fails the original gate: **0 of 6 scheduled
confirmations meet the strict four-second SLO; all 42 planned business packet
exposures remain in the denominator; the no-attack baseline fails first.**
This note records source inspection and an unimplemented native observation
specification. It contains **zero new native executions**, no measured speedup,
and no service-availability qualification.

The measured campaign used head
`b5bb7bc8d7ffe79d46c6a58fd5189e2bb9e4550c`, tree
`8be28a72673ce318d60a464898ab610d9ba39216`, AuthenticatedV1 and RawR14.
Its [retained analysis](../pon-fixed-host-root-f0-b5bb-readback-20261105/analysis.json)
binds the prepared executable, before/after source observations, raw report,
controller resource observations and service-empty finalization. The corresponding
[native job](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41964674522/job/127038806677)
is historical evidence, not an execution of the current candidate.

The call-chain review below uses integration source
`f9977c5d6d1b57880967ef36dcd1570010cbbe4f`, plus the importer boundary amendment
in `346b15148bf9b0b1319b047e37c6df0d92ccfc93`. Source inspection does not transfer
the old executable's measurements to either newer source. Ownership remains in
[the portability inventory](../../config/portability-inventory-v1.json), and work
remains under [the single development plan](../../docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md).

## What the old observations establish

All times below are seconds, converted directly from retained integer
nanoseconds. CPU means the measured calling thread; it is not aggregate CPU for
every worker or owned process. Stage intervals are nested. They must not be
added, or subtracted from one another to manufacture exclusive attribution.

| Observation | Baseline | Valid-work-root phase |
| --- | ---: | ---: |
| Ordinary client imports started / successful | 14 / 14 | 5 / 4 |
| Client import wall time | 23.368586812 | 15.374301136 |
| Client import thread CPU | 5.401201965 | 1.585730854 |
| History network wall time | 0.308889425 | 0.328417233 |
| Host checkpoint calls | 166,743 | 43,310 |
| Host checkpoint wall time | 6.612842651 | 3.296422510 |
| Host checkpoint thread CPU | 4.038066182 | 1.236897535 |
| `account_graph` stage calls | 124 | 24 |
| `account_graph` wall time | 15.396977190 | 10.657761129 |
| `account_graph` thread CPU | 3.738849684 | 1.089253706 |
| Timely packet ACKs / planned packet exposures | 17 / 21 | 7 / 21 |

The baseline also records 168 `verify_state`, 14 `admission`, 14 `publish`,
42 `state_at`, and 2 `activation` stage calls. Its `complete_commitment`
stage accounts for 182 calls and 0.170707677 seconds of calling-thread CPU.
These observations justify investigating the real authenticated importer and
its graph checkpoints. They do not identify a safely removable verification,
show that all graph calls traverse the complete graph, or establish an exact
percentage of graph cost attributable to Host checks. A successful page import
or a timely packet ACK is not an independent business confirmation.

The Host observations report throttling under the declared limits and no OOM.
There is no established wrapper/parser defect that converts this native failure
into success. These findings and their limitations are retained in the
[original analysis](../pon-fixed-host-root-f0-b5bb-readback-20261105/analysis.json).

## The actual client path

The F0 client opens its own AuthenticatedV1 verifier, seeds it, and imports each
received public History page through
`receive_public_page_from_before_observed(&mut verifier, ...)`. Only when the
imported position reaches the requested tip does it invoke the ordinary
`verifier.confirmation(...)` path. See the
[native F0 client](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/f9977c5d6d1b57880967ef36dcd1570010cbbe4f/trillionnium/crates/trnm-pon-node/tests/support/multiprocess_root_phase_host.rs).

| Boundary | Actual work and binding that must remain |
| --- | --- |
| Public observed wrapper | `receive_public_page_from_before_observed` resolves the original fixed Host parent, performs fresh initial/final observations, supplies fresh checkpoint observations, and explicitly constructs `Owner::Exclusive(node)`. |
| History importer | `receive_observed` uses the same original business deadline and metered CPU owner; checked work reaches `admit_work_checked_with_control`. A complete page retains the ordinary activation path. |
| Admission parent | `check_admission_parent` reads the actual parent state and checks task and manifest bindings. Private parent reuse is already guarded by the same SQLite `data_version` and `total_changes` epoch, including a second check after the original callback. |
| Admission transaction | `admit_work_checked_with_parent` writes the block, delta and snapshot under the original `TransactionScope`, then calls `publish_with_readback`. |
| Authenticated publication | `publish_with_readback` checks the current parent, checks the actual delta against before/after state, applies account graph changes, commits the complete after-state relation and writes its actual record. Only after the final relevant write does it create `PostWriteReadback`. |
| Persisted readback | The same transaction re-reads packet/delta material, verifies parent and child state against execution, verifies ancestry, and checks the active state before commit. The original transaction identity is checked on both success and failure. |
| Complete-page activation | `activate_with_fault_and_progress` retains actual attach/detach and publication transactions. A scope belonging to admission or one activation transaction cannot authorize a different transaction. |
| Independent confirmation | The client must reach the requested tip and complete the original confirmation checks inside the scheduled deadline. Retained importer success does not substitute for this boundary. |

Primary source: [public wrapper](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/f9977c5d6d1b57880967ef36dcd1570010cbbe4f/trillionnium/crates/trnm-pon-node/src/ingress.rs),
[importer](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/346b15148bf9b0b1319b047e37c6df0d92ccfc93/trillionnium/crates/trnm-pon-node/src/ingress/history_import.rs),
[store admission and activation](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/f9977c5d6d1b57880967ef36dcd1570010cbbe4f/trillionnium/crates/trnm-pon-node/src/store.rs),
[authenticated publication and verification](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/f9977c5d6d1b57880967ef36dcd1570010cbbe4f/trillionnium/crates/trnm-pon-node/src/store/native_authenticated.rs).

The amendment in `346b151` removes one immediately duplicated resource check
before the first Shared mutex acquisition attempt in each owner call and adds the post-observation
deadline fence for both owner branches. **The F0 independent client uses the
Exclusive branch.** The Shared deduplication therefore does not establish a
repair of its dominant client-import/account-graph cost. The Exclusive deadline
fence is a boundary correctness change, not a measured performance result.

The ordinary History CPU epoch markers already use the dedicated metadata path;
the reviewed source does not support the hypothesis that starting/finishing this
epoch unconditionally invokes a generic full-graph atomic transaction. See
[ordinary owner accounting](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/f9977c5d6d1b57880967ef36dcd1570010cbbe4f/trillionnium/crates/trnm-pon-node/src/store/operator_continuous_owner.rs).

## Reuse that already exists, and the boundary we did not change

`verify_state_with_readback` always loads and checks the current record and
compares the complete commitment of the actual current State before considering
graph reuse. `PostWriteReadback` is private to the original write transaction,
unchanged write epoch, original context and checked ordinary schema. Its eligible
records are bounded to the child, genesis, the verified child's nominated
parent, and the actual active tip; a whole-root match binds the complete account
Root, including node, digest, count and balance. Original callbacks and final
scope checks remain mandatory. See
[readback ownership](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/f9977c5d6d1b57880967ef36dcd1570010cbbe4f/trillionnium/crates/trnm-pon-node/src/store/native_authenticated/post_write_readback.rs).

When no whole-root receipt matches, the verifier either traverses the ordinary
current SQL graph or obtains private `GraphAccess` bound to that same immutable
State and Record. A previously sealed, fixed-size frontier may certify exact
subtrees within the unchanged transaction. Every node that is actually visited
retains its original progress/Host checkpoint; skipped certified descendants
produce no synthetic checkpoints. Complete-state binding, actual exposed leaves,
root/count/balance, node identity, path/depth, and the final unchanged-source fence
remain checked. See the [ordinary graph verifier](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/f9977c5d6d1b57880967ef36dcd1570010cbbe4f/trillionnium/crates/trnm-pon-node/src/account_archive_prototype/native_store.rs)
and [scoped graph verifier](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/f9977c5d6d1b57880967ef36dcd1570010cbbe4f/trillionnium/crates/trnm-pon-node/src/account_archive_prototype/native_scoped_readback.rs).

There is a real repetition candidate: a named parent can undergo another partial
traversal while the same sealed frontier remains valid. The regression
`real_different_roots_use_bounded_subtrees_without_promoting_partial_results`
explicitly requires repeated partial uses while the corresponding whole-root
receipt remains absent. Partial results do not nominate a parent, mint a new
whole-root receipt, replace the source, or enlarge the frontier. Promoting them
would change a deliberate proof boundary, and this iteration leaves that boundary
intact. See the [existing frontier regression](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/f9977c5d6d1b57880967ef36dcd1570010cbbe4f/trillionnium/crates/trnm-pon-node/src/store/native_authenticated/post_write_readback/frontier_tests.rs).

Current-state arithmetic reuse also already exists. Complete commitment entries
bind exact canonical current bytes and namespace; an immediate account projection
is privately bound to the same immutable State. These are not retained database
validity verdicts. Removing the fresh graph read or reusing Host admission would
not follow from their existence. See [arithmetic cache](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/f9977c5d6d1b57880967ef36dcd1570010cbbe4f/trillionnium/crates/trnm-pon-node/src/store/native_authenticated/arithmetic_cache.rs)
and [current-account projection](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/f9977c5d6d1b57880967ef36dcd1570010cbbe4f/trillionnium/crates/trnm-pon-node/src/account_archive_execution/state_witness.rs).

## Why the existing stage count cannot answer the remaining question

`HistoryStage::AccountGraph` starts only in the `!reused` branch. It combines
ordinary traversal, scoped traversal with no subtree hit, successful partial
traversal, and errors after entering that branch. Whole-root hits do not enter
the stage. Subtracting `account_graph.calls` from `verify_state.calls` is invalid:
state verification can fail before branch selection, and final fences can trigger
ordinary verification again. The existing `StageObservation` records wall/CPU,
unwind and unknown-CPU accounting, but no visited-node or graph-mode outcome.
See [stage observation](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/f9977c5d6d1b57880967ef36dcd1570010cbbe4f/trillionnium/crates/trnm-pon-node/src/store/native_authenticated/history_arithmetic.rs).

Whole-root `hits`, `partial_uses`, `subtree_hits` and the scoped verifier's `hits`
are currently `cfg(test)` fields. The production library used by the integration
test does not expose them. `VerifiedGraph::source_used()` is returned only after
successful traversal. Inferring partial use from that return loses a real subtree
hit followed by failure or cancellation. Merely possessing a frontier is not a
partial hit; it may match no visited node.

A wrapper around `progress` could count calls that actually reach that callback,
but by itself cannot distinguish those cases, root rejection before the first
callback, or final-fence invalidation. Accurate failure-inclusive telemetry
therefore needs coordinated observation in the graph loop and its caller. It is
not a one-line renaming of the existing stage. No such interface change is made
here: the local environment has no Rust compiler, and error/unwind-sensitive
changes across these native layers cannot be compiled and verified locally.

## Proposed native observation, not implemented in this increment

Use a bounded, diagnostic-only accumulator owned by the existing history
observation. Keep the existing stage timing around actual work and add a separate,
explicitly versioned graph-observation namespace. Do not change signed packets,
state/witness bytes, admission results, cache eligibility, graph traversal order,
Host calls, deadlines, or the number of confirmations. The schema and all readers
must be reviewed together before implementation; this note does not assert that
every current downstream reader permits extra fields.

| Observation point | Required meaning |
| --- | --- |
| Branch selection after current Record/State checks | Record an actual whole-root candidate or a traversal selection; retain failures before actual verifier entry separately. |
| Ordinary/scoped verifier entry | Start one traversal attempt even if root loading fails before any node callback. |
| Actual DFS node pop | Count `node_boundaries_started` immediately before the original callback and `node_boundaries_passed` only after it returns successfully. These are visited boundaries, not a claim that a node was completely validated. |
| Actual frontier hit in the scoped loop | Increment a real subtree-reuse counter only when the exact certified branch is taken. Preserve the count if a later node, callback, final fence, or scope finish fails. |
| Traversal return | Distinguish a completed full/no-hit traversal, a completed partial traversal, and unsuccessful attempts with or without actual subtree use. A failed no-hit attempt is not a completed full verification. |
| Whole-root final fence and scope finish | Distinguish initially selected reuse from confirmed reuse, invalidated reuse, callback error, and unwind. Do not report a final confirmation from the earlier candidate match. |
| Final aggregation | Preserve success, error, unwind, unfinished/unknown, observation failure and overflow conditions. Keep all starts in the denominator. Unknown or incomplete observations cannot qualify a run. |

The likely implementation sites are `verify_state_with_readback`, the ordinary
`verify_account_values` loop, `native_scoped_readback::verify`, and the existing
history observation accumulator. A per-attempt guard should carry real event
counts through early return and unwind into bounded totals; it must not retain a
State, SQLite verdict or subtree authority. Completed full traversals, completed
partial traversals and confirmed whole-root hits can then be reported alongside
all unsuccessful attempts without assigning them invented modes. A whole-root
hit performs zero graph-node visits but still performs current record/state and
original boundary checks.

Do not add a timer, allocation, lock, SQL query or synthetic Host callback at every
node solely to produce these metrics. Prefer bounded local counters, then one
aggregation at attempt end; their actual execution cost remains inside the
original native wall/CPU envelope. Never subtract instrumentation cost, move work
outside the deadline, replay a warm cache off-clock, or estimate skipped-node work
as work actually executed.

Native tests must distinguish at least: an ordinary full traversal; a scoped
traversal with an available frontier but no hit; an actual partial traversal; a
confirmed whole-root hit; malformed root rejection before the first node;
cancellation at a node boundary; an actual subtree hit followed by later error;
final-callback mutation that invalidates earlier reuse; transaction replacement,
schema change and an already-consumed scope; unwind/observation failure; and a Host
observation that crosses the original deadline. Existing non-promotion,
source-immutability and callback-order regressions remain unchanged. These are
required future native checks, not test results from this note.

## Required replay and acceptance

Build the exact next candidate in the hosted native environment and bind its
source tree, compiler profile and executable hash before execution. Retain
after-execution source observations, original report/finalization records and all
planned requests. Run the unchanged F0 controller/profile under:

| Original constraint | Required value |
| --- | --- |
| State / witness backend | AuthenticatedV1 / RawR14 |
| Host `cpu.max`; `cpu.max.burst` | `25000 100000`; `0` |
| Host memory; swap; pids | `2147483648`; `0`; `256` |
| Metered refill; burst; start reserve | 250,000,000 ns/s; 2,000,000,000 ns; 100,000,000 ns |
| Original phases | Baseline and valid-work-root, 30 seconds each |
| Hostile producers | 24 in the attack phase |
| Business schedule | Offsets 1, 5, 9 seconds in each phase |
| Confirmation requirement | Original depth 6, strict elapsed time < 4,000,000,000 ns from the scheduled offset |
| Planned denominators | 6 confirmations; 42 business packet exposures |

The baseline must pass before attack resilience is credited. Failed, late,
cancelled or unobserved planned work remains in the original denominator even if
the baseline fails. Evaluate the new graph diagnostics inside that same actual
delivery run, with original outer wall/CPU accounting. Investigate actual complete
delivery and independent confirmation, not only graph throughput or successful
page imports. Compare exact source/binary runs; historical measurements cannot
stand in for a replay of the changed candidate.

A passing finite F0 pair would still not establish sustained novel-input
resilience, the separate original issue #639 from-zero four-second/16-producer
gate, independent operator/WAN behavior, or production readiness. Those obligations
remain separate. This inspection finds a concrete observation gap and a bounded
next measurement, but no unconditional state-check deletion safe to claim as the
baseline repair.
