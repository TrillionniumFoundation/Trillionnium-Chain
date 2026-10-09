# M10 Contributions, immutable release and actual task lifecycle

Revision: invariant-driven revision3. Selected target: `pon-nakamoto-v1`.
[Sole development plan](../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md); [exact invariant registry](../../config/pon/invariants-v2.json).

## Scope and ownership

Signed experimental contributions and release transitions; public model value and independent evaluator trust are not inferred.

The claims below apply to their named component and tests, not to an independently accepted full native node.

## PoN State machine

### M10.SubmitContribution

Validate the signed128-block intake round, full context-bound contribution id,64-block lifetime,256 active and512 total current-round records. Current-round repeats reject; old-round signed transactions remain invalid after reclamation.

**Atomic/commit boundary:** Count active current-parent candidates; preserve same-parent duplicate keys; old-parent retirement leaves root-bound release authority intact.

### M10.PublishEvaluatedRelease

Verify bundle minimum positive score; bind exact components root, accepted leaf scores/owners and total; recompute release id; debit sponsor; record maturity and claims; only then adopt pointer. Local Hepta use still requires generation admission.

**Atomic/commit boundary:** Same state transition and block delta; reorg reverses pointer/escrow but not historical inference.

### M10.SubmitFactorContribution

Only `linear-factor-witness-dev-v2`, native public evaluation and the legacy task
profile select revision11/tag23. M00 decodes the full ILF2 rank1..2 B/A witness;
M06 `integer_factor_candidate_v2::admit` loads the actual current ILM2 model (or the
actual adopted release's full artifact), authenticates its chunks/family/hash and
recomputes all771 BA coordinates and all3855 candidate coefficients. Its complete
candidate and context-bound duplicate rows enter the original staged State.
Equivalent basis, sign and zero-padding witnesses over the same parent/round/slot
are refused across authors; different BA does not prove different model behavior.
`build_witness` is producer convenience, not admission or evaluation authority.

**Atomic/commit boundary:** Original M06 full State/receipts/reversible deltas;
Node publishes only through its existing durable admission/activation. Same-parent
same128-block-round markers survive expiry/abort, and fork/reopen restore the actual
branch facts. No new SQL owner, durable schema or reward ledger is introduced.

**Dedicated error summary and bounds:** `FACTOR_PROFILE`, `FACTOR_PARENT`, `FACTOR_MODEL_HASH`,
`FACTOR_MODEL_RANGE`, `FACTOR_COMPUTED_HASH`, `FACTOR_NOOP`,
`DUPLICATE_FUNCTION_UPDATE`; rank1..2, slot0..2, scale1024, i16 coefficients
[-32767,32767], signed transaction921/1441B within2048B, complete model7756B in
8 raw1024B chunks, at most1542 checked products, unchanged65536 State keys.
The [complete layered error catalogue](../protocol/pon-nakamoto-v1/details/NATIVE_INTEGER_FACTOR_CANDIDATE_V2.md#errors-and-validation-order)
separates witness codec, model/parent, duplicate and inherited execution refusals;
this short list is not exhaustive.

The actual component receipt names four Rust `#[test]` controls in
[`integer_factor_candidate_v2.rs`](../../trillionnium/crates/trnm-pon-node/tests/integer_factor_candidate_v2.rs):
`exact_variants_refuse_and_real_fork_restores_duplicate_window`,
`missing_score_abort_keeps_same_round_marker_and_new_round_allows_update`,
`loaded_release_parent_full_range_and_new_round_are_native`, and
`cli_selects_fresh_profile_and_genesis_before_any_candidate`.
These include real signed admission,128-block adoption, loaded parents and fork/reopen.
The responsibility registry binds these four real attributed Rust tests. The navigator
checks their source selectors separately from whether an exact recorded invocation
actually ran them; a source binding is not a component receipt or a new whole-source
qualification. Source-group budgets, general functional attribution,
independent evaluator governance, positive ML gain and public acceptance remain open.

## M10.PendingNotHistory

**Invariant:** Inactive contributions cannot exhaust pending capacity forever; signed intake windows bound same-parent history, reject expired-window replay, and preserve independently rooted release claims. Published release metadata retains the exact model artifact/family/parent after candidate reclamation.

**Scope:** Signed experimental contributions and release transitions; public model value and independent evaluator trust are not inferred.

**Atomic boundary:** Revision3 signs submission_round in the fixed 176-byte contribution payload and ID; deterministic window retirement precedes transactions; claims use unchanged release-root membership.

**Failure schedule:** 257 zero-scored contributions; Same-parent duplicate after retirement; Candidate expiry; Three releases and claims with original rows removed; Fill512 zero-score historical records without an adopted model; Cross128-block window with old signed payload; Positive evaluated candidate outlives64-block expiry.

**Expected result:** Inactive contributions cannot exhaust pending capacity forever; signed intake windows bound same-parent history, reject expired-window replay, and preserve independently rooted release claims. Published release metadata retains the exact model artifact/family/parent after candidate reclamation.

**Resource and retention rule:** 256 active candidates, at most512 records per128-block window,64-block candidate lifetime; old-window signatures reject before history is recreated.

## Concrete regression selectors

`formal/pon-nakamoto-v1/test_invariants.py::CapacityTests.test_zero_score_history_does_not_consume_pending_capacity`

`formal/pon-nakamoto-v1/test_invariants.py::CapacityTests.test_expiry_releases_capacity_without_dropping_current_parent_nullifier`

`formal/pon-nakamoto-v1/test_native_execution.py::NativeExecutionTests.test_three_signed_release_generations_preserve_payout_and_retirement`

`formal/pon-nakamoto-v1/test_invariants.py::CandidateWindowTests.test_full_history_window_reopens_without_old_signed_replay`

`formal/pon-nakamoto-v1/test_invariants.py::CandidateWindowTests.test_round_is_part_of_contribution_and_signature_identity`

`formal/pon-nakamoto-v1/test_invariants.py::CandidateWindowTests.test_positive_evaluation_expires_and_cannot_be_adopted_late`

`formal/pon-nakamoto-v1/test_native_execution.py::NativeExecutionTests.test_native_round_boundary_retires_history_and_rejects_old_signature`

These exact functions contain executable assertions. The registry only checks binding; actual outcomes and source/input identities belong to the separate qualification report.

## Worker command termination and wait ownership

The real Worker LLM command collector in
[`command_runtime_exec.rs`](../../trillionnium/crates/trnm-worker-agent/src/command_runtime_exec.rs)
retains its requested command deadline, fair nonblocking stdout/stderr drains and
8 MiB aggregate output bound. Cleanup has one additional absolute 1-second budget,
shared by group termination, descendant waits and the final direct-leader wait.

On Linux it enables process-wide child adoption once and never toggles that setting
around concurrent calls. It keeps the direct leader unreaped while signalling its
owned group and discovering adopted children through every `/proc/self/task/*/children`.
Only children with this process as parent and the pinned leader's group qualify;
starttime/parent/group are checked before and after opening a pidfd, and each wait
uses that descriptor. Unknown children receive no signal or wait. A disappearing
task requires another complete scan. The direct leader is reaped last, preserving
its actual exit status. Missing proc/pidfd support, changed identity or incomplete
cleanup refuses; expected descendant SIGKILL never changes a command refusal into success.

Permanent adoption affects the Worker process. The separate transaction adapter's
`ProcCommand::output` path retains its existing contract and is not certified by this
bounded LLM collector. On Darwin the existing group-termination/direct-leader-wait
contract remains; it does not assert Linux descendant adoption/reaping. Deliberate
credential/group escapes and process/host failure are outside this ordinary
same-group cleanup guarantee. This is not sandboxing or public service qualification.

## Module-specific threat and residual work

Lifetime counters, generation-stale scores, duplicate rewards and unbounded same-parent spam.

Per-window capacity may be exhausted temporarily. Account/work-registration history, independent evaluator policy and economic Sybil fairness remain unqualified.

## Current source and verification

- [`formal/pon-nakamoto-v1/ledger.py`](../../formal/pon-nakamoto-v1/ledger.py).
- [`trillionnium/crates/trnm-mvcc-fee/src/pon_executor.rs`](../../trillionnium/crates/trnm-mvcc-fee/src/pon_executor.rs).

No test binding or local campaign grants independent acceptance, ordinary Hepta execution or production activation. Preserve the exact source, profile and environment of every outcome.

## Executed evidence and scope

[Responsibility-level evidence navigation](README.md#responsibility-and-evidence) reads
measured commits from immutable receipts. The module's entries in
[module-maturity-v1.json](../../config/pon/module-maturity-v1.json) identify actual callable
owners, controlled entrypoints, backends, persistence and exact observed test selectors.
Run `python3 scripts/ci/report_module_evidence.py --module M10` from the repository
root to see subject-byte and complete recorded-runtime matches separately, plus scenarios
not observed in each package. A byte match is not a new test run or product acceptance.
Historical v1/v3/v4 results are never repinned. The sole plan selects further work.

## Bounded empirical evidence and source budgets

The explicit [native model evidence v3](../protocol/pon-nakamoto-v1/details/NATIVE_MODEL_EVIDENCE_V3.md) binds candidate admission and release allocation to actual full integer inference and known-source budgets. A pre-adoption participant objection ends that candidate attempt without funding an indefinite escrow. Public historical-task memorizer successes are test fixtures; prospective usefulness remains separate.

## Exact composition in the fresh revision14 profile

The explicit [model composition V4](../protocol/pon-nakamoto-v1/details/NATIVE_MODEL_COMPOSITION_V4.md)
uses the existing signed tag23/8/9 and ledger, with fresh profile, policy and evidence
namespaces. At tag8, M06 loads the actual current full parent and2–4 complete
components, verifies `bundle = parent + sum(component - parent)`, and rejects any
subset of at least two components whose complete relative update is exactly zero.
The bundle must beat the actual parent, all four frozen controls and every component;
every allocation weight must equal its freshly evaluated positive leave-one-out gain.

Tag23 alone does not certify composition. An unrelated candidate can consume intake
quota yet fail release admission. Known-source caps use the actual floored payouts,
with dust retained for the original deadline refund. The bounded composition receipt
is embedded in the existing release row. Reorganization reverses that branch state;
local irreversible operations retain their separate owner. Exact derivation does not
prove training causality, general fair allocation or future usefulness. Revision13
keeps its prior individual-component gate and namespaces.

The independent Python comparator recomputes the actual native release identity,
allocation root, complete composition record, floor payouts, source reservations and
dust from the exported signed-lifecycle inputs. It also requires the second generation
to use the first actual adopted model bytes and release reference. This closes an
implementation conformance gap without treating the public fixed-corpus examples as
new evidence of market demand, independent contributors or future model benefit.
