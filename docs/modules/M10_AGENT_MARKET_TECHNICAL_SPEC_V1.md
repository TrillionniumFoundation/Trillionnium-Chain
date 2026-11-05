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

#### Explicit revision16 contribution and release

The separate [model evolution V5 contract](../development/specs/pon/MODEL_EVOLUTION_V5.md)
routes signed tag24 through `model_evolution_v5::admit`, the same M06 executor
and the existing Node state/delta owner. It loads the actual complete current
ILM3 parent and admits at most three rank-bounded operations over base, router
or experts plus a nonempty three-slot enable mask. Equivalent factor bases are
normalized to the full resulting model for duplicate detection. The existing
tag8 path requires exactly one self-allocation matching the native evidence,
positive gain and source budget before adopting the complete candidate.

The [optional task-window contract](../development/specs/pon/MODEL_TASK_WINDOWS_V1.md)
fixes owner, exact source bytes, manifest identity and activation schedule in
the context before genesis. An author cannot select evaluation roots per
candidate. Native tests cover joint router/expert then base/mask adoption from
the actual successor parent, neutral non-publication, cross-profile refusal and
two controlled new-text windows. Separate Python vectors and Node CLI/reopen
checks name these new sources; they do not extend the historical four-test
factor receipt or grant Hepta installation authority.

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

The real Worker LLM and transaction command collector in
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

Permanent adoption affects the Worker process. The compiled `FlushSubmissions`
commit and reveal calls now use the same bounded collector. Each transaction
attempt receives `TRNM_TX_ADAPTER_TIMEOUT_MS` (default 10,000 ms, minimum 1 ms),
resolved once for the flush. A timeout or output-collection error stops the current
flush with an uncertain result; it cannot authorize another attempt, a reveal after
an uncertain commit, or an accepted acknowledgement. Deterministic adapter exit
codes retain their existing retry and terminal-receipt meanings. The original
private journal remains available for owner reconciliation.

The replay reader opens a regular file without waiting for a FIFO writer, checks
the opened descriptor, and reads at most 64 MiB plus one detection byte. It verifies
the 100,000 nonblank-record ceiling before any adapter effect. Growth after the
metadata read cannot turn this into an unbounded read. These are local replay
resource limits, not a chain transaction validity or permission change.

Integration of PR326 also corrects its source wiring: its initial retry-helper edits
were in files not included by the compiled `main.rs` module graph. The effective
bounded runner is now in that existing compiled owner, and
[`flush_bounded_runtime.rs`](../../trillionnium/crates/trnm-worker-agent/tests/flush_bounded_runtime.rs)
invokes the actual worker binary for both transaction phases, aggregate output
overflow, replay limits and FIFO rejection. Uncompiled helper tests are not evidence
for this call path. On Darwin the existing group-termination/direct-leader-wait
contract remains; it does not assert Linux descendant adoption/reaping. Deliberate
credential/group escapes and process/host failure are outside this ordinary
same-group cleanup guarantee. This is not sandboxing or public service qualification.

## Development worker commit/reveal salt ownership (isolated M10 candidate)

The local `trnm-worker-agent` development CLI previously derived its commitment salt
from the public task ID. A low-entropy result could therefore have its committed
preimage guessed before reveal. The proposed owner-only repair selects a new 256-bit
OS CSPRNG salt for every automatic task, with no clock/PID/task-ID fallback. It
changes neither the ledger commit/reveal hash formula nor any settled historical
submission, network profile, signed consensus domain or Hepta execution permission.

For an automatic `--submit`, the worker first acquires a same-process and
cross-process lock over a single owner-only submission journal; the exact private
record is synced before the transaction adapter may consume it. Reopening the
same task/result/worker returns the original salt, not a fresh commitment.
Conflicting identity, corrupt/truncated rows, symlinks, hard links, non-owner
or group/world-readable files, and missing entropy fail closed; they never
create a second task commitment. A crash during the append may leave an
incomplete row that requires explicit owner reconciliation rather than a
silent truncation or new salt. The journal and CLI output remain local secrets
until reveal. Operators must not publish the pre-reveal output or journal.

The explicit manual `commit-reveal` command accepts caller-provided material;
its secrecy and local log custody remain the caller's responsibility.
Its former `--submit` path, however, used a normal create/append open and
could create a world-readable log of the **unrevealed manual salt** under a
standard umask, or follow a final-component symlink. Manual submissions now
write through the same private journal inode lock as the automatic owner,
with `0600` new-file permissions, regular-file/owner/single-link checks,
`NOFOLLOW`, a finite log-size bound, newline-completeness check, synced
file and parent directory, and exact inode recheck. It preserves the
caller's chosen salt, hash and explicit manual append behavior, never
silently regenerating a salt. A preexisting public or linked manual log
fails closed rather than being automatically chmod'd or rewritten; prior
exposure of a salt cannot be repaired by changing permissions afterward.
On non-Unix hosts manual `--submit` now refuses instead of writing an
insecure fallback. Terminal output and manual command disclosure remain
the operator's responsibility; these controls do not guarantee secrecy
against the same UID, physical compromise or shell history. Previously
submitted deterministic salts remain historical: migration cannot retroactively
restore a commitment's hiding property. On non-Unix hosts automatic submission
refuses instead of silently reverting to a deterministic salt. No standalone
reference test proves a deployed adversarial client, an independent mining
participant, or model utility. The unchanged original mainline and paired Hepta
branch are not promoted by this separate M10 candidate.

### Unrevealed salt and captured CLI streams

A private journal does not protect an unrevealed salt if the same automatic
`run-once --submit` invocation also prints it into systemd, CI, or agent
stdout/stderr. For submitted run-once output, the existing JSON field names
`salt_hex` and `template_reveal` are retained but their values are
`null`; the public commitment hash and template remain intact. Explicit
manual `commit-reveal --submit` suppresses only the reveal command from its
ordinary output and retains the caller-selected salt in the original private
journal. Non-submit manual display remains unchanged, as does the explicit
`execute` result-plus-salt developer operation.

The default `flush-submissions` **dry-run** previously printed the saved
`salt_hex` in a reveal preview, even when that salt had never been revealed
on-chain. Preview output now retains the adapter, task identity and public
result hash but uses the literal `[unrevealed-salt-redacted]` placeholder.
Both an automatic CSPRNG salt and a caller-selected manual salt are kept
only in the original private journal. Two real CLI subprocess regressions
require zero salt bytes in stdout/stderr, unchanged journal bytes and no
transaction ACK during a dry-run. The explicit `--execute` transaction
adapter still receives the original exact reveal arguments when permitted;
this change does not silently submit or alter their bytes.

The existing transaction adapter reads the complete owner-only journal, never
a redacted stdout rendering. This is not proof against same-UID attackers,
host-level telemetry/memory inspection, or exposure through a manually supplied
`--salt-hex` process argument, shell history or separately captured raw
journal. No PoN work, signed packet, model or FinalUse authority changes.

### Shell-template argument boundary (isolated worker hardening)

The human-facing `trnm-node tx commit-result` and `reveal-result`
POSIX-shell command templates now render each caller-derived string as one
argument. Only the existing conservative plain-token alphabet is emitted
without quotes; other UTF-8 strings are single-quoted with embedded quotes
escaped. The original worker identity bytes, commitment input, nonce, salt
generation, result hash, signed Chain bytes and journal persistence are not
rewritten. Ordinary safe worker names keep their existing command bytes.
The durable journal now uses that same renderer when writing and checking
the original record, so a restart cannot switch to a second command.

This is command-template hardening, not proof that a Worker executes the
template safely, that arbitrary Windows shells interpret POSIX quoting, or
that raw diagnostic lines containing untrusted identity are terminal-safe.
The Worker does not dispatch these displayed commands. The existing
first-salt durable replay and tamper refusal remain required, as do
independent release and work-admission checks. No production authority
is granted by this development-only change.

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
