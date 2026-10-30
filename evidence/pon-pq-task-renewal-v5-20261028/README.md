# Native PQ task renewal V5: source candidate and retained observations

## Qualification boundary

This continuation implements a fresh **NPQ5/PQP5** task lifecycle, including
atomic dual-authorized command 22 and requester-only command 19 followed by an
explicit waiting state and a new source authorization through command 21.
**Native execution of this V5 candidate is NOT_RUN locally.** Shared-disk stop
conditions prevented code generation and native execution; neither metadata
compilation nor passing Python readers is native acceptance. The mandatory
hosted gate requires 204 passing tests, retains all eight original library
ignores, and retains the complete original 180-test cohort. The earlier NPQ4
hosted success belongs to its own source and cannot qualify these changes.

The parent is local `a1815707d29d424a8ec89d3701a7cf914572a416`, byte-equivalent
to remote `1d4778507e1e99ab54cca72b7c26b6ec2ff33344` with tree
`a7ac9da2199e8a9024c0daca800f0bd5ffef5c05`. The exact final changed-file inventory,
metadata-input joins, retained failures and bounded check receipts accompany
[qualification.json](qualification.json), [validation-summary.json](validation-summary.json)
and [observations.tar.xz](observations.tar.xz). These files separate observations,
source-derived expectations and work still requiring native execution.

This is a fresh-profile research candidate. Existing NPQ1/2/3/4 names, encodings,
signature domains and stores retain their selection and semantics. V5 does not
enable a negotiated fallback or a trusted migration constructor. A real signed
claim without a V5 migration anchor must fail. Model/evaluation commands
6–9/12–17/23–24, historical retired-key governance, source-chain retirement,
custody, transport, whole-chain PQ and P1 completion remain open. Production
activation, real economic demand and useful neural work remain unqualified.

## Actual permission owners and state transitions

The [new M00 lifecycle codec](../../trillionnium/crates/trnm-protocol/src/qualified_work_task/pq_lifecycle_v5.rs)
defines independent V5 lease, full-lease revocation, renewal, registration and
atomic-renewal encodings. The [M01 verifier](../../trillionnium/crates/trnm-crypto-primitives/src/qualified_work_task/pq_lifecycle_v5.rs)
binds the actual transaction kind and complete payload to the independent
requester and source ML-DSA roles. A command-22 signature cannot be extracted and
reused as a command-21 authorization.

The [M06 owner](../../trillionnium/crates/trnm-mvcc-fee/src/pon_executor/pq_accounts_v2/tasks_v5.rs)
resolves the current lease and both accounts from actual State. The caller does
not choose a source in place of that resolution. Current account generation,
key identity, requester nonce, old lease ID, prior statement and branch state
are checked during preparation and again before applying the fee/state patch.
Authority rotation or revocation in the same block excludes use of either role
in either command order. A separate private unit control prepares a real atomic
renewal and then tries applying it after requester/source rotation, revocation,
staged renewal and another branch's statement. Each stale application is
required to refuse before changing fee, nonce or State.

| Command | Real authorization | Required resulting state |
| --- | --- | --- |
| 18 | Current requester; source account must exist in State | Open lease, no usable source statement |
| 19 | Current requester; old lease/revision/prior statement must match State | New lease revision, explicitly `awaiting-source` |
| 20 | Current requester; signed full lease must equal current State | Revoked task; actual activation records stable local withdrawal |
| 21 | Current requester and current resolved source | Dual-authorized statement for the current lease, active task |
| 22 | Current requester and current resolved source | Atomic new revision and new source statement, active task |

Renewal preserves the original scope, demand, generation, identities, material,
meter and output history. It requires exactly the next revision, a still-valid
old lease, no future start gap, strict expiry extension and the original validity
and retention bounds. No fee or leaf is published for a failed precondition or
either failed signature.

Current lease, initial lease and last dual-authorized lease are deliberately
separate State fields. Command 19 cannot turn an earlier source signature into
authorization of the longer window. Cold validation keeps the old signed lease
and raw statement while task eligibility refuses the pending revision. Command
21 must explicitly sign the new current lease and correct previous statement.
The native regression source contains a complete 22 → 19 → 21 sequence: a
nonempty fifth witness fragment is retained while awaiting the source and is
actually cleared when a shorter command-21 proof replaces command 22.

A material block may include renewal while crediting the independently verified
parent task under its original eligible window. This does not grant future work
to the pending successor. The original task meter and output identity survive
renewal; conflicting output is refused. The candidate validates a cloned
resulting State before assigning the caller's State, preserving no-mutation-on-
error behavior. Historical output is compared with the initial authorized lower
bound, not a later renewed start height.

## Full proof retention and unchanged capacity limits

The original limits remain 1,048,576 bytes per packet, 524,288 bytes of aggregate
transactions, 9,432 bytes per native PQ transaction, 4,096 bytes per State value,
32 task slots, and 49,188 bytes per complete W1 proof. There is no new packet or
leaf budget. The local withdrawal table retains its original finite 1,024-entry
limit; exhaustion refuses instead of dropping history.

The following are **source-derived codec expectations with executable assertions**,
not observed native throughput, proof cost or capacity qualification:

| Object | Expected exact size |
| --- | ---: |
| V5 lease | 344 B |
| Full-lease revocation payload | 348 B |
| Requester renewal payload | 412 B |
| Registration payload | 652 B |
| Atomic renewal payload | 1,032 B |
| Complete dual registration command | 7,894 B |
| Complete dual atomic renewal command | 8,274 B |
| 32 complete atomic renewals | 264,768 B |
| Ordinary packet containing those 32 renewals and full W1 | 314,348 B |

The entire transaction proof is stored across five bounded witness leaves under
a fresh namespace. The chunk payload limit is 2,000 bytes. Registration uses
2,000/2,000/2,000/1,894/0 bytes; atomic renewal uses
2,000/2,000/2,000/2,000/274 bytes. Fragment metadata binds index, ordering,
total length, task identity and statement kind. All signatures, metadata and
chunk sizes are checked before the first staged leaf write, and the common
fee/nonce/state patch remains atomic. Missing, duplicated, reordered, oversized,
cross-task and mixed-branch fragments are required to fail cold authorization.

The 32-renewal test requires 64 real command signatures and all 160 witness leaves.
It separately checks a 520,548-byte mixed valid block and refusal at 524,811 bytes
against the original aggregate ceiling. Eligibility, material validation and
cold reconstruction perform additional checks; the 64-signature assertion does
not claim to measure total Node verification cost. Actual shared-host W1 timings
will be retained by the hosted gate without being promoted to isolated
worst-case invalid-input or propagation-cost measurements.

## Ordinary Node, actual packet evidence and monotonic local withdrawal

The [V5 Node path](../../trillionnium/crates/trnm-pon-node/src/store/pq_tasks_v5.rs)
uses the ordinary pool, material resolver, full reference W1, admission,
activation, SQL persistence, output accounting and cold recovery. Explicit
NPQ5 packet, network, parameter, SQL and signed domains must agree. PQ4 and
legacy stores cannot open as V5, and no classical inner signature is borrowed.

Stable local withdrawal identity is derived from the State-bound lease's
network, parameters, genesis, demand, generation, requester and source. Revision
and renewed window are excluded. Thus a heavier fork containing a different
renewal revision cannot resurrect local permission to mine the same lineage.
The full signed current lease in command 20 retains the precise withdrawal
revision and real owner context for later reconstruction.

Withdrawal rows are appended only in the activation SQL transaction and are
bound to the actual activation event and activation generation. Cold audit
reconstructs every first activation from the actual original packet and verifies
its transaction root, even for detached blocks. It compares the complete first-
withdrawal inventory, order, full lease identity, revision, demand, block and
generation. Later activations do not overwrite the original evidence. Deleting
a row, changing its revision, substituting transaction bytes while preserving an
old header/W1, or changing first-activation history must refuse cold opening.

This local withdrawal policy does not change branch-relative consensus validity:
a peer's valid work on a live branch can still be admitted while the withdrawn
local producer cannot obtain material to mine it. The new heavier-fork test
contains a real command-22 successor, not a revision-free mock. Physical database
I/O and rollback of an entire external storage snapshot remain outside this
finite local-history contract.

## Executed local checks and required hosted checks

Local checks use the real Rust 1.95.0 metadata compiler and strict
`clippy-driver -D warnings`, with each selected external artifact and source input
hashed. The four changed libraries, M00/M06 unit targets and two V5 integration
targets are covered. They emit metadata only. They do not execute test bodies,
link a new executable, perform a full Cargo build, or qualify all targets/features.
The exact locked/offline Cargo metadata independently resolves 173 packages,
26 workspace members and 173 dependency nodes without changing the lockfile.

The complete strict legacy evidence reader executes 76 tests. It understands the
new explicit V5 selectors only to reject transfer of legacy qualification to PQ
schemas or packets. It still returns the original 4,775-byte legacy schema and
retains all earlier token, source-mutation, SQLite and packet negatives. New and
retained gate readers execute 12 and 10 tests; source-integrity and evidence-source
negative suites execute 34 and 38 tests. Format, source inventory, CI contract
and project preflight checks are separately recorded. Exact times, exit codes,
before/after source maps and command outputs are in the retained observations.

The working copy is intentionally sparse. The full source fence actually refuses
its hidden tracked entries; this refusal is retained, not disabled. Small needed
format, formal-reader and test-vector files were restored from exact parent Git
objects with independent identity receipts. One old missing evidence blob remains
an inherited object reference; the continuation does not invent or replace it.
Only hosted CI on the complete published tree can supply a clean full-source
and full-build qualification.

The [new finite native gate](../../scripts/ci/run_native_pq_tasks_v5.py) requires:

- The original 180 passing cases and eight original library ignores, unchanged.
- One additional M06 apply-time reauthorization unit case, 16 real M06 V5
  integration cases, and seven ordinary Node V5 integration cases: 204 passing
  tests in total, with zero new integration ignores or filtered cases.
- All 37 V5 actual full-W1 phases, including ten material phases and the complete
  32-renewal packet, with exact raw/packet/proof sizes and no substituted phase.
- All 26 original V4 full-W1 phases and the retained V1/V2/V3 cohorts.
- Fresh locked Cargo compilation and strict M00/M06/Node
  `--all-targets --all-features` Clippy, original 2,400-second whole-command
  budget, one Cargo build worker and original 60-minute job ceiling.

Synthetic reader logs qualify only the parser's refusal behavior. Missing cases,
new ignores, filtered cases, compiled-only output, partial proofs, shorter
fragments, old-profile phases and understated packet sizes cannot qualify V5.

Preserved local failures include the initial missing sparse test vector and fuzz
lock, the first Clippy range-pattern diagnostic, and the first Node integration
tuple-complexity diagnostics. Their source fixes have actual successful metadata
or reader rechecks. No failed observation is converted into a native pass.

## Reviewed source pins and remaining blockers

The [independent review](recent-batch-independent-review.json) authorizes only the
two changed shared-source pins in the existing recent-batch workflow:
`store.rs` and `native_authenticated/arithmetic_cache.rs`.
[The byte-delta receipt](recent-batch-pin-delta.json) verifies that all 16 guards
remain, the other 14 pin values remain exact, and all other workflow bytes,
four lanes and original 25-minute limits are unchanged. This review is scoped
to those two diffs, not the complete V5 runtime; updating pins does not supply a
successful recent-batch result.

The immediate blocker is the new exact-source hosted native gate, including its
204 actual outcomes, complete W1/material phases and strict fresh Cargo/Clippy.
The complete V5 authority implementation also awaits independent runtime review.
There is no supported V4-to-V5 or legacy-to-V5 task migration. Historical model
signers, retired-key slashing/appeal authority, remaining model command ownership,
independent migration trust/source retirement, whole-chain PQ and P1 completion
remain explicit open work rather than being accepted through this task profile.
