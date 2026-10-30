# Native PQ task permissions v4 — research candidate

Status: **implementation candidate; new native execution NOT RUN locally**.
The selected path is fresh NPQ4 `18 → 21 → 20`: a requester opens a lease,
the actual requester and source independently authorize one task, and the
requester can revoke that lease. The ordinary Node material, W1, output,
activation, cold-read and heavier-fork paths share this namespace. This does
not qualify the remaining model, evaluation, renewal, migration or operator
authority paths, real demand, model utility, whole-chain PQ or activation.

The parent is published Draft #524 head
`29e1f194742e436b44b4c8758777341e62fe2bd8`, tree
`40dab4b86e38ee541a93a8e232a2442d3160e8fd`; local parent
`ab4a7daf9892035c435608b9a7d9f3b3952b1a39` has the same tree. Its
[164-test hosted Cargo observation](../../../../evidence/pon-pq-hosted-a1e407-20261028/README.md)
is retained historical evidence. It does not certify this changed runtime.

## Actual owners and signed binding

The [M00 framing owner](../../../../trillionnium/crates/trnm-protocol/src/pq_native_accounts_v2.rs)
selects `AccountProfile::TasksV4` explicitly. Its `NPQ4\x04` commands and
`PQP4\x04\0\0\0` packets have separate statement, wire and owner-context
domains. The TPQ1 algorithm remains ML-DSA-65; role 1 is the requester and
role 2 is the source for command 21. Both proofs cover the complete joint
core, including both key descriptors and the lease-bound payload. No inner
Ed25519 statement or caller-selected verification flag substitutes for either
proof. Distinct account keys are not proof of independent human control.

The [M06 task owner](../../../../trillionnium/crates/trnm-mvcc-fee/src/pon_executor/pq_accounts_v2/tasks_v4.rs)
resolves the source from the actual parent lease. It checks the requester
against that lease and both current account authorities before signature
preparation, again before applying the command, and again when admitting
registered material. A cached private prepared command is not sufficient
after a lease replacement, revocation or authority rotation. Invalid inner
or outer proofs cannot consume a ledger nonce, charge a fee or publish a
partial witness leaf.

Replay binding includes the network, parameters, genesis, NPQ4 domain,
requester account and account nonce, both current key generations and IDs,
the exact lease ID, the source sequence and the prior statement ID. The
revocation payload contains the exact lease ID as well as demand ID, slot,
requester and expected revision. Command expiry is checked against its
original admission header time; later material use separately checks the
signed lease's block-height window. Height and timestamp are not conflated.

Commands are resolved against the parent, and a block cannot combine an
authority change with a task command referring to that authority in either
order. One task command per demand per block also rejects open/register and
revoke/register pairs in both orders. A source or requester rotation retires
the old task statement for future work. Fresh dual proofs may re-register the
same bound model/input/task/output meter with the next source sequence and
prior statement; they do not reset an already consumed output meter.

## Complete bytes and bounded storage

The [fresh lease codecs](../../../../trillionnium/crates/trnm-protocol/src/qualified_work_task/pq_lifecycle_v4.rs)
use `PQL4`, `PQR4` and `PQT4` and separate demand, lease, source-record and
withdrawal-frontier hashes. Old lease encodings are refused.

| Item | Exact bound or size |
| --- | ---: |
| Lease / revocation payload | 344 / 176 bytes |
| Task registration payload | 652 bytes |
| Signed open / revoke command | 4,053 / 3,885 bytes |
| Complete dual-proof registration | 7,894 bytes |
| Registration witness fragments | 2,000 + 2,000 + 2,000 + 1,894 raw bytes |
| Largest fragment as canonical JSON hex string | 4,002 bytes |
| Original maximum State value | 4,096 bytes, unchanged |
| Task slots / witness leaves at full occupancy | 32 / 128 |
| Full 32-registration cohort | 252,608 raw bytes and 64 real proofs |
| Original per-block transaction byte/count limits | 524,288 bytes / 256 commands |
| Original packet / complete W1 proof limits | 1,048,576 / 49,188 bytes |
| Retained local revocation capacity | 1,024 distinct lease IDs |

Each lease opening allocates one metadata leaf and all four empty witness
leaves. Registration cannot create a hidden future key liability or disguise
two signatures as the old single-signature allowance. Every fragment index,
length, total length and exact key coverage is checked; reassembly parses the
entire NPQ4 envelope and checks its task and lease binding. Cold material
eligibility verifies both actual proofs using the current State authorities.
Missing, reordered, duplicated, oversized, truncated and cross-task fragments
are explicit negative cases. The global State, account, fee, transaction and
packet limits remain in force.

The full-slot fixture verifies capacity for 32 signed registrations. Only one
of those registrations is exercised with actual supplied matrix material in
the Node capacity case; this is not a claim of 32 useful model tasks. Its
deterministic public fixture is a real matrix/W1 execution control, not proof
of a real user's demand or a neural model's benefit.

## Node publication and monotonic local revocation

The [explicit PqNodeV4 owner](../../../../trillionnium/crates/trnm-pon-node/src/store/pq_tasks_v4.rs)
uses ordinary M05, M06, W1 and SQLite publication. Fresh SQL statement and
removal tables use version 4, and `local_pq_task_revocations_v4` records the
first actual activation event for each revoked lease. The activation event
and local revocation row share the original publication transaction. A cut
before publication cannot publish either half; normal recovery must publish
both together. A heavier chain may restore branch-relative ledger state but
cannot remove the local owner's retained revocation evidence.

Cold audit reconstructs the first revocation from all retained activation
events, including detached blocks, and compares the exact ordered records.
Every event packet's actual transaction list is rebound to its header root.
This additional check matters because block ID and complete original W1 alone
do not bind a separately replaced transaction list read from local storage.
The native negative control replaces a detached revocation packet with an
empty transaction list while retaining its original header, block ID and W1,
and also deletes the local row; cold open must refuse. Restoring the exact
original bytes and row must restore the valid cold path.

Local production refuses a lease the owner previously revoked. Remote block
validity still follows its actual parent State, so another node's valid block
on the heavier unrevoked branch remains admissible. This separation avoids a
node-local history rule becoming divergent consensus. It does not provide an
outside anti-rollback anchor against replacement of the complete database.
The current audit scans the retained activation history on cold open and local
material use; an unbounded-history cost claim is not made. Exhaustion of the
explicit 1,024-lease local history capacity fails closed and requires a future
separately designed bounded retention/anchor policy, not silent deletion.

The ordinary output owner accepts the independently verified W1 product,
records at most one product per bound meter and mints no reward. A valid
authority rotation or lease revocation in the successor suppresses output
credit; malformed or missing authority State remains an execution error.

## Validation contract and current observation

[Retained local observations](../../../../evidence/pon-pq-tasks-v4-20261028/README.md)
separate Rust metadata checks, Python reader controls and actual native
execution. Shared disk exhaustion prevents a fresh local Cargo/ELF run. Four
runtime libraries and the four new unit/integration compilation targets were
typechecked against recorded immutable dependency artifacts; direct
warnings-denied Clippy is recorded separately. These are not native test
execution or full Cargo graph qualifications. Initial sparse fixture/import
and formatting failures are retained rather than replaced by later passes.

The [finite hosted runner](../../../../scripts/ci/run_native_pq_tasks_v4.py)
retains the original 2,400-second total command budget, single build worker,
exact before/after source fences, Rust 1.95.0, locked Cargo graph, formatting
and selected M00/M06/Node all-target/all-feature warnings-denied Clippy. It
requires all previous 164 selected tests plus two new unit cases and fourteen
new integration cases: **180 passed tests is the required result, not a local
observation**. The complete unit-name map retains exactly the eight original
ignored component-timing cases. All 44 integration cases must execute with
zero ignored or filtered cases.

The five new Node cases require 26 actual complete W1/reference/admit/SQL phase
records, including six registered-material calls. The parser checks full raw
command and proof sizes, exact case rosters and complete phase counts. Reported
wall time is shared-host observation; it is not isolated CPU/energy cost,
worst-case invalid-input cost or network throughput. Synthetic parser tests
never count as native execution. The strict legacy evidence reader recognizes
the new closed selector joins while returning only the unchanged 4,775-byte
legacy schema. NPQ4 packets, schemas and local revocation tables cannot borrow
that legacy qualification.

## Remaining concrete authority owners

All rows below remain outside this new namespace. The source references are
the actual owners in this repository, not a proposed blanket PQ envelope.

| Commands / path | Current permission owner and remaining work |
| --- | --- |
| 6: model contribution | `pon_executor` binds the classical ledger sender to contribution/family/current-parent/artifact/components. It needs a native PQ author and account lifecycle in the model profile. |
| 7: model evaluation | The configured evaluator set and contribution owner exclusion control the actual vote. The evaluator authority, rotation and frozen-round semantics remain classical. |
| 8: adoption/release | The actual ledger sender funds the release; accepted contribution records, evaluation policy, allocation root and model-evidence owner control adoption. These permissions and their reorg/cold paths remain unconverted. |
| 9: reward claim | The allocation leaf binds contribution, claimant sender and score, with maturity/deadline and remaining-budget checks. The claimant and release/model profile remain classical. |
| 12: legacy task registration | The classical envelope installs the legacy `work:` record. NPQ4 refuses this command and any imported legacy task records. |
| 13: signed development task | The actual configured demand/source/withdrawal/sequence owners plus the inner `SignedQualifiedWorkTask` Ed25519 proof remain unconverted. |
| 14–15: evaluation commit/reveal | Frozen evaluator membership, round, plan, commitment, exclusion and evidence owners remain tied to the classical sender. |
| 16: evaluator conflict | `public_evaluation::conflict` verifies two actual embedded classical envelopes, in addition to the submitting envelope. All three roles require explicit conversion. |
| 17: appeal | The actual contribution author and appeal state/round/evidence authorize the request; outer sender conversion alone is insufficient. |
| 19 / 22: renewal | Existing lease renewal and atomic requester-plus-source renewal remain outside NPQ4. Command 22's inner classical source statement must be replaced with independently resolved PQ authority in a future namespace. |
| 23 / 24: factor/evolution candidates | Integer candidate/evolution witness owners, current model parent, evidence policy, round/evaluator membership and author sender remain unconverted. |
| Original 18 / 20 / 21 | Existing lifecycle-v2/v3 encodings continue their own semantics. Only explicit NPQ4 receives the fresh 18/20/21 behavior above; no old database is upgraded. |
| Native migration / custody | NPQ4 has no trusted migration constructor. Existing NPQ2/3 anchor trust, source retirement, physical rollback and operational key custody remain separate obligations. |
| Transport, History, Hepta | Peer/session signatures, operator/journal recovery authority, actual model install and subsequent-task Final-use authority do not inherit this task-registration result. |

The classical execution branches are in
[pon_executor](../../../../trillionnium/crates/trnm-mvcc-fee/src/pon_executor.rs),
[qualified_task_lifecycle](../../../../trillionnium/crates/trnm-mvcc-fee/src/qualified_task_lifecycle.rs)
and [public_evaluation](../../../../trillionnium/crates/trnm-mvcc-fee/src/public_evaluation.rs).
Their paths are kept available in their original profiles; they are neither
disabled to satisfy this candidate nor declared PQ by an outer wrapper.
