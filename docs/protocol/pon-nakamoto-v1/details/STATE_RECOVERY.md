# S1 — branch state, atomic reorganization and irreversible facts

Executable specification: `formal/pon-nakamoto-v1/ledger.py`. Native owner targets remain
M06 execution, M07 persistence and M08 coordination; this Python implementation is their
shared executable contract, not a second production owner or a claim of native completion.

## S1.1 Persisted records

SQLite uses WAL and synchronous=FULL. One process holds `owner.lock` with nonblocking
exclusive flock for the whole connection lifetime. A second writer fails WRITER_BUSY.
Directory/database symlinks are rejected; full descriptor/sidecar hostile-path fencing
and independent anti-rollback anchoring remain additional production obligations.

| Table | Key and required columns | Responsibility |
|---|---|---|
| metadata | key PK, value; exact parameter commitment | refuse a different genesis/profile in the same namespace |
| blocks | id32 PK, parent32, height, chainwork64-byte BE, header, body, proof, state_root | immutable fully validated branch record |
| deltas | (block,key) PK, before nullable bytes, after nullable bytes | forward/undo values for every actually changed key |
| active | singleton=1 PK, tip32, generation | only public canonical state pointer |
| kv | (generation,key) PK, canonical value | independently readable committed generation |
| reorg | singleton PK, old_tip,new_tip,generation,steps,position,status | exact durable transition intent and progress |
| events | (generation,ordinal) PK,kind,block | ordered remove/add index notifications published with active head |
| effects, separate DB | operation-id PK,payload commitment,generation,state | irreversible local dispatch observation; NOT chain state |
| revoked, separate DB | operation-id PK | monotonic local revocation; NOT detached on chain rollback |

No table accepts an arbitrary peer-provided root as authority. blocks are inserted only
after target, real work, transaction signatures, transitions and all roots validate.
Missing parent returns UNKNOWN_PARENT. Unavailable evidence never creates an accepted
block. Duplicate exact block admission is idempotent. Mutable node observations are not
stored as deterministic transaction results.

## S1.2 Admission, branch state and roots

For a candidate whose parent is active, read tip/generation/kv/root inside one SQLite
read transaction. For other retained parents, replay immutable branch deltas from the
fixed genesis. Before each change verify that the current value equals `before`; after
each block verify its exact root. This reference is bounded by4096 ancestry records and
65536 keys. It intentionally does full state copying/recomputation; it is not a scalable
incremental production database benchmark.

Admission commits `blocks` and all `deltas` in one IMMEDIATE transaction. An invalid
signature, root, task, target, trace or resource limit leaves no partial block/delta.
Chainwork is derived, checked to512 bits and encoded as64 bytes. Required target comes
from the candidate branch, not the active branch or request body.

## S1.3 Reorganization transaction protocol

Input: fully validated candidate tip with strictly greater cumulative work. Equality
retains the current tip. Find common ancestor; order detach from old tip toward fork and
attach from fork toward new tip. At no time expose a mixture as one public state.

1. Under one transaction allocate generation g+1, copy active g state into it, persist
   exact old/new tips, ordered steps, position=0 and status=staging. Commit. This is the
   `intent` crash cut. If an intent is already active, resume it instead of replacing it.
2. For each step, atomically apply all its key changes and advance position. Detach
   expects `after` and writes `before`; attach expects `before` and writes `after`.
   Absence is represented by NULL, not by empty bytes. Mismatches fence the transition.
3. Recompute the target root from staged generation. Until this agrees, leave public
   active unchanged. `before-publish` is an explicit crash cut after root verification.
4. In one transaction publish active(new_tip,g+1), all ordered remove/add events and
   status=done. Commit. `published` is the final crash cut.
5. Consumers cursor by (generation,ordinal). Replaying the same generation is harmless;
   a stale confirmation includes its old tip/generation and cannot authorize new work.

While staging, candidate admission and new mining template creation fail
REORG_IN_PROGRESS. Historical reads can observe the complete old generation; after
publication they observe the complete new one. Unused generations may be collected only
after relevant readers finish; the current bounded implementation retains them.

## S1.4 Crash behavior and executable counterexamples

The tests terminate a real child with `os._exit(86)` at intent, two detach cuts, three
attach cuts, before-publish and published. Parent process opens SQLite again and resumes
without relying on the child's memory. Every cut must yield the same target root,
exactly five events for the completed generation and an idempotent second recovery.
This is process-crash behavior on the stated filesystem; it does not prove power-loss
behavior, storage-controller durability or that flock survives hostile namespace swaps.

Counterexamples also cover a second writer, false state root, same-work fork, malformed
work and duplicate reward. Future native implementation must consume these same inputs
and reproduce roots and crash classifications; adding an equivalent heading is not enough.

## S1.5 External effects and publication

Before a real effect, the local authority must check the exact task/lease/attempt,
current permission and accepted chain confirmation risk, then persist a unique local
operation/payload/generation record. The executable example demonstrates uniqueness and
separate lifetime; it does not itself issue Hepta final-use capabilities. After reorg,
that record remains. Retrying the same effect yields OPERATION_ALREADY_ENTERED and must
query/reconcile the original target operation rather than execute it again.

Compensation requires a new explicit authorization and economic policy. A disappeared
chain nonce cannot erase an already served inference or external payment. Ledger receipt,
model usefulness, local authority and physical execution fact remain different types.

The independent checkpoint components retained in the Rust workspace can support a
future trusted frontier. A local SQLite effects table alone does not resist simultaneous
rollback of every local and remote record. No such protection is claimed by this test.

## S1.6 History availability, pruning and deeper forks

The experimental implementation retains complete work certificates and deltas; it does
not silently treat a pruning depth as finality. A bounded-replay limit returns a named
resource error and requires verified resynchronization before service. Production sync
must stream validated ancestry/checkpoints without imposing an artificial permanent
reorg cutoff. That streaming native owner is not implemented by this example.

Consensus proofs here contain both matrices and trace, so future verifiers need only the
retained block/certificate and installed verifier version. Public model bytes have a
separate availability/retention obligation. Deleting an expired expert file cannot make
past valid work depend on a mutable download URL. Historical code/data format migration
requires explicit context; no old PoCO decoder or automatic restored namespace is used.
