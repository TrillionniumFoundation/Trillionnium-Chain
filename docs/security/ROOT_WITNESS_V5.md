# Root witness V5: conditional recovery and acknowledgement

## Status and guarantee

`WitnessedRootOwnerV5` is a strict research API alongside `RootOwnerV3`. It is
not selected by the M15 production CLI and grants no installation, payment,
redispatch, or FinalUse authority. The V3/V4 common-restore counterexample remains
valid and retained.

The conditional guarantee is narrow: **if an honestly operated witness preserves
its durably acknowledged register outside the declared common-restore domain,
its independently provisioned policy remains trusted, and the host supplies a
cryptographically fresh challenge for each exchange after restore, an
acknowledged V5 operation cannot be erased by restoring the owner database,
original anchor and their old recovery floor together.** An unavailable,
inconsistent or malformed witness fails closed. No static floor or V3 fallback
is available through V5.

The implementation provides the client protocol, server-side request
authenticator, strict owner composition and a typed durable register component.
The protocol suite retains its in-process real-signature witness fixture. A
separate suite defines controls for the register using real SQLite files and
dual-family signatures. Neither component is a deployed witness service or
independent physical custody evidence. Production service integration,
independent provisioning and a separate-domain restore drill remain required.

## Common-restore domain and external trust

The deployment must enumerate the state that one restore can rewind together:

- Owner SQLite, journal checkpoints, pending records and local snapshots.
- Original anchor state and its backups.
- Cached recovery floors, configuration, recovery-epoch pins and key backups.
- VM and process-memory snapshots, including random-generator state and any
  entropy sources that the same restore can rewind or clone.
- Any shared host, storage controller, administrator or backup mechanism that can
  restore the purportedly independent witness along with those components.

`WitnessPolicyV5` binds a nonzero restore-domain commitment, a nonzero explicit
recovery epoch, the complete canonical V3 enrollment and an immutable witness
roster. Domain and epoch values are declarations requiring independently trusted
provisioning; their existence does not prove that a backup excludes the witness.
The witness must survive outside that declared domain and return the latest
durably acknowledged head for the exact policy binding. Separate files, UIDs or
key identifiers alone do not establish that assumption.

The client also relies on OS `getrandom` supplying fresh challenges after
recovery. Calling that API does not itself prove that a restored or cloned VM
has fresh random-generator state or independently renewed entropy. If the same
complete request and challenge can recur, a previously signed read response
cannot be rejected solely for carrying that old challenge; a surviving witness
does not make a replayed response into a new live read. Deployments that restore
VM or process memory must establish their random-source recovery assumptions
separately. The file-restore tests below neither roll back the OS random source
nor verify entropy renewal after VM snapshots, and their result must not be
extended to that broader restore model.

The witness roster is disjoint from the original root, writer and anchor keys.
Every retained root-policy transition and future rotation/recovery/policy change
is also checked for witness-key reuse. Key separation is an enforceable protocol
condition, not proof of different operators or independent hardware.

## Versioned authenticated protocol

V5 has fresh signature/hash namespaces for enrollment commitment, policy
binding, writer request, request digest and witness receipt. The V3 journal and
anchor wire domains are unchanged. Each read or compare-and-set uses an OS random
challenge and signs the complete request, including the policy binding, request
kind, exact predecessor and target. Both writer and witness signatures use the
existing dual-family quorum verifier and the original `OwnerBudgetV3`.

The owner checks the complete request digest, challenge, binding, response
outcome and exact head. Wrong epoch/domain/enrollment, another roster, replayed
request context, bad signatures and ambiguous CAS outcomes are refused. Callback
success and error paths preserve the original budget identity, cancellation latch
and deadline. They do not issue a fresh quota.

The witness service must authenticate requests using its separately provisioned
`WitnessPolicyV5`, serialize exact predecessor-to-immediate-successor CAS,
durably record the target before issuing an `Advanced` receipt, and never use the
request to replace its enrollment/policy or register. A signed receipt from a
service that violates those conditions is not a proof of durable history.

## Typed durable register

`DurableRootWitnessV5` implements the existing typed `RootWitnessTransportV5`
contract with a private SQLite register. It uses the V5 policy, writer request
and witness receipt domains. It does not use the older single-family witness
wire protocol and adds no daemon, public listener, wire codec or M15 integration.

`register_new` takes the complete enrollment as well as the separately
provisioned witness policy. It verifies their binding and derives the initial
head from that enrollment; a caller cannot supply an unrelated version-zero
root. Creation is exclusive. An existing empty, partial or foreign database is
not overwritten or silently enrolled.

`open_existing` requires the complete trusted policy and an independently
authenticated exact current head. Both an older and a newer stored head are
refused when they differ from that external pin. The database cannot supply its
own pin, and a signed request for a different policy cannot replace enrollment.
In particular, after an uncertain COMMIT or an ACK failure, a later read of the
same database must not be used to promote the old pin automatically. Cold
recovery requires explicit reconciliation using authority retained outside the
restored database and its sibling files. This component provides no automatic
recovery service for that independent authority.

An exchange verifies the complete writer quorum before entering the register
transaction. A malformed or unauthenticated request cannot mutate the register
or permanently fence its live owner. A CAS must match the exact stored
predecessor and immediate successor. The register retains the predecessor so
that an exact retry can acknowledge the same transition after cold reopen;
another predecessor or a competing successor receives a signed mismatch.

SQLite COMMIT, main-file synchronization and parent-directory synchronization
precede an `Advanced` receipt. The owner is fenced before attempting COMMIT.
An uncertain commit result, subsequent signing failure, cancellation, budget
replacement or failed final check leaves it fenced. Already committed state is
not rolled back merely because acknowledgement failed. The signing callback
uses the original operation budget, including its identity and deadline; both
callback success and error paths are checked. After signing and verifying the
witness quorum, the owner rechecks the exact persisted row and held file and
directory identities before returning a receipt. This final check applies to
ordinary reads as well as CAS acknowledgements.

SQL progress checks and checks before and after callbacks preserve the same
deadline and cancellation state. They do not establish a hard wall-clock cutoff
or preemptible cancellation for an OS synchronization call or an arbitrary
blocking signing callback.

The component holds an exclusive file lease, requires private file/directory
permissions, refuses a foreign schema and checks the named inode against held
identities. These checks do not make a private directory safe against arbitrary
concurrent administration by its owner UID. SQLite opens a checked pathname
without exposing its main-file descriptor; the checks do not exclude a same-UID
swap-and-restore race. That administration remains trusted. File and directory
sync calls also do not constitute a physical power-loss experiment.

The separate `root_witness_v5_durable_native` suite defines twelve controls for
exact CAS/retry/cold reopen; stale-database and independently retained-pin
contrast; conflicting transitions; real SQLite COMMIT-busy refusal; failure or
wrong quorum after commit; original-budget replacement/cancellation; malformed
writer requests; complete policy binding; exclusive ownership and inode
replacement; partial/foreign schema and constructor refusals; read/CAS signing
callback row changes; and Root pending recovery after a lost durable ACK without
another CAS. **A defined control is not a native execution result.** The
COMMIT-busy test exercises a real database refusal; it does not prove behavior
under physical power loss or every storage failure.

The stale-database control deliberately retains the remaining counterexample:
restoring both the database and its supposedly independent pin allows the old
state again. Durable SQLite is useful persistence, but it cannot establish its
own freshness after every relevant authority has been rolled back.

## Append and recovery ordering

A V5 append performs these steps under one original operation budget:

1. Freshly read the witness, replay local signed history and read the original
   anchor. All three current heads must agree exactly.
2. Validate the root transition and durably stage its exact pending bytes.
3. Compare-and-set the original anchor to that exact target.
4. Compare-and-set the independent witness and authenticate its exact target ACK.
5. Recheck the held database, finish the same pending record and return success.

Any error fences the session. In particular, witness timeout or lost ACK does not
delete pending state or report successful completion. The local journal is
finished only after acknowledgement.

On explicit reopen, a fresh witness response supplies the ancestry floor
internally. A committed head with no pending record must equal the witness head;
an unwitnessed append through V3 cannot be promoted merely because the witness is
one of its ancestors. A pending transition must be fully authenticated, and the
witness may only be at its exact predecessor or target.

`resume_pending` replays the complete staged signatures before it can mutate the
witness. The complete signed history and every root-role check share one SQLite
read transaction, returning exact current and pending head commitments. It then
reads the live witness, allowing the following native owner replay to detect
any callback change. Before any witness CAS, the ACK hook requires that replay's
exact predecessor and target to equal the previously checked pair. A different
but validly signed pending record cannot inherit the earlier role check.
It freshly checks the original anchor at the pending target. If the
witness is already at that target, recovery only completes the local record. If
it is still at the exact predecessor, recovery may submit only that same witness
CAS. It never resubmits the original anchor CAS, creates a new root statement,
changes a nonce, clears uncertain state, or executes an external effect.

Every V5 `context` and `observe_current_intent` again queries the live witness and
requires exact current-head agreement. Observations remain non-clonable,
non-serializable, borrowed point-in-time values with no effect capability. V5
exposes neither its inner V3 owner nor a conversion or `Deref` escape.
The live witness client also rejects a lower version or a different root at the
same version after it has observed a head. That in-memory rule does not survive a
complete process restart and cannot replace the external durable register.

## Required evidence and retained limits

The native suite `root_witness_v5_native` uses real PQ signatures for successful
append/readback, common owner/anchor restore, complete response binding, wrong
signature/outcome, epoch separation, unavailable witness, lost ACK, pre-CAS
disconnect, corrupt pending, budget replacement/cancellation, runtime witness
regression, root-key-role checks and V3-bypass refusal. A separate seventeenth
test replaces a pending normal operation and its anchor during the witness-read
callback with another genuine signed pending rotation that reuses witness keys.
It requires snapshot-change refusal before any witness CAS, with the changed
pending state retained and the session fenced. This is separate from corrupt
signature/state controls; it checks a valid alternate transition at a callback.

It also deliberately restores **the witness itself** and confirms that the old
state again passes. Passing this negative control preserves the fundamental
limit: fresh signatures cannot reconstruct history lost by every authority.
Nothing in the suite proves physical independence, prevents an administrator
from selecting rolled-back trust pins, verifies post-snapshot random-source
freshness, demonstrates a WAN deployment, or grants whole-chain post-quantum
qualification. M15 and all effect sinks require their own separately verified
integration and recovery evidence.

Validation command on Linux (requires the repository-pinned OpenSSL PQ build):

```sh
cargo test --offline --locked --manifest-path trillionnium/Cargo.toml \
  -p trnm-pon-node --features pq-root-v3 \
  --test root_witness_v5_native --test root_witness_v5_durable_native \
  -- --nocapture --test-threads=1
```

Keep `independent_common_restore_exclusion_proved=false`,
`whole_chain_pq_qualified=false` and `production_activation=false` until the
separate evidence required for those claims exists. Native protocol test success
must not be substituted for those missing deployment and security arguments.
