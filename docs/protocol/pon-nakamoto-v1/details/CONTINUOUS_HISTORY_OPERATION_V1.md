# Authorized single-successor History operation

This is a restricted development component for the original twenty-five-package
native candidate. It preserves the V5 signed-view, allocation, journal and
consensus meanings. It provides an enabled route for one exact successor of the
current active block. It does not authorize arbitrary History import or qualify
the whole History subsystem, public networking, production operation or model
quality. The acceptance status and actual runs are recorded in the
[sole development plan](../../../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md)
and the [increment evidence](../../../../evidence/pon-history-journal-operation-20261027/README.md).

## Ownership and permission

The externally protected configuration must already contain an authenticated
V5 TaskView selecting two independently signed recipient allocations:
`receiver-validation` and `receiver-activate`. Both must bind the same canonical
packet digest, parent, active generation, native matrix task, instance class and
declared task binding. A local request selects their exact operation identifiers.
It cannot supply a signature substitute, create an allocation, extend a budget,
choose a new authority key, or promote a decoded packet into an admitted packet.

The external entry is `receive_public_owned_history_from`. It always obtains
the original fixed administrator-owned Host permit for its concrete source,
including a loopback proxy. The protected controller's `receiver-history` step
uses this entry. The crate-private native adapter exists for composition and
controlled unit fixtures; its tests do not certify that public Host admission
or a hostile network campaign has passed. Generic `receive_page`/`sync_from`
retains `OWNER_CONTINUOUS_HISTORY_DURABLE_REQUIRED` in continuous mode.

The order is deliberate:

1. Check the bounded request and actual active pair, then select exact already
   authenticated claim identifiers. Reserve the original validation claim in
   the original journal and start its durable CPU operation.
2. Parse the bounded Page, hex and canonical packet inside that interval. Require
   one complete page, exactly one packet, the exact requested tip and active
   parent, and the originally signed packet digest.
3. Apply the original recipient exact-packet check and the original journal's
   nonce-window check **before** State restoration, full W1 or M06. Packet
   authentication does not override the upper signed delegation's nonce range.
4. Carry the same permit, CPU checkpoint and Host resource check through task
   and lease reads, admission context, full W1 and original M06 execution. M06
   uses the original worker accountant; children join on success, cancellation
   and panic before the one validation interval settles.
5. Preserve the actual native result and actual accounting result separately.
   Only a known successful validation proceeds to a separately reserved and
   started activation claim. Activation uses the original internal progress
   callbacks and original State/SQLite commit path, then settles once.

The pre-existing protected single-packet `continuous_validate` entry applies the
same exact-recipient and original nonce-window checks inside its paid interval,
before State restoration. An independent fresh-signed-claim test first reproduced
its acceptance of packet nonce 8 under an upper delegation allowing only nonce 9;
the repaired entry refuses this case before Work or worker creation. This is
distinct from the nonce check omitted in the first, unpublished History adapter.

A malformed authorized page consumes its reservation and actual CPU; it does not
consume the activation claim. Repeating an operation cannot start another scope.
Calling the raw journal settlement twice is a different invariant violation: the
original implementation refuses it and persists an accounting fault. No caller
may treat that faulted journal as a successful clean reopen.

Cooperative callbacks bound checked segments, not every instruction. Original
SQLite/root primitives remain indivisible. This component introduces no hard
preemption, second CPU clock, free worker pool or refunded reservation.

## Worker configuration and cancellation

The existing constructor still defaults to one worker. An explicit local
constructor accepts only `1`, `2`, `4` or `8`, rejecting another count before
persistent work. All workers share the original CPU domain and worker accounting.
Choosing two workers is configuration, not an authorization or an extra budget.

`ContinuousEpochCancellation` contains only the original epoch counter and its
expected value. It lets an actual scoped worker or local owner cancel the current
view without sharing a SQLite Node across threads. It cannot affect a later view
or a fresh process, grant credit, settle a scope or undo admission. A cancellation
after a committed native effect must preserve that effect in the result.

## Explicit held recovery

Successful validation can leave an admitted best block while activation is
cancelled and the active block remains its parent. The ordinary V5 constructor
continues to reject this condition with `OWNER_CONTINUOUS_RECOVERY_ADVANCE_HOLD`.
Deleting that refusal would expose a generic node before the missing authorized
activation was complete.

The new **local request** schema is
`restricted-continuous-single-successor-recovery-v1`. Its fields are `target`,
`prior_validation_operation_id`, `prior_validation_settled_record_sha256`,
`validation_operation_id` and `activation_operation_id`, in addition to `schema`.
All identifiers are exact lowercase hex strings. This schema changes no V5
signed field or stored record and does not invent a new signature authority.

Recovery requires all of the following:

- A non-pristine original journal with known accounting, no pending reorg
  intent, and the original valid clean-restart token or the original valid
  known-unclean-process restart token. Pending or unknown CPU debt remains HOLD.
- An actual stored best packet which is the selected target, whose parent is
  exactly the still-active block and whose height is its exact next height.
- An original known-settled validation scope whose retained record hash,
  operation, packet digest, parent, generation, task, class and binding match.
- Two fresh independently signed, selected, unspent validation and activation
  allocations in the current authenticated view, matching the same packet and
  active pair, and a packet nonce inside the original delegation window.

The constructor returns `ContinuousHistoryRecovery`, which owns a private Node.
It exposes readback, cancellation, one exact resume and close; it has no public
Node getter, mutable dereference or listener. The owner additionally restricts
permissions to the two selected operations and refuses view refresh while this
recovery is pending. Startup retains the original active metadata and performs
no automatic best-tip activation.

`into_ready` releases ordinary Node access only after the selected resume really
activates the target at exactly the next active generation, both original CPU
scopes have known persisted settlements, and no scope remains in flight. Closing
an unfinished held recovery does not clear the database discrepancy: an ordinary
cold open still encounters the original refusal.

The protected one-shot CLI is `operator-continuous-history-recover`, with the
same seven pinned launch arguments as `operator-continuous`. Its distinct launch
schema is `restricted-owner-continuous-history-recovery-launch-v1`. It contains
the original protected Inputs, the local selection, concrete source, raw Page,
bounded local worker count and `startup_wall_seconds`. That deadline bounds
startup; signed validity, original CPU accounting and cooperative callbacks
remain the operation controls. The command starts no receiver listener and
preserves native outcomes even when metadata readback or close later fails.

## Clean reopen and actual process crash are separate

The ordinary positive tests close and drop a Node, then reopen from its original
journal. Those observations are **cold reopen**, not process-crash evidence.

The process test uses two distinct executions of the same source-bound native
test binary. The first performs actual W1 and two-worker M06 validation, persists
known validation and cancelled-activation settlements, atomically publishes a
known-prefix barrier, and parks without CleanClose. A bounded external guardian
checks the exact child PID, known receipts and absence of child processes, sends
SIGKILL only to its own child, and obtains actual `wait4` resource usage. The held
pidfd maps the owned namespace PID to the mounted `/proc` namespace. PPid, NSpid,
PID-namespace inode, executable digest and process start time must agree; signals
and wait4 still use the original owned PID. A complete public process-parent
snapshot at the parked barrier must show no descendants. Missing or inaccessible
observations fail rather than becoming an empty child set. A real-grandchild
negative test checks that the observer detects a live descendant.

Reported timeval values, exposed by Python as floating point seconds, are
converted to integer nanosecond units and retained alongside their original
representations. This does not establish nanosecond measurement accuracy or a
general physical CPU-cost bound.

The local test authority signs the observed exact prefix and actual residual
using explicitly disclosed test keys. The test invokes the **original** protected
`prepare_known_unclean_restart` action. Repeating the same signed residual is
refused without another charge. A second fresh native process uses the original
restart token, begins with zero CPU credit, opens the held recovery, spends fresh
claims and completes actual activation. Old receipts, spent claims and debt
remain unchanged. The helper test is ignored in an ordinary libtest sweep because
only its owning mandatory test supplies pinned process configuration; that test
executes the helper twice and requires the second process to actually pass.

This is a controlled SIGKILL after a **fully known settled prefix**. A crash
inside an unknown or unsettled scope remains HOLD. It does not qualify arbitrary
crash points, storage-controller loss, SQLite physical power loss, WAN intake or
an external Registry2 authority. Fixture checkpoint/activation material is
synthetic, while its native producer, scalar full-W1 verifier, two-signature
verification, startup, M06 and durable journal calls are real.

| Cut point | Result in this V5-compatible increment |
| --- | --- |
| Validation and activation complete, known settlements, clean close | Actual cold reopen preserves receipts and spent history |
| Actual worker cancellation or panic, joined children, known settlement | Actual retry needs a fresh signed claim; failed work remains charged |
| Validation committed and known-settled; internal activation cancelled and known-settled | Actual held cold reopen and independently killed-process recovery activate the exact successor |
| During full validation, before known settlement | Original pending/unknown HOLD remains; not qualified by the known-prefix test |
| Admission committed but CPU terminal record absent | Cross-store unresolved window; not qualified |
| Activation SQLite COMMIT completed but CPU terminal record absent | Cross-store unresolved window; not qualified |
| Arbitrary fork or partially committed multistep reorg | New authorization/effect protocol and actual recovery evidence still required |

The original journal cannot issue its known-unclean restart token while a scope
is pending, a claim is unstarted, or accounting is unknown. The new selector
does not change this rule. Whole History P0 remains OPEN; the enabled path above
is an increment, not completion by retaining other paths permanently disabled.

## General fork import remains a new authorization design

V5 binds an operation's parent to the owner's current active parent. Importing
arbitrary branches or multiple parents requires a new signed namespace that
separately names the owner's stable frontier/generation and each logical
execution parent. Claims must bind exact packets, target roots and branch task
state; a distinct activation claim must bind the expected old frontier and target.
Any batch must explicitly authorize each packet before its paid decode/Work.

That future design must preserve the monotonic local journal across reorg and
define cross-store crash outcomes: a native admission can commit before the
accounting terminal record. It needs explicit operation/native-commit linkage,
known residual recovery, pending-intent handling and adversarial multi-parent
tests. It cannot be obtained by silently changing V5 `parent`, resetting spent
history, accepting a selector as authority or enabling a generic importer.
