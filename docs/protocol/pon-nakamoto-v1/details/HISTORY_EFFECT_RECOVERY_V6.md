# History effect recovery V6 research namespace

This is an independent, local research owner. It is not a V5 migration, a
consensus permission, a production activation, or a claim that all History crash
points are qualified. V5 signatures, journal events, refusal conditions and
ordinary Node openers retain their original meanings.

## Authorization and state

The protected local authority input pins two distinct authority keys, exact
signed envelopes, an owner/store identity, a source identity and an **externally
supplied latest spent anchor**. Neither the request decoder nor the journal being
recovered may manufacture that latest anchor. Envelopes use the new
`TRNM-HISTORY-EFFECT-RECOVERY-V6` domain and distinct budget, operation and recovery
message tags, with separate signature-role bytes.

An operation names its owner's `frontier` (active block, active root and
generation) separately from the packet's `execution_parent` (block, root and
height). The latter is never a substitute for the current owner permission.
Validation and activation operations independently bind their operation/request
nonce, process epoch, exact packet digest and target/root, both paired operation
identities, native task/material binding, and finite resource allowances.
Authorization nonces are distinct from the canonical packet's unchanged W1 nonce.

The new journal and native storage schema have fresh namespaces. An old or
ordinary Node opener cannot open the required-owner store. Public callers retain
the original fixed concrete-source Host permit. The native owner remains opaque;
no mutable Node, unrestricted dereference or automatic background recovery is
released while an operation or reconciliation is pending.

| Transition | Required durable fact |
| --- | --- |
| Authorized to spent intent | One fsynced journal event records the exact fresh signed operation and adds its entire allowance to irreversible spent counters before Native execution; the event binds owner frontier, execution parent, phase and packet/effect identity |
| Intent to native commit | Original W1/M06/State rules pass; a unique effect marker is inserted in the **same SQLite transaction** as the native effect |
| Native result to known settlement | All actual scoped children join; the original shared scalar operation supplies its unchanged measured receipt |
| Unknown process to covered reconciliation | Independently pinned closed-process evidence, exact journal/marker readback and a conservative cost bound inside the original pending claim's allowance |

The native marker binds owner, store, epoch, intent, validation/activation
operation IDs, phase, exact packet/target/root and old/new active generations.
It is not a receipt invented after COMMIT. Any identity/phase/target discrepancy
between marker, journal and signed outside context is a refusal.

Every stored non-genesis block must have an exact validation fact in both the
outside-anchored journal and SQLite marker set. A syntactically valid cached
packet is insufficient. Reusing previously validated bytes preserves the
historical marker's original epoch and still requires a fresh operation with
current signed frontier, task and nonce fences. Activation additionally matches
its specifically paired validation operation and current epoch. Fresh V6 native
database files are created with mode `0600`; recovery does not chmod or accept an
old file with broader permissions.

A cancellation handle names one exact operation. It can only set that operation's
existing cancellation flag; it grants no permission, extra CPU credit or worker.
Native children join through the original M06 worker accountant before the same
owner CPU operation settles. The handle cannot cancel a later operation. After
actual Native execution and CPU finish, a late journal lock or persistence error
is returned alongside both original observations and leaves the owner unavailable.
Missing effect readback retains an unresolved scope even if its CPU receipt is
known. A successful native return for a different tip is not target success.

## Unknown CPU is retained as unknown

A crash does not manufacture owner or worker measurements. A recovered scope
retains its original unknown split, or any already observed receipt, permanently;
it receives a separate prepaid-debt
reconciliation record. The original complete reservation stays spent, including
unused capacity, and no refund or repeat settlement is permitted.

The initial research recovery is deliberately conservative: one unresolved
Native scope in a serialized owner, an independently closed process with all
descendants accounted for, and a conservative reported-process CPU bound that is
itself no larger than that **specific original scope's** CPU ceiling. A sufficient
sum of unrelated reservations does not prove that an individual operation stayed
within its authority. A subsequent signature cannot retroactively make an
original overrun authorized.

Linux wait4 observations retain their original reported precision and a named
counter model; they are not physical host-cost measurements or a general
nonpreemptive worst-case bound. Missing closure, ambiguous identity, unknown
descendants, insufficient bound, conflicting anchors, unsupported pending state
or mismatched marker remains an explicit unresolved case. None is relabeled as
an exact CPU receipt. Administrative recovery creates no Native effect or CPU
epoch. After the outside authority pins its resulting journal anchor, a fresh
independently signed startup reserves another full allowance and obtains the
private verified epoch token. It constructs the original scalar **cold** epoch
with zero initial credit; only its original refill can create later volatile
credit.

The named counter model is `linux-wait4-timeval-quantized-v1`: preserve the
original user/system float strings and microsecond integer observations, then
bound the sum with two additional microseconds. This bounds the named reported
counter, not arbitrary scheduler-accounting error, physical energy or CPU cycles.
The supervising process must actually own, identify, SIGKILL and wait4 the child.
The present accepted descendant-accounting profile is explicitly
`source-bound-native-thread-only-fixture-v1`, with the exact native helper selector
and binary digest included in the outside-signed raw observation. Its locked
source uses scoped M06 threads and does not launch subprocesses. The observer
pins the directly owned thread-group leader through its pidfd, namespace and
start time, signals only that pidfd with SIGSTOP, and actually waits for the
stopped status. It checks all observed threads are stopped, then allows at most
four complete parent-graph observations to obtain two consecutive identical
graphs. A missing or denied row never supplies an empty set; every incomplete
observation is retained. An unexpected descendant remains UNKNOWN under this
profile. SIGSTOP is not termination and closes no CPU receipt. Actual owned-PID
SIGKILL and wait4 remain mandatory after observation.

The raw `all_descendants_closed: true` field is restricted to that source-bound
thread-only fixture. Two present PPid graphs cannot establish that an arbitrary
earlier child never became orphaned or reparented, nor recover its CPU usage.
The raw observation therefore also records
`historical_process_tree_observed: false`. General subprocess support would need
an original owner/subreaper adoption and accounting history; it is not supplied
by the empty current graphs. The recovery parser rejects an arbitrary-process-
tree profile. Unknown or ambiguous process observations cannot be treated as an
empty descendant set. Administrative signature, bounded journal and SQL metadata
reads are control-plane work; they do not constitute a measured physical-cost
qualification.

The first namespace is deliberately finite (at most 256 authorized operations,
bounded marker/block scans and bounded journal frames). Its source identity
names the published baseline; exact changed source and executed binary are bound
by the increment evidence rather than asserted by a source string at runtime.

## Effect reconciliation and acceptance targets

If the exact native marker and corresponding durable data exist, recovery
completes accounting without repeating the native effect. If no native effect
committed, the old operation remains spent and retry requires a fresh signed
operation/request nonce. It keeps the same canonical packet bytes. A partial
native reorg cannot be described as an absent effect or silently auto-completed.

Mandatory actual-process tests for this increment are a kill during validation
(including an actual scoped-worker cut point) and a kill after native activation
COMMIT but before journal settlement. Each must demonstrate a fresh process,
no initial credit, immutable prior spend/unknown history, rejection of duplicate
reconciliation, exact native readback, and a subsequent authorized operation.
Known-prefix V5 success is not a substitute for these observations. Actual results
must be recorded in the sole development plan and increment evidence before any
acceptance claim is changed.

The database uses the original SQLite WAL and `synchronous=FULL` settings. Journal
publication fsyncs a new complete event file, links its final no-replace name,
fsyncs the directory, removes the temporary name and fsyncs the directory again.
These mechanisms assume the filesystem and storage honor those durability calls.
The present crash barriers occur after the required journal publication or SQL
COMMIT has returned; they do not inject a torn append, partial fsync, SQLite-page
write failure or physical power loss. An unexpected journal name, partial event,
anchor or marker discrepancy remains a refusal rather than an inferred commit.

| Cut point | Current acceptance boundary |
| --- | --- |
| Actual registered worker active after durable validation intent | Mandatory native SIGKILL/new-process control; receipt split remains unknown and whole original allowance stays spent |
| Activation SQL COMMIT returned, before journal settlement | Mandatory native SIGKILL/new-process control; exact existing marker prevents duplicate effect |
| Known validation followed by cancelled activation | Covered separately by the published V5 known-prefix increment; it does not qualify the two V6 windows |
| Process exit during journal publication, startup, close or SQLite COMMIT | Not qualified by the two named barriers |
| Partial detach/attach reorganization | Requires a separate signed continuation namespace and atomically bound checkpoints; a bare preexisting reorg row supplies no new authority |
| Arbitrary subprocess creation, orphaning or adoption | Unsupported by the thread-only observer profile; no process-tree CPU closure claim |
| Physical power loss or faulty storage durability | Not qualified |

The acceptance scope excludes startup/clean-close crashes, torn journal
publication, arbitrary partial reorg continuation, physical power loss, external
Registry2 truth and a public Host campaign. Those cases retain their explicit
refusals until separately implemented and tested; their refusal is not completion
of whole History P0. The synthetic model and disclosed local authority fixture
exercise real signatures, W1, two native M06 workers and storage only. This local
Ed25519 authorization prototype does not establish an end-to-end PQ chain.
