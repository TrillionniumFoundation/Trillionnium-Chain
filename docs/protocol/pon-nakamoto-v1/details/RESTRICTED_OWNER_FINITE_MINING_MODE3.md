# Restricted owner finite mining mode3 source candidate

This is a new local service policy, `restricted-owner-node-v3`, with a trusted
operator issuer and a finite local control pipe. It changes no PNW1 bytes,
consensus task lease, M05 arithmetic, original M06/fees/subsidy/receipts/root,
branch schema or confirmation definition. It does not enable permissionless
mining, authenticate task provenance or funds, prove useful AI work, economic
hardness, global cheapest mining, physical costs, anonymous fairness or hard CPU
preemption. No new implementation has been compiled, signed or executed by its
author. All actual qualification fields are None until Root closes them.

The exact basis is Root CPU5, commit
`fa77a4bec0af1a8a2412f6b73eea68782e1d9e22`, tree
`dda23bbd7e8215a2ef53b9c31b0de230f49a2fc9`, full 3344 tracked-file map and
18 Root-formatted owned files. CPU5's actual qualification and all earlier
Pool/Core/CPU failures are preserved separately. They do not qualify mode3.

## Exact interfaces and signed purposes

`operator_mining_policy::TaskView` is a separate strict typed declaration, not
an old exact-packet or Pool grant. Registry and task-owner public keys, complete
expected typed body, full envelope SHA, latest sequence/digest, journal path and
source/context are fixed by the outside Root before material loading. A view
cannot choose its own authority. `deny_unknown_fields`, exact expected-body
parity and both strict Ed25519 signatures are mandatory. Keys must be distinct.

The TaskView signature bytes are `TRNM-RESTRICTED-MINING-TASKVIEW1`, role byte
1 (registry) or 2 (task owner), u32 little-endian length, then complete typed
`serde_json::to_vec(TaskView)` bytes in the Rust struct field order. Public
`task_view_signing_bytes` only validates and returns those bytes; it does not
sign, authenticate or issue a Native capability. Source/tag1 scientific
verification remains separate. Old Registry2/packet/Pool signing domains are
never fallback authorization.

`operation_id` binds `TRNM-RESTRICTED-MINING-OP1`, registry ID, operator ID,
network, parameters, actual parent, outside operation nonce, exact payload and
new purpose. Each string is u32-LE length plus its canonical lowercase hex
bytes, followed by the strict purpose enum JSON. Two operation IDs may not
have the same purpose and exact payload in one view. Operation selection cannot
silently reserve a different ID.

There are five purposes:

- `startup-catalog`: exact full six-material catalog SHA, reserved before complete
  catalog hashing or checkpoint Settings construction.
- `parent-reconcile`: exact signed current active tip and generation; startup
  may only retain that pair, with no pending reorg intent and best tip equal to
  current active. Any automatic advance/recovery intent is HOLD.
- `search`: exact miner, legal timestamp, ordered full signed transaction-byte
  digest, empty group-ID list, positive nonce-first and count 1..4096. All
  transaction bytes also require the signed `allowed_task_commands` SHA list.
- `winner-validation`: SHA256 of the full actual winning packet and the original
  Search operation ID. It authorizes original full Work and original full M06
  admission, not activation.
- `activate`: the same full winning packet SHA and original Search operation ID,
  but a distinct operation. It authorizes original durable activation only.

The historical field name `allowed_task_commands` means a sorted list of at
most 16 SHA256 values of complete ordinary signed transaction bytes, not command
names/tags or unsourced permission. The ordered batch digest independently binds
count, order, lengths and full bytes under
`TRNM-RESTRICTED-MINING-ORDERED-TX1`. The public source helper returns that exact
digest. Up to 256 raws/524288 bytes remain bounded; original signatures/nonces
and all M06 predicates still apply. No submit or Pool grant is borrowed.

The complete task requires original Maintenance tag1, dimension64,
Q4294967291, canonical-u32-le, model/input IDs and complete material SHA,
model revision/layer selector, full lease SHA, A/B SHA, full catalog and recipe
SHA. Actual source material, lifecycle eligibility, lease, task ID, A/B matrices
and original parent State are rechecked in Search. Source/class/cost/model/layer
labels and reuse declarations remain operator declarations. Tag22/AI/legacy
profiles are unsupported in this candidate; no missing qualification is filled.
Each call uses the original full preparation. There is no external prepared
artifact/product/State-successor cache load or shortened Work verifier.

## Durable local view, claims and accounting

The fresh v3 node marker, database metadata and Linux0700 journal pin mode,
registry/operator/NPG/source identity, two keys and private path. Opening the
restricted store through an unrestricted or v1/v2 opener refuses. There is no
migration, reset or rotating journal. A complete linked next view uses the same
keys/source/catalog and exact actual current parent. Journal anchor and every
claim are O_EXCL0600, file-fsynced and parent-fsynced; partial/unknown files cause
HOLD. Sequence rollback/replayed operations/revocation refuse. Reorg/history
never refunds a local claim or rewinds the latest view. A crash before a packet
is durable retains its reservation and requires outside recovery judgment.

Every purpose consumes both independent accumulated histories: all claims for
the native task across declared classes, and all claims for the declared class
across tasks. Signed operation/allocation ceilings bound each history. Changing
class cannot reset task usage and changing task cannot reset class usage.
CPU/material/DA/funding/reuse amounts in these histories are allocation
reservations; they are not actual measured class costs or verified balances.
Original CPU5 accounting separately enforces the same volatile service epoch,
100ms reservation, two outstanding workers, 2s capacity, .25 refill and original
owner/scoped/live residual arithmetic. O already includes Work, so no W is added
again. No signed per-class actual CPU meter, balance proof or physical cost is
claimed. The finite standalone controller uses one explicit local CPU domain;
a serving actor must pass `PublicServer::mutation_cpu_domain` instead.

Search claims persist complete declared task/class/source/reuse/allowlist
binding. WinnerValidation/Activate require that exact original claim and its
durable real Search result, including parent/generation/full packet SHA.
Packet header task must also equal the current signed native task before
expensive context processing. A linked view cannot relabel a retained winner.

Epoch cancellation invalidates the installed view including unused grants.
It never captures a new epoch for an old view. Only a valid linked next view
updates the installed epoch. Private operation scopes carry immutable permission
and the same original live CPU checkpoint, no Node/RefCell/State/SQL lock across
math. All actual workers retain original join/accounting semantics.

Unknown accounting after finish latches the epoch and writes a durable static
fault marker. An independently held-directory sink survives failed Node open;
unfinished operation Drop also persists a fault marker during early return or
unwind. No marker write is called a success when fsync/identity/persistence
fails: failure is returned or emits the static unwind persistence-failure label,
and the original claim remains. Original Native errors stay errors. A known
postcommit result is preserved when final CPU sampling fails; CPU fault is
reported separately, never a fictional rollback/ACK. Deep root construction,
complete proof generation and SQLite commit remain nonpreemptive.

## Real finite controller and legal startup

`operator_owned_finite_mining` is an actual example source with a protected
Root-owned JSON launch file and Root-owned bounded stdin pipe. It is not a public
RPC, automated authority or old Node binary. Root must build a new example with
an empty target, current source integrity and the original locked Cargo graph.
The only constructor is `Controller::open_pinned`: absolute600mode launch,
full held regular single-link UID/identity/SHA checks, separately supplied two
public keys and current source/policy/Registry2 IDs, followed by typed authority
validation. File data cannot override these outside parameters.

Startup must use a fresh mode3 store and existing complete checkpoint catalog.
It cannot copy an old restricted marker/DB. Original
`Settings::development_with_operator_checkpoint_tile` verifies bootstrap approvals
and initializes original registered lifecycle State in genesis. Separate
StartupCatalog and ParentReconcile claims allow only that exact genesis pair.
A first genuine Maintenance tag1 Search may use an exact empty ordinary batch;
any nonempty batch must be outside-signed and pass full original M06. Search
never pretends an old parent1 packet or boolean is new State. A later block uses
its genuinely activated parent and a complete new signed view, original State
reconstruction and actual lease checks. Parent1/packet2 historical fixtures are
material/reference inputs only, not authority or a migrated DB.

The controller keeps one Node and CPU domain alive across a maximum 32 frames
within a maximum90s process deadline. Linux stdin polls in <=50ms slices, each
frame <=256KiB. Control purposes are exact Refresh, Search, WinnerValidation,
Activate, CancelEpoch and ReadStatus. Startup CPU and each actual mutation's
owner/scoped CPU are emitted separately. Search emits every started nonce,
challenge, complete-proof SHA, original ticket result, final fence and status;
all failed nonces remain in its denominator. The eligible packet is returned as
full hex only if result publication, Native operation and accounting succeeded.
Every CPU total includes setup plus failed trials; there is no invented per-nonce
CPU, global-fastest or hard-preemption assertion. Error/stopped/unknown fields
must be consumed; process rc0/control-pipe-close is not Native acceptance.

A minimal actual sequence is: outside fixed signed view1 with StartupCatalog,
ParentReconcile and Search; open current new example; Search; retain full result;
outside sign linked view2 with exact winning packet/related Search and distinct
WinnerValidation+Activate; Refresh; WinnerValidation; Activate. Do not sign an
unknown/dummy winner in advance. A no-winner/exhausted/cancelled search stays a
closed failure/exhaustion and is not retried/refunded as that operation. For a
second ordinary block, outside signs a new exact batch/search using actual new
parent/generation and a further linked view. Original full reference must start
at complete genesis and execute every new admitted block, ordered receipts/root
and all complete SQL tables; original closed report/root is never State oracle.

The journal has a total256 claim/view/result bound. Two startup claims plus
three claims per successful Search/Validation/Activate permit only a short
bounded experiment (at most84 successful chains before other claims and the
stricter32 controller steps). This cannot run or inherit the original241-block/
8193-input continuous acceptance. Extending that requires a new audited bounded
retention/authority design, not reset/rotation, workload reduction or budget
expansion. Automatic Pool enable/status/reconcile/selection/prune and generic
maintenance-builder/public miner paths explicitly HOLD in mode3. Existing mode2
normal Pool behavior remains unchanged.

## Root-only qualification and current HOLD

Original envelope: whole build600wall/480CPU/8GiB address+RSS/2GiB file/jobs2/
thread1; all original Node targets/tests, inventory/checks and strict all-target
all-feature Clippy. New example is built under the same locked graph. Root
alone formats/applies/builds/tests/signs. Actual child/wait4/reaped/zero-adopted,
source-before/after, lock, executable single-link SHA and full raw streams are
mandatory. No previously qualified binary is substituted. Runtime leaf is
90wall/60CPU/1GiB+2GiB file within600whole, including startup and control pipe.
The complete original reference/SQL phase remains within that whole envelope,
using its original bounded verifier. No author executes these phases.

All actual mode3 commit/tree, example/source/runtime executable and qualification
receipt, actual outside keys/views/claims, Search/nonces/Work/M06/SQL/activation
and network references are None/HOLD. The companion outside source owner prepares
signing and controller orchestration from these exact new interfaces; its new
source and evidence are independently qualified. The 27 new test definitions
exercise signed context, purpose separation, replay/latest, independent task/class
budgets, actual parent generation fencing, cancelled epochs, full byte allowlist,
held initialization-fault persistence and protected launch parsing. They are
unexecuted definitions, not Work/State/miner evidence.
