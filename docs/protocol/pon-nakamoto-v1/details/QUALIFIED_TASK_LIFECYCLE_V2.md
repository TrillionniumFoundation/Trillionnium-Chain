# Q2 — renewable, revocable, bounded development task leases

A separately selected [V3 atomic successor](QUALIFIED_TASK_LIFECYCLE_V3.md) fixes the
sole-task gap when a producer includes tag19 without source tag21. V2 remains unchanged;
its historical pair-command continuity runs do not prove atomic inclusion.

The sole registry is [qualified-task-lifecycle-v2.json](../../../../config/pon/qualified-task-lifecycle-v2.json).
This explicitly selected `signed-task-lifecycle-dev-v2` context uses consensus revision7,
a fresh network/parameter/genesis commitment and separate source signature/statement-ID
domains. It does not upgrade an existing store. [Q1](QUALIFIED_WORK_TASK.md) and its
`signed-task-dev-v1` fixture, signatures and roots retain their original semantics.
The implementation is a transition helper for the existing M06 native ledger, not
a second task ledger, work engine or local authorization/withdrawal owner.

This removes the fixed16-demand and immutable1000-height maintenance-window constraints
when operators explicitly submit authorized new requests and renew before expiry.
It does not establish truthful demand, independent administration, lawful permission,
computational hardness, a whole-model result, remote DA or public-network readiness.
All registry acceptance flags remain false.

## Exact controls, domains and costs

The existing main ledger envelope verifies requester/source sender signature, network,
account balance, fee limit, expiry and `account.nonce+1`. The ledger nonce remains a
public transaction sequence. No randomization or nonce-name disguise is required.
The main envelope includes the following exact, bounded payloads:

| Tag | Payload | Bytes | Authenticated sender |
| --- | --- | ---: | --- |
| 18 | `DemandLeaseV2`, `QDL2` | 344 | Requester |
| 19 | `DemandLeaseV2`, `QDL2` | 344 | Current requester |
| 20 | `DemandRevocationV2`, `QDR2` | 144 | Current requester |
| 21 | `SignedLifecycleTaskV2`, `QWA2` | 684 | Lease source |

Each fixed development base fee is100 units; the existing envelope-byte fee rule still
applies. These are ledger resource charges, not a proven public-market price, Sybil cost
floor or work difficulty. Tags18–21 are rejected outside the fresh task profile.

`QDL2` order is magic4, LE16 version2, slotu8, purposeu8; then nine32-byte hashes
`network, parameters, demand_id, requester, source, source_record, authorization_scope,
availability_manifest, availability_root`; then fiveLE64 integers `generation, revision,
not_before, expires, available_until`; then cost_classu8 and sevenzero reserved bytes.
Unknown versions, lengths, padding, purposes and cost classes are rejected.
Slot is0..31; generation and revision are nonzero. Requester and source must be different
nonzero keys. Different keys do not prove separate people, machines or administration.

Demand identity is `H("qualified-demand-id-v2",network,parameters,requester,LE64(generation))`.
Lease identity is `H("qualified-demand-lease-v2",exact344bytes)`.
Source record binding is `H("qualified-demand-source-record-v2",lease_id,source_record)`;
withdrawal frontier binding is `H("qualified-demand-frontier-v2",lease_id)`.
These fields authenticate statements; they do not grant local permission.

`QDR2` order is magic4, LE16 version2, slotu8, zeroreservedu8; then32-byte `network,
parameters,demand_id,requester`; then LE64 expected_revision. Revision checks prevent
stale controls from silently affecting a later lease. The requester signs the main
envelope; no wire boolean can substitute for that authentication.

`QWA2` is magic4, lease_id32, the unchanged exact584-byte `QWT1` matrix manifest and
source signature64. The unsigned620 bytes are signed through
`H("qualified-task-source-sign-v2",unsigned_bytes)`. Statement identity is
`H("qualified-task-manifest-v2",unsigned_bytes)` and excludes signature bytes.
The v1 signature domain/packet cannot authenticate a v2 statement. Network and
parameters additionally bind the fresh profile. Every source/context/purpose/window/DA
field must match the current consumer lease; `source_record` and `withdrawal_head`
must equal the derived lease-bound values above.

Cost class1 remains the experimental64×64 field-matrix relation: exactly16384 model
bytes and16384 input bytes, canonical LE32 values less than4294967291, declared262144
logical multiply-add units and `hardness_status=0`. Zero, identity, low-rank, reused or
producer-prepared matrices remain legal. These declared logical units are not effective
CPU/GPU cost or an expensive-attempt lower bound. There is no accepted hardness value,
larger-work fallback or arbitrary random task presented as useful computation. The
private crypto material admission still checks actual artifacts, derived matrices and
task identity. A valid source signature on false material hashes passes only statement
authentication and must fail actual material admission before full work replay.

## State machine and continuous operation

The lifecycle namespace contains `qualified-demand-generation-v2` and exactly the keys
`qualified-demand-slot-v2:00` through`:31`. Each record is at most4096 canonical JSON
bytes and stores one current lease, one signed statement, source sequence, immutable
bound model/input/task/meter, status and one output counter/product. There is no growing
per-demand registry or per-renewal output nullifier in this namespace.

An open request uses global branch generation exactlyprevious+1, revision1, a canonical
derived demand identity and a free slot. Replacement of an old slot is permitted only
when `old.available_until < height`, including revoked slots. Old signed requests cannot
reopen their earlier generation on the same canonical state. Checked overflow fails.
Each lease requires `not_before >= admission_height`, `expires > admission_height`,
a validity interval at most1000 blocks and `available_until == expires+100`.

Renewal preserves demand/generation/requester/source/purpose/cost, source record,
authorization scope and DA identities. It requires revision exactlyprevious+1,
submission no later than the previous expiry, an overlapping window and later expiry.
First-bound model/input/task/meter, source sequence and output counter remain unchanged.
The prior source statement immediately ceases to match the new lease ID; the source must
sign and register a successor with source sequence exactlyprevious+1. The requester can
renew and the source can register in canonical order in the same block. Work eligibility
always comes from the predecessor state: the new statement first supports the next block,
and cannot provide its own registration block's work.

Operators must renew and re-sign before the final eligible block. A missing successor,
expired task, revoked task or absent material fails eligibility. If every task is expired
or revoked, the chain cannot manufacture an authorized next block. No legacy maintenance,
unsigned matrix, task randomness or optimistic registration fallback is selected.

Revocation requires the current requester, exact demand and expected revision and changes
the record to terminal `revoked`. Renew/register and subsequent-parent work eligibility
then fail. Repeated revocation is rejected. Retention keeps its existing finite deadline;
revocation does not authorize immediate slot reuse or claim that archived bytes vanished.
Revocation included in a block also suppresses that block's arithmetic-output credit.

Within one demand, a source re-signature, renewal, producer switch, header/challenge change
or repeated work cannot reset `output_count`: nonmaintenance has at most one exact
arithmetic output, maintenance has zero. A different product for an already consumed
meter fails. First-bound material cannot change during renewal. Two simultaneous active
demands cannot register the same matrix task. Once the former demand expires, a genuinely
new demand may use the same artifacts under a new generation; this is not an infinite
global content-novelty filter and truthful new demand remains attested. The output counter
does not prove model value or issue an additional token reward.

## Genesis, retention and rollback scope

The explicit bootstrap helper derives actual model/input matrices and signs a maintenance
statement for slot0, requester public-development account1 and source public-development
account0, generation1/revision1/window0..1000/retention1100/source_sequence1/registered_height0.
It emits zero arithmetic-output credit. Public fixture key seeds are reproducible and
are not production secret custody or independent demand. Genesis contains this bounded
fixture so the first block can carry independently signed open/register controls.
The returned lifecycle state is merged into the existing genesis owner; it does not
change account balances, ledger nonces or charge fictitious genesis transaction fees.

100-block retention is a signed finite obligation and a metadata-reuse gate. Present
material checks do not prove future availability, storage repair, custodian independence
or service under attack. The32×4096-byte limit bounds only this lifecycle metadata;
historical blocks, branch deltas, full transcripts, physical receipts and other namespaces
remain separate DA/storage budgets. APFS or filesystem free-space observations do not
qualify this retention contract.

Demand state, generations, source sequences and arithmetic meters are branch-relative
consensus state and roll back with their existing delta/undo owner. Independent local
legal/withdrawal history and physical-effect deduplication must remain monotonic under
their original owners. Reorganization does not erase that local history or repeat a
physical action. This module does not create a replacement withdrawal database or
claim globally irreversible on-chain cancellation.

Transport challenge puzzles remain separately scoped resource protection. Renewability
does not cure cheap legal-matrix mining, prepared-work shortcuts, historical-parent
false-transcript costs, slot capture, authenticated identity rotation or public fairness.
Fastest valid producer and sustained budget-matched hostile ingress remain separate P0
measurements; lifecycle tests cannot certify them.

## Verification and ownership

M06 `qualified_task_lifecycle::apply_verified_command` is called through the existing
executor's verified envelope, account/fee checks and tracked `View`. Its exact reads and
bounded prefix scans participate in ordered MVCC conflict validation/reexecution.
`eligible_task` privately constructs its result from the actual parent snapshot and
revalidates the current stored source signature, lease ID, window, bound material and
source sequence. The Node work owner checks actual artifact/matrix bytes before replay.
`consume_output` consumes only the existing verified product identity under that private
parent eligibility; it does not grant model adoption, local effect or public activation.

Exact codec tests retain an independently calculated fixed lease-ID vector, all payload
truncations, trailing bytes, padding, version/domain separation and overflow/resource
failures. Crypto tests cover real signatures/materials, v1 signature rejection, updated
lease rejection, genuinely signed false model/input claims and the continuing legal
cheap-matrix limitation. Native executor tests use real envelope/source signatures and
account-derived ledger sequences to check open/register, parent delay, renewal/output
preservation, material/sequence replay, cancellation/retention, canonical parallel
generation conflicts, failure atomicity and more than16 recycled demands. The last item
is an executor transition test, not proof of chain mining beyond height1000 or72-hour
operation. Node/distributed observations must separately report actual packets, failures,
work costs, resources, duration and retained source commitments.
