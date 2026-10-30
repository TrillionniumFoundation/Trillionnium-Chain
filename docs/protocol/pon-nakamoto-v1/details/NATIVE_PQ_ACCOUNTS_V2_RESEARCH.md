# Native PQ accounts v2 research boundary

This is an implementation record under the
[sole development plan](../../../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md).
It describes a fresh, valueless `pon-native-pq-accounts-v2` network profile.
It is not a deployed-store upgrade or an assertion that the chain is quantum
secure. The original PNX1 and first PQ transfer profile retain their own packet,
State and SQL namespaces. No dummy Ed25519 signature authorizes a PQ2 command.

## Current evidence

The current source is a successor of the exact published native-PQ transfer
source `33945bc5cdf91977792faefefed0981f6b88222c`. The actual intermediate gates
below are separate observations, not interchangeable qualification results.

| Gate | Actual result | Scope |
| --- | --- | --- |
| M00 selected codec cases | 4 passed, 0 failed, 43 filtered | Actual new framing and signing-core tests |
| First M06 compilation | Failed | A retained Config test needed an explicit absent PQ2 field; original failure retained |
| First M06 selected cases | 2 passed, 0 failed, 90 filtered | Real ML-DSA funding, registration, rotation and task-permission effects |
| First migration cases | 2 passed, 2 failed, 90 filtered | Actual continuity reward-queue refusal at the imported genesis |
| Corrected M06 selected cases | 4 passed, 0 failed, 90 filtered | Real migration proofs and conserved reward-height translation; synthetic unit Header is explicitly not verified work |
| Node library metadata | Passed | Locked, offline compilation of the actual packet/store/pool composition; no Node case executed |
| First Node test metadata | Failed | Private Settings access in the new fixture; no native case executed |

The last failure is retained. Narrow read-only signing helpers and a strict
original-Node checkpoint exporter replace the private-field fixture accesses.
At the time this record is introduced, the corrected nine-case Node integration
target has not run. Its eventual exact-source terminal output, including failures,
must govern runtime claims. Source checks, successful parsing and compilation do
not substitute for real ML-DSA, PoN work, State execution or SQLite replay.

## Owners and actual paths

| Layer | Existing owner and new composition |
| --- | --- |
| M00 | [NPQ2 codec](../../../../trillionnium/crates/trnm-protocol/src/pq_native_accounts_v2.rs) builds the complete signing core and unverified frame; it cannot supply a missing State key |
| M01 / M06 | [PQ2 State and execution](../../../../trillionnium/crates/trnm-mvcc-fee/src/pon_executor/pq_accounts_v2.rs) resolves actual current keys and calls the real TPQ1 ML-DSA verifier before the original prepared-execution path |
| M05 | [Original local pool](../../../../trillionnium/crates/trnm-pon-node/src/store/mempool.rs) performs actual typed admission, nonce/fee/branch preview and local SQL persistence |
| M06 task permissions | The original `apply_task_command` owns tags 2–5. A stable PQ2 account is its owner/provider identity; rotation does not replace the task owner with a new key ID |
| Packet and Node | [PQP2 packet](../../../../trillionnium/crates/trnm-pon-node/src/pq_accounts_v2.rs) and [opaque Node composition](../../../../trillionnium/crates/trnm-pon-node/src/store/pq_accounts_v2.rs) delegate to the original full W1, admission, activation, authenticated State and reorganization owners |
| Conditional import | [Migration projection](../../../../trillionnium/crates/trnm-mvcc-fee/src/pon_executor/pq_accounts_v2/migration.rs) requires explicit external prior-PQ trust and a separately pinned source checkpoint |

The opaque `PqNodeV2` has no `Deref`, no ordinary-Node escape and no legacy network
listener. Its State read and signing-digest helpers do not confer permission;
admission and execution re-read the selected parent and current authority.
The selected SQL schema retains the original atomic writer and adds distinct
PQ2 statement/removal tables and exact raw-frame bounds. A mismatched old store,
old packet or settings profile refuses. No existing SQL schema is silently
expanded or migrated.

## Signed fields and limits

The NPQ2 common fields bind network, parameters, exact genesis, stable account,
chain nonce, UTC expiry, full-byte fee ceiling and current generation. The joint
statement domain is `TRNM/PoN/NativePQCommandStatement/v2\0`. Every role signs the
same complete command, witness descriptors and any carried SPKI. TPQ1 owner
context additionally binds the profile, command and exact role. Semantic
statement IDs are SHA-384 over that signing core; raw transaction IDs commit the
complete NPQ2 bytes, including signature randomness. The original transaction
sequence root continues to commit the complete raw frames.

| Operation | Witnesses | Exact frame bytes | Byte-budget ceiling |
| --- | --- | ---: | ---: |
| Transfer, zero to 512 memo bytes | Current key, resolved from actual State | 3,751–4,263 | 122 at the largest frame |
| Reserve task | Current key, resolved from actual State | 3,789 | 138 |
| Cancel task | Current key, resolved from actual State | 3,741 | 140 |
| Record receipt / accept task | Current key, resolved from actual State | 3,773 | 138 |
| Register pending account | New key with full SPKI and possession proof | 5,691 | 92 |
| Rotate authority | Current-key proof plus full new SPKI and new-key proof | 9,272 | 56 |
| Anchored import claim | Independently precommitted prior-PQ proof plus full new SPKI and possession | 9,432 | 55 |

These are floor divisions of the unchanged 524,288-byte transaction budget,
subject also to 256 transactions, 16 members per submitted pool group and the
full 1 MiB packet ceiling. They are serialization limits, not measured TPS.
Ordinary registered commands save the repeated 1,974-byte SPKI, but still require
actual key lookup, State validation and cryptographic verification. No inference
about WAN propagation, adversarial verification cost or energy follows from the
byte count.

The frame's UTC expiry is checked against the validated block Header timestamp.
The pool previews at the original branch MTP plus one, with checked overflow.
Stored replay uses the stored Header timestamp, never wall-clock `now`.
Parent, height, exact timestamp, profile/config, genesis, State and the actual
generation/SPKI participate in reuse validity. A signature checked only for
duplicate possession at time zero does not become an admission cache or an
eligible typed result. Signature verification precedes a duplicate result;
randomized re-signing cannot bypass the semantic statement index.

Chain account nonces are branch State. The TPQ1 operation sequence in this new
domain follows that chain nonce. Local pool ordinals and explicit-removal history
are separate monotone local data. A heavier valid branch can restore an account
nonce or prior key generation and reclassify retained pool rows. It cannot rewind
the local ordinal or erase an explicitly pruned statement's removal record.

## Accounts, registration and rotation

Positive transfers and mature positive PoN rewards may create a pending account
at any nonzero address. Neither zero transfers nor zero actual rewards create
one. A pending account has no authority and cannot spend until its actual key
possession and registration fee pass. The finite fresh-genesis seed list is not
a runtime miner registry and provides no additional consensus weight. A miner
may direct a normal PoN reward to an unregistered address.

Fresh registration requires the pending address to equal the new key ID. It
installs generation one using the actual State keys `pq-auth-v2`, `pq-key-v2`
and `pq-key-status-v2`; subsequent rotations keep the account address stable.
Those leaves are checked by the original canonical State grammar and committed
by the actual State root. Stored SPKI is strict, and its 3,950-byte JSON string
fits the unchanged 4,096-byte State-value cap. Historical generations are
contiguous, old generations remain retired, and the current generation is live.
Orphan leaves and inconsistent type/cardinality/key identity refuse.

Rotation binds the exact current authority digest and generation `g + 1`, and
requires genuine current-key and new-key proofs. The new key cannot duplicate a
retained generation for that account. Actual M06 application reads the selected
State again. A sender changing authority is exclusive within that block in both
orders, so another command cannot borrow a stale or partially changed cache.
The original task owner/provider remains the stable account. A valid heavier
fork can roll a rotation out; branch reauthorization then uses the restored key.
This is explicit chain semantics, not an irreversible off-chain revocation.

The profile caps a key history at 16 generations and still uses the original
65,536-key State limit. These limits and the initial/import seed bound of 64 are
research bounds; neither makes permissionless lifetime capacity solved. Base
fees 200 for registration and 400 for rotation/claim, plus full raw-byte fees,
are fixed experimental parameters, not calibrated CPU/storage prices. With the
current subsidy of 1,000, registration's 5,891-unit fee requires six such rewards
if the new account has no other funds; those rewards also obey the original
20-block maturity rule. The real native fixture is required to test that path.

## Conditional migration and its independent trust premise

An old Ed25519 signature cannot establish the unique original owner after Shor
has made that signing key forgeable. This implementation therefore does not
accept an old-Ed-plus-new-PQ double signature as sufficient retrospective PQ
ownership. It implements a conditional new-network import from an independently
trusted PQ registry and independently selected source checkpoint.

`TrustedPqPrecommitments::pin` is an explicit protected startup choice, not a wire
message and not a successful-verification Boolean. The experimental fixture
constructs and freezes that prior registry before it obtains the source
checkpoint. That chronology and registry are an additional premise; the original
repository did not already supply such a registry. Its exact account coverage,
keys, generations and source network/genesis enter the anchor commitment.

The original `Node::pin_native_pq_migration_checkpoint` exporter only accepts an
unowned authenticated source Node at the externally pinned current active block.
It refuses policy/mining/continuous owners, native I/O/growth observation and
public-service accounting/listener/unknown epochs, rather than escaping their
operation budgets. It first requires the original ready state, refusing an unfinished source
reorganization even while its old active root remains valid. It runs the original
complete W1 verifier for that retained packet, reads the original State, checks its Header root and rechecks the active
tuple. Stored packet existence does not become a work proof. This read-only
exporter neither establishes source finality nor locks or retires source assets.

The untrusted `CheckpointMaterial` type also remains usable by narrow component
tests. Possession of such a value, a hash-matching Header or the public test seeds
does not constitute verified source work. Native claims require the actual
original-Node path and its separately pinned checkpoint.

The migration constructor enumerates all source account balances/nonces, task
escrows and pending rewards. It requires exact registry coverage of source
accounts and relevant task/reward identities. Missing or extra identities,
collisions, source nonce overflow and positive unsupported quota/release
liabilities refuse. Tasks retain owner/provider/output/status and remaining
escrow; future deadlines translate by subtracting the source height. A positive
task obligation with no representable remaining window refuses. Future rewards
retain exact amount/payee and translate into the unchanged 20-block maturity
window, without early payout or merging. The actual original mandatory owner
pays and removes them. Imported rewards must match the pinned projection byte
for byte until maturity and must be absent afterward. Old profiles keep the
original empty-genesis reward contract.

Projected account balances plus escrow/reward liabilities must equal the source
issued supply. Optional distinct fresh-genesis seed balances are added explicitly
with checked arithmetic. Immutable import leaves bind the full anchor, original
account facts and permission digest. A claim signs the anchor ID, source
checkpoint/root/account, original nonce/balance/permission digest and new
generation, with both actual prior-PQ and new-key proofs. It consumes the original
nonce plus one, installs the new current key and flips the branch-local claimed
marker atomically. It does not mint the imported funds a second time. A valid
heavier fork can detach the claim and restore the original lock/nonce/escrow;
only a properly revalidated claim can attach again.

This projection does not prove source-chain locking, retirement, economic
finality or absence of cross-network double use. It must remain a valueless new
network experiment until those external premises have an independently designed
protocol and actual evidence. Explicit source trust is not a consensus vote or
extra PoN weight.

## Runtime controls and remaining work

The new Node target contains nine actual controls: pool/State/PoN/SQL/cold/fork,
randomized-signature duplicates and explicit pruning, Header/MTP/expiry bounds,
the 122-largest-transfer ceiling, old-profile/schema refusal, interrupted
original reorganization, reward-funded open registration, task permissions
through rotation/reorg, and actual old-Node checkpoint import/claim/reorg.
The original unit cases include zero credits, both authority-change orderings,
key/proof mismatch, omission/conservation/collision and translated-height bounds.
Every actual invocation and failure must be preserved with its source identity.

Test phase observations measure complete actual calls on the shared host,
including failed results and complete PoN search where applicable. They separate
signature/State checks, pool insertion, work search/reference validation,
admission/SQL and branch reauthorization. A canonical ML-DSA signature for another
statement is an invalid-proof control, not a proven globally most expensive
adversarial input. These wall times are not isolated CPU, worst-case budgets,
proof of miner work hardness, network throughput or energy measurements.

Only tags 1–5 and the three explicit new account commands are in NPQ2. Original
tags 6–12 (contribution/evaluation/release/reward/quota/work registration), original
13–24 extensions and any inner Ed-signed evidence remain individually open; their
refusal by NPQ2 is not migration. Transport, service/governance/operator identity,
History authority and Hepta final-use have not thereby changed to PQ authority.
Quantum security of complete W1 mining, transparent-proof soundness, resource
metering, physical rollback and production activation remain independent open
gates. This slice does not close P1 or claim a quantum-secure chain.
