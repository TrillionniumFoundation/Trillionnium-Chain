# Fresh native PQ transfer slice, version 1

This is an explicit research composition on PR 504 source
`829c5d28ec9a0fc13de2bd098b477cbacacdb4b7`. It uses the existing native owners
for M05 admission, M06 state execution, complete PoN work, SQLite persistence,
branch activation and recovery. It does not install a production network or
migrate an existing chain. The [existing ML-DSA authorization component](PQ_NATIVE_AUTHORIZATION_V1.md)
and its separate local operation journal remain separate mechanisms.

The public entry is `Settings::native_pq_transfers_v1` followed by
`pq_native_v1::PqNodeV1::open`. The opaque wrapper holds the original `Node`;
it has no `Deref`, `into_node`, legacy listener or operator-authority escape.
Original Node constructors reject the new profile, and the wrapper rejects old
settings. Raw magic does not choose a profile. A fresh descriptor commits all
sorted public keys, balances, genesis timestamp, profile and capacities into
new network/parameter commitments; the new signature domains explicitly bind
the resulting genesis hash too. Test genesis allocations have no real value.

## Actual ownership and wire formats

| Owner | Selected behavior |
| --- | --- |
| M00 `pq_native_transfer_v1` | Strict NPQ1 syntax, full DER SPKI, wire/semantic identity and signing statement. Parsing grants no permission. |
| M01 `pq_auth::verify_tpq1` | Actual ML-DSA-65 verification of the entire expected TPQ1 statement. |
| M05 `store/mempool.rs` | A native view supplies the full NPQ1 body to the original `TypedAdmissionGate`, with actual signature/current-authority hooks, pending-prefix preview, capacity and SQLite group ownership. |
| M06 `pon_executor::pq_native_v1` | A genuine PQ prepared variant, actual current State reads, original nonce/fee/transfer arithmetic, mandatory processing, rewards, conservation, receipt and root computation. |
| Original Node | Selected PQP1 codec, complete W1 verification, current-parent execution, root comparison, original atomic storage, ancestry, activation and cold recovery. |

NPQ1 contains the following exact bytes. It never constructs an Ed25519
`Envelope` or accepts a dummy legacy signature.

| Offset | Field | Rule |
| --- | --- | --- |
| 0..4 | Magic | `NPQ1` |
| 4 | Version | 1 |
| 5 | Algorithm | `0x65`, ML-DSA-65 only |
| 6..8 | QTX1 byte length | Big-endian u16, 3,631–4,143 |
| 8..10 | SPKI byte length | Big-endian u16, exactly 1,974 |
| 10..12 | Reserved | Zero |
| 12.. | QTX1 | Existing transfer body, memo and full TPQ1 signature frame |
| Following QTX1 | SPKI | Exact strict DER public key |

The entire transaction is 5,617–6,129 bytes. Byte fees, pool bytes and block
transaction bytes include the frame and SPKI. A block allows at most 256 records
and 524,288 transaction bytes: only **85 maximum-size transactions** fit. The
original one-MiB packet cap remains. A local group has at most 16 members; the
pool remains bounded by 256 records and 524,288 bytes.

PQP1 is `PQP1 01 00 00 00`, the unchanged 318-byte PNH1 header, the original
little-endian u16 transaction count/length framing, full NPQ1 records, and the
unchanged complete PNW1 proof. Header-only SQL projections and the ancestry
index explicitly include the extra eight prefix bytes. Ordinary `Packet`/PNX1
codecs keep their old rules. The header transaction root is still
`sequence_root("transactions", full_raw_transactions)`.

The M05 canonical wire digest is SHA-256 of domain
`TRNM/PoN/NativePQWire/v1\0`, big-endian u32 raw length and complete NPQ1 bytes.
The semantic identity is SHA-384 of domain
`TRNM/PoN/NativePQStatement/v1\0`, network, parameters, genesis and the existing
48-byte QTX1 statement identity. It excludes randomized signature bytes.
`TRNM/PoN/NativePQTransferOwner/v1\0` binds network, parameters, genesis,
account ID and the exact profile in the TPQ1 owner context. TPQ1 purpose is 1.

## Current authority is committed State

Every registered account has three leaves in the original State:

* `account:<id>`: original balance and chain nonce;
* `pq-auth-v1:<id>`: exact schema, algorithm, key ID, generation and retirement;
* `pq-key-v1:<id>`: full strict SPKI encoded as lowercase hex.

The key JSON is 3,950 bytes, below the existing 4,096-byte leaf limit. All three
leaves count toward existing State key/size limits. The entire authority/key
membership and exact record grammar are checked against the frozen descriptor.
M06 reads both authority and key through the actual `View`, adds them to its
read set, and checks the supplied SPKI against those reads. A prepared signature
never supplies current account authority. Root cache reuse still requires these
State checks and the original actual-State/root bindings.

This first slice permits one to 64 genesis-registered public keys, generation
one, active and immutable. Recipients and miners must also be registered.
Unregistered keys, modified generations, retired authorities, missing leaves,
key substitutions and configuration substitutions reject. This deliberately
leaves open registration, retirement and rotation transitions. Those require
separate reviewed signed commands and reorganization rules.

Original Node SQL owns account, authority/key State, supply, block, canonical
deltas, authenticated commitments and active slots. There is no PQ authority
side database. A distinct schema identity changes only the explicitly selected
pool body cap and adds retained-statement/removal mappings. Exact schema and
TEMP-object checks run for this profile; old stores cannot be silently opened
as PQ stores. An explicit unknown or empty PQ profile selector refuses the
legacy root path. Enabling the pool checks the selected store, registered miner,
current State and deterministic preview time before committing configuration.

## Time, reorganization and local history

Actual transfer expiry is checked against the already-validated block
`Header.timestamp`. Equality with `expires_at` is valid. Execution receives an
explicit timestamp; missing PQ time rejects. Old PNX1 expiry keeps its original
height semantics. Cold reads use stored validated header/state facts and never
reinterpret expiry against wall-clock time at restart.

The pool's deterministic preview time is the original upper median of at most
11 parent-first timestamps plus one, with checked overflow. It is not simply
parent time plus one. The original header rule permits a successor timestamp
below its immediate parent's timestamp when it is above this median. Mining
reexecutes at the actual candidate timestamp; a queued preview is not an
expiry or inclusion promise for a later timestamp.

The TPQ1 sequence in this transfer domain is the **chain account nonce**. It
can return to an earlier value on a valid heavier-fork reorganization. It is
never sent to, or used to reset, the independent local `PqAuthorizationOwner`
operation sequence. Pool insertion/removal ordinals stay outside reversible
chain State and do not detach with balances or nonces.

The original pool reclassifies retained rows against the new branch, including
previously expired or sequence-consumed rows. A retained semantic statement
maps to one complete original group. Every incoming ML-DSA signature is
verified before a duplicate result, including randomized re-signings. This
possession-only duplicate check uses time zero to avoid declaring an already
retained expired row a new valid admission. Its receipt explicitly grants no
new M05 admission or current inclusion authority. Actual M05/M06 queue preview
uses the branch timestamp, authority, fee, balance and nonce checks.

Explicit terminal pruning records both the original wire removal ordinal and
the semantic identity in the same SQLite transaction. A randomized re-signing
cannot erase that local decision. Admission-triggered cache eviction remains
separate: it preserves its monotone original history, removes only retained
cache mappings, and makes no finality assertion. Requeue after a legitimate
reorganization does not rewind local insertion/removal history.

## Validation and remaining gates

The source includes real public-test-key ML-DSA signing, actual original M05
admission/ready counts, complete W1 generation plus independent reference
verification, original Node admission/activation, cold reopen, heavier-fork
nonce rollback/requeue, explicit pruning, whole-byte limits, timestamp boundary
and partial-reorganization recovery controls. The exact source-bound execution
records, including failures, must decide their result; compiling these controls
is not a native success.

Run from `trillionnium` with the repository-pinned toolchain and exact lock:

```sh
cargo test --locked -p trnm-protocol --lib pq_native_transfer_v1::tests::
cargo test --locked -p trnm-mvcc-fee --lib pq_native_v1::tests::
cargo test --locked -p trnm-pon-node --test native_pq_v1 -- --test-threads=1
```

The local prototype uses the existing ordinary SQLite owner. These tests do
not qualify the separate physical I/O boundary, power-loss behavior or physical
rollback protection. A cooperative fault-injection cut is not a physical crash.
The ordinary Node's existing trust in retained local validated-packet facts is
inherited. This slice does not add the independent journal/SQLite validation
markers or external rollback anchors studied by the History recovery work;
malicious replacement of the complete local database is outside its protection.
Source-bound subset results do not replace whole-workspace or original CI gates.

P1 remains open. Registration, other command tags, governance, transport,
Hepta installation/final-use, key custody and recovery are not migrated. A
future rotation/migration needs its own domain, old authorization plus new PQ
key possession, one-time execution, supply and detach/attach semantics. If the
old Ed25519 secret is already obtainable through Shor's algorithm, a new dual
signature cannot identify the original human owner by itself.

ML-DSA authentication does not prove W1's minimum work cost or close its quantum
mining/soundness analysis. No algorithm, registry or local operation gains
consensus weight. The unchanged pure PoN N64/R8/q work, target, DAA and branch
selection remain; no independent hash puzzle, added grinding, PoS or BFT is
introduced. Whole-chain post-quantum and production qualification stay **OPEN**.
