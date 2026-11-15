# Native PQG1 / QTX1 account owner v1

Status: **development candidate; HOLD / NO GO**. This is a fresh, explicit
transfer-only profile under the original M06 executor and M15 Node. It does not
activate a network, certify an old-chain export, migrate task/model authorization
or establish whole-chain quantum security. The default profile is unchanged.

## One account execution owner

The optional `pq-native-openssl` feature admits a native `QTX1` transfer only after
strict frame parsing, a pinned ML-DSA-65 key, actual OpenSSL EVP verification,
the selected network, imported key generation, expiry and nonce floor checks.
A private typed command then enters the **existing** M06 transfer implementation.
That owner still checks the current branch nonce, balance, fee limit, exact byte
fee, maximum transactions, account limits, rewards and total issued units. It
still produces the ordinary state delta, receipt and complete root. There is no
parallel balance ledger, synthetic classical signature, public `verified=true`
constructor or transport signature used as account authority.

The selected account policy refuses every PNX1 transaction. An ordinary profile
refuses QTX1. Qualified task lifecycle entrypoints retain the original PNX1
statement and cannot accept a QTX1 command. This profile supports transfers only;
unsupported owners are unavailable, not silently executed with classical keys.

`QTX1` v1 is the existing research wire, now parsed natively: a 144-byte fixed
header, at most 512 memo bytes and one exact 3,487-byte TPQ1 frame. The transaction
is 3,631–4,143 bytes. The explicit profile binds an 8,192-byte per-transaction cap
and 16 transactions per block; those are versioned profile limits, not changes to
the existing 2,048-byte default. The fee uses the full received wire length. The
48-byte logical identity commits the body and pinned key ID, excluding randomized
signature bytes. Re-signing cannot create a new nonce or different receipt.

## Migration and frozen obligations

`import_genesis` parses exact PQG1 v1 bytes and compares an independently supplied
source digest, old/new networks, old selected head, withdrawal head, protocol,
issued amount, explicit genesis timestamp, target projection root and target
genesis. The protocol identity commits the externally fixed timestamp, so a
different timestamp cannot reuse the same signed migration. It does not obtain
those expectations from the incoming message. The old source is bounded to
128 accounts and 256 liabilities. Accounts and liabilities must be strictly
ordered, unique and within the original integer and conservation rules.

Each active imported account requires both an actual Ed25519 signature by the old
key and an actual ML-DSA-65 signature by the new key over the identical original
PQG1 migration statement. That statement binds the complete export, both
networks, selected head, withdrawal head, protocol, exact old account row, new
key ID, incremented generation and expiry. An independently revoked old key
cannot migrate. This dual-key step must precede compromise of the old classical
key; a signature by a quantum-forged old key cannot establish historical ownership.
An attacker who can already sign for the old key can also select their own new
PQ key and produce both signatures. A frozen old balance snapshot alone does
not solve this ambiguity. The independently authenticated **target key mapping**
must already be fixed, for example by a PQ commitment authenticated before the
old key is compromised or an explicitly trusted migration authorization. The
exact target projection/genesis pins enforce that mapping here; the importer
does not establish its external authenticity. A newly written native negative
control gives an adversary the published old test keys and checks both signatures
under an attacker PQ roster against the original target pins. Its post-change
native execution is not qualified: no completed execution receipt was recovered
for source `e6429b9a226ac43682f11ecb5f760ef0243c35a7`. The key-compromise limitation
above follows from the authorization assumptions, not an unexecuted test result.

The original `next_nonce` becomes the native account's current nonce minus one;
subsequent execution cannot reset below that floor. Unmigrated accounts retain
their full balance in distinct quarantined addresses with no signing policy.
All four source liability classes retain their exact original 81-byte records
under fresh immutable `pq-import-liability:` rows. They remain **locked** and are
included in total conservation. No expiry, omission, refund, payment or completion
is invented. Executing their original future settlement remains a required
separate migration, so this profile cannot claim an economically complete import.

The opaque `VerifiedPqGenesis` can only be constructed after these checks. Its
policy binds immutable execution configuration, key roster, nonce floors and
all locked obligations. External source-history completeness and monotonic
withdrawal authority are still prerequisites. Local bytes and dual signatures
do not independently prove either one.

## Native work, branches and transport

`Settings::from_pq_account_import` selects fresh native parameter and genesis
domains, including the imported source/projection and original execution context.
The actual QTX1 network ID is the domain-separated hash of the migration's
declared address namespace, **complete resulting native parameter ID**, source
digest and target genesis. QTX1 signs this derived ID. The declared namespace by
itself is insufficient: a retained pre-fix native test actually applied one signed
transfer in two differently parameterized import contexts that reused it.
Keeping PQG1's existing address projection and deriving this later native network
ID avoids a circular hash dependency and leaves the PQG1/QTX1 wire grammars intact.
The new state may only open with the explicit PQ network backend. Ordinary
Node constructors and classical listeners refuse it. Incoming packets may parse
the new transaction grammar, but parsing alone adds no authorization: full W1,
parent/task checks, original M06 execution and exact state root remain mandatory.

Account nonces follow the ordinary branch state and change through the original
stored deltas on reorganization. PQ peer sequences, pending outcomes and local
revocations remain in the separate existing durable transport owner outside
reorganization state. Policy bytes and native context must match at cold open.
This is the original loopback-only, bounded, operator-pinned transport profile;
it is not public discovery, confidential transport or independent WAN acceptance.

The miner field remains a reward address. Valid original PoN work does not need
membership in the imported account roster. Rewards may therefore mature to an
unregistered address; this creates no signing key, registration or spending
permission. Such funds are unspendable in this deliberately incomplete profile
until a separately specified public account registration owner exists. Requiring
the migration roster as a mining qualification would violate the open PoN goal.

## Remaining production authorization gaps

| Owner | This candidate | Remaining requirement |
| --- | --- | --- |
| Imported account transfers | Native QTX1, real ML-DSA, original M06 balance/nonce/fee owner | Public account creation, rotation, revocation, recovery and complete transaction set |
| M05 queued intake / task observers | Existing PNX1-only owners; no silent QTX1 conversion | Versioned native PQ queue schema, prefix admission and appropriate observations |
| Old export and migration cutoff | Exact external pins and real dual possession signatures | Independently authenticated complete old history and pre-compromise cutoff |
| Imported monetary obligations | Exact locked records; no money omitted or minted | Versioned authorization and original settlement lifecycle for every class |
| Peer request/response and replay | Existing native PQ transport and persistent local owner | Public discovery, confidential channels, rotation, physical antirollback and WAN |
| Qualified task source/demand | Unavailable in transfer-only account profile | Native versioned PQ task and actual owner migration |
| Cell release / model installation / FinalUse | No new permission | Native PQ identity lifecycle across all original Chain and Hepta owners |
| PoN and succinct proof security | Unchanged original work; signatures add zero weight | Complete quantum-effective work/resource and proof soundness analysis |

The [source and execution record](../../evidence/pon-pq-account-native-20261028/README.md)
separates attempted builds, actual test results, exact source manifests and
remaining gates. Existing failure reports remain part of the record. Source
integrity checks and component tests do not promote release flags.
