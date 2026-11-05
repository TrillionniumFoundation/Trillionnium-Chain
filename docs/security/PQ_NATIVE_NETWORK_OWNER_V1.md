# Native PQ network owner v1

Status: **development candidate; HOLD / NO GO**. This document is a new source
reconstruction dated 2026-10-27. Its bytes are not the missing historical document
whose Git blob was `d427bef2933b8b75598829fc8a2a6e8ad45619bc`.

## Authority and selection

`trnm-pon-node` exposes `ingress::pq_network` only with the explicit, default-off
`pq-native-openssl` feature. `Node::open_with_pq_network` selects a fresh
`StateBackend::PqNetworkV1` database and records one immutable canonical policy.
Legacy and other selected backends refuse this database. Legacy, authenticated,
public-v2 and public-v3 listener constructors refuse the PQ backend. There is no
"try ML-DSA, then Ed25519" branch in this profile.

The separate explicit [native PQ account candidate](PQ_NATIVE_ACCOUNT_OWNER_V1.md)
can now compose a transfer-only imported account policy with this transport.
The original transport-only context retains its old account rules; selecting
PQ transport by itself still does not migrate account authority. The imported
account context has fresh parameter/genesis bindings and refuses all PNX1
transactions. Its task, model and liability-settlement owners remain unavailable.

The operator independently pins the network, parameter identity, genesis, server
ML-DSA-65 SPKI, positive generation and one to 64 peer SPKIs. Keys provided by an
incoming frame cannot join the roster. The policy hash commits all these pins,
the profile name and the ledger limits. A changed policy cannot silently reopen
the database. This is operator-pinned private transport, not decentralized key
discovery, account authority or confidential transport.

The profile accepts only a loopback listener, a positive lifetime no longer than
one hour and bounded client calls no longer than ten seconds. The server processes
connections sequentially. This is deliberately insufficient for WAN acceptance
or an honest-service guarantee under CPU exhaustion.

## Wire and real cryptography

Requests use `PNQ1`, a big-endian payload length, one exact 3,487-byte TPQ1 frame
and canonical serialized native `Request` bytes. Responses use `PNP1`, the same
framing and a signed `PqResponse`. Both directions are at most 2 MiB including
their envelope. TPQ1 fixes ML-DSA-65, purpose 6, the network, a direction-specific
policy/peer owner context, signer key ID, generation, sequence, expiry and SHA-384
payload commitment. The 176-byte unsigned statement is actually signed and
verified by the Rust OpenSSL EVP adapter; its signature is 3,309 bytes. The
operator-pinned SPKI grammar, algorithm identity and key ID are checked before
any signature observation is returned.

`PqSignatureObservation` has no public field constructor, `Deserialize` or
`Clone`; syntax parsing cannot create it. Its existence proves only a valid
signature under the supplied exact expectations. The private `VerifiedRequest`
additionally binds the immutable policy and canonical native request. Neither
object grants account spending, installs a model or supplies chainwork.

The logical request ID hashes the authenticated **unsigned** TPQ1 statement.
ML-DSA's randomized signature bytes therefore cannot mint a second operation.
A differently signed copy of the same statement uses the same replay entry and
cached response. Changing the request while reusing a consumed sequence refuses.

## Durable execution, replay and revocation

The native SQLite owner records `pq_network_peer_v1` and
`pq_network_request_v1` outside reorganization State. New requests consume a
contiguous positive sequence; gaps refuse. Before dispatch the owner reserves
the exact request bytes and a worst-case 2 MiB response. The existing native
dispatch still performs real work verification and application execution.
Successful and failed completed outcomes consume their sequence and retain the
exact signed response. A lost acknowledgement can be retried without a new
logical operation.

Pending operations survive restart. After their signed expiry, a later request
can durably retire them as `EXPIRED_UNCONFIRMED`; this does not assert that an
effect never happened and does not roll it back. The process invalidation epoch
prevents an old cooperative phase from subsequently committing under expired
authorization. Local operator revocation is irreversible in this profile, is
checked at admission and completion and survives real chain reorganization and
cold reopen. There is no remote un-revoke or policy rotation operation.

The ledger has at most 4,096 records and 16,777,216 charged bytes. Completed rows
charge exact request plus response; pending rows charge request plus the full
response reservation. Reopening authenticates retained requests and responses,
checks operation IDs and sequence shape and recomputes both limits. The limit is
not physical SQLite allocation, CPU time or a guarantee against storage rollback
by an administrator. Cooperative checks cannot preempt an OpenSSL call, SQLite
commit or kernel call.

The capacity test's exact claim is limited: 13 large signed invalid-packet
requests charge 13,724,854 bytes. The **next request of that same large class**
plus its worst-case response reservation exceeds the 16 MiB budget, including
after reopen. Smaller requests might still fit. This is not full CPU depletion,
a public saturation test or an honest-service SLA.

## Native owner coverage

| Owner / seam | Selected PQ network profile | Remaining migration |
| --- | --- | --- |
| Peer request and response authentication | Real in-process ML-DSA-65, strict TPQ1, direction and policy pinning | Public discovery, key rotation, encryption and independent WAN acceptance |
| Peer sequence, lost ACK, revocation | Native SQLite replay owner outside reorg State | External monotonic antirollback and physical crash campaign |
| Block W1 validation and fork choice | Existing complete native verifier; transport adds zero work | Quantum-effective cost and useful-work qualification are separate |
| PNX1 account authorization | Existing Ed25519 path in transport-only context; explicit PQG1/QTX1 import candidate is separately bound and refuses PNX1 | Complete public account creation/rotation/revocation and all transaction owners |
| Account nonce and reorg | Original M06 owner; the separate transfer-only import preserves its nonce floors and branch deltas | Complete imported obligations and account key lifecycle |
| Qualified task source/demand signatures | Existing classical authorization | Versioned PQ task wire and actual branch-state authorization owner |
| Cell publication, retrieval and custody signatures | Existing owners plus separate PQ research prototypes | Native unified authorization and publisher-offline retrieval acceptance |
| Hepta install / FinalUse / future evaluation | Existing external owner; no permission minted here | Real PQ artifact signer lifecycle and three actual future-use rounds |
| Miner identity / deployment approvals | Existing classical development identities | Explicit separately versioned ownership and migration |

PNX1's installed transaction cap is 2,048 bytes, smaller than one ML-DSA-65
signature. Raising a feature flag or wrapping PNX1 in signed transport does not
solve that incompatibility. A new packet/transaction profile must bind wire,
execution costs, keys, migration state and replay ownership together. A generic
"verified=true" callback or a transport signature standing in for an account
signature is not an acceptable bridge.

## Source and evidence

The native patch was recovered from the exact source arrays embedded in one
surviving native test executable. Two equal arrays in that executable are one
build, not independent verification. They recovered 1,032 inputs, including 19
changes relative to `ac469237422d43805845e8b9a6839ad14e1028e7`. The missing original
checker, tests, contract and CLI `main.rs` changes were not recovered. The present
checker/tests/contract and any CLI repair are new reviewable source changes with
fresh blob pins. No old commit or tree identity is claimed.

The [source reconstruction and exact-source validation report](../../evidence/pon-pq-native-reconstruction-20261027/README.md)
separates surviving executable observations from fresh compilation. The
[cross-source checker](../../scripts/ci/check_pq_research_integration.py) enforces
exact source pins and false whole-chain activation claims, including nested PQ
modules in the native Node. That checker is source integrity, not a semantic
verifier or independent acceptance certificate.

All production activation, whole-native-authorization migration, physical
rollback resistance, quantum PoN hardness, independent acceptance and public WAN
claims remain false or unqualified. The sole development plan and M00–M17 owner
boundaries remain authoritative.
