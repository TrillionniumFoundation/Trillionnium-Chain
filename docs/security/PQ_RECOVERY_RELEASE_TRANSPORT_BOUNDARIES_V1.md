# Recovery, release authority and hybrid transport boundaries V1

Status: component development; whole-chain and deployed-effect qualification remain
open. This contract continues the [sole development plan](../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md).
The existing [six-domain PQ claim boundary](WHOLE_CHAIN_PQ_CLAIM_GUARD_20261031.md)
still applies. No production or consensus activation flag changes.

## 1. Recovery requires an independently retained complete journal head

`trnm-checkpoint-store` already retains an append-only journal of complete expected
and target checkpoints. Each record includes the preceding record hash; record
sequence, checkpoint scope, expected predecessor and target are revalidated during
replay. Its former daemon startup authenticated that journal against a sibling
head file. Restoring both files to a mutually consistent old snapshot passed those
structural checks. A fresh independent expectation is necessary to distinguish
that snapshot from the state actually reached before the restart.

The strict startup path separates explicit first registration from cold recovery.
Registration refuses an existing namespace. Recovery requires the independently
retained complete journal checkpoint: record count **and** record-chain root. It
compares that expectation before repairing a local head file or binding the Unix
service. A missing, truncated, locally older, locally newer or same-count/different-
root journal requires reconciliation. No path silently reseeds the journal or
derives the recovery expectation from the files being recovered.

The expectation covers the entire journal, including every scope. Comparing only
the latest generation of one scope would miss removal of another scope's consumed
state. Exporting a local checkpoint is a serialization operation: its external
retention and freshness must be established before it is used to authorize a later
recovery. Reading an old local export during the same restart does not supply that
freshness.

The existing V2 record and CAS wire encodings retain their identities. The new
recovery checkpoint encoding has a distinct magic/version and rejects trailing or
noncanonical bytes. The legacy structural `open` API remains explicitly limited;
the daemon uses the strict registration/recovery paths.

### Meaning of the checkpoint

The journal proves that its recorded expected/target transitions form its retained
history. It does not validate the business meaning of arbitrary roots supplied by
an owner. In particular, the PNQ2 `PqWitnessV4` root covers resource, peer and request
tables. That mutable-state CAS protocol does not establish append-only FinalUse
consumption, provider effect receipts or retirement history.

For actual effects, the same serialized consuming owner must enforce all of these
conditions before it returns a dispatch capability:

1. A durable intent binds the stable operation ID, original authorization,
   subject/scope, exact effect payload and reserved budget.
2. The expected independent checkpoint matches the current one; the full current
   revocation/retirement state is checked at the atomic claim boundary.
3. A given authorization and operation can be claimed only once. Reusing the ID
   with a changed payload or replacing it with a new nonce does not repair an
   unknown outcome.
4. The effect adapter receives that original stable ID. Confirmation records a
   receipt bound to the same operation and payload.
5. An entered or unknown operation is reconciled by the same ID. An adapter without
   idempotency or authenticated result lookup leaves a pending obligation.

Prepared, claimed, entered and confirmed are different facts. A successful witness
CAS followed by a lost reply or uncertain local commit cannot authorize a fresh
dispatch. A restored snapshot from before intent creation must encounter the
independent consumed state before the adapter is entered again.

The cross-repository FinalUse/ProviderEffect owner integration, signed append-
consistency protocol, provider semantics, physical power-loss testing and external
fault-domain qualification remain required. This component does not choose PoN's
main chain or issue business authority. Witness unavailability pauses operations
that require it and must be included in availability measurements. If every replica,
witness and retained expectation is rolled back together, no fresh fact remains
from which to prove the earlier execution.

The design requirement follows the atomic expected-old-checkpoint and persist-
before-response rules of [C2SP tlog-witness v1.1.0](https://c2sp.org/tlog-witness@v1.1.0).
The local hash-chain/CAS journal is its own protocol; C2SP Merkle consistency,
signed-note and cosignature interoperability are separate work.

## 2. Root and online release roles have separate authority

`trnm-release-bundle::pq_release` adds a bounded project-specific binary profile
using the existing canonical RustCrypto ML-DSA-65 verifier. Independently pinned
root metadata defines a threshold offline root plus distinct online roles for node
software, protocol configuration, Cell manifests and Cell activation. Public keys
are strict DER SPKI and must match their key IDs. Signature verification never
imports a replacement public key from a candidate's signature list.

Every accepted release binds the network, role, current root generation, exact
previous owner checkpoint, previous content, next role version, expiry and content
digest. Thresholds count distinct pinned keys. Cross-role key reuse, duplicate
signatures, wrong role/network, stale roots/checkpoints, expired metadata, invalid
signatures and version skips are refused without advancing the owner state.

Root rotation requires signatures from both the previous trusted root quorum and
the proposed successor root quorum over the exact same successor root. The successor
is the next generation and binds the preceding root digest. Removed keys enter a
retired-key set and cannot reappear in a later root. A Cell candidate or an online
role cannot promote its own output into a new trust root.

Re-selecting previously published content requires explicit signed rollback
approval while the release/activation version continues to increase. Cell
activation additionally requires that the target is the currently approved Cell
manifest. A successful role observation supplies release authenticity and version
policy; it does not supply model-quality acceptance, FinalUse, account permissions
or consensus activation.

The existing V0 bundle source, SBOM, provenance and artifact checks compose with
real current-role verification through `accept_bundle`. The authorization kernel is
an in-memory owner component. `recover_pinned` replays the accepted signed events
from the pinned initial root and compares the reconstructed terminal checkpoint
with an independently supplied expectation. Event order, observed times, role
versions, content history and retired keys are preserved. The same 8192-event bound
applies to live updates and recovery; reaching a history limit pauses updates
instead of evicting security records. Its complete state and events must be durably
committed with an independent fresh checkpoint before a production installer
consumes the result. Re-running initial bootstrap is not recovery.

Bundle identity binds the network and role independently of root generation.
After root rotation, the current role quorum can approve the same historical bundle
digest at a new release version. The new authorization still binds the current
root generation and checkpoint: an old root's signature cannot authorize that
rollback. Repackaging an artifact creates a different bundle identity; the kernel
does not infer semantic equivalence between two differently packaged contents.

This binary profile is distinct from a complete TUF client. TUF root/timestamp/
snapshot/targets download, delegation, canonical JSON, repository consistency and
SDK conformance remain separate. [TAP 21 version 1](https://github.com/theupdateframework/taps/blob/21efd9762c6bae5c6f61199d1fce7756c9dd18d2/tap21.md)
signs `b"tuf\x01" || SHA512(canonical_metadata)` with pure ML-DSA and an empty
context. It is not HashML-DSA. Complete TAP 21 support includes ML-DSA-44, -65 and
-87; an ML-DSA-65 adapter alone is a restricted profile. These byte rules belong to
the separate TAP 21 adapter rather than this project's binary-role namespace.

## 3. Test the actual fixed transport provider

The TLS and mTLS probes use the declared `TRNM_PQ_OPENSSL` binary and the already
validated `TRNM_PQ_OPENSSL_SHA256`, `TRNM_PQ_OPENSSL_VERSION` and `OPENSSL_DIR`.
The native probe must compile against headers and libraries from that same provider
prefix. A system `openssl` on PATH, or an unrelated `-lssl`/`-lcrypto`, cannot stand
in for the frozen backend. Temporary probes and private test keys stay in the test
directory and are not release assets.

[RFC 10024](https://www.rfc-editor.org/rfc/rfc10024.html) defines
`X25519MLKEM768`, `SecP256r1MLKEM768` and `SecP384r1MLKEM1024`. Generic TLS controls
exercise the selected standard groups with actual ML-DSA certificate verification
and application bytes. The existing PPH1/TPQ1 peer profile retains its explicit
ML-DSA-65 plus `X25519MLKEM768` contract; supporting other groups in a library does
not silently broaden that peer profile.

The mTLS controls require both endpoint identities, the allowed group, the TLS
version, identity pins and matching exporter bytes. Classical identity, wrong PQ
parameter set, unsupported protocol/group, absent client identity, wrong key pin
and insufficient application-role authorization must refuse. A valid TLS handshake
provides channel and peer-identity evidence. Current application permissions,
revocation, nonce, budget and FinalUse remain separate checks.

## 4. Nonsecret key-asset and recovery responsibilities

This is the source-level asset inventory. No deployed secret, production key roster
or recovery device has been inspected or changed by this component work.

| Asset | Owning boundary | Required lifecycle/recovery evidence |
| --- | --- | --- |
| Offline release root keys | Pinned `PqReleaseRootV1.offline_root` | Provisioned root digest, quorum custody, old/new quorum rotation, retired-key preservation, independent cold recovery |
| Node software release keys | `NodeSoftware` role | Exact bundle/source/SBOM binding, distinct key threshold, expiry and monotonically increasing role version |
| Protocol configuration keys | `ProtocolConfiguration` role | Separate role and version policy; protocol activation retains its own owner |
| Cell manifest keys | `CellManifest` role | Immutable content identity and release closure, current role generation, approved content rollback |
| Cell activation keys | `CellActivation` role | Current published manifest, independent activation decision and increasing activation version; no root promotion |
| Checkpoint recovery expectation | External checkpoint startup owner | Complete journal count/root retained outside the restored files; unavailable or mismatched expectation refuses startup |
| PNQ2 writer/witness keys | Existing `WitnessBinding` / `DurableWitness` | Distinct pinned identities, signed request/reply domains, exact independent reopen checkpoint; limited three-table coverage |
| Peer TLS identity keys | Fixed provider mTLS/PPH1 test profile | Real ML-DSA certificate identity, approved hybrid group, exporter binding, application trust/permission checks |
| FinalUse issuer and provider-effect identity | Existing Hepta FinalUse/ProviderEffect owners | Stable operation mapping, current revocation, durable consumption/receipts and actual independently witnessed effect recovery |
| Key generation, backups and signing devices | Operator/key-custody boundary | Entropy, seed import/zeroization, backup inventory, recovery authorization and signer-device failure tests on actual deployed assets |

The existing RustCrypto/OpenSSL differential path remains the canonical verifier
plus an independent test source, with no OR fallback. A third implementation such
as [mldsa-native v2.0.0](https://github.com/pq-code-package/mldsa-native/releases/tag/v2.0.0)
must pin its source and prove interoperability with exact modes/contexts/encodings.
Its primitive or assembly proofs do not qualify the full protocol, recovery system
or chain. Cross-architecture and hardware signing-device results remain unknown
until they are actually executed.

## 5. Reproduction and acceptance

Run the complete changed Rust packages with the pinned workspace lock, strict
Clippy, formatter, the actual fixed-provider TLS/mTLS tests and the existing source-
integrity negative tests. Preserve the original cold-rollback counterexample and
wrong-provider failures. The compact reproduction record identifies exact source
bytes, commands, provider identity and actual outcomes; successful component tests
do not close the outstanding integration, independent deployment or physical
rollback assumptions above.
