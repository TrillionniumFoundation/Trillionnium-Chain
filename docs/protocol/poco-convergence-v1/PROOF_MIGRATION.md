# PCC1 — Proof semantics and migration contract

Status: **candidate contract; no migration implementation or activation claim**.
Read with [README.md](README.md) and
[AI_RESOURCE_STATE_MACHINE.md](AI_RESOURCE_STATE_MACHINE.md).

## 1. Non-negotiable rule

Changing a function, binary, schema name or JSON tag cannot strengthen an existing
proof. A historical live-node QC MUST NOT be rewritten as a PoCO three-chain
finality proof. A manifest, administrator signature or new genesis cannot make
an old unsafe quorum threshold retrospectively BFT-safe.

PCC1 preserves the frozen v0 wire/verification semantics and proposes new local
integration contracts. It allocates no implicit protocol number and enables no
AI extension under an existing runtime commitment. New semantics require an
explicit version/profile registry, new domains where required, accepted codecs
and vectors, and signed governance activation on an accepted release.

## 2. Closed proof-class dispatch

A proof class is an untrusted decoding discriminator, not a capability. Choose
exactly one registered decoder from the claimed schema/protocol/chain identity,
then authenticate all its fields against an independently trusted context. Unknown,
mismatched or ambiguous classes fail. Never try successive decoders until one
accepts, normalize a bad proof, or infer a new format from similar fields.

| Proof class | Permitted use | Forbidden conclusion |
|---|---|---|
| `legacy-live-qc` | historical signature-claim inspection under the exact legacy set/codec | BFT finality, new-chain state authority, settlement permission |
| ordinary PoCO QC | certified block and imported lock/view effects after full validation | finalized state solely from this QC |
| PoCO TC | justified view progress under imported rules | block certification, lock erasure or finality |
| `poco-three-chain-v0` | finality under the full authenticated v0 predicate | certifying another target, epoch or runtime |
| epoch handoff | exact old/new-set and anchor authorization | an ordinary three-chain across two sets |
| availability evidence | exact data retrieval/retention obligation of its profile | execution correctness or financial settlement |
| verification evidence | the exact pinned computational/attestation statement | subjective truth outside that statement |
| migration import | explicit target-genesis allocation/provenance accepted by target governance | a historical-finality upgrade or automatic cross-chain bridge |

An authoritative result is represented internally by a private, context-bound
verified type issued only by the appropriate verifier/authority. Caller-provided
booleans, identifiers, digest strings, JSON metadata and public constructors cannot
manufacture that type. Its lifetime/generation and target root are checked by the
consumer. A testkit structural predicate must never return such a production type.

## 3. Complete finality verification and receipt binding

A v0 finality verifier performs all of the following, not only the shape checks
in the Python testkit:

1. decode exact bounded canonical bytes and reject trailing/unknown fields;
2. resolve chain/genesis, protocol, epoch, parameters and validator set from a
   trusted genesis/checkpoint plus verified transition history, not the proof's
   self-asserted set;
3. verify each signed proposal's actual scheduled leader and full signing context;
4. verify each QC signature, unique canonical signer, membership and recomputed
   weighted quorum; reject synthetic anchors as ordinary certifying QCs;
5. verify parent links, heights, views, exact justify-QC digests and every required
   TC and referenced QC under the imported predicate;
6. verify the claimed finalized target is the oldest certified block or a proven
   ancestor, not the newest QC's block;
7. verify the relevant state/receipt/event commitment and inclusion proof against
   that target header, including exact transaction identity and outcome;
8. verify the receipt's business stage and profile meaning before a consumer acts.

Full validators additionally execute the bounded application predicate before
voting. A light client instead relies on the stated consensus-validity assumptions
and authenticates the committed facts; it must not claim it independently reran
all AI computations. Same hash strings without these bindings are insufficient.

RPC/SDK/indexer output declares chain/genesis, protocol/profile, proof class,
finalized block/height/root, transaction/receipt identity, business stage, verifier
profile, and projection freshness. Display `local`, `admitted`, `certified`,
`authorization-finalized`, `result-accepted` and `settlement-finalized` distinctly.
An indexer may be stale or rebuilt, but cannot promote `certified` to `finalized`.

An exact old byte proof may remain available through a historical API. That API
returns its original class and trust statement, never a current authority token.
Default clients reject unknown proof versions rather than displaying a green
finality indicator. SDK builders do not silently change chain IDs or signing domains.

## 4. Initial migration mode: new chain instance with explicit import

The first convergence migration supports only a fresh chain/genesis and fresh
signing namespace. This is an implementation target, not a runnable migration
command supplied by this change. In-place conversion of legacy live-node databases,
keys, vote rows, WALs or finality receipts is forbidden.

The reviewed import descriptor contains, in exact logical order:

```text
schema/version and migration policy hash
source chain/genesis, source protocol/proof class, source release identity
source checkpoint/header and original proof digest (or explicit absence)
source exported state/receipts/obligations roots and export artifact digests
source trust classification and governance acceptance basis
target chain/genesis, target protocol/runtime/profile and validator-set commitments
target initial application root, balances/supply and imported-obligation root
transformation program/configuration digests and deterministic input/output manifests
per-object/asset reconciliation root and discrepancy dispositions
fresh signer-namespace and key-policy commitments
profile/data-retention continuity plan and retired namespace descriptors
approval threshold, signer identities, signatures and acceptance record
```

All fields are mandatory except an explicitly typed absent source proof, which
requires the distinct non-finality import policy. Canonical encoding, signatures,
maximum sizes and cross-language vectors must be accepted before a descriptor
can authorize a target genesis. Hashing arbitrary JSON is not that encoding.

Source evidence is classified honestly:

- authenticated v0 finality can establish the corresponding old chain fact under
  its old assumptions; it still is not a target-chain transaction;
- a valid legacy multisignature establishes attribution only to the extent of
  its verified signatures, set and context;
- an unproven or manually reconciled snapshot is an explicitly trusted allocation
  input, not cryptographically established historical finality.

Target governance can accept a clearly labelled allocation based on weaker source
evidence only through its explicit trust policy. It cannot relabel that evidence
as BFT finality. Wallets, explorers and APIs preserve the distinction permanently.
The migration does not create an implicit redeemable bridge or guarantee that old
and new balances cannot both be spent on their independent networks.

## 5. Migration state machine and atomic handoff to the new node

```text
SourceEvidenceClassified
 -> ExportSealed
 -> ReconciliationVerified
 -> TargetStaged
 -> TargetRootVerified
 -> GovernanceAuthorized
 -> FreshNamespaceInitialized
 -> RecoveryVerified
 -> NetworkEligible
```

Each stage records exact predecessor, context, artifact roots, generation and
readback. Approval of a different export, transformation, binary or target root
does not authorize this one. Configuration changes invalidate dependent evidence.

Export includes balances, supply, replay floors, capabilities, task/lease/attempt
revisions, escrow, obligations, profile code/commitments, service indexes, artifact
retention and any permitted historical receipt references. Verify per-asset supply
and escrow conservation independently of the exporter. Derived indexes are rebuilt
from authenticated state and compared, not trusted because they were exported.

A target unable to service an old task's exact verification/retention profile
must reject the import or explicitly drain/cancel/reconcile that liability under
an accepted policy. It may not mark it settled, release storage early or pay it
again merely to make counters balance. Imported liabilities have distinct,
context-bound identities to prevent collision with new tasks.

Create the target in a new filesystem and signer namespace. Verify zero prior
signing history for that namespace and bind it to the new genesis. Use fresh
consensus keys for this initial mode; old keys and old databases are read-only
historical material. No same-path overwrite, renamed WAL or vote-watermark reset
is an acceptable migration. Stage and verify all projections before atomic
activation of the new namespace descriptor. Reopen and verify before networking.

After a target signature or target finality has escaped, rollback means a separately
verified recovery of that same target identity or an explicitly new instance.
Restoring a pre-migration image and signing again is forbidden. An aborted staging
attempt is not authority to reuse partially initialized signing state.

## 6. Same-instance epoch/runtime upgrades

The existing v0 old/new-set handoff specification remains the only applicable
same-instance kernel contract. Ordinary three-chain proofs never cross it.
A future application/runtime upgrade needs a finalized version/parameter commitment,
complete old/new authorization, exact old terminal proof, a new context-bound
anchor, and evidence that outstanding tasks/verifiers/retention remain serviceable.

PCC1 does not activate an in-place upgrade route. Negotiated network versions
cannot activate consensus semantics; local feature flags cannot do so either.
An unsupported proposed version is refused before signing. Mixed-version operation
requires a published compatibility matrix and exact transition vectors, not
'best effort' decoding or acceptance of whichever root is available.

Changing a finality predicate, hash domain, signed layout, root format, verifier
program or economic meaning is a semantic migration. A function-name change is
not the relevant boundary. Dual historical reading is permitted; dual active
consensus authority over one signing namespace is not.

## 7. Required evidence and negative matrix

| Case | Required result |
|---|---|
| rename legacy QC to new proof class | reject before authority issuance |
| one or two QCs passed as finality | reject |
| valid signatures but wrong chain/genesis/set/epoch/parameters | reject |
| same block coordinates but another justify-QC digest | reject where exact embedded digest is required |
| newest certified block claimed finalized | reject absent its own complete proof |
| synthetic genesis/epoch anchor counted toward three QCs | reject |
| malicious source-supplied validator set | reject without trusted set derivation |
| ordinary QC or availability certificate used to pay | reject |
| local admitted receipt displayed finalized | contract test fails |
| old nonce/key generation imported as fresh authority | reject |
| export omits escrow/task/retention liability | reconciliation fails |
| target changes verifier for outstanding tasks | reject or drain under accepted old rules |
| migration abort/crash after any stage | no ambiguous signer/network release |
| two independent exports/builds disagree | no activation |
| new instance silently presented as old history | reject policy and client acceptance |

Required evidence includes independently generated raw proofs, genuine signatures,
wrong-context and truncation vectors, source-to-target state reconciliation,
independent builds, clean install/reopen, power-loss and HSM cases, light-client and
SDK interoperation, index rebuild and signed governance records on one artifact.
Structural fixtures are insufficient to verify cryptographic authenticity.

The included testkit checks only selected class/relationship rejections and
resource/replay examples. It does not implement the import descriptor, historical
verifier, authenticated migration, byte codec, genesis writer or SDK. Their status
remains false in the candidate manifest; existing repository release truth is unchanged.
