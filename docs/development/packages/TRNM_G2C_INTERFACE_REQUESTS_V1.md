# G2C typed upstream interface requests v1

Requester: `A14 / G2C_VERIFY_CHALLENGE_V1`  
Branch: `agent/a14-g2c-verify-challenge-v1-20260829`  
Classification: `candidate-non-normative`

Acceptance requires the owner to publish an exact commit/tree, versioned
interface digest and invalidation set. A14 does not edit owner implementations.

## G2C-ICR-A11-ARTIFACT-AVAILABILITY-V1

Owner: A11.

Required immutable evidence reference:

```text
artifact namespace and artifact ID
artifact digest and byte length
provider set and certified-provider bitmap
AvailabilityCertificate schema/version/digest
retention/challenge hold coordinate
complete-retrieval proof or exact repair state
Order/height binding
```

A certificate is unavailable or invalid when any provider, digest, namespace,
retention, height or completeness binding differs. A local file or caller
supplied digest is not DA authority.

## G2C-ICR-A12-TASK-LEASE-PROFILE-V1

Owner: A12.

Required Task/Lease/profile facts:

```text
Task and Lease IDs and versions
controller/capability/session lineage
provider and verifier identities
verification profile ID/version/hash
profile valid-from, expiry and revocation coordinate
challenge window and policy hash
price/bond policy references
```

No fallback profile is permitted. Subjective profiles must retain
`objective_settlement_allowed=false` and `poco_weight_allowed=false`.

## G2C-ICR-A13-EXECUTION-RECEIPT-V1

Owner: A13.

Required receipt facts:

```text
transaction ID and canonical index
parent state/JMT root and version
result state/JMT root and version
read-set/version digest
write-set digest
resource vector and fee facts
receipt status: Success, Reverted or OutOfResource
receipt digest and block coordinate
```

The carrier grants no Order, settlement or PoCO-weight authority. A14 must
reject a receipt whose JMT/Order proof is not independently supplied by A16.

## G2C-ICR-A16-ORDER-JMT-PROOF-V1

Owner: A16 plus accepted G1 finality.

Required proof binds the exact receipt to an accepted block, ordered ancestor
finalization, canonical application JMT root/version, validator set, consensus
parameters and whole-node checkpoint lineage. Composite roots and local
SQLite heads are forbidden substitutes.

## G2C-ICR-A15-CHALLENGE-ECONOMICS-V1

Owner: A15.

A14 publishes only challenge state and decision facts. A15 independently owns
bond lock/release/slash, payment/refund and conservation. Every A14 record
retains:

```text
economic_authority=false
settlement_authority=false
order_reorg=false
poco_weight_authority=false
```

## G2C-ICR-A17-APPEAL-GOVERNANCE-V1

Owner: A17 / G5 governance preparation.

Required policy freezes maximum concurrent challenges, one-appeal or
multi-appeal rule, reviewer independence, deadline extension, conflict of
interest, emergency halt and governance activation. Until accepted, the A14
candidate permits one local appeal for state-machine testing only and grants no
governance authority.

## Acceptance and invalidation

Owner replies must include:

```text
request_id
owner
source_commit
source_tree
interface_version
interface_digest_sha256
accepted=true
reviewer
invalidation_set
```

Any accepted digest change reopens profile resolution, evidence ordering,
challenge transitions and all downstream settlement/light-client evidence.
