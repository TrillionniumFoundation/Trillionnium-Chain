# G2D typed upstream interface requests v1

Requester: `A13 / G2D_EXECUTION_MVCC_FEE_V1`  
Branch: `agent/a13-g2d-execution-mvcc-fee-v1-20260829`  
Classification: `candidate-non-normative`

No request below grants A13 authority to edit another owner's implementation.
Acceptance requires an owner reply containing an exact source commit/tree,
interface version, canonical digest and invalidation set.

## G2D-ICR-A10-A12-AGENT-TRANSACTION-V1

Owners: A10 and A12.

Required immutable carrier:

```text
chain/genesis/protocol/epoch binding
operation kind and schema version
transaction ID and canonical bytes digest
controller, capability and session-key lineage
nonce lane and nonce
Task/Lease identifiers where applicable
ordered declared read set: object ID + exact version
ordered declared write set: object ID + expected version
resource limit vector
fee schedule/profile identifier and hash
expiry/revocation coordinate
```

Requirements:

- sorted unique object sets;
- no implicit read or write;
- no profile fallback;
- exact capability attenuation and nonce scope;
- unknown fields/versions fail closed;
- carrier decoding creates no execution, JMT, settlement or Order authority.

## G2D-ICR-A16-APPLICATION-JMT-V1

Owner: A16.

Required read/commit contract:

```text
parent application JMT root/version
object proof for each declared read and write
fresh readback generation
canonical block/Order coordinate
compare-and-swap successor token
new application JMT root/version
receipt-root and write-set-root binding
external whole-node checkpoint predecessor
```

Requirements:

- composite/local roots cannot substitute for the application JMT;
- stale proofs, ABA generations, copy/rename rollback and root drift fail before
  commit;
- A13 returns a candidate write set and receipt set only;
- A16 retains state-root, proof, state-sync and light-client authority.

## G2D-ICR-G1-A16-ORDER-FINALITY-V1

Owners: accepted G1 integration and A16.

Required finality permit binds exact height/view/block/parent, validator-set and
parameter hashes, payload/body digest, application parent root, ordered
ancestor-finalization proof and rollback coordinate. A local transaction index
or execution receipt is never finality authority.

## G2D-ICR-A15-FEE-APPLICATION-V1

Owner: A15.

A13 exports deterministic fee facts only:

```text
payer
resource vector
fee schedule/profile hash
checked fee amount
payer debit delta
fee-sink credit delta
transaction and receipt identifiers
block coordinate
```

A15 must independently authorize balance availability, refund, burn, treasury,
escrow/bond and settlement movement. A13 receipts retain:

```text
economic_authority=false
settlement_authority=false
poco_weight_authority=false
```

## Acceptance and invalidation

Any accepted reply must include:

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

Changes to any accepted digest reopen worker-count equivalence, read-version,
receipt-root, fee-conservation and downstream G2C/G2E/G2F evidence.
