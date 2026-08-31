# PoCO Consumption Certificate v0

Status: **P0 normative logical schema; not an economic-security or privacy claim**

Schema version: `0`

## 1. Purpose

A Consumption Certificate is a consumer-signed claim that a named provider delivered a named task output measured in canonical consumption units for a bounded chain-height window. Once accepted and finalized on chain, it may become an input to a later PoCO epoch snapshot.

A certificate is not:

- a consensus vote, QC, or finality proof;
- proof of social usefulness, fair pricing, party independence, or sybil resistance;
- a mint instruction or proof that payment cleared;
- a perpetual entitlement to validator membership or weight;
- a privacy-preserving proof.

Finality comes only from PoCO-BFT quorum certificates. Voting capacity is separately capped by active slashable bond.

## 2. Canonical body

`ConsumptionCertificateBodyV0` is encoded with `CEV0` in this exact field order:

```text
schema_version                u16       // 0
genesis_hash                  Hash32
chain_id                      ConsensusString
provider_id                   Bytes
consumer_id                   Bytes
consumer_key_id               Bytes
task_id                       Bytes
output_commitment             Hash32
meter_id                      Bytes
meter_version                 u32
consumed_units                u128
billing_start_height          u64
billing_end_height            u64
consumer_nonce                u64
settlement_commitment         Hash32
measurement_evidence_root     Optional<Hash32>
```

All `Bytes` fields use their active consensus-parameter bounds. IDs are opaque canonical bytes; human labels are not part of the certificate.

`output_commitment` identifies the accepted output or result. `settlement_commitment` identifies the separately verified funded settlement/escrow obligation. `measurement_evidence_root`, when present, authenticates supporting spans or meter evidence but does not make that evidence private or automatically valid.

Wall-clock timestamps are intentionally absent. The billing interval is chain-height based and MUST satisfy:

```text
billing_start_height <= billing_end_height
billing_end_height < acceptance_height
consumed_units > 0
```

## 3. Signature and certificate ID

Let:

```text
body_digest = Digest(
  "trnm.poco.consumption-certificate.v0",
  ConsumptionCertificateBodyV0
)
```

The consumer key signs the 32-byte `body_digest` with strict Ed25519 as specified by PoCO-BFT v0.

The certificate ID is derived independently of signature bytes:

```text
ConsumptionCertificateIdV0 = struct {
  body_digest: Hash32
}

certificate_id = Digest(
  "trnm.poco.consumption-certificate-id.v0",
  ConsumptionCertificateIdV0
)
```

The submitted `ConsumptionCertificateV0` contains the body, consumer signature, and certificate ID. A verifier MUST recompute both digests. Excluding signature bytes from the ID ensures that one logical signed claim has one identity.

## 4. Identity and nonce rules

At acceptance height, `consumer_key_id` MUST resolve in finalized pre-state to the exact Ed25519 public key authorized for `consumer_id`. The authorization must cover the billing window and acceptance operation.

For each tuple `(consumer_id, consumer_key_id, provider_id)`, an accepted `consumer_nonce` MUST be strictly greater than every previously accepted nonce for that tuple. The state transition records the new maximum. A certificate with a repeated or lower nonce is invalid.

The tuple

```text
(consumer_id, provider_id, task_id, output_commitment,
 billing_start_height, billing_end_height, consumer_nonce)
```

MUST also be unique. The chain stores accepted certificate IDs and rejects duplicate bodies even when submitted by another account.

`provider_id` and `consumer_id` MUST differ byte-for-byte. This does not prove that two identities are independently controlled. Until related-party classification is finalized, certificates from related or unresolved relationships contribute zero PoCO units.

## 5. Meter and unit rules

`meter_id` and `meter_version` select a finalized on-chain meter definition. That definition MUST deterministically specify:

- the task/output binding it measures;
- conversion into the single canonical `consumed_units` scale used by the active PoCO parameters;
- maximum units per certificate and billing window;
- required measurement-evidence format, if any;
- eligibility or deprecation epochs.

An unknown, inactive, ambiguous, or deprecated meter is invalid for new acceptance. A meter definition change takes a new version and affects no previously signed body.

The mainnet meter registry, measurement-evidence verification, and privacy-preserving proof format are `UNDECIDED`. The reference profile therefore permits schema and shadow-pipeline testing only; it does not authorize production economic weight.

## 6. Acceptance transition

Either the provider or another fee-paying submitter MAY submit a certificate. Submission authority does not replace the consumer signature.

The deterministic acceptance transition MUST verify, in order:

1. canonical encoding, field bounds, schema version, genesis hash, and chain ID;
2. recomputed body digest and certificate ID;
3. strict consumer signature and key authorization;
4. provider, consumer, task, output, billing-window, and nonce rules;
5. recognized meter/version and deterministic unit bounds;
6. absence of the certificate ID and uniqueness tuple from accepted state;
7. a valid, funded, unused `settlement_commitment` under application rules;
8. any active relationship, challenge-deposit, and admission rules;
9. checked arithmetic for all counters and indexes.

Acceptance records at least:

```text
certificate_id
body_digest
provider_id
consumer_id
task_id
consumed_units
meter_id and meter_version
acceptance_height
acceptance_block_id
status
```

The transaction MUST explicitly consume or reserve the referenced funded settlement according to application rules; a mere hash reference cannot create payment. The exact market price and settlement policy are application/economic concerns, not a multiplier in the v0 voting-weight formula.

## 7. Finalization, maturity, challenge, and revocation

An accepted certificate is not finalized until its acceptance block is finalized by PoCO-BFT. Its `finalized_epoch` is the epoch of that finalized acceptance block.

The certificate contributes to no snapshot until the maturity rule in `poco-bft-v0/05-poco-weights-bond-and-slashing.md` passes. A certificate that is revoked, successfully challenged, duplicated, or otherwise invalidated in the finalized snapshot state contributes zero.

Challenge evidence and revocation transitions MUST be deterministic, objective where possible, and idempotent. The exact fraud-proof formats, challenge deposits, adjudication policy, and mainnet consequence schedule are `UNDECIDED`. They must be frozen and audited before production PoCO-weight activation.

Later revocation cannot retroactively rewrite an already active epoch's validator set. It affects later snapshots and may produce separately specified accountability consequences.

## 8. PoCO snapshot use

The certificate contributes only its `consumed_units`, after maturity, decay, and all hierarchical caps. It does not contribute payment value, token price, signature count, or raw task count.

The snapshot algorithm groups certificates by provider validator, task, and consumer; applies per-certificate, per-consumer/provider, per-task/provider, and per-provider caps; converts capped units to raw capacity; and caps that capacity again by active slashable bond. See the normative formula in the weight document.

One certificate ID may appear at most once in a snapshot input. Duplicate IDs invalidate candidate construction rather than increasing weight.

## 9. Privacy and data availability

The base v0 body exposes relationship identifiers, task/output commitments, units, meter identity, and billing heights to chain observers. A hash commitment does not hide low-entropy data by itself.

Raw task output or detailed spans SHOULD remain off chain when not required for deterministic validation, but honest validators must obtain every datum required by the active admission rules before accepting the transaction. Availability and retention policy for off-chain measurement evidence is `UNDECIDED` and cannot be assumed from certificate finality.

## 10. Required test vectors

The future conformance suite MUST include:

- byte-exact body, digest, signature, and ID vectors;
- wrong-chain, wrong-genesis, wrong-domain, wrong-key, and alternate-encoding rejection;
- duplicate ID, duplicate tuple, and non-monotonic nonce rejection;
- billing-boundary and `u128` maximum cases;
- meter version activation/deprecation cases;
- acceptance-before-finality and maturity-boundary cases;
- challenge/revocation idempotence once those schemas are frozen.
