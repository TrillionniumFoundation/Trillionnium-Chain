# PCB1 — post-quantum Cell bundle and dual-role attestation research

**HOLD / NO ACTIVATION.** This file documents a narrow, executable offline
cryptographic model/Cell identity experiment; not a P2P swarm, immutable Hepta
publication, authorized export, independent future-window evaluation, durable
custody, legitimate model admission, model release or production blockchain
implementation. Based on TPQ1 research PR #399 and the QTX1 child PR.

## PCB1 canonical release manifest

Strict fixed binary header (166 bytes) plus 1–16 sorted and unique Cell records
(96 bytes each). All multi-byte integers are unsigned big-endian. UTF-8/JSON,
unknown versions, reordered Cell IDs, ambiguous lengths and trailing bytes
reject. No executable pickle/model loading occurs.

| Offset | Field | Bytes |
|---|---|---:|
| 0–3 | magic `PCB1` | 4 |
| 4 | version `01` | 1 |
| 5–36 | network | 32 |
| 37–68 | compatible model family | 32 |
| 69–100 | parent release (zero permitted at bootstrap) | 32 |
| 101–108 | release generation (positive) | 8 |
| 109–156 | shared Base content ID | 48 |
| 157–164 | shared Base byte length | 8 |
| 165 | Cell count 1–16 | 1 |
| 166 onward | sorted Cell ID32 / generation8 / content ID48 / length8 | 96 each |

Each content ID is
`SHA384("TRNM/PoN/PQCellContent/v1\\0" || BE64(length) || exact bytes)`.
The manifest ID is
`SHA384("TRNM/PoN/PQCellManifest/v1\\0" || BE32(manifest length) || canonical manifest)`.
Every base/Cell content object must be present, at most 64MiB each, non-empty,
with exact byte count and digest. This does not prove remote storage, allowed
redistribution or runtime/ABI/model compatibility.

## Distinct, real FIPS 204 signatures

Use existing TPQ1 canonical 176-byte statement / ML-DSA-65 signature.
Contexts bind network and parent release through
`SHA256("TRNM/PoN/PQCellContext/v1\\0" || network || parent release)`.
Generation and operation sequence are mandatory and match the caller-expected
values; all signatures expire against an externally admitted `now`.

- Evaluation TPQ1 purpose=3 signs a typed payload:
  `EVAL_DOMAIN || manifest_id || frozen_evaluation_plan_digest48`.
- Release TPQ1 purpose=4 signs:
  `RELEASE_DOMAIN || manifest_id || frozen_evaluation_plan_digest48 ||
  reviewer_count8 || sorted unique reviewer_key_ids32[]`.
- A minimum two separate reviewer **key identities** from an explicit
  caller-supplied roster of at least three keys must each have a genuine
  valid evaluation signature. The release key is separately allowlisted and
  is not counted as a reviewer.
- Changing the reviewer combination invalidates the exact release signature,
  even if each original reviewer signature remains valid. Duplicate reviewer
  keys do not count twice; old/reassigned key IDs cannot be rewritten into an
  authorized evaluation without a fresh signed context.

**Critical remaining authority**: a supplied roster is not a verified independent
reviewer committee, and signatures alone do not authenticate task provenance,
actual model scores, stronger baselines, holder diversity, export permission,
anti-Sybil independence, future utility or network availability. The output is
`ResearchObservation(adoption_authorized=False)`; this cannot issue Hepta
Final-use, activate a release pointer, mint a settlement or override revocation.

## Reproduction and negative cases

```sh
cd formal/pon-nakamoto-v1
python3 -m unittest -v test_pq_cell_release.py
```

The test uses five fresh real ML-DSA-65 keypairs, correct 2-of-3 reviewer
signature verification, release signed over the locked reviewer IDs, tampered
shared-Base and Cell bytes, every manifest byte mutation, reordered/duplicate
Cell IDs, wrong key/expiry/network/family/parent/generation/sequence, altered
evaluation plan, forged/duplicated reviewer, one signer exercising two roles,
signature tampering and no authority elevation. Exact local test artifact and
blob identities appear at [evidence](../../evidence/pon-pq-cell-release-v1/README.md).

## Still unclosed for real Chain/Hepta production

1. M09: distributed chunked content store, Merkle proofs, erasure/redundancy,
   real remote retrieval, custody obligations, authenticated repair and retention.
2. M10/M11: **independently authorized** evaluator roster, real frozen
   out-of-time training/evaluation, model safety and signed data withdrawal,
   conflict-of-interest and dispute rules.
3. M12/M14: versioned PQ settlement and consumer receipts, reorg effects and
   source-approved model adoption.
4. M00/M01/M02/M04/M05/M06/M07/M08/M13/M15–M17: complete native PQ
   cryptographic implementation, ledger activation, multi-host attack validation,
   quantum work security and independent full-system acceptance.

No `production_activation` flag, current genesis, W1 work rule, native
contract, live database or key is changed by this research.
