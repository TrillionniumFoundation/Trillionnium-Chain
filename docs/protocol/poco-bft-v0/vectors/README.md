# PoCO-BFT v0 golden vectors

Status: **partial P0 conformance evidence**

The committed vectors in this directory are reconstructed by implementations
that do not call the Rust consensus crates:

- `parameters-v0.json` freezes the complete reference
  `ConsensusParametersV0` CEV0 value and digest. It is checked by
  `scripts/ci/check_poco_bft_v0_parameters.py` and reproduced by
  `cd trillionnium && cargo test -p trnm-consensus-types`.
- `wire-foundation-v0.json` freezes primitive boundaries, every v0 domain on
  an empty payload, a complete common consensus context, one block header and
  block ID, proposal/vote/timeout signing roots, and a validator-set hash. It
  is checked by `scripts/ci/check_poco_bft_v0_wire_vectors.py`.
- `ed25519-v0.json` freezes an RFC 8032 public key and signature over the
  foundation vote root, plus wrong-root, mutated-signature, undecodable-key,
  and small-order-key rejection cases. The exact bytes are reproduced by
  `cd trillionnium && cargo test -p trnm-consensus-crypto`; the public file
  contains no seed or private key.
- `anchor-finality-v0.json` freezes the exact empty-signature `GenesisQC`, a
  skipped-view genesis `ProposalSignV0`, the independently domain-separated
  `HandoffDescriptorV0`, the nested epoch authorization/anchor, three complete
  `CertifiedHeaderV0` values, and `FinalityProofV0`. It is reconstructed by
  `scripts/ci/check_poco_bft_v0_anchor_finality_vectors.py`, which also proves
  that a substituted justify-QC signer subset, a missing proposer signature,
  and a mismatched TC selection fail the logical relationship checks. Its
  reused `Signature64` bytes are shape-only fixtures; the composite objects do
  not claim valid Ed25519 signatures or quorum thresholds.

Run the independent checks from the repository root:

```sh
./scripts/ci/check_poco_bft_v0_parameters.py
./scripts/ci/check_poco_bft_v0_wire_vectors.py
./scripts/ci/check_poco_bft_v0_anchor_finality_vectors.py
```

These are partial vectors, not complete protocol conformance. The new
anchor/finality gate covers exact bytes, digests, nesting, and selected logical
near-misses, but not composite signature validity, weighted thresholds, a
general parser, or a light-client implementation. Remaining QC/TC threshold,
epoch transition, evidence, Consumption Certificate, parser-rejection, and
light-client vectors remain release-blocking obligations in
`../07-invariants-and-conformance.md`. The Ed25519 vector proves only the
verification boundary; it does not supply signing or key-custody integration.
