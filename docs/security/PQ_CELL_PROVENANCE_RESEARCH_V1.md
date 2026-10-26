# PCV1 — end-to-end post-quantum Cell provenance research

**Status: RESEARCH ONLY / HOLD_NO_GO / production_activation=false.**
Pinned parent: PR #408 \`research/pq-cell-custody-canonical-retrieval-20261026\` at
\`7cca6f76c5b6c7ac71bcccc1ce94da380360af40\`. This is an additive child of
#408 → #406 → #405 → #399. No existing PoN W1, PNW1, chainwork, Ed25519
transaction, block target, Hepta Final-use, governance, keys or deployment changes.

## What gap this increment closes (research scope)

The existing PCA1 catalog signature cryptographically binds a PCC1 chunk tree
to the hash of an *alleged* purpose=4 PCB1 release frame. It intentionally
does not validate that the original release frame was itself signed by the
independently selected trusted release owner, or that real independently
approved reviewers signed the exact evaluation plan. Moreover, a Merkle-valid
chunk tree need not reconstruct the *particular* Cell content commitment
registered by PCB1.

\`formal/pon-nakamoto-v1/pq_cell_provenance.py\` adds an offline **single
fail-closed verification chain** that checks all these facts before returning
an informational \`PQProvenanceObservation\`. This never mints Final-use,
Chainwork, storage payment, model-adoption, publication or release authority.

1. Parse exact \`PCB1\` version-one bytes with a second explicit strict decoder:
   header 166 bytes + 1–16 canonical sorted-unique Cell entries ×96 bytes.
   Derive exact \`SHA384(MANIFEST_DOMAIN || BE32(length) || manifest_bytes)\`.
   The caller supplies a separately pinned expected manifest digest.
2. Select one exact shared Base (zero 32-byte selector) or named Cell ID
   (nonzero 32 bytes). Enforce the content length and domain-separated SHA384
   content digest stored in PCB1. This checks the reconstructed **entire**
   object; possessing some valid Merkle branches does not suffice.
3. Check PCC1 network, release-manifest digest, active release generation,
   object length, caller-pinned catalog digest, canonical Merkle tree and
   **every** provided fixed-order chunk. A matching Merkle tree over another
   object's weights is rejected even with a newly signed catalog.
4. Independently verify 2–3 genuine **ML-DSA-65** evaluator signatures over
   \`EVAL_DOMAIN || manifest_digest || locked_plan\`, each with TPQ1
   \`purpose=3\`, exact network, context, generation, sequence and expiry.
   The reviewer roster (at least 3 distinct signer IDs) comes from the
   caller; duplicate reviewers, unlisted keys and a release-signer/reviewer
   collision reject.
5. Verify the original genuine release owner's **ML-DSA-65** TPQ1
   \`purpose=4\` signature over the exact sorted reviewer list, the same
   locked plan and the same manifest. Match its full signed-frame digest
   against an **independently pinned expected release-frame ID**.
6. Verify PCA1 catalog signing by the **same** trusted release owner, anchored
   to that actual verified original release frame, the caller-pinned
   preceding catalog head and the catalog root. Late signatures cannot silently
   overwrite a different pinned release/catalog.

All signature operations delegate to the existing OpenSSL 3.5+ TPQ1 ML-DSA-65
reference verifier. There is **no** Ed25519 fallback or fake success path.

## Threat-derived executed tests

\`python3 -m unittest -v test_pq_cell_custody.py test_pq_cell_provenance.py\`

At the recorded local source and environment: **25 tests, 0 failures**
(15 retained custody, 10 new PCV1 cases). The new cases cover:
- positive PCB1 reviewer → release → catalog → full Cell → actual signed
  provider chunk retrieval;
- attacker catalog substitution under the *same* original release;
- a catalog that has a correct self-consistent Merkle root and genuine new
  release-owner catalog signature but **incorrect PCB1 Cell weights**;
- real release/reviewer signature corruption, signer substitution,
  unlisted/duplicate reviewers, insufficient roster and quorum swap;
- wrong network/family/parent/generation/sequence/locked plan/original-release
  frame/catalog/previous head, expiry and true-vs-integer boundary;
- omitted, reordered and mismatched chunks, Base/Cell selector confusion;
- every byte of the exact PCB1 manifest mutated, invalid count,
  duplicate/unsorted cells, trailing data, wrong version, malformed length;
- no misleading authority / storage payout / production flags in output.

The executable environment, exact Git source SHAs and raw console output are
retained in \`evidence/pon-pq-cell-provenance-v1/\`. This is *local* conformance,
not independent cryptographic certification.

## Remaining P0 production boundaries — NOT CLOSED

- Independently provisioned trustworthy roster, release/manifest/catalog
  anchors, current Hepta export permission and withdrawal/frontier owner.
- Native Rust audited ML-DSA/ML-KEM, HSM/secret key custody, deployed
  authenticated hybrid P2P and deterministic block/fee/nonce/reorg
  integration. No trusted producer should use OpenSSL CLI subprocesses.
- Streaming/cold model loader, content-preserving atomic CAS publish,
  bounded VRAM, real version-compatible encoder and Cell composition.
  The current verifier explicitly requires all chunks for one object.
- Public, independent operator/peer availability; encrypted transport,
  anti-Eclipse/Sybil/DoS, persistent storage retention/coding/repair,
  independently metered retrieval proof and geographic custody diversity.
- Authenticated on-chain release and export authority, quantum-secure
  PoN work hardness, deep reorg, historical Ed25519 liabilities, physical
  power-loss and third-party cryptographic review.

Any future native implementation must use one versioned new profile and
independently evaluated activation. This research branch MUST NOT become a
silent in-place fallback, consensus hard fork, product Final-use or deployed
P2P service through a documentation change.
