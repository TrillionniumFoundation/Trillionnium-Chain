# G2A DA-FULLREP-V1 candidate evidence

This directory is a candidate-only contract and replay index for
`G2A_DA_FULLREP_V1`.  It is not a signed G2A exit, a production availability
certificate, or an activation/release assertion.  The machine-readable
contract is [`fullrep-model-contract-v1.json`](fullrep-model-contract-v1.json).

## Exact source and scope

The current replay source is the exact published A10 candidate tuple:

```text
repository = TrillionniumFoundation/Trillionnium-Chain
base_ref   = refs/heads/feature/chain-a10-g20-traceability-v2-20260829
base_commit = 044224a3a6c9100cd64961ea34a28031bb78a636
base_tree   = 02fb16fd12d2c6387495087e3eff578c2c44100a
package = G2A_DA_FULLREP_V1
agent = A11
profile = DA-FULLREP-V1
```

The model is an independent, transport-independent assurance model.  Its
keyed envelope tag is only a deterministic candidate witness; it is not an
Ed25519 production signer, requester registry, peer admission mechanism, or
Order authority.  The Rust DA crate remains the owner of the local candidate
implementation and its full-range proof types.

## Reproduce

Run from a clean checkout of the exact source tuple:

```sh
bash scripts/project-preflight.sh --audit
bash scripts/ci/check_da_fullrep_model_v1.sh
```

The focused clean-snapshot gate rejects tracked edits and untracked files before running the
model.  It parses JSON/TOML with duplicate-key and non-finite-number rejection,
checks the exact base tuple, executes the self-test, validates the certificate
and authenticated full-range response, and replays the retained strict
negative cases.  Python bytecode is disabled (`-B`) so the gate does not leave
generated files in the checkout.

The self-test reports five positive transitions, six compatibility negatives,
ten strict type/binding negatives, and two authenticated-envelope negatives.
All seven fault-matrix entries are
required to reject.  A fresh clean-clone replay is still required before any
queue admission or promotion.

## Closed candidate facts

- a manifest checksum is established before an attestation can be emitted;
- object IDs include the namespace and complete byte length;
- only complete, digest-matching bytes satisfy the full-replication request;
- a response signer must be an attestor named by the active certificate, with
  receipt and returned-chunk identifiers recomputed before verification;
- repair requires at least one complete matching source and preserves the
  target manifest;
- withholding evidence names a provider that is actually in the certificate;
- retention/challenge holds and a strict boolean Node permit gate GC;
- `DA-DAS-V1` and sampling-only certificates reject closed.

## Remaining blockers and non-claims

The candidate does not close authenticated production P2P, generic range
dissemination, durable requester/responder signer journals, ArtifactEvidence
Node authority, accepted A08/A10 interfaces, exact `BatchRef` retrieval-before-
vote integration, whole-node CAS/anti-rollback, or production GC.  Those are
typed upstream blockers and remain `BLOCKED_UPSTREAM`; no local model result
changes `g2a_exit`, production, activation, or normative-freeze truth.

The A11 commits were replayed onto the pinned A10 head before this evidence
was regenerated.  When A08/A10 interfaces are accepted or the base/plan tip
changes again, retain this envelope as superseded and regenerate all vectors
and evidence on the exact new tuple.  Do not edit old evidence to make a
replay pass.
