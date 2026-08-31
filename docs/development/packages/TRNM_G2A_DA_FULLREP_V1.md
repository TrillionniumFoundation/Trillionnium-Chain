# G2A DA-FULLREP-V1 package

Status: **BLOCKED_UPSTREAM / candidate-only independent full-replication model**

Package ID: `G2A_DA_FULLREP_V1`

Agent: `A11`

Profile: `DA-FULLREP-V1` (full replication; DAS disabled)

## Authority and exact source tuple

The package was replayed against the exact published A10 candidate head
required by the agent contract:

```text
repository = TrillionniumFoundation/Trillionnium-Chain
base_ref   = refs/heads/feature/chain-a10-g20-traceability-v2-20260829
base_commit = 044224a3a6c9100cd64961ea34a28031bb78a636
base_tree   = 02fb16fd12d2c6387495087e3eff578c2c44100a
```

The machine manifest is
[`trnm-g2a-da-fullrep-v1.toml`](trnm-g2a-da-fullrep-v1.toml), and the evidence
contract/index is
[`../../evidence/g2a-da-fullrep/README.md`](../../evidence/g2a-da-fullrep/README.md).
The six A11 commits were replayed onto that A10 head; if A08, A10, the plan
tip, or the candidate base changes again, this envelope is superseded and must
be replayed; it is not silently rebased.

## Objective and owned surface

A11 closes the bounded independent assurance slice for durable-before-attest,
manifest and namespace binding, complete authenticated retrieval, exact repair,
certified-provider withholding, retention holds, and test-only GC permission.
The owned candidate paths are:

```text
trillionnium/crates/trnm-poco-da-v1/**
docs/protocol/poco-ai-native-v1/da/**
docs/protocol/poco-ai-native-v1/vectors/**       # DA vectors only
conformance/da/fullrep-v1/**
tools/da-fullrep-model/**
scripts/ci/check_da_fullrep_model_v1.*
docs/evidence/g2a-da-fullrep/**
this package document and manifest
```

Order vote authority, production GC permit issuance, DA-DAS activation,
sampling claims, and other agents' surfaces are forbidden.

## Closed candidate facts

1. A provider creates a deterministic manifest checksum before `attest()` can
   return a certificate row; replaying different bytes or retention metadata
   rejects.
2. Object IDs and certificate statements bind namespace, complete byte length,
   digest, retention window, and full-replication mode.
3. An authenticated request envelope binds requester identity, nonce, exact
   full range, height window, and a deterministic candidate response tag.
   This models the interface only; it is not a production Ed25519 signer.
4. Retrieval returns only complete digest-matching bytes.  Partial ranges,
   stale certificates, namespace substitution, and quota/expiry violations
   reject before a response is emitted.
5. A retrieval responder must be an attestor in the active certificate, not
   merely an active committee member; response and chunk identifiers are
   recomputed before verification.
6. Repair accepts complete matching source bytes and persists a fresh manifest;
   no source or inconsistent source cannot manufacture a repaired record.
7. Withholding evidence is valid only for a provider named by the active
   certificate and records the request nonce; it is not automatic slash or
   Order authority.
8. Retention/challenge holds block deletion.  GC requires an explicit boolean
   Node permit in this model; this package cannot issue a production permit.
9. `DA-DAS-V1` and sampling-only certificates are rejected while the
   `DA-FULLREP-V1` profile is selected.

## Reproduction and vector counts

```sh
bash scripts/project-preflight.sh --audit
bash scripts/ci/check_da_fullrep_model_v1.sh
```

The clean-snapshot gate parses the manifest, evidence contract, and conformance
fixture with strict duplicate-key/non-finite-number/type checks, then runs the
independent model with Python bytecode disabled.  The fixture retains five
positive cases, six compatibility negatives, ten strict binding/type negatives,
two authenticated-envelope negatives, and seven fault cases.  A passing local
command is candidate evidence only; a
fresh clean-clone replay and independent review are required for queue
admission.

## Upstream blockers and non-claims

This package remains `BLOCKED_UPSTREAM` for:

- accepted A08 CEV1 registry and accepted A10 W0-W7/`BatchRef` interfaces (the
  pinned A10 head is still a candidate and is not accepted evidence);
- authenticated production requester/responder peer envelopes and signer
  journals;
- ArtifactEvidence integration with the canonical transaction wire;
- exact proposal `BatchRef` + complete retrieval-before-vote binding;
- whole-node CAS, anti-rollback, finality-owned retention and production GC;
- multi-host withholding/repair evidence and production network authority.

The following truth flags remain false:

```text
g2a_exit=false
authenticated_network=false
order_vote_authority=false
whole_node_gc_authority=false
data_availability_sampling_active=false
production_candidate=false
production_consensus_activation=false
normative_freeze=false
```

No model output, vector count, or local Rust test changes global G2/G2A,
activation, release, or production truth.  Failed safety, durability, root,
custody, or interface mutants remain retained and are never removed to make a
rerun pass.
