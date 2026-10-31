# Post-quantum authority boundary inventory — candidate snapshot v1

This is a **source-bound inventory of known classic cryptographic admission and authorization implementations**, not a declaration that any path is deployed or activated. A path being present in a repository is not proof of current production reachability, and removal of a marker is not proof of post-quantum security. The claim gate always reports `pq_chain_qualified: false`.

The candidate snapshot is based on the exact #593 head `6ec0bc9274cce37a83642686350e4a945daf23f8`; #593 stacks on #591 and ultimately the unqualified research baseline. Every path below is audited against checkout bytes by `scripts/security/pq_claim_gate.py` and is a trigger of `pq-production-claim-gate.yml`. The trust root and caller reachability must still be independently reviewed before any acceptance.

| Scope | Candidate code boundary | Current classic mechanism | PQ migration requirement |
| --- | --- | --- | --- |
| Hepta artifact handoff | `trillionnium/crates/trnm-research-protocol/src/hepta_handoff.rs` | `SignedHeptaAdmissionV1` Ed25519 | Require independently pinned V2 ML-DSA authority; refuse V1-as-PQ fallback; prove actual caller uses new gate |
| Cell provider discovery | `trillionnium/crates/trnm-data-availability/src/cell/discovery.rs` | `CellProviderRecordV1` Ed25519 | Independently pinned PQ provider roster/lease; no classic discovery downgrade |
| Node authenticated ingress | `trillionnium/crates/trnm-pon-node/src/ingress.rs` | Development peer allowlist + `verify_hex_strict` from Ed25519 primitive | Record real listener and dispatch authorization; enforce independently owned PQ identities, no legacy fallback |
| Transfer transaction | `trillionnium/crates/trnm-types/src/transfer.rs` | `TransferTx` accepts `ed25519` signature scheme and address derivation | Versioned, domain-separated PQ native transaction, nonce and reorg/rollback ownership rules |
| Research command | `trillionnium/crates/trnm-research-protocol/src/command.rs` | `SignedResearchCommandV1` with Ed25519 Nakama/Hepta role | Replace authority-root verification and revoke old authorization at activation epoch |
| Agent market task store | `trillionnium/crates/trnm-task-kernel/src/store.rs` | Ed25519 session/controller verification | PQ owner/session binding, replay, provenance and final-use checks on actual dispatch path |
| Bilateral settlement | `trillionnium/crates/trnm-service-settlement/src/engine.rs` | `SIGNATURE_SCHEME_ED25519_V1`, registered bilateral keys | PQ provider+consumer settlement, independent registry, failure/reorg and anti-downgrade tests |

**Not closed by this inventory**: production reachability and all authority callers; governance, upgrade, release and rescue ownership; original classic key custody; hybrid AND-verification transition policy; capacity under invalid ML-DSA inputs; W1 transparent prover/FRI and PQ-128 external security assessment; quantum cheapest-legal PoN attack lower bound and difficulty/chain-selection analysis; external monotonic rollback anchor with independently durable witness roster. A new version must record each owner, last classic fallback, caller and threat model with positive and adversarial evidence.

A test pins every candidate marker to real source bytes. If an implementation changes or disappears, update the inventory only after reviewing the effective new trust root; do not mark the chain qualified on an absent grep match.
