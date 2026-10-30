# External PQ recovery witness V1 (research only)

An independently managed witness can sign an exact local recovery state using
ML-DSA-65, a fresh one-time challenge and a monotonically increasing external
sequence. The receiver obtains a pinned ML-DSA public key and the minimum
sequence from **independent storage**, not from its potentially rolled-back
SQLite database. The verifier matches exact network/genesis, tip, state root,
effect journal head, owner generation and height. A reorged or newer chain
requires a fresh observed witness; this component does not guess ancestry.

Signed domain: `trnm-external-pq-recovery-witness-v1`.
No Ed25519 fallback. The canonical CBOR wire is limited to 8192 bytes,
and signed timestamps are valid for no longer than 300 seconds.

**Threat boundary:** If an attacker can roll back both the local database
and the claimed external minimum sequence/challenge, the verifier cannot
detect it. If a witness signs a forged snapshot or uses a compromised key,
the signature alone provides no truth. A deployment MUST provision an actual
independent witness/HSM/monotonic quorum, define its key rotation, audit
equivocations and test unavailable or contradictory witness cases. Current
source is only a strict receiving component; no external witness service,
consensus finality, node recovery hook, signer custody, real power-cut
rehearsal or production activation is delivered here.

Positive and refusal tests are at
`trillionnium/crates/trnm-research-protocol/tests/pq_rollback_witness_v1.rs`.
