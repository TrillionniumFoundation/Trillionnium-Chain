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

## Bounded majority witness aggregation (V1 research extension)

`verify_pq_recovery_quorum_v1` verifies **every** supplied ML-DSA-65
recovery witness against an independently supplied, fixed DID + key roster.
The source requires 2–16 distinct key/DID pairs and a strict majority:
2-of-3 succeeds; 1-of-3, duplicate DID, duplicate ML-DSA key, duplicate
receipt, untrusted receipt and an invalid *extra* signature fail closed.
Every witness has its own independently persisted replay floor and fresh
challenge. Every verified witness must attest the exact same local tip,
State root, effect head, height, generation, chain and genesis.

This is only a typed, bounded **read-only observation**. Distinct keys do not
prove distinct independent operators. The caller must independently provision
and pin the roster, its rotation epoch, durable external monotonic sequences
and one-time challenges. A rotated roster must have its own externally
authenticated transition; this module does not approve one. A rollback
attacker controlling both local state and those alleged external anchors
still wins. A stale, contradictory or unavailable majority MUST prevent
recovery; quorum evidence never confers consensus, FinalUse or effects
authority. No production hook, external signer service, HSM or physical
power-failure qualification is claimed.

Focused cases live in the existing
`trillionnium/crates/trnm-research-protocol/tests/pq_rollback_witness_v1.rs`.
The original four witness tests and historic Hepta tests remain unchanged.
