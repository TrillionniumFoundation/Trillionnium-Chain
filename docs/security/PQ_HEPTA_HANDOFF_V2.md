# Research-only PQ Hepta handoff V2

A separate **ML-DSA-65** signature profile signs the exact existing
HeptaArtifactAdmissionV1 fields with a fresh V2 domain, chain, DID and public key.
It is opt-in, not a production activation, and does not reinterpret legacy
Ed25519 V1 bytes.

**Security boundary:** the self-signed parser does not authenticate a Hepta
owner. The receiving owner MUST pass an independently pinned 1,952-byte ML-DSA
verifying key, DID, exact Chain namespace and a freshly observed complete
admission into verify_for_context. Neither parsing nor verification confers a
FinalUse, install, export, payout or external-effect replay right. Validate the
current withdrawal head and durable operation journal at the actual effect.

Limits: deterministic CBOR; 8,192-byte maximum envelope; 3,309-byte signature;
64 MiB existing artifact bound; strict domain and version; no Ed25519 fallback.
FIPS pure ML-DSA uses an empty FIPS context over explicitly domain-tagged bytes.

Execute:
- cargo test --locked --manifest-path trillionnium/Cargo.toml -p trnm-research-protocol --test pq_hepta_handoff_v2
- cargo test --locked --manifest-path trillionnium/Cargo.toml -p trnm-research-protocol --test protocol_v1
- cargo clippy --locked --manifest-path trillionnium/Cargo.toml -p trnm-research-protocol --all-targets -- -D warnings

This does **not** close: a PQ authority registry, Hepta ordinary request wiring,
Cell provider or network PQ identities, ML-DSA implementation independent audit,
W1 PQ128, quantum mining/DAA, physical rollback anchoring, independent WAN tests.
All public/production qualification flags must remain false.
