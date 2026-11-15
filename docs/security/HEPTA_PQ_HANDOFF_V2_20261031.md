# Hepta ML-DSA-65 admission V2 — bounded PQ-only research candidate

**Status: DRAFT / HOLD.** This is a separately versioned, in-process
cryptographic admission candidate. It does **not** activate the main chain,
migrate historic ownership, grant FinalUse, replace the existing
research-protocol state machine, or qualify whole-chain PQ-128.

## Verified boundary and exact source

- Entry: `trnm_research_protocol::SignedHeptaAdmissionV2::verify_for_context`.
- Wire: `THP2`, version 2, ML-DSA-65 algorithm `0x65`, zeroed reserved bytes,
  bounded chain ID and DID, signer **key ID and key generation**, the original
  `HeptaArtifactAdmissionV1` canonical CBOR fact tuple and one 3,309-byte
  ML-DSA-65 signature. The maximum packet is 8,192 bytes.
- Signed message: fixed binary domain `TRNM/Hepta/ArtifactAdmission/ML-DSA-65/v2\0`
  plus all exact unsigned wire bytes. The signature authenticates chain,
  signer identity, generation and the full owner fact tuple together.
- Cryptography: shared `trnm-crypto-primitives` RustCrypto ML-DSA-65 exact
  message verifier; pinned canonical DER SPKI and independently computed
  `trnm-protocol` ML-DSA key ID. The packet never supplies its own SPKI.
- Authority: an externally provided, bounded `PqHeptaAuthoritySetV2` with
  **one current signer generation per DID**. Missing, unknown, duplicate,
  retired, expired or revoked identities reject. There is no
  `AuthoritySetV1`/Ed25519 OR fallback, autodiscovery or packet-driven
  rotation.
- Freshness: at each use the receiver must pass an independently current
  destination chain ID, full owner admission snapshot and trusted timestamp.
  Signature verification alone does not check withdrawal/registry state.
  This library neither owns a durable nonce/journal nor issues an effect token.
- Parser: length and version checks precede allocation; canonical admission
  CBOR is decoded and round-tripped; malformed, trailing, oversized or
  wrong-algorithm bytes are refused. `decode_untrusted` returns **no**
  authenticated capability. Only `verify_for_context` checks cryptography.

## Required tests

```sh
cargo test --locked --manifest-path trillionnium/Cargo.toml -p trnm-research-protocol --test hepta_handoff_pq
cargo test --locked --manifest-path trillionnium/Cargo.toml -p trnm-research-protocol
cargo fmt --manifest-path trillionnium/Cargo.toml --all -- --check
cargo clippy --locked --manifest-path trillionnium/Cargo.toml -p trnm-research-protocol --all-targets -- -D warnings
python3 scripts/ci/test_pq_chain_claim_guard.py -v
python3 scripts/ci/pq_chain_claim_guard.py
```

Coverage submitted with the candidate: real ML-DSA signing/verification,
canonical wire, Ed25519/algorithm downgrade, bad signature, stale
generation, different key, duplicate pin, wrong DER/key binding, revocation,
expiry, destination mismatch, modified withdrawal head, tampered owner facts,
oversize/truncation/reserved bytes and trailing bytes.

**Evidence limitation:** these are authored Rust tests, not a claim of their
execution; record the exact branch SHA, compiler, operating system and actual
test output before promoting the branch. The Python HOLD guard cannot attest
to cryptographic correctness.

## Remaining integration blockers

1. Pin the V2 roster via an authoritative, rollback-resistant and
   replay-protected Hepta owner; define and validate actual PQ key rotation,
   recovery, revocation and current-generation transitions. A caller-supplied
   roster or timestamp is a trust boundary, not proof of provenance.
2. Route every **PQ-only** artifact admission, run/start, release, model install
   and FinalUse consumer exclusively to V2 and reject V1; identify all
   historical and classical-only entry points. Retaining legacy V1 for
   explicit development does not make it safe for PQ-only authority.
3. Bind the actual Hepta final-use token, operation journal, generation fence,
   CNS route and withdrawal owner at the moment of effect. This library
   validates a fact tuple; it cannot make a state transition alone.
4. Cold restart, whole-database rollback, retained-history, reorganization
   and cross-node recovery need a separately trusted monotonic anchor or
   explicitly bounded recovery policy.
5. Independently measure invalid-signature CPU amplification, key/roster
   memory, propagation, packet caps, source lockfile tests and end-to-end
   real-owner behavior. Maintain the separately unqualified W1/FRI,
   quantum work/DAA and WAN acceptance gates.

No new production claim, consensus profile, fork-choice rule or installed
Hepta owner is changed by this candidate.
