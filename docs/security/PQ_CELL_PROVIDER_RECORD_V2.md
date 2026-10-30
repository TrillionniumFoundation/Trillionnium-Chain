# PCP2: ML-DSA-65 Cell provider signed-hint boundary (draft)

**Scope:** source-only cryptographic research primitive in
`trillionnium/crates/trnm-crypto-primitives/src/pq_cell_provider.rs`.
**Status:** unintegrated / not PQ network qualification / not public or production.
**Tracking:** [P0 whole-chain PQ gates #562](https://github.com/TrillionniumFoundation/Trillionnium-Chain/issues/562).

## Authority boundary

A provider advertises a *location hint*, never proof of content, custody,
independent replication, license, permission to download, consent, model
release, Hepta install/FinalUse or chainwork. The receiver MUST independently
obtain: (1) the exact six-digest request from its selected Cell/chain authority;
(2) the 1,952-byte ML-DSA-65 verification key from a trusted, persistent roster;
(3) a monotonic per-identity/per-manifest sequence high-water from the
appropriate owner; and (4) current trusted time. Values copied from the peer
advertisement do not establish authorization.

`SignedPqCellProviderRecordV2::from_wire` parses **untrusted data**.
`verify_for_pinned_context` validates the signature *and* expected owner pins.
It returns an inert `VerifiedPqCellProviderHintV2` with an endpoint, sequence
and expiration; it cannot issue release/permission/custody capability.

## Canonical PCP2 encoding

Fixed 3,580 bytes, big-endian integers; exact byte offsets:

| Offset (exclusive end) | Size | Field |
| --- | ---: | --- |
| 0..4 | 4 | magic `PCP2` (never `CDP1`) |
| 4..196 | 192 | namespace, network, parameters, genesis, Cell context, manifest (32 each) |
| 196..228 | 32 | SHA-256(`trnm.cell-provider-mldsa65-key.v2\\0` concatenated with pinned public key) |
| 228..247 | 19 | canonical endpoint family, 16-byte IP region, 2-byte port |
| 247..255 | 8 | signed sequence |
| 255..263 | 8 | issue Unix seconds |
| 263..271 | 8 | expiry Unix seconds |
| 271..3580 | 3,309 | FIPS 204 ML-DSA-65 signature |

The signed message is
`trnm.cell-provider-mldsa65-signature.v2\\0 || wire[0..271]`.
The FIPS 204 ML-DSA context argument is the empty string; the signed message
has an application-specific, fixed purpose prefix. Encoding is intentionally
**not** interoperable with the old 335-byte, Ed25519-signed `CDP1` format.

The unsigned portion is 271 bytes. Eight complete records plus the one-byte
count need 28,641 response bytes, within the existing 32 KiB *response
envelope*. This arithmetic is not a verified networking throughput or CPU
budget: real ML-DSA rejection and mixed valid/invalid loading still require
original-limit measurements.

## Mandatory rejection policy

- Wrong version, length, disabled/empty digest, malformed IP representation,
  zero service port, sequence zero, TTL outside 1..=300 s: reject before crypto.
- A different request, untrusted public key or key identifier, replayed
  sequence, issued time beyond the permitted 5 s skew or expired record:
  reject before signature verification.
- Malformed or wrong-context signature: reject. Never accept classical V1
  signatures as an alternative.
- The Cell transport MUST check the advertised destination against its
  independently configured outbound address policy. A valid signature does
  not prove control of the endpoint.
- Expiry does not reset sequence high-water, identity quotas, or a lost
  externally anchored epoch. Concurrent identities with equal sequence but
  different signed content need explicit equivocation handling.

## Unclosed engineering gates

1. **M09 live wire and directory:** create separately namespaced `PCP2`
   request/response and persisted record owner with fixed resource budgets.
   Existing CDP1 SQLite assumptions (335-byte rows, classic 32-byte owner)
   cannot be reinterpreted as PQ. Unknown, mixed or downgraded wires must fail
   under explicit PQ-only policy.
2. **Owner/roster:** bind public keys to trusted Hepta/Chain Cell provider
   roster/epoch and actual lifecycle, including rotation, revocation,
   reorganization, and independent expiry/high-water retention.
3. **Recovery:** witness a monotonic high-water outside a rollback-capable
   provider database. A self-consistent restored SQLite file remains unsafe.
4. **Acceptance:** native tests on exact SHA and both architectures; complete
   8-provider honest and malicious signed traffic with actual wall/CPU/RSS,
   serialization and total bytes, IP policy, retrieval, loss, repair and
   original deadlines. Report any failed lane and unchanged negative controls.
5. **System-wide PQ:** separate gates for transactions, governance, Hepta
   FinalUse, proof-system security, quantum mining advantage and external
   recovery must still pass. PCP2 by itself cannot change the chain's
   `whole_chain_post_quantum=false` conclusion.

Focused proposed native commands from `trillionnium/`:

```sh
cargo test --locked -p trnm-crypto-primitives pq_cell_provider -- --nocapture
cargo clippy --locked -p trnm-crypto-primitives --all-targets -- -D warnings
cargo fmt --all -- --check
```
