# PCS1 deadline repair and native TPQ1 cryptography

Status: **development component — HOLD_NO_GO — no activation**.

Parent source: PQ research PR #495,
`6f4b9cae0dafcb0e6bc171e2aa9b8f630e74eca6`.
The sole development plan remains unchanged. No fork-choice, chainwork,
transaction limit, account migration, reward, model selection or FinalUse
authority is changed by this component.

## Original defect and repair

The old PCS1 client checked the overall deadline only before an attempt. Its
`recv` loop used a fixed five-second idle timeout. A peer could repeatedly send
a small amount of data before that idle timeout, making the configured overall
deadline ineffective. The executor also waited for still-running futures while
unwinding. The original cryptographic oracle could start a new fifteen-second
process allowance after the network deadline was exhausted.

One `OperationBudget` now carries the original monotonic deadline through peer
key parsing, connect, send, every receive, response verification, OpenSSL child
processes, future waits, readback and publication checks. A new retry never
resets it. On failure the owning fetch cancels the shared budget **before** the
executor waits: registered sockets are shut down and closed, registered crypto
children are killed, and their owning workers reap them before returning.
Only literal `127.0.0.1` is allowed, including direct `_request` use; no DNS
lookup enters this research boundary. The server uses one request budget too.

Real localhost TCP regression tests transmit incomplete frame prefixes and
bodies slowly enough to avoid the original idle timeout. They cannot reach
signature acceptance and contain no fake successful cryptographic verifier.
The parent source fails both 0.3-second deadline assertions after approximately
1.4 seconds. The repaired source also tests shared socket cancellation, actual
child-process timeout and reaping, and two concurrent stalled fetch workers
terminating without a destination or staging file.

This is a bounded resource-control repair, not hard real-time OS qualification.
Python cannot preempt an uninterruptible kernel filesystem operation or promise
scheduling latency. Checks surround local persistence operations. If a deadline
or filesystem error occurs after the exclusive publication link, the immutable
destination is retained for reconciliation; the function does not acknowledge
success or pretend the publication was rolled back. Busy/timeout observations
remain distinct from evidence of cryptographic fraud.

## Actual native ML-DSA component

The explicit `pq-native-openssl` feature in `trnm-crypto-primitives` now exposes
`pq_auth`. It is disabled by default. The Rust implementation uses the safe
`openssl` bindings, pinned to 0.10.81, and actual in-process OpenSSL EVP
ML-DSA-65 signing/verification. No CLI subprocess result is its trust boundary.

`PqNativeVerifier::from_pinned_spki` requires the exact 1974-byte ML-DSA-65 DER
SPKI grammar and an independently supplied key-ID pin. It checks the provider's
name-based algorithm identity and exact DER roundtrip. Every `verify` call first
uses the existing `trnm_protocol::pq_frame` parser for all six purpose domains,
network/context/key, generation/sequence/expiry, canonical length and SHA-384
payload binding, then executes pure ML-DSA-65 one-shot EVP verification.

Only successful EVP verification creates the opaque borrowed
`PqSignatureObservation`. A correctly sized all-zero signature can still pass
the deliberately unverified frame parser, but cannot create that observation.
No observation is a ledger admission, replay consumption, storage contract,
model installation or FinalUse grant. The private-key adapter accepts an
already-owned `PKey<Private>` and performs no implicit key generation, file
loading, export or production HSM custody. Callers remain responsible for
authorizing each signing intent and maintaining durable logical operation IDs.

The five native tests execute real signing and verification for all purposes,
all 176 statement-byte mutations, altered/zero signatures, mismatched context,
payload, key, lifetime and sequence, noncanonical SPKI and Ed25519 downgrade.
They also cross the adapter/direct EVP boundary using the same native TPQ1
frame. This is independent API composition, not an independent implementation
of the ML-DSA mathematical primitive. No successful crypto stub is installed.

## Reproduction and evidence

Requires an OpenSSL 3.5+ ML-DSA provider and the repository's Rust toolchain.
Set the command environment to the actual reviewed OpenSSL installation:

```sh
bash scripts/project-preflight.sh
python3 -m unittest discover -s formal/pon-nakamoto-v1 -p test_pq_cell_swarm_deadline.py -v
python3 -m unittest discover -s formal/pon-nakamoto-v1 -p test_pq_cell_swarm.py -v
cargo test --manifest-path trillionnium/Cargo.toml --locked -p trnm-crypto-primitives --features pq-native-openssl
cargo clippy --manifest-path trillionnium/Cargo.toml --locked -p trnm-crypto-primitives --features pq-native-openssl --all-targets -- -D warnings
python3 scripts/ci/check_pq_research_integration.py
```

Original logs, source hashes, commands, host versions and result scope are in
[the evidence directory](../../evidence/pon-pq-cell-deadline-native-v1/README.md).
The historical corpus receipts retain their original scope; new source pins
identify this refinement and do not retroactively upgrade older test runs.

## Remaining boundaries

- The installed native ledger, miner/account identity and fee/nonce owners have
  not migrated to PQ. The old 2048-byte transaction limit cannot carry a
  3309-byte ML-DSA-65 signature. No default-profile fallback is added.
- This optional native component is not a qualified integrated PQ node,
  quantum-resistant PoN work proof, public transport, independent custody or
  physical anti-rollback mechanism.
- The loopback swarm fixture is not a WAN/DHT or multi-operator acceptance
  test. A complete download does not prove model efficacy, source consent,
  permanent availability or an original Hepta installation/FinalUse receipt.
- Cryptographic validity alone does not make a historical release current or
  override a legitimate higher-work PoN reorganization.

Primary API references: [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final),
[OpenSSL ML-DSA](https://docs.openssl.org/3.5/man7/EVP_SIGNATURE-ML-DSA/),
[Rust OpenSSL safe API](https://docs.rs/openssl/latest/openssl/pkey/struct.PKey.html).
