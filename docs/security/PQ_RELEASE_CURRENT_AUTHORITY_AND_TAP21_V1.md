# Current Cell authority and the TAP 21 ML-DSA-65 adapter

Status: component implementation and local verification; **HOLD_NO_GO** for a
complete updater, deployment, or autonomous activation. The base is Chain
`5a5ddbd4577207af7f7771a4a50c76620f32940f` (PR #698). This work closes a cached
publisher-observation gap and adds an interoperable signature construction using
the existing RustCrypto acceptance path. It does not install new roots, select a
Cell, authorize FinalUse, or change PoN fork choice.

## Cached observations require current authority

`VerifiedCellPqReleaseV2::release_at` previously accepted only a time value. Its
initial verification could remain cached after a key retirement or an approved
release-sequence change. The accessor now requires a
`CellPqReleaseExpectationV2` supplied by the current authority owner. It checks:

- strict current SPKI encoding and key-id correspondence;
- current key not-before, expiry and revocation time;
- the original network, parameter profile, signer key id, key generation and
  release sequence against the current view;
- the original verification interval and authorization expiry, even if a later
  key policy extends its own expiry.

The verified object's fields remain private, and the old time-only API is a
compile-fail example. The actual `trnm-cell` acquisition caller was migrated.
That CLI pins its public policy for one command and limits acquisition by a
monotonic deadline. It is not a live authority service or an activation path.

The negative tests cover a cached proof after retirement, rotation, sequence
advance, scope change, invalid current SPKI and lifetime change. A separate test
selects the same old content at a new approved sequence: the old authorization
and cached proof fail, while a newly signed authorization for that sequence
passes. The content digest can be unchanged; the authorization sequence cannot.

**Freshness is an owner integration requirement.** Reusing a copied old
expectation can still reproduce an old view. This API does not create the durable
monotonic sequence owner, serialize activation with retirement, or make a local
backup resistant to complete-state rollback. An activation service must fetch
its current view at its atomic commit boundary and bind the selected pointer,
retirement/revocation frontier and sequence to independently fresh persistent
state. That work cannot be inferred from successful acquisition verification.

## Exact TAP 21 construction, bounded project profile

[TAP 21 v1](https://github.com/theupdateframework/taps/blob/master/tap21.md) is
Accepted, last modified 2026-09-30. It signs these exact bytes with pure ML-DSA
and an empty context:

```text
ASCII("tuf") || 0x01 || SHA512(OLPC-canonical-JSON(signed_metadata))
```

`trnm_crypto_primitives::pq_auth::tuf` implements this construction for the
existing ML-DSA-65 verifier and signer. The trusted scheme must be exactly
`ml-dsa-65/1`. Unknown versions, leading zeroes, different parameter sets and
alternate spellings fail. The scheme comes from trusted TUF metadata; the
signature cannot choose it. The adapter reconstructs canonical bytes from the
parsed `signed` value and computes its own hash. It never accepts an external
prehash, prefix or algorithm fallback.

OLPC canonicalization sorts object keys, emits no formatting whitespace, and
escapes only quotation marks and backslashes. Parsed control characters and
UTF-8 are retained according to that canonical format. This is deliberately not
ordinary `serde_json::to_vec` serialization. Resource limits are 1 MiB canonical
output, depth 64 and 65,536 values; this profile accepts only i64/u64 integers and
rejects floating-point values. The higher-level parser must reject duplicate
JSON fields before constructing `Value`.

**This is not full TAP 21 or TUF-client conformance.** TAP 21 v1 requires support
for ML-DSA-44, ML-DSA-65 and ML-DSA-87. This project's installed primitive supports
65, so 44 and 87 are rejected, not treated as 65. The adapter consumes a strict
pinned DER SPKI after the existing key parser; it does not implement the TUF
JSON key container, PEM conversion, TUF key-id calculation, threshold roles,
root rotation, expiry/freeze checks, snapshot/timestamp checks, delegated target
scope or persistent rollback protection. `VerifiedTufMetadataV1` is a signature
observation and carries no root, release or FinalUse authority.

## Independent public fixture and repeatability

`tests/fixtures/pq/tuf_tap21_mldsa65_v1.json` contains Unicode, quotation marks,
backslashes, control characters, booleans, null and integer metadata. Its
canonical representation was produced by the real
[securesystemslib v1.5.0 encoder](https://github.com/secure-systems-lab/securesystemslib/blob/v1.5.0/securesystemslib/formats.py),
not a Python copy of the Rust implementation. Its ML-DSA-65 signatures were
created through cryptography 50.0.2 using OpenSSL 4.0.3. The deliberately public
test seed is 32 bytes of `0xb1`; no production key or stored private-key export is
involved. The fixture contains a correct empty-context signature and a signature
with the wrong context `b"tuf"`. The audit first verifies that signature in its
actual context before requiring rejection with an empty context.

Pinned upstream Git blob ids:

| securesystemslib v1.5.0 file | Git blob SHA-1 |
| --- | --- |
| `securesystemslib/__init__.py` | `31edbbe96f4cffefcba008e577967f7e16412893` |
| `securesystemslib/exceptions.py` | `bce02977f32ed3882a4e930d4def6f1376d4165d` |
| `securesystemslib/formats.py` | `447bef28a8797cb3687707fd0f9ddec447e0d204` |

The fixture has 318 canonical bytes and a 68-byte pre-signing message. Its file
SHA-256 is `d56d1c460e0372e262fe4d0cfc4b255b9dc325eda93e512638bedbd3e18deef2`.
The audit/recreation helper checks those source pins and executes the checked
bytes directly, without using a stale module/bytecode cache or rereading the
source after hashing. It independently recomputes
canonical bytes/SPKI/key id, verifies both context cases, and optionally writes
a newly signed fixture to a new file. OpenSSL signing is randomized, so a
recreated signature need not be byte-identical. Run from repository root with
a local checkout of the pinned SDK and a cryptography installation that exposes
ML-DSA:

```bash
python3 trillionnium/crates/trnm-crypto-primitives/tests/tuf_tap21_fixture.py \
  --sslib-source /absolute/path/to/securesystemslib-v1.5.0
cargo test --locked --manifest-path trillionnium/Cargo.toml \
  -p trnm-crypto-primitives --test tuf_tap21
cargo test --locked --manifest-path trillionnium/Cargo.toml \
  -p trnm-data-availability cell::pq
cargo test --locked --manifest-path trillionnium/Cargo.toml \
  -p trnm-data-availability --doc
cargo test --locked --manifest-path trillionnium/Cargo.toml \
  -p trnm-data-availability --test pq_cell_cli
```

The Rust suite checks independent verification, signing of the independently
encoded message, mutation of signed role/version/expiry/targets, unsupported
schemes, wrong contexts and prefixes, raw-metadata/raw-digest fallback denial,
integer/encoding limits, malformed signatures and incorrect key pins. A fixture
pass does not establish complete SDK interoperability or production custody.

## Authority roles and key assets still requiring deployment closure

The release architecture must keep these authorities distinct. A Cell candidate
can propose content and metadata; it cannot supply the trusted root or promote
its own signature observation into any of these authority roles.

| Authority or asset | Existing repository surface | Required owner/deployment boundary |
| --- | --- | --- |
| Offline update root and recovery root | New TAP 21 adapter; M15 `trnm-release-bundle` candidate build/SBOM/provenance contract | Provision offline threshold roots, authorize each root transition with old/new policies, retain versions outside restorable target state; this adapter does not provision them |
| Node software and protocol configuration targets | M15 build/provenance contract | Separate delegated scopes, authenticated target hashes and versions, current expiry and rollback checks before installation |
| Cell manifest publisher | `CellPqReleaseAuthorizationV2`, current `CellPqReleaseExpectationV2`, `trnm-cell` | Independent host pin and current publisher sequence; content verification never establishes model quality or execution permission |
| Cell evaluation and activation | Existing acquisition/release declarations and separate runtime/FinalUse owners | Separate evaluation approval and activation metadata; activation sequence advances even when selecting historical content; serialize selection and revocation against fresh durable authority |
| ML-DSA signing seed and expanded key | `PqNativeSigningKey::from_owned_seed`, zeroizing memory, CLI seed-file adapter | Qualified entropy/provisioning, inventory owner and role, protected generation/backup/restore, device/HSM interface and retirement controls; memory zeroization is not a custody or side-channel proof |
| Public identity roster | Strict SPKI/key-id parser and `CellPqKeyPinsV2` | Versioned authenticated distribution, independent rotation authority and persistent retired-key history; public roster data must not introduce signing secrets |
| Transport exchange and identity keys | Existing PQ/native peer research and canonical identity verifier | Explicit standard group negotiation plus PQ identity authentication, downgrade rejection and key rotation; no direct TLS-to-chain permission mapping |
| Witness checkpoint/recovery keys | Independent witness/effect-consumption owners | Separate failure domain, current append history and keys, atomic expected-old checkpoint advancement; witness signatures do not create business permission |

Backups must preserve the distinction between recoverable content/ledger state
and non-forgettable retirement, activation and effect-consumption history. If
all authorities and witnesses can be restored to one old snapshot, no local
signature algorithm can prove the missing future history. An unavailable fresh
owner or witness can therefore block new relevant activation/effects; acceptance
must include that availability cost.

## Transport implementation and observed local validation

`formal/pon-nakamoto-v1/pq_mtls_probe.c` is an executable loopback research
probe. It requires TLS 1.3, the negotiated `X25519MLKEM768` group, a valid mutually
authenticated certificate chain, an ML-DSA-65 peer key and an independently pinned
public-key digest before application traffic. Its TLS exporter binds network,
genesis and profile to a session tag. The other RFC 10024 groups are not enabled
by this probe's accepted profile. A new negative test supplies a valid, trusted
Ed25519 client identity and the accepted hybrid group: the peer is still refused
with `peer_not_mldsa65`. Hybrid key exchange alone does not pass the identity gate.

The installed `trnm-pon-node/src/ingress/public_v3.rs` path uses `TcpStream` and
`TcpListener` directly. Its `pq_identity.rs` layer verifies pinned ML-DSA history
messages, but the path does not wrap these sockets in TLS or enforce an RFC 10024
negotiated group. Probe results therefore establish neither deployed transport
confidentiality nor a TLS-derived chain capability. Connecting a qualified TLS
transport to that path and qualifying rotation/recovery remain deployment work.

Local Linux x86_64 validation on the stated PR #698 base passed the eight TAP 21
integration tests (also with `serde_json/arbitrary_precision` enabled), the full
193-test data-availability all-target/all-feature package run, all nine
compile-fail documentation tests and scoped all-target/all-feature Clippy with
warnings denied. The SDK fixture audit passed, including positive verification
of the alternate signature with context `b"tuf"` before its empty-context
rejection. Six selected real TLS/mTLS tests passed against the pinned OpenSSL
3.5.9 provider: positive session/exporter binding, wrong key pin, classical-only
group refusal, cross-session signed-hello replay refusal and the classical peer
identity negative. The fixture's independent signature generator used OpenSSL
4.0.3 through cryptography; it is distinct from that TLS provider. These are
local component results, not a full TUF conformance, CI, ARM, or deployment claim.

## Current external standards boundaries

- [RFC 10024](https://www.rfc-editor.org/rfc/rfc10024.html), Standards Track,
  August 2026, defines X25519MLKEM768, SecP256r1MLKEM768 and
  SecP384r1MLKEM1024. This specifies hybrid key exchange. Peer identity
  authentication and application authority are separate. This patch does not
  install or qualify a TLS stack or negotiate these groups.
- [C2SP tlog-witness](https://github.com/C2SP/C2SP/blob/main/tlog-witness.md)
  provides an append-consistency/checkpoint design reference. A counter
  signature alone does not show that old consumption records were retained.
  TUF signature construction does not itself supply a witness or fresh storage.
- [mldsa-native v2.0.0](https://github.com/pq-code-package/mldsa-native/releases/tag/v2.0.0)
  is an independently implemented FIPS 204 testing source. Its C/native proofs
  and tests cover their stated implementations and properties, not this chain,
  TUF policy, the operating system, key custody or external exactly-once effects.
  The separate differential harness records its own pinned source and observed
  architecture; this document does not widen those results.
