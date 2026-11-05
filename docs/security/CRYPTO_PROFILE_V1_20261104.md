# Cryptographic configuration v1 — explicit scope, candidate parameters, no activation

Status: **Draft / HOLD**. The original profile implementation was developed on
`5a5ddbd4577207af7f7771a4a50c76620f32940f` and recorded at `ad081dac` in PR #698.
The original `885b6e82` delivery composed that implementation with branch head
`04be4748e653a30fae2d66275b4bed83e6eabb8b`, preserving its `7eba9107` integration
and separate fuzz-lock repair. Later increments retain that history and add the
trusted retirement API described below. The [evidence index](../../evidence/crypto-profile-20261104/README.md)
attributes each execution to its exact source; earlier results do not validate
later changes. This profile work does not activate a network, migrate deployed
keys, change PoN work, or qualify whole-chain PQ.
The [sole development plan](../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md)
owns the remaining engineering order. The original
[six-domain claim guard](WHOLE_CHAIN_PQ_CLAIM_GUARD_20261031.md) remains binding.

## Security target before parameter selection

The target is an authenticated, downgrade-resistant effect path under an active
network/storage adversary, including a future adversary able to forge classical
public-key signatures. Every authorization root must be explicitly provisioned,
and every current effect must recheck the owner's current profile, role, key
generation, revocation, nonce, resource reservation and FinalUse conditions.
Signature mathematics alone does not establish any of those permissions.

| Obligation | Required property | This increment |
| --- | --- | --- |
| Transaction/account/task | Current trusted state selects the suite and namespace; old nonce floors and liabilities survive migration/reorg | Existing NPQ2–NPQ6 owner gains an explicit configuration ID; migration qualification remains open |
| Peer transport | Pinned roster, network/genesis, current lifetime, replay ledger and cumulative resource bounds | Existing PNQ2 bytes retained; fixed descriptor mapping and separate retained/live types |
| Governance and software release | Independently pinned PQ roots, review/threshold policy, immutable release closure and revocation | Candidate domains are specified; deployed authorizers are not implemented by this registry |
| CURRENT and FinalUse | Last-use recheck, consumed-use identity, scope/generation and external monotonic frontier | Candidate message contexts only; no production capability is returned |
| Recovery | All effect-bearing state related to independently administered monotonic state; ambiguous CAS reconciled | Existing three-table witness scope unchanged; whole-effect recovery remains open |
| Work and chain selection | Precisely fixed relation, hash/transcript obligations, cheapest legal classical/quantum cost and invalid-work budget | Original PNW1 is referenced unchanged; independent qualification remains open |

The conservative candidate uses ML-DSA-87 and 512-bit collision commitments.
This is a **parameter experiment**, not an assertion of a uniform system security
bit count. The complete system is limited by its weakest relevant authorization,
hash, proof, recovery or work assumption. Confidentiality and key establishment
are separate requirements; signed PNQ2 plaintext does not provide them.

## One complete identifier, selected outside the message

The implementation is
[`crypto_profile.rs`](../../trillionnium/crates/trnm-protocol/src/crypto_profile.rs).
`CryptoProfile` is an internal registry selector, not an on-wire authority.
`bind(ProfileBinding)` creates a `BoundCryptoProfile`; its `crypto_profile_id` is
SHA-512 over a framed, versioned canonical configuration. The 64-byte ID has one
128-character lowercase-hex display representation. Whitespace, uppercase,
truncation, invalid digits and alternate encodings are rejected.

The committed configuration includes:

- Exact algorithm/parameter set, public-key and signature lengths, Pure mode and
  empty FIPS context. HashML-DSA, raw/internal-mu and alternate algorithms have no
  verification fallback. Deterministic and hedged signatures use the same
  verifier; signature bytes cannot certify a signer's random-number source.
- Key/signature/message encoding and the owner namespace. Legacy SPKI is the
  exact existing DER/OID with no optional parameters. New CPQ1 carries raw FIPS
  public keys and signatures, fixed field order, big-endian lengths and no tail.
- Network, parameters, genesis, protocol version, scope, activation height and
  an optional exclusive retirement height. No unspecified network or sentinel
  retirement value can alias another configuration.
- Distinct account, migration, task, operator, peer, governance, release,
  CURRENT, FinalUse and recovery purposes. Candidate signatures bind their
  purpose, complete signer set, owner generation, key epoch, sequence and
  validity interval.
- Separate hash-use entries, output lengths, byte/attempt limits, and the exact
  external work-configuration digest. Unintegrated legacy uses are explicitly
  marked `NotIntegrated` and are not upgraded by an algorithm label.

`CryptoProfilePolicy::from_trusted_state` must receive authenticated state from
the real owner; it does not authenticate its constructor arguments. Incoming
IDs are compared with that selection. They cannot negotiate a different suite.
This existing API uses retirement heights declared in the immutable descriptor
and continues to refuse open-ended historical descriptors.

For a later retirement of an originally open-ended current profile, the owner
registers its unchanged descriptor with `RetiredCryptoProfile::from_trusted_state`
and supplies that record to `from_trusted_state_with_retirements`. The trusted
effective end is exclusive, strictly after activation, no later than any
predeclared end and no later than the current profile's activation. It is owner
state, not a new field in the descriptor or historical message. The original
configuration bytes and ID remain unchanged; rebinding the old descriptor with
a newly declared end would produce a different ID and is not substituted here.
Both policy paths share the same bounded-history, duplicate, network/genesis,
scope and nonoverlapping effective-window checks. Authentication, persistence
and migration of the retirement schedule remain the real owner's obligations.

`select_current` refuses an inactive selection and **both candidate profiles**.
`select_historical` checks the registered interval and that the supplied record
height is no later than the policy height. It does not authenticate that a record
was accepted; the owner must establish that separately. Its result is a different
type and cannot be passed to `recheck_current`. The latter checks the latest
configuration and state generation; application roles, nonce, funds and final-use
checks remain mandatory at the effect owner.

There is no current-87 activation API. A future activation requires the actual
governance/state transition, migration/recovery and capacity evidence. Editing
a received ID or treating a mathematical observation as a capability cannot
supply that transition.

## Preserve the exact legacy namespace

The current ML-DSA-65 baseline remains unchanged. The following are explicit
read-only mappings of already pinned owner configurations:

| Owner | Binding | Existing limits retained |
| --- | --- | --- |
| `pq_accounts_v2::crypto_profile_id(cfg)` | Runs `policy(cfg)` first; binds the validated network, parameters, genesis and NPQ version 2…6 | NPQ2…5: 9,432-byte envelope / 256 transactions / 512 verifications; NPQ6: 16,384-byte envelope / 64 transactions / 64 verifications; aggregate transaction bytes 524,288 |
| `PqNetworkPolicy::crypto_profile_id()` | Settings select NativePeer/version 2 at fresh genesis; incoming data cannot replace it | 2 MiB wire; 64 connections; 32 MiB ingress bytes; 64 verification attempts; 4,096 records / 16 MiB ledger; original lifetime and CPU policy |

The PNQ2 `PolicyRecord`, canonical JSON, existing policy digest, SQL namespace,
request/response domains, TPQ1 frame, and stored bytes are not rewritten.
Legacy wire versions implicitly select the original fixed suite; no profile
field is inserted into historical signatures. `require_profile_claim` compares
an external declaration to this owner-selected ID, and rejects candidate IDs.
This mapping is not a completed CPQ1 migration of the legacy runtime.

The descriptor reads the exact TPQ1 domains, DER prefix, purpose range and
lengths from the existing parser, the actual NPQ prefix/domain/role tables and
transaction/verifier limits, and the shared PNQ2 domains/directions/response
schema/roster/transport/byte/record/lifetime limits used by the real Node owner.
It does not replace those values with a prose label or a second numeric copy.
The legacy Operator mapping is explicitly refused until its different complete
message grammar and all compound resource limits have a precise registration;
the existing operator implementation is unaffected by that refusal.

`verify_retained_request` now produces a `RetainedRequest` containing only
peer/sequence/expiry/operation facts. It carries no live request body or wire,
and no `Into`, `From` or `Deref` conversion to `VerifiedRequest`. Shared private
authentication does not itself construct a live request. Only the live wrapper
produces the private-field `VerifiedRequest` accepted by admission. Retained
response validation returns `()`, not a live response. Existing pending-expiry
retirement still requires its original transaction, current clock and witness;
the read-only historical facts do not authorize dispatch.

## Candidate CPQ1 authentication and resource accounting

[`pq_candidate.rs`](../../trillionnium/crates/trnm-crypto-primitives/src/pq_candidate.rs)
uses the existing locked RustCrypto `ml-dsa = 0.1.1` dependency for actual
ML-DSA-65 and ML-DSA-87. Owned seeds and expanded signing keys use zeroize-on-drop.
Fixed public benchmark seeds are not provisioning material. The old canonical
ML-DSA-65/OpenSSL differential adapter is unchanged.

[`pq_profile_auth.rs`](../../trillionnium/crates/trnm-crypto-primitives/src/pq_profile_auth.rs)
connects the complete candidate protocol to real signatures. A verifier receives
its bound configuration and entire key set out of band. It derives SHA-512
profile-bound key IDs, sorts the complete signer set and rejects duplicates.
The actual signed message includes the full payload and complete signer set;
there is no application prehash substitution. The same canonical message is
signed by every required key. A carried key cannot replace a pinned key.

CPQ1 wire is `magic || BE32(message_len) || signed_message || key/signature
records`. Each record contains `BE32(key_len) || raw_key || BE32(signature_len)
|| signature`. `check_candidate_wire` compares the exact expected message,
fixed lengths and pinned keys, and rejects extra bytes. Its intermediate result
is explicitly unverified. Only subsequent real signature checks produce a
`CandidateSignatureObservation`, which is still not current authorization.

Candidate bounds are deterministic: signed message at most 65,536 bytes;
complete wire at most 131,072 bytes; at most eight distinct signers; 64 total
verification reservations and 8,388,608 charged bytes in one owner batch.
Reservation precedes parsing, hashing and verification. Failures are retained,
sub-signatures cannot reset the aggregate budget, and overflow exhausts it.
These are bounded research limits, not measurements justifying a production
cap increase. Wall-clock/CPU deadlines remain separate node admission policies
and are not consensus validity predicates.

## Hash uses and the W1 boundary

| Use | Legacy mapping | Candidate experiment |
| --- | --- | --- |
| Configuration identity | New descriptor only | SHA-512 / 64 bytes |
| Legacy PQ key ID | Original SHA-256 / 32 bytes | Profile- and purpose-bound SHA-512 / 64 bytes |
| TPQ1 payload | Original SHA-384 / 48 bytes | Full canonical candidate message is signed; optional candidate payload commitment is SHA-512 |
| State/release/proof commitment, address, Merkle node, proof transcript | Not certified by the legacy descriptor | Distinct purpose tags and SHA-512 / 64 bytes; adoption by each actual subsystem remains open |
| Work challenge and ticket | Original PNW1 SHA-256 relation | **ExternalNativeWork**; generic candidate commitment API rejects these uses |

`native_work_configuration_digest` binds the exact existing
[`work-profile-v1.json`](../../config/pon/work-profile-v1.json) bytes under its
own SHA-512 namespace. It is a reference identity, not a replacement for the
work hash. `pon_work.rs`, `pon_wire.rs`, challenge, ticket, full transcript,
proof bytes, target interpretation and difficulty are unchanged. Any future
change to those relations needs a new work configuration and renewed cheapest
legal-work, invalid-verification and quantum/fork-choice analysis.

## Parameter comparison and reproducible observations

| Parameter | Relative NIST category | Raw public key | Signature |
| --- | --- | ---: | ---: |
| ML-DSA-65 | 3 | 1,952 bytes | 3,309 bytes |
| ML-DSA-87 | 5 | 2,592 bytes | 4,627 bytes |

These values are from [FIPS 204](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf),
Tables 1–2. The [official publication page](https://csrc.nist.gov/pubs/fips/204/final)
lists potential errata; this increment does not claim a complete independent
conformance or side-channel audit. Pure mode/context and HashML-DSA are different
interfaces. Algorithm labels do not reveal whether an application supplied a
short digest instead of its intended message; the CPQ1 layer therefore binds the
entire canonical message itself.

[NIST IR 8547 final, October 2026](https://nvlpubs.nist.gov/nistpubs/ir/2026/NIST.IR.8547.pdf)
distinguishes collision and preimage categories by use. A 256-bit hash's preimage
classification cannot qualify a collision-based release or state commitment.
NIST categories are relative attack benchmarks, not whole-chain quantum bits.
SHAKE256 would also need an explicit output length and a separate implemented
profile; this increment implements SHA-512 for the candidate commitment API.

Run the current pinned, locked dependency graph and component controls. The
composition inherits the Linux `sha2/asm` backend and `sha2-asm = 0.6.4`, plus
`serde_json` as a normal crypto-primitives dependency, from the later integration.
The original `ad081dac` observations retain their original graph and binary
identity; they do not certify this combined source or its performance:

```bash
bash scripts/project-preflight.sh
cargo test --locked --manifest-path trillionnium/Cargo.toml -p trnm-protocol -p trnm-crypto-primitives --lib
cargo test --locked --manifest-path trillionnium/Cargo.toml -p trnm-protocol --doc
cargo test --locked --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --all-features --lib ingress::pq_network
cargo clippy --locked --manifest-path trillionnium/Cargo.toml --workspace --all-targets --all-features -- -D warnings
cargo run --locked --release --manifest-path trillionnium/Cargo.toml -p trnm-crypto-primitives --example pq_parameter_bench -- --samples 64
```

The parameter observer uses a separate, explicit `TRNMCPB1` measurement frame.
It reports actual encoded bytes, complete multi-signature frame encode/parse/
verify, key construction, signing including self-verification, valid/late-invalid
verification and early size rejection. It measures fixed local inputs and
pre-expanded verifier reuse; it does not measure CPQ1 effect authorization,
production PNQ2/NPQ6 transactions, network saturation, WAN or independent client
confirmation. Its empirical p99 at 64 samples is the sample maximum and is not
a qualified production tail. Raw samples and incomplete-run failures must be
retained with exact source, binary, dependency/toolchain and host identities.

## Remaining acceptance, not supplied by a descriptor

Before any whole-system claim or 87 activation: migrate every real authorizer
into its independently pinned protocol state; establish governance/release and
cross-repository CURRENT/FinalUse composition; preserve old ownership, nonce,
liabilities and revocation across fork/recovery; extend the independently held
monotonic frontier to every effect-bearing state; complete original-hardware
valid/invalid-input, multisignature, queue/RSS/WAL/WAN and business-confirmation
acceptance; and independently qualify the unchanged or newly versioned W1
proof/work assumptions. All six whole-chain gates remain **UNQUALIFIED**.
