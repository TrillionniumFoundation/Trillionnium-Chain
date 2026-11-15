# CPQ1 full-content commitments, candidate V1

Status: implemented candidate interfaces; production activation and whole-chain
PQ qualification remain false. The base is PR #723 at
`12e510b211110d93d9ead07e02c07a1eecc28ae9`, tree
`a8c9634b9e0d59ccc9fd6a03875eee7fc76c099f`. This increment preserves the existing
CPQ1 descriptor, profile IDs, native work relation, signed legacy formats and
state/release/checkpoint owners. It supplies new versioned content formats and
actual readback interfaces; it does not silently migrate any deployed state.

## 1. Security property and seven distinct hash uses

The claim is deliberately about the encoded bytes that were actually read.
An observation is not current authority, historical provenance, finality,
immutable custody, model compatibility, or a certificate of physical work.

| Use | Required relationship | Decision in this increment | Outstanding qualification |
| --- | --- | --- | --- |
| Locator ID | Find candidate objects | Old 32-byte IDs may remain aliases; never substitute for a complete CCH1 claim | Audit every live owner that still accepts an alias as authority |
| Second preimage | Prevent replacement after content is pinned | Full 64-byte SHA-512 directly over context, length and actual content | Actual hash assumptions, bounded message sizes, targets and lifetime exposure |
| Chosen-pair collision | Prevent two prepared objects sharing one authorization | Same full SHA-512 with distinct version/kind and injective framing | Concrete reduction and aggregate failure budget |
| Merkle binding | Bind actual leaves, their order and tree shape | Existing 32-byte trees are unchanged; full-state CST1 is a separately recomputed candidate commitment | New 64-byte leaf/internal/empty-root formats, tree-size/index/role binding and exact proofs before tree migration |
| Fiat–Shamir | Bind complete statement and challenge generation | CCH1 is not a Fiat–Shamir suite and is never used as a replacement transcript | Concrete backend, field/FRI, shared oracle/permutation model, extraction, recursion and QROM reduction |
| PoN work threshold | Bind a candidate to an exact work relation/target | Original PNW1 SHA-256 challenge/ticket relation remains separately selected | Cheapest legal strategy, quantum search/DAA/fork rules and actual resource costs |
| KDF/key derivation | Extract and expand secret entropy with context | CCH1 is a public content hash, never a KDF; any new derivation needs an explicit HKDF-HMAC-SHA-512 or separately specified analyzed suite | IKM/salt/info contract, entropy, key lifecycle and actual caller coverage |

This is an implementation decision for these candidate interfaces, not a claim
that NIST mandates SHA-512 everywhere. No hash output width by itself proves a
whole protocol's quantum security.

### Query estimates are not system security bits

For a sufficiently large-domain ideal random function with an n-bit output,
generic single-target quantum preimage search has square-root query scaling;
generic collision finding has cube-root scaling. At constant success
probability these suggest the following exponents:

| Output bits | Preimage query exponent | Collision query exponent |
| ---: | ---: | ---: |
| 256 | 128 | 85.33... |
| 384 | 192 | 128 |
| 512 | 256 | 170.66... |

The original BHT result concerns r-to-one functions; Zhandry explicitly treats
random functions. These are idealized generic query estimates, not concrete
SHA-512 proofs, physical operation/energy costs, or lifetime success bounds.
Multiple targets, preprocessing, failed attempts, recursive proof uses and
reduction losses require a separate system budget. Quantum memory, coherent
evaluation and time-space restrictions cannot be omitted when discussing cost.
Long-message second-preimage subtleties also prevent a universal claim based
only on output width. See the primary references below.

## 2. Why wrapping a legacy digest is insufficient

For any pair with `SHA256(m0) == SHA256(m1)`, necessarily
`SHA512(SHA256(m0)) == SHA512(SHA256(m1))`. The outer hash cannot recover the
distinction the inner hash discarded. This argument does not assert that a
practical SHA-256 collision has been found.

The same bottleneck occurs when a new hash covers a manifest whose only
payload/dependency references are old short hashes. A strong commitment to that
manifest protects its literal bytes; it does not strengthen the referenced
objects. The new adapters therefore read actual state rows, file bytes, model
payloads, dependency contents and checkpoint/public-key material. Old references
that remain in a format are explicitly identified as literal aliases.

No length heuristic can distinguish a genuine 32-byte payload from a supplied
32-byte digest. The core accepts both as bytes. Typed subsystem adapters and
independently fixed expected commitments supply the object meaning. A claim
carried alongside an untrusted download is not an independent expectation.

## 3. Exact CCH1 encoding and hashing

Implementation: [content_commitment.rs](../../trillionnium/crates/trnm-protocol/src/content_commitment.rs).
All integers are unsigned big-endian. The record is exactly 213 bytes; every
other length, unknown kind, non-CCH1 magic, zero profile ID and zero instance is
rejected. No suffix, optional algorithm negotiation or normalization is accepted.

| Field | Bytes | Meaning |
| --- | ---: | --- |
| Magic | 4 | `CCH1` |
| Profile ID | 64 | Complete existing CPQ1 configuration ID |
| Content kind | 1 | 1 state, 2 release artifact, 3 model manifest, 4 model payload, 5 migration checkpoint |
| Instance | 64 | Independently selected application/object context |
| Generation | 8 | Owner generation, also compared with the signed CPQ1 envelope |
| Encoded content length | 8 | Exact byte length of this format's complete content |
| Digest | 64 | Full SHA-512 result |

The first 149 bytes form `header`. The digest is exactly:

```text
SHA512("TRNM/CPQ1/FullContent/SHA512/v1\0" || header || actual_encoded_content)
```

The context includes network/parameters/genesis through the existing profile
ID, plus the independently chosen instance and generation. It does not upgrade
external objects referenced by old identity fields in that profile descriptor.
The existing descriptor and `HashPurpose::ALL` are unchanged, avoiding an
accidental rewrite of historical profile IDs.

`ContentClaimV1` is a decoded declaration. `ObservedContentV1` has no public
constructor or deserializer and is returned only after a complete exact read.
Decoded contexts may contain arbitrary untrusted profile labels; hashing always
uses the fixed SHA-512 suite and does not select a verifier from that label.
The signature join independently requires the pinned candidate profile ID.

### Read termination and accounting

`observe_reader` uses an 8 KiB buffer. It consumes exactly the declared number
of bytes and then requires EOF. Short input, excess input, any I/O error
(including Interrupted/cancellation) or arithmetic overflow returns no complete
observation. An empty payload is representable; typed adapters impose their own
meaningful size restrictions.

One caller-owned `ContentReadBudget` reserves each declared length plus one EOF
probe before reading. Failures do not refund reservations; exceeding either
cumulative read or byte limit exhausts the budget. It is a logical read budget,
not a wall-clock deadline, CPU limit or measurement of RSS. The owner remains
responsible for cancellation, bounded admission, lifetime charging and immutable
object custody. State/configuration encoding has separate explicit bounds.

## 4. Actual subsystem adapters and exact scope

### State: CST1 and SCF1

[M06 adapter](../../trillionnium/crates/trnm-mvcc-fee/src/content_commitment_v1.rs)
encodes every sorted State row and complete supported Config material. It does
not call the old state-root function to produce the new content commitment.
SCF1 includes the four existing identity literals, every evaluator, all fees,
complete params and complete model registry. CST1 includes SCF1 and every key
and canonical JSON value, including zero/empty and unfamiliar rows.

Config is exhaustively destructured, so future fields cannot silently disappear
from this format. Opaque PQ-policy/task-window configurations are explicitly
refused until their complete encoding is specified. Integer/ASCII JSON, depth,
row count, key/value and configuration byte bounds are candidate format rules.
Two immutable-borrowed passes determine length and stream rows while retaining
only configuration and one row. This is not a consensus-root replacement or a
proof that the supplied state arose from valid execution.

### Release: RAC1

[M15 adapter](../../trillionnium/crates/trnm-release-bundle/src/content_v1.rs)
hashes RAC1, the complete artifact entry and the raw file bytes in one framed
stream. The old artifact SHA-256 is checked for compatibility, but does not
stand in for those bytes. Logical name, media type, executable flag, declared
size and old platform/source-path labels are all included directly.

The Unix retained-file variant checks a regular descriptor at offset zero and
its before/after identity, size and timestamps. This detects observed changes;
it does not assert an atomic snapshot against a privileged writer. Full SBOM,
build inputs, external platform/source objects, root roles and checkpoint-chain
migration remain separate obligations. Existing M15 authorization is unchanged.

### Models: TCM2 and TCC2

[M09 adapter](../../trillionnium/crates/trnm-data-availability/src/cell/content_v2.rs)
defines TCM2: complete family/legacy metadata plus a full ModelPayload CCH1
claim. A separately pinned ModelManifest claim protects its complete encoding.
Payload readback recomputes both manifest and actual whole-payload commitments.
The five old dependency aliases alone convey no dependency authority.

The separate TCC2 direct-dependency closure adds fixed base/parent/tokenizer/layout/runtime roles
and their complete content claims. Closure readback requires actual payload
and all five dependency readers, uses a shared budget, and returns a distinct
opaque result only when every full-content check succeeds. Role tags and order
are committed; omitted dependencies cannot be replaced by old locators. This
establishes byte binding for those five declared objects, not the completeness
of their transitive dependencies, model compatibility, quality or FinalUse.

### Migration: CMG1

CMG1 contains the old checkpoint locator, genesis, complete Header encoding,
trace, sorted unique precommitted source accounts, actual full SPKIs and key
generations, followed by complete CST1 state/configuration. The legacy locator
is checked against the actual header, but the new hash reads the full materials.
Distinct states with an identical old root/locator therefore yield distinct
new content commitments in the deterministic regression fixtures.

Source finality, state-root consistency, historical ownership, registry timing,
source retirement and independently current custody remain original-owner
checks. Embedded ancestry hashes remain literal references; this adapter does
not reconstruct or strengthen all historical ancestors. Missing actual source
content must not be promoted by hashing an old anchor ID.

## 5. Signature join and migration authorization

[verify_candidate_content](../../trillionnium/crates/trnm-crypto-primitives/src/pq_content_auth.rs)
requires a complete CCH1 record as the CPQ1 payload, checks it against the actual
content observation, and compares profile, generation and permitted purpose.
StateSnapshot maps to Recovery, MigrationCheckpoint to Migration, and release/
model content to Release. CURRENT/FinalUse are not granted by this interface.
Wrong joins consume the original cumulative signature reservation; malformed
content cannot reset the owner budget.

The original verifier checks real ML-DSA-65 or ML-DSA-87 with independently
pinned keys, complete signer set, envelope and profile. A valid signature over
only a 64-byte digest still fails the new complete-record interface. Tests also
sign complete claims carrying foreign/legacy profile labels with genuine keys:
generic signature verification succeeds, but the content join rejects them.

Actual adoption must additionally use independently authenticated current owner
state, signer roles/quorum, epochs/nonces, exact action/target, expiry/revocation
and a non-rewinding recovery frontier. Rehashing authenticates no lost history.
If only obsolete signatures/short anchors remain, a new independent migration
authorization is required; the new digest cannot establish the old provenance.

## 6. Verification and remaining gates

The [TCG3/CMH2 continuation](CONTENT_GRAPH_AND_HISTORY_READBACK_V1.md) adds a
separate typed declared graph traversal and a bounded genesis-to-checkpoint
full-State ancestry observation, including a read-only native Node caller.
All CCH1/TCM2/TCC2/CST1/CMG1 encodings above remain byte-compatible. The new
interfaces do not turn the older direct-content results into stronger readback
types, discover unknown loader dependencies, or restore old historical authority.

The five Python framing vectors are independent of Rust and are also consumed
by native Rust tests. Synthetic vector profile IDs test encoding only and are
not selectable profiles. Native tests cover exact byte framing, every context
byte, truncation/tails/EOF errors, shared budget exhaustion, old-digest wrapping,
all adapters, actual ML-DSA signatures and profile/role/generation separation.

```bash
bash scripts/project-preflight.sh
python3 scripts/ci/check_content_commitment_vectors.py
cargo +1.95.0 test --locked --manifest-path trillionnium/Cargo.toml \
  -p trnm-protocol -p trnm-crypto-primitives -p trnm-data-availability \
  -p trnm-mvcc-fee -p trnm-release-bundle --lib
cargo +1.95.0 test --locked --manifest-path trillionnium/Cargo.toml \
  -p trnm-protocol -p trnm-crypto-primitives -p trnm-data-availability \
  -p trnm-mvcc-fee -p trnm-release-bundle --doc
```

Run the original locked graph, formatting, strict affected-package all-target/
all-feature Clippy, source-integrity negative controls and repository checks on
the frozen source. Actual results and failures belong in the evidence receipt;
the existence of this document or a workflow is not a passing execution.

Production owner wiring, complete live migration, 64-byte Merkle proof support,
all external dependency/build closures, opaque state configuration coverage,
KDF caller adoption, FS/QROM instantiation, lifetime quantum bounds and PoN
physical-cost/fork qualification remain separate open gates. HOLD / NO-GO,
no production activation, and no whole-chain PQ qualification are preserved.

## Primary references

- [Grover, quantum search](https://arxiv.org/abs/quant-ph/9605043).
- [Brassard–Høyer–Tapp, quantum collision algorithm](https://arxiv.org/abs/quant-ph/9705002).
- [Zhandry, random-function collision query bounds](https://arxiv.org/html/1312.1027v3).
- [NIST hash policy](https://csrc.nist.gov/Projects/Hash-Functions/NIST-Policy-on-Hash-Functions)
  and [PQC FAQ](https://csrc.nist.gov/Projects/post-quantum-cryptography/faqs).
- [RFC 9162, Merkle tree role/shape principles](https://www.rfc-editor.org/rfc/rfc9162.html#section-2.1.1).
- [RFC 5869, HKDF](https://www.rfc-editor.org/rfc/rfc5869.html).
- [CFRG Fiat–Shamir draft](https://datatracker.ietf.org/doc/draft-irtf-cfrg-fiat-shamir/):
  revision 04, 2026-11-02; an Internet-Draft, not a final standard.
- [Chiesa–Di–Hu–Zheng, post-quantum succinct reductions](https://eprint.iacr.org/2025/2166):
  project-specific state-restoration and commitment extraction obligations remain.
