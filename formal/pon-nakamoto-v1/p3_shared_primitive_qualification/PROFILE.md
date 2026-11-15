# Tagged SHA3-512 research profile R1

Status: **HOLD_NO_GO**. This is a new, incompatible experimental profile.
The old Poseidon2 profile, historical observations and production dispatch
remain separate. The complete W1 relation is the existing SHA-256 AIR and
five-lane packed carry AIR. No SHA3 recursive-verifier AIR is added.

## Frozen primitive and parameters

The implementation uses RustCrypto `sha3 = 0.10.9`, the FIPS 202 SHA3-512
interface, with rate 576 bits, capacity 1024 bits and all 512 output bits.
P3 packages are locked to 0.8.0. The field is Goldilocks
`p = 18446744069414584321`; the extension is `F_p[X]/(X^2-7)`.
All application roles share this one concrete primitive. Tags distinguish
inputs; they do not provide independent random oracles.

| Setting | SHA component | Packed arithmetic component |
|---|---:|---:|
| Component number | 1 | 4 |
| Trace log height | 13 | 14 |
| Main columns | 7,728 | 370 |
| Preprocessed columns | 27 | 180 |
| Quotient chunks | 2 | 1 |
| Trace next row | Present | Absent |
| Preprocessed next row | Absent | Absent |
| Proof magic | `W1S3SH01` | `W1S3PC01` |

Both components use binary Merkle trees, cap height zero, FRI
`log_blowup=2` (factor four), `log_final_poly_len=0`,
`max_log_arity=1`, 64 queries, zero grinding and no zero knowledge.
The new module owns its constants and configuration types; it does not
inherit a mutable legacy `proof_config` parameter bundle. Compile-time
assertions check the field modulus and the imported AIR widths.

## Exact hash frame

All integer encodings below are unsigned little endian. The input to SHA3-512
is the following concatenation. Variable byte lengths count bytes, not bits.

| Order | Field | Encoding |
|---|---|---|
| 1 | Magic | ASCII `TRNM-W1-SHARED-HASH` followed by one zero byte |
| 2 | Frame version | `u16(1)` |
| 3 | Profile length and profile | `u16(length)` followed by ASCII `TRNM-W1-P3-SHA3-512-TAGGED-R1` |
| 4 | Descriptor length and descriptor | `u16(length)` followed by the exact descriptor below |
| 5 | Component | `u32`: 1 or 4; context derivation alone uses 0 |
| 6 | Role | `u8`: leaf 1, branch 2, transcript 3, statement context 4 |
| 7 | Statement context | Exactly 64 bytes |
| 8 | Payload | Role-specific bytes below |
| 9 | Payload length | `u64(payload byte length)` |

The exact descriptor is one ASCII line without a terminal newline:

```text
p3=0.8.0;sha3=512;r=576;c=1024;F=18446744069414584321;E=X^2-7;binary;cap=0;log_blowup=2;log_final_poly=0;max_log_arity=1;queries=64;pow=0;zk=0;sha=d13,w7728,p27,q2,next1;carry=d14,w370,p180,q1,next0
```

The suffix permits streaming leaf and transcript iterators without collecting
the payload. The fixed header lengths, fixed-width context and trailing
payload length give an injective frame encoding within the bounded domain.
That is an encoding property, not a collision-resistance proof.

| Role | Payload |
|---|---|
| Leaf | Canonical field values in order, each encoded as `u64 < p`; length suffix distinguishes empty, zero and zero-extended rows |
| Branch | Left 64-byte digest followed by right 64-byte digest, with length suffix 128 |
| Transcript | The byte sequence supplied by the frozen P3 challenger adapter, with its byte-length suffix |
| Statement context | `u32(3)`, then three records in fixed order: `u8(tag)`, `u64(length)`, bytes; tags 1/2/3 mean canonical public statement / independent expected header / independent expected artifacts |

Context derivation uses component zero, role four and a zero 64-byte context.
Every leaf, branch and transcript frame then includes the resulting context
digest. The runner first validates canonical statement encoding and the
statement's plans against independent expectations. For full W1, the public
statement is 377,290 bytes, the expected header 318 bytes and expected
artifacts 64 bytes. The generic hash helper alone does not validate these
application semantics.

## Digest and transcript representation

Merkle digests are eight **raw** `u64` words. Word `i` is the little-endian
interpretation of output bytes `8*i .. 8*i+8`. Reversing this operation
preserves all 64 output bytes. Digest words are not Goldilocks elements;
values at or above `p`, including `u64::MAX`, remain valid digest bytes.
Only actual field values use canonical field validation.

The challenger is P3 0.8.0
`SerializingChallenger64<Goldilocks, HashChallenger<u8, TranscriptHasher, 64>>`.
It inherits the locked P3 observation order. The underlying hash challenger
pops bytes in reverse digest order; the field adapter forms eight-byte
little-endian candidates and rejects candidates at or above `p`.
Extension coefficients are sampled separately. Query-bit sampling follows
the existing P3 adapter. No new semantic tag is inserted between individual
P3 transcript messages.

Two inherited state aliases are intentionally covered by regression tests:
observe-call segmentation is not recorded, and different numbers of popped
bytes within one output block followed by the same new observation can give
the same future state. These do not themselves show a W1 forgery, but rule
out claiming generic transcript-history injectivity from these hash frames.
The fixed protocol schedule needs its own Fiat-Shamir analysis. Field
rejection sampling has no deterministic attempt limit, so encoded-input
bounds are not a total CPU or wall-time bound.

There are no explicit height, position, tree-type or matrix-boundary fields
in leaf or branch preimages. Actual verifier geometry remains a separate
condition. Role framing does not silently add these missing tags.

## Wire admission

The outer magic is checked before the new proof representation is decoded.
The payload uses the frozen P3 0.8.0 / bincode 1.3.3 fixed-integer shape.
The structural scanner validates all field elements, fixed vector lengths,
Option tags, trace degree, envelope size and absence of trailing bytes.
It admits bounded pruned frontiers; exact frontier consistency belongs to
the cryptographic verifier. Both proof buffers are scanned before either
allocation-owning decode or preprocessing begins.

| Bound | SHA | Packed arithmetic |
|---|---:|---:|
| Minimum encoded proof bytes | 4,245,541 | 317,701 |
| Maximum encoded proof bytes | 4,855,845 | 1,001,733 |
| Fixed field elements scanned | 529,232 | 38,243 |
| Fixed vector headers | 1,338 | 1,339 |
| Maximum sibling digests | 9,536 | 10,688 |

The pair plus the exact public statement is at most 6,234,868 encoded bytes.
These are syntax/operation counts, not a maximum for all heap allocations,
process RSS, receiver CPU or service latency. A scanner-admitted all-`ff`
digest is valid syntax and still requires cryptographic verification.
Old and new proof magics are rejected by the other profile's scanner.

## Source and reference checks

- [Native hash/configuration module](../w1_public_stark_research/src/tagged_sha3.rs)
- [Allocation-free structural scanner](../w1_public_stark_research/src/tagged_sha3_wire.rs)
- [Complete W1 runner](../w1_public_stark_research/examples/tagged_sha3_backend.rs)
- [Native proof and role tests](../w1_public_stark_research/tests/tagged_sha3_profile.rs)
- [Independent Python byte specification](reference_vectors.py)
- [31 fixed vectors](../w1_public_stark_research/tests/tagged_sha3_reference_vectors.json)

The Python reference independently uses `struct` and standard-library
`hashlib.sha3_512`; it neither imports nor parses the Rust implementation.
Vectors cover both components, empty and zero-extended leaves, raw digest
words outside the field, transcript lengths around the 72-byte rate boundary,
and typed context boundaries. Native tests call the actual role APIs.
Their exact JSON SHA-256 is
`c891c42cbd7751c920073c7701494d710016cbf56e933408893b0536996cc0a5`.
These are finite interoperability checks, not collision-security tests.
