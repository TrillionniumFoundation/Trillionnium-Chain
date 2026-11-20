# Research protocol native components

`canonical.hepta` implements the encoder and decoder primitives from the retained
`trnm-research-protocol/src/canonical.rs` in HIA. `hash.hepta` implements its
domain-separated canonical hash using the existing native streaming SHA-256
functions. Both build with the pinned HIA self-hosted compiler and expose the
existing private borrowed-buffer `f0` ABI. Python and Rust are test drivers;
neither supplies a decision to the native implementation.

`external_key.hepta` also implements the original public `ExternalKey` derivation,
byte access, hexadecimal/display output and canonical CBOR encoding. These native
components are part of M10's research protocol. `payload.hepta` implements all
seven `ResearchCommandV1` payloads, including their canonical encoding, strict
decoding, validation, command type and primary object reference. Signed envelopes,
protocol state transitions, Hepta handoff, full consumer integration and
original-package retirement still require implementation and acceptance. The
primitive decoder leaves protocol versions, enum discriminants and round-trip
checks to the typed consumer; the payload implementation performs those checks.

## Canonical byte interface

The 24-byte `RCB1` request header contains the four magic bytes, an operation byte,
three zero reserved bytes, an argument as little-endian u64, and a cursor as
little-endian u64. The remaining bytes are the input payload. Decoder cursors are
relative to that payload. Encoder cursors are relative to the output data area.
The cursor is supplied explicitly so a caller can perform a sequence of the
original primitive operations with no hidden owner or state.

The output begins with four little-endian u64 fields. A successful encoder writes
the next cursor and three zeros, followed by its data area. It appends at the
supplied cursor and preserves the preceding bytes. A decoder returns the next
cursor and the fields shown below. Borrowed byte/text results identify the exact
input span; the decoder does not copy or normalize input bytes.

| Operation | Original method | Argument | Result fields after cursor |
| --- | --- | --- | --- |
| 0 | `Encoder::uint` | u64 value | zero, zero, zero |
| 1 | `Encoder::bytes` | unused | zero, zero, zero |
| 2 | `Encoder::text` | unused | zero, zero, zero |
| 3 | `Encoder::array` | element count | zero, zero, zero |
| 4 | `Encoder::bool` | 0 or 1 | zero, zero, zero |
| 5 | `Encoder::null` | unused | zero, zero, zero |
| 6 | `encode_option_digest` | 0 for None; 1 with exactly 32 input bytes | zero, zero, zero |
| 16 | `Decoder::uint` | unused | value, zero, zero |
| 17 | `Decoder::array_len` | unused | count, zero, zero |
| 18 | `Decoder::array` | expected element count | zero, zero, zero |
| 19 | `Decoder::bytes` | unused | zero, span offset, span length |
| 20 | `Decoder::bytes_exact` | expected byte count | zero, span offset, span length |
| 21 | `Decoder::text_bounded` | maximum UTF-8 byte count | zero, span offset, span length |
| 22 | `Decoder::bool` | unused | 0 or 1, zero, zero |
| 23 | `Decoder::option_digest` | unused | presence, span offset, span length |
| 24 | `Decoder::finish` | unused | zero, zero, zero |
| 25 | private `Decoder::head` | unused | value, major type, zero |

Return codes 0–7 and 10 identify success, `UnexpectedEof`, `UnexpectedType`,
`ForbiddenAdditionalInfo`, `NonMinimalEncoding`, `InvalidUtf8`,
`ArrayLengthMismatch`, `ByteLengthMismatch`, and `TrailingBytes`. A length
mismatch returns expected/actual/zero after the cursor. Other decoder failures
return three zeros and preserve the exact cursor advancement of the original
method. In particular, type errors follow complete head parsing, a text bound
error precedes body acquisition, and an exact byte-length error follows body
acquisition. No error is inferred from a signal or timeout.

The borrowed ABI additionally returns 64 for insufficient output/scratch or an
out-of-range encoder output cursor, and 65 for an invalid request shape. It
requires at least 32 output bytes and 32 scratch bytes. Rejected encoder input
and insufficient output never publish a partial encoding. Text encoder inputs
must be UTF-8, matching the original `&str` parameter. Unsigned arithmetic checks
remaining extents before adding lengths, including u64::MAX length/cursor inputs.

## Canonical hash

The `RCH1` request consists of the four magic bytes, a little-endian u32 domain
byte length, the UTF-8 domain, and the complete message. The native code hashes
the exact original sequence:

`TRNM_RESEARCH_PROTOCOL_HASH_V1\0 || u32_be(domain.len) || domain || u64_be(message.len) || message`.

It writes the 32-byte digest and preserves the rest of the output. The scratch
minimum is the existing streaming SHA-256 state's 1,208 bytes. The two framed
lengths are independent, and neither the domain nor the message is interpreted
as CBOR by the hash function. Return codes 5, 64 and 65 reject an invalid UTF-8
domain, insufficient borrowed extents and an invalid request shape respectively.
The shared test ABI retains its existing 1 MiB per-buffer maximum; this is a
bounded component interface, not retirement of every original generic caller.

## External keys

The `REK1` byte interface has an eight-byte header: magic, an operation byte, a
zero reserved byte, and a little-endian u16 namespace length. The namespace and
identifier follow. Operation 1 derives from a canonical lowercase UUID, operation
2 derives from an external ASCII identifier, and operation 3 accepts exactly
32 key bytes with an empty namespace.

Successful calls write 130 bytes: the 32 key bytes, their 64 lowercase hexadecimal
characters, and the 34-byte canonical CBOR byte string. The hex output is also
the original Display output. Raw zero keys remain valid for `from_bytes` and
rendering, as in the original public type; payload-specific nonzero validation
is a separate consumer obligation.

Derivation preserves the exact original domain and framing:

`TRNM_RESEARCH_EXTERNAL_KEY_V1\0 || u16_be(namespace.len) || namespace || kind || u16_be(id.len) || id`.

UUIDs contribute their 16 decoded bytes with kind 1. External identifiers
contribute their original bytes with kind 2. Namespace validation precedes
identifier validation. The namespace admits only 1–64 lowercase ASCII letters,
digits, `.`, `-`, `_` and `:`. External IDs admit 1–256 visible ASCII bytes excluding
backslash. UUID parsing requires all 36 bytes of the lowercase 8-4-4-4-12 form;
no normalization is performed.

Return codes 1, 2 and 3 correspond to the original invalid-namespace, invalid-UUID
and invalid-external-ID variants. The borrowed ABI adds 64 for insufficient
output/scratch and 65 for malformed framing. At least 130 output and 1,208 scratch
bytes are required; refusals preserve both complete buffers. Successful calls
preserve output beyond byte 130 and scratch beyond byte 1,208.

Six tests execute 5,463 comparisons with the actual retained public Rust crate,
732 independent hashlib checks and 24 ABI/capacity controls. They cover every
ASCII byte in every UUID position, namespace and identifier alphabets and bounds,
Unicode rejection, multi-error precedence, every bit of raw keys, domain/kind
separation and untouched canaries. The Rust adapter calls the original methods;
it does not copy the derivation algorithm. This finite type implementation does
not qualify generic Serde, research commands/state, handoff or Node integration.

## Seven typed command payloads

`payload.hepta` implements the seven public command variants from the unchanged
`trnm-research-protocol/src/types.rs`. It preserves each nested struct's array
length and version, the outer command tag, exact field order and shortest CBOR
heads. Decoding rejects unsupported versions, unknown enum discriminants,
nonminimal lengths, invalid UTF-8, truncated bodies and trailing bytes before
performing the original round-trip and semantic validation in their original
order. No host callback supplies a decoded value or validation result.

| Kind | Public payload | Command type | Primary object |
| --- | --- | --- | --- |
| 1 | `MatchEvidenceCommitmentV1` | `match_evidence_commitment_v1` | match evidence |
| 2 | `EvaluationCommitmentV1` | `evaluation_commitment_v1` | evaluation commitment |
| 3 | `IssueWorkloadReceiptV1` | `issue_workload_receipt_v1` | workload receipt |
| 4 | `CreateResearchClaimV1` | `create_research_claim_v1` | research claim |
| 5 | `DeclareLicenseV1` | `declare_license_v1` | license declaration |
| 6 | `ChallengeResearchClaimV1` | `challenge_research_claim_v1` | claim challenge |
| 7 | `ClaimResolutionV1` | `resolve_research_claim_v1` | claim resolution |

The private borrowed-buffer entry takes a 24-byte `RTP1` header: magic at bytes
0–3, operation at byte 4, three zero bytes, a little-endian u64 kind at byte 8,
and eight zero bytes. The rest is the payload. Operation 1 encodes a typed value
without semantic validation, matching `CanonicalCbor`; operation 2 also calls
the original-equivalent validation; operation 3 decodes canonical bytes,
re-encodes and compares the complete input, then validates. Operation 3 requires
kind zero because the CBOR command contains its actual kind.

The typed representation follows each Rust struct's field order. All integers,
enum tags, booleans, collection counts and option flags occupy little-endian u64
words; keys and digests occupy 32 raw bytes. An object reference consists of kind,
key and version. A contribution consists of key, role, accepted work units and
contribution hash. A claim share consists of key and basis points. Collections
start with their count, optional digests start with 0 or 1, and strings start with
their UTF-8 byte count. Typed booleans, enums and u16 fields must fit their actual
public type even when semantic validation is disabled. The adapter is private;
this layout does not alter the public canonical encoding or stored schema.

The output has a 128-byte fixed prefix. Its first eight u64 words are canonical
byte length, typed byte length, command kind, command-type byte length, error
name index, two error details, and primary object version. Bytes 64–95 are the
primary object key; bytes 96–127 are the zero-padded command type. Canonical bytes
and typed bytes follow consecutively. The key, kind and version are independently
compared with the original `primary_object_ref().canonical_bytes()` result.
Output after these bytes remains untouched.

Return codes 1–11 represent `CanonicalDecodeError` variants, including original
expected/actual lengths, unsupported version and unknown discriminant. Codes
101–115 represent, in declaration order, the original payload errors from
`ZeroExternalKey` through `UnexpectedAmendedClaimants`. The exact stable field
name indexes and detail mapping are recorded in `test_research_payload.py` and
its Rust observation adapter. A protocol error zeroes the fixed output prefix
except for the name and two details; it preserves the remainder. Native traps,
signals and incomplete batches are never translated into protocol refusals.

Semantic checks include strict contributor/key ordering, full object-reference
tuple ordering, every nonzero requirement, exact reference kinds, original
collection bounds, checked u64 work-unit addition, exact declared totals, exact
10,000 basis-point ownership, optional digest rules, evaluation consistency,
resolution-specific amended shares and the original restricted SPDX expression
grammar. Validation order is observable: a multi-error input returns the same
first error as the original public method.

The borrowed interface requires at least 128 output bytes and
`2560 + 16 * payload_byte_length` scratch bytes, with checked arithmetic before
allocation or pointer arithmetic. The scratch allowance covers the complete
normalized typed representation and canonical re-encoding. Return 64 indicates
insufficient output or scratch; 65 indicates malformed borrowed framing or a
typed representation that cannot exist in the original type. These refusals
leave the complete output untouched. The input is read-only, and the scratch
canary beyond the declared bound remains unchanged. The existing native test
runner's 1 MiB per-buffer bound still applies; this finite interface does not
qualify every unbounded generic or Serde consumer.

Seven tests completed 6,968 actual original/native comparisons and 20 ABI
controls. They include all seven encode/validate/decode paths, every truncation
of valid fixtures, all 256 first bytes, canonical scalar and collection
boundaries, full-width numeric mutations, overflow, incorrect ordering,
multi-error precedence, optional values, 512 deterministic CBOR mutations and
128 full-width typed mutations. Expected results come from the retained public
Rust crate, not a copied Python implementation. This acceptance covers the
payload component; it does not certify signed commands, state or package
retirement.

## Reproduction

With the pinned compiler and toolchain environment used by the existing HIA
workflow, run:

```sh
python3 -m unittest hia.tests.test_research_canonical -v
python3 -m unittest hia.tests.test_research_external_key -v
python3 -m unittest hia.tests.test_research_payload -v
```

The suite builds the original locked workspace dependency graph in offline mode
and then compiles `rust_research_canonical_reference.rs` against the resulting
`sha2` and `thiserror` artifacts. Its `include!` reads the original canonical
module without editing it. The oracle observes the original private decoder
cursor and invokes the actual methods. Missing dependencies, compilation errors,
native traps and incomplete batches fail the suite.

Coverage includes every CBOR first byte, all u64 shortest-form boundaries,
wrong-major/nonminimal precedence, reserved and indefinite forms, truncated
headers and bodies, length overflow, exact/bounded lengths, optional digests,
trailing data, every single-byte UTF-8 input, multibyte scalar boundaries,
surrogates/overlong forms, deterministic random inputs, encoder append cursors,
output canaries and the original hash framing. The suite prints exact source,
compiler, native artifact and original-oracle identities with its actual counts.
