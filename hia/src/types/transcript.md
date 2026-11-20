# Native transcript values and Merkle proofs

`transcript.hepta` implements the nine explicit public functions and methods of
the original `trnm-types/src/transcript` module as HIA v8 machine code. Its shared
SHA-256, integer formatting, buffer access and UTF-8 functions are selected from
their existing HIA owners through `hia/components.json`.

The original Rust implementation remains an unchanged differential reference.
Python supplies test values, framing, independent hash controls and artifact
observations. It does not execute any native transcript method on behalf of the
compiled HIA module.

## Complete explicit method surface

| Operation | Original public API | Native result |
| --- | --- | --- |
| `0` | `relay_auth_envelope_hash` | The exact 32-byte envelope hash |
| `1` | `transcript_segment_root` | `Result<Hash32, TranscriptError>` |
| `2` | `transcript_segment_proof` | Root and one complete proof, or the original error |
| `3` | `transcript_segment_proofs` | Root and ordered proofs, preserving repeated targets |
| `4` | `transcript_segment_tree` | Materialized Merkle layers; the result reports its public root and leaf count |
| `5` | `verify_proof` | Boolean result for arbitrary typed proof values |
| `6` | `TranscriptMerkleTree::root` | Root read from the actual materialized tree |
| `7` | `TranscriptMerkleTree::leaf_count` | Number of leaves in that tree |
| `8` | `TranscriptMerkleTree::proof` | `Some` complete proof or `None` for an invalid leaf index |

Operations `6`–`8` receive the same envelope segment as tree construction and
then call the corresponding tree method. The original tree's levels are
crate-private. The standalone value interface does not introduce a decoder for
arbitrary externally supplied internal tree state. Native tree construction
stores every real layer in the caller's workspace; the named
`trnm_transcript_tree_root`, `trnm_transcript_tree_leaf_count` and
`trnm_transcript_tree_proof` helpers consume that initialized representation.

The transport covers explicit method values. It does not implement a general
Serde replacement, a relay verifier, replay ownership, durable tree storage,
Node integration or the rest of `trnm-types`. No crate or original implementation
is eligible for retirement on the basis of this component alone.

## Original semantics retained

The envelope hash uses the unchanged `TRNM_P2P_V1` domain and exact field order:
domain, chain ID, message type, version, task ID, session ID, decimal sequence,
decimal timestamp, sender, recipient, nonce, payload-hash text and signature
text, separated by ASCII `|`. UTF-8 bytes are preserved exactly. There is no
trimming, case folding, escaping or signature validation in this hash method.
The raw payload bytes are excluded, exactly as in the original function.

The sequence is an unsigned 64-bit value and the timestamp an unsigned 128-bit
value. Their decimal representations cover their complete original ranges.
The typed interface permits fields longer than the relay JSON decoder's limits:
Rust callers can construct `RelayAuthEnvelope` values directly, and the original
transcript methods do not impose those decoder limits.

Segment collection follows input order. It skips every sequence below the
requested start, stops at the first sequence above the end, and requires each
included sequence to equal the current expected sequence. It does not sort the
envelopes. Batch proof construction rejects empty targets before checking the
range. Target errors follow successful segment collection, and repeated targets
produce repeated proofs in their original order.

The original increment uses saturating `u64` arithmetic. Consequently, a segment
whose end is `u64::MAX` still returns `MissingSequence { expected_seq:
u64::MAX }` after that last sequence. The native port preserves that behavior;
it does not change the original boundary while claiming an equivalent rewrite.

Each odd Merkle layer duplicates its final node before hashing the pair. The
proof for that node includes the duplicate hash with direction `Right`.
Verification requires equal path and direction lengths, hashes ordered pairs,
and compares the resulting accumulator with the supplied root. An empty proof
is valid precisely when its leaf equals the root. Arbitrarily long proof paths
are supported when their supplied input extent is valid; the verifier does not
apply the tree's internal level-table size to an independently supplied proof.

## Borrowed-buffer entry

```text
f0(input: readbuf, output: mutbuf, workspace: mutbuf) -> u32
```

The caller supplies distinct borrowed buffers. All integers in the local value
transport use little-endian encoding. This fresh local transport does not change
the original signed envelope domain or claim compatibility with persisted Rust
Serde encodings.

### Request header

Every request begins with an 80-byte header:

| Offset | Size | Value |
| --- | --- | --- |
| `0` | `8` | `TRNMTP1` followed by NUL |
| `8` | `8` | Operation `0`–`8` |
| `16` | `8` | Inclusive start sequence |
| `24` | `8` | Inclusive end sequence |
| `32` | `8` | Target sequence for operation `2`; target leaf index for `8` |
| `40` | `8` | Envelope count |
| `48` | `8` | Target count for operation `3` |
| `56` | `8` | Proof path count for operation `5` |
| `64` | `8` | Proof direction count for operation `5` |
| `72` | `8` | Reserved, zero |

Unused fields must be zero. Operation `0` requires one envelope and zero start
and end. Operation `5` has no envelopes or sequence range. Operations other than
`3` have no target vector. Only operations `2` and `8` use the single target
field. All counts and lengths are checked against remaining buffer extents
before addition, multiplication, indexing or allocation-sized work.

### Envelope and proof values

For envelope operations, each record has a 120-byte fixed prefix followed by its
string and payload bytes:

| Record offset | Value |
| --- | --- |
| `0` | Total record length, including this prefix |
| `8` | Sequence, `u64` |
| `16` | Timestamp, `u128`, occupying 16 bytes |
| `32`–`104` | Ten `u64` UTF-8 byte lengths |
| `112` | Raw payload byte length |
| `120` onward | Ten strings in length-table order, then the raw payload |

The ten strings are chain ID, message type, version, task ID, session ID,
sender, recipient, nonce, payload-hash text and signature text. The complete
envelope framing and all string UTF-8 values are validated before any method
executes. A batch target vector follows the last envelope as consecutive `u64`
values.

Operation `5` instead carries a 32-byte root, a 32-byte leaf, all 32-byte path
nodes, and one byte per direction. Direction `0` means `Left`, and `1` means
`Right`. Different path and direction counts are valid typed inputs and yield
`false`; an unknown direction byte is malformed transport.

### Result header and values

A successful transport evaluation, including a semantic `Err`, writes a
48-byte header and its complete payload:

| Offset | Value |
| --- | --- |
| `0` | `TRNMTR1` followed by NUL |
| `8` | Semantic result tag |
| `16`, `24`, `32` | Three result or error fields |
| `40` | Payload byte length |
| `48` onward | Exact payload |

| Tag | Original semantic result | Fields at `16`, `24`, `32` |
| --- | --- | --- |
| `0` | Success | Operation-specific value, then zero fields |
| `1` | `EmptySegment` | All zero |
| `2` | `EmptyTargets` | All zero |
| `3` | `InvalidRange` | Start, end, zero |
| `4` | `MissingSequence` | Expected sequence, zero, zero |
| `5` | `OrderMismatch` | Expected sequence, received sequence, zero |
| `6` | `TargetOutOfRange` | Target sequence, start, end |

Success payloads for operations `0`, `1`, `4` and `6` contain the 32-byte hash or
root. Operation `4` also puts the leaf count in the first result field. Operation
`7` puts the leaf count in that field and has no payload. Operation `5` places
its boolean `0` or `1` there and has no payload.

A proof is encoded as a 32-byte leaf, `u64` path count, `u64` direction count,
all path hashes and all direction bytes. Operation `2` returns a root followed
by one proof. Operation `3` returns a root, a `u64` proof count and that many
complete proofs. Operation `8` puts `1` in the first result field and emits its
proof for `Some`; it puts `0` there and emits no payload for `None`.

The scalar return distinguishes local transport refusals from semantic results:

| Return | Meaning |
| --- | --- |
| `0` | Complete semantic result written |
| `100` | Malformed or noncanonical local framing |
| `101` | An envelope string is not valid UTF-8 |
| `102` | Insufficient output or workspace capacity |
| `103` | Shared SHA-256 operation refused |

All refusals preserve the output buffer. Successful results preserve the output
suffix beyond their exact result. Framing, UTF-8, capacity and ordinary semantic
errors are detected before workspace mutation. A shared-hash refusal can leave
intermediate workspace state and never publishes a partial result.

## Workspace and arithmetic bounds

Envelope hashing requires 2,600 bytes. It formats both unsigned counters before
initializing SHA-256, so the shared `oj_json128` temporary words cannot overwrite
an active hash context. The shared SHA context occupies `[0,1208)`, domain and
decimal bytes occupy `[1208,1279)`, and the shared decimal helper uses bytes
starting at 2,560.

Proof verification uses a 32-byte accumulator at `[1280,1312)` and requires
1,312 bytes when it hashes at least one pair. Empty proofs and mismatched vector
lengths need no workspace. Same-workspace SHA updates are always disjoint from
the shared context.

For a tree with `N > 0` selected leaves, the required workspace is:

```text
4096 + 32 * (N + ceil(N/2) + ceil(ceil(N/2)/2) + ... + 1)
```

The implementation checks each level against remaining workspace capacity
before summing or multiplying. It stores count, root and level metadata at
2,600, the level table at 2,688, and all actual hash nodes starting at 4,096.
The 64-entry level table covers every count representable by the borrowed-buffer
and `u64` value domain. Tree capacity and output capacity are checked before
building any layer. No fixed envelope-count, field-length or payload-length
ceiling substitutes for these extent checks.

The shared SHA-256 full wrappers support the SHA-256 byte-count domain through
`2^61 - 1`, independently of the retained transport owner's smaller limit.

## Qualification

`hia/tests/test_transcript.py` links `rust_transcript_reference.rs` to the
unchanged original `trnm-types` library using the repository's pinned Rust
1.95.0. The adapter calls all nine original APIs. It also runs all eight retained
original transcript module tests in a separate build directory, without
modifying or rebuilding the supplied reference library.

The native suite covers exact field order, unsigned decimal boundaries and full-width values,
Unicode and control bytes, odd layers, complete single and batch proofs,
duplicate targets, sequence/error priorities, the original maximum-sequence
behavior, tampering, arbitrary proof paths, exact capacities, malformed lengths,
invalid UTF-8 and deterministic randomized method comparisons. Separate child
processes execute the same artifact with actual unaligned fields and payloads
larger than 2 MiB. These processes load no HIA compiler modules.

The report retains original-source hashes, the original library and adapter
identities, compiler receipt, emitted artifact, method observations and retained
test output. Native component qualification does not certify a complete native
Node or authorize removal of the remaining original crate.
