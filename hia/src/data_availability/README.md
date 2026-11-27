# Native Cell RS(6,4) byte codec

`rs46.hepta` implements the Cell RS(6,4) encode and recovery operations from
[`cell/erasure.rs`](../../../trillionnium/crates/trnm-data-availability/src/cell/erasure.rs).
The HIA source compiles directly to native machine code through the pinned
self-hosted compiler. One source implements the full original chunk extent of
**1 through 4,194,304 bytes** and every permitted four, five or six shard input.

The codec uses GF(256) with polynomial `0x11d`. Its first four generator rows
are systematic; the two parity rows are `[27,28,18,20]` and `[28,27,20,18]`.
Recovery performs Gaussian elimination over the field and table-based row
application. All supplied shards must have distinct, strictly ascending indices.
It decodes the first four, verifies zero padding and the original source SHA-256,
and verifies consistency of every supplied shard, including extras. Corrupted
input is refused; recovery never searches for a favorable alternate subset.

The implementation reuses the canonical SHA-256 initialization and compression
functions from `crypto/sha256_stream.hepta`. Its block and padding driver covers
the original four MiB chunk limit. The existing transport stream helper retains
its own size contract. No host-language hash or erasure implementation runs in
the native codec.

## Selected chunk pins and ownership

The entry consumes the selected manifest identifier, chunk index, source length
and source SHA-256. These values represent the result of the original
`CellRs46ChunkBindingV1` selection. A caller integrating this component must obtain
them from its validated, retained TCM1 and context owner. Shard headers are always
compared with those separate selected pins.

This component returns byte-validation and recovery results. The separate
[read-only TCM1 codecs](CELL_MANIFEST.md) verify manifest bytes and expose
indexed metadata without supplying owner pins. Live TCM1/context
authorization, provider authentication, durable shard storage, retention,
network serving and the Node's adoption transaction remain separate owners.
The original data-availability package remains required for those behaviors.

## Native entry and exact extents

The borrowed entry is `f0(input:readbuf, output:mutbuf, scratch:mutbuf) -> u32`.
`HRS1` is an in-process codec request format, with no change to CRS1 wire bytes
or any existing signed or durable domain. The caller supplies disjoint private
buffers. A successful call returns zero. Every refusal preserves the entire
output buffer; scratch may change after the structural input checks.

| Request offset | Bytes | Meaning |
| --- | ---: | --- |
| 0 | 4 | ASCII `HRS1` |
| 4 | 1 | Version `1` |
| 5 | 1 | Operation: `0` encode, `1` recover |
| 6 | 1 | Count: `0` for encode, `4..6` for recover |
| 7 | 1 | Zero reserved byte |
| 8 | 32 | Selected manifest identifier |
| 40 | 4 | Selected chunk index, unsigned little endian, `0..16383` |
| 44 | 4 | Selected source size, unsigned little endian, `1..4194304` |
| 48 | 32 | Selected original source SHA-256 |
| 80 | Variable | Original source bytes, or concatenated complete CRS1 shards |

Let `n` be the selected source size and `L = ceil(n/4)`.

| Operation | Exact input bytes | Exact output bytes | Minimum scratch bytes |
| --- | ---: | ---: | ---: |
| Encode | `80+n` | `6*(81+L)` | `4096+4*L` |
| Recover | `80+count*(81+L)` | `n` | `4096+4*L` |

Encode first checks the complete source hash, then writes all six original CRS1
shards in ascending index order. The first four payloads partition the source
in order and add at most three zero bytes. Recover publishes its source bytes
only after every validation succeeds. Maximum encoded output is 6,291,942 bytes;
maximum recover input is 6,292,022 bytes; maximum scratch is 4,198,400 bytes.

CRS1 remains the original 81-byte header: magic at `0`, manifest at `4`, chunk
index at `36`, source size at `40`, source hash at `44`, shard index at `76`,
and shard payload length at `77`. CRS1 integers use big endian. Each shard body
has exactly `L` bytes. Every complete header, all pins and all payload bytes are
checked, including input beyond the four rows needed for decoding.

| Return code | Meaning |
| ---: | --- |
| 0 | Encode or recovery succeeded |
| 1 | Invalid HRS1 header or input/output/scratch extent |
| 2 | Selected source size outside the original range |
| 3 | Selected chunk index outside the original range |
| 4 | Invalid operation-specific shard count |
| 5 | Invalid CRS1 magic, shape, index or payload coverage |
| 6 | Nonascending or duplicate shard indices |
| 7 | A shard differs from the separate selected chunk pins |
| 8 | Reconstructed padding is nonzero |
| 9 | Original source SHA-256 does not match |
| 10 | A supplied shard is inconsistent with the reconstructed codeword |
| 11 | Singular recovery matrix |

Codes `1..4` validate the in-process adapter before typed original operations.
For recover, order is checked before the per-shard shape/pin scan. The original
Rust observation adapter decodes serialized CRS1 values before invoking the typed
recovery method, so multiply-invalid wire errors can have a different first
diagnostic. Accepted inputs and complete successful outputs are compared exactly.

## Executable checks

Set the pinned `HIA_TOOLCHAIN_ROOT`, `HIA_NATIVE_COMPILER` and
`HIA_NATIVE_COMPILER_SHA256`, then run:

```sh
python -B -m unittest -v hia.tests.test_rs46
```

The suite executes all 65,536 field products against independent polynomial long
division, all 255 nonzero inverses, exact CRS1 known answers, all fifteen four
shard subsets, all six five shard subsets and all six shards together. It covers
short sources, SHA block and padding boundaries, complete four MiB and four MiB
minus one sources, every byte of a small codeword mutated separately, mismatched
pins, required/extra corruption, nonzero padding with recomputed consistent parity,
strict ordering and malformed extents. The full six-shard input is also executed
at 6,292,022 bytes; corruption of the final byte of its sixth shard is rejected
before any of the 4 MiB output is published. Every native buffer has guards; rejected
outputs retain their original bytes. A second direct machine compiler runs the
same source on exact wire and all recovery combinations.

[`rs46_original.py`](../../tests/oracles/rs46_original.py) additionally builds the
complete original Rust crate in an isolated workspace. Its observation child
constructs the selected private chunk value only at the test boundary and calls
the unchanged original methods. It runs all retained original erasure tests and
compares actual original and native acceptance and output bytes. Source pins,
compiler identity, complete raw observations and the independent original
executable belong to that comparison; missing or failed execution is an error.

With the same HIA variables and the original Rust 1.95.0 toolchain selected:

```sh
python -B -m hia.tests.oracles.rs46_original --output /absolute/new/rs46-original
```

The mandatory `native-rs46-original` CI job executes this command independently.
Its output retains the actual executed original test binary and native library,
all comparison inputs/outputs, compiler events and unchanged source inventories.

These checks qualify the native byte codec. They do not retire the complete
data-availability package or complete its integration into a running HIA Node.

## Typed transaction-batch protocol context

The private [constructor](protocol_context.hepta) implements the retained
`trnm_data_availability::ProtocolContextV1::new` boundary and emits the
original Borsh value. It takes two opaque 32-byte hashes in genesis/stack order,
followed by all chain-ID bytes. It accepts exactly 1–128 ASCII bytes, including
control bytes and NUL, as the original does. Zero hashes are valid here:
construction establishes only a typed value, not protection or identity.

The successful output is `schema:u16 LE || genesis:32 || chain_len:u32 LE ||
chain || protocol:u32 LE || stack:32`; both versions are fixed to 1.
Status 100 means fewer than 64 bytes, 2 means the chain is outside the
constructor's typed domain, and 102 means insufficient output. All three leave
output untouched; extra capacity and scratch are untouched on success too.
No cryptographic, availability, membership or storage authority follows from
a matching value. Original Rust and both pinned HIA backends are compared by
[test_da_protocol_context](../../tests/test_da_protocol_context.py).

## Typed data-availability object identity

The [private constructor](typed_object_id.hepta) takes exactly
`namespace:u8 || kind:u16 LE || digest:32`. It admits the original
TransactionBatch namespace (0) and the six typed object kinds. It distinguishes
the original explicit ArtifactEvidence exclusion (status 2) from any unknown
namespace (3), before checking the private typed kind domain (4). A wrong
extent (100) or insufficient output (102) cannot publish a partial result.
Success emits the exact original 35-byte Borsh value. The digest is opaque;
this does not verify that an object exists, is stored, or is certified.

The [differential](../../tests/test_da_typed_object_id.py) checks all 256
namespace tags and every original kind against the locked Rust library and both
native backends. Out-of-domain raw kind codes are private ABI refusals, not
fabricated calls with a Rust typed kind.

## DA author value construction

The [private author value constructor](author_authority_value.hepta) accepts
`public_key:32 || first:u64 LE || maximum:u64 LE || byte_quota:u64 LE ||
outstanding:u32 LE || author_id`. The ID is arbitrary bytes of length 1–256.
It checks nonzero first sequence, no inverted interval, and nonzero quotas
before inspecting the public key, as the unchanged Rust constructor does.

The original uses Dalek's permissive public-point decompression followed
by its small-order rejection; the strict signature or canonical-hex
predicate is not interchangeable. The native caller uses the existing
Research public-Y normalizer and shared group decoder. In scratch only,
it selects the sign-zero representative: negating the point cannot
change decompression's existence or point order, and sign-one zero
still denotes the same weak point under Dalek. Both outcomes are checked
against the original, including unparseable encodings, weak points, and
both signs of all 19 over-field values. The return keeps the input public
key bytes exactly as given, not a normalized encoding.

With 140,512 disjoint scratch bytes and sufficient output, success emits
`id_len:u32 LE || author_id || public_key || first || maximum ||
byte_quota || outstanding` (the original derived Borsh bytes). Status 3
means bad fields; 6 and 7 distinguish the original invalid public point
and weak point messages under the same Rust error code. Private framing
and capacity statuses are 100 and 102. Refusals leave output untouched;
the input and spare output are unchanged in all cases. Matching this
value does not confer author membership, authorization, signature
verification, storage, or any node policy effect.

[Locked original and both stock HIA backends](../../tests/test_da_author_authority_value.py)
compare exact status, bytes, and buffer boundaries.

## DA author transcript from an unsigned batch envelope

The [private transcript constructor](batch_author_transcript.hepta) takes
one exact Borsh `DaBatchEnvelopeV1` loan. It first checks typed framing and
UTF-8, then performs the original context version and chain checks,
namespace check and envelope shape checks in that order. The valid
input's envelope schema and the author statement schema are both 1.

The first SHA-256 computes `BatchIdV1` from the complete original Borsh
envelope. The second uses the schema/context/namespace/epoch/committee/
author/sequence prefix of those same bytes, then appends the BatchId
computed in this call. Both SHA-256 inputs begin with the original
domain's little-endian `u32` byte length and exact ASCII domain. No
external digest, pre-checked flag, signature or key is accepted. A
successful call writes the two actual 32-byte hashes in BatchId,
author-transcript order. No result is written on refusal, and the
input and output tail are unchanged.

The private profile admits at most 1 MiB for the complete byte loan and
requires 1,296 disjoint scratch bytes and at least 64 disjoint result bytes.
It does not impose the authority constructor's separate 256-byte author
ID limit; the original envelope method only requires a nonempty ID.
Statuses 2/3 distinguish unsupported context versions and invalid chains,
4/5 preserve explicit ArtifactEvidence vs unknown namespace, and 6 is an
invalid envelope. 100/102/103 are private frame/capacity/internal codes.
The exact 1 MiB fixture is compared on both stock emitters and the
unchanged Rust; its one-byte-larger counterpart is only a Rust control.

The [original comparison](../../tests/test_da_batch_author_transcript.py)
uses real `UnsignedTransactionBatchV1::build` in the unchanged crate
with generated synthetic item bytes and a public-only fixture key. It
does not sign or verify signatures, interpret statement hashes as trust,
validate membership or quota on a supplied envelope, or activate a node
or storage path.

## DA chunk coordinate and byte commitments

The [private chunk commitment](chunk_commitments.hepta) accepts an
original Borsh `DaChunkCoordinateV1` followed immediately by the
Borsh byte vector (`u32` little-endian length and its exact bytes).
Both length-prefixed fields in the coordinate and the trailing vector
must fit the loan exactly. The chain text must be well-formed UTF-8
for typed Borsh decoding; no context, namespace, policy or membership
validation is inferred from these bytes. Chunk bytes must be nonempty,
and the coordinate's actual `u64` byte-length claim must equal the
vector payload length.

The native call computes SHA-256 with the original Borsh string
domain prefix for each digest. For ChunkId it hashes the exact coordinate
under `trnm.portable.v2.da-chunk-id.v1`; for bytes it hashes the vector,
including the vector's length, under
`trnm.portable.v2.da-chunk-bytes.v1`. It writes the two 32-byte
commitments in that order only once both are computed. No externally
checked digest is used. The fixed profile permits a complete loan of
at most 1 MiB, requires 1,296 scratch bytes and 64 result bytes, and
leaves the immutable input and spare result bytes untouched. Status
6 is the length/empty-chunk refusal; 100/102/103 are private frame,
capacity and hash failure. Refusal makes no result write.

[Independent original comparisons](../../tests/test_da_chunk_commitments.py)
build real unsigned batches in the frozen Rust crate, obtain each chunk
from its public accessor, and compare native ChunkId to the public Rust
value and native byte digest to Rust's original serialized field. The
private original constructor is not exposed to the test caller; malformed
and capacity probes are explicitly native-only controls. Exact 1 MiB
is compared under both fixed emitters; 1 MiB plus one is an original-only
control. This surface does not validate any Merkle path, certificate,
signature, storage, retrieval, repair right, or node-accepted authority.

## DA chunk inclusion path comparison

The [private path comparator](chunk_inclusion_path.hepta) takes the
same three values as the original pure `verify_merkle_path_v1`:
a supplied leaf hash32, a supplied expected root hash32, and one
complete Borsh `DaChunkInclusionProofV1`. The proof consists of
little-endian `u32` index, item count and path count, followed by
`level:u32 LE || sibling_side:u8 || sibling_hash:32` per step.
Neither external hash is trusted or checked against a certificate.

The comparator preserves the original index/count, truncation,
level and side, duplicate-final, trailing-step, then root ordering.
It hashes each parent with the exact Borsh leaf-domain string,
little-endian level and ordered siblings under the original
parent domain. Its final root hashes the same leaf-domain string,
original item count and running hash under the separate root domain.
A canonical count fits `u32`, so at most 32 sibling steps are visited.
The private framing cap is 1 MiB total; 1,472 scratch bytes are needed.
No byte result is produced, and the input, output and scratch canary
beyond the declared extent are untouched.

Statuses 50–55 respectively preserve the original coordinate,
truncation, level/side, duplicate-final, trailing-step and root
mismatch observations. 100/102/103 are private frame, capacity and
internal errors, not Rust protocol results. An otherwise matching
proof only establishes equality to the supplied root, not admission,
membership, authorization, proof of availability or repair right.

[The differential](../../tests/test_da_chunk_inclusion_path.py)
runs the actual original private generator and comparator on paths
from frozen Rust unsigned batch construction. It verifies the
tracked Rust tree, copies it into a fresh test directory and appends
only one `cfg(test)` module reference whose source is the committed
fixture. While the fixture is present, it runs only the test build
and the one exact test selector, rejecting evidence of non-test DA
compilation at that stage. The original bytes are restored before
any non-test rebuild. It compares the two clean non-test libraries
from the same path byte for byte and checks for marker absence. No
production Rust file is modified and the offline witness does not
sign, open a database, access a network or obtain certified state.

## DA chunk-bound inclusion comparison

The [private composition](chunk_bound_inclusion.hepta) has no supplied
leaf, ChunkId, byte digest or prior result. One immutable loan contains
`HCD1` followed by 28 zero bytes, the supplied expected root hash32,
the exact Borsh proof above, then the exact Borsh coordinate and byte vector.
The proof vector count determines its only boundary; both typed chunk
sections must consume the remainder exactly. The native comparison
requires that the proof and actual chunk use the same index (status 56,
a composition guard). It also checks nonempty bytes and exact coordinate
length (status 6). It checks typed UTF-8 but derives no context, namespace
or policy authority from the coordinate.

The composition calls the existing pinned chunk digest helper over each
same-loan subspan, uses both resulting commitments and the original
little-endian chunk index to compute the actual `chunk_leaf_v1` domain
hash, then continues into the unchanged Merkle scan. Status values 50–55
retain the original path observations. The complete loan is capped at
1 MiB, needs 1,472 disjoint scratch bytes and produces no byte output.
The HIA call never modifies input or the caller result buffer.

[Original comparisons](../../tests/test_da_chunk_bound_inclusion.py)
run the actual private Rust chunk constructor, leaf, generator and
verification in the same isolated test-only mechanism as the standalone
comparator. They include a real same-coordinate chunk-byte change that
alters the root comparison, exact 1 MiB through both stock emitters,
and the one-byte-larger original-only contrast. The unchanged ordinary
Rust library is independently rebuilt and compared before and after
the test-only fixture is installed and removed. This comparison is not
a signed message, trusted certificate root, retrieval authority, or
a storage/repair approval.
