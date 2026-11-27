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
