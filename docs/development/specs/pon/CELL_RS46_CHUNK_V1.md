# Cell RS(6,4) Chunk V1

Status: bounded native candidate component. `HOLD_NO_GO` remains in force.
This profile extends [Cell byte storage](CELL_MODEL_STORAGE_V1.md). It does not
change TCM1, its hash domain, any cache schema, consensus, or release authority.

## Object and authority

The unit of erasure coding is one existing TCM1 chunk of 1 through 4,194,304
bytes. `CellRs46ChunkBindingV1::from_pinned_manifest` checks the owner-supplied
manifest ID, complete Cell context, and chunk index. The binding retains the
original manifest ID, index, exact source length and original chunk SHA-256.
Neither a shard header nor a shard's content address supplies these pins.

`encode_chunk` first checks the original chunk length and hash, then produces
four systematic data shards and two parity shards. `recover_chunk` accepts
four through six supplied shards, checks their identities and shape, decodes,
checks canonical padding, and verifies the original chunk length and SHA-256.
Every supplied extra shard is checked against the reconstructed codeword.
Successful output is the exact original chunk under the existing hash
assumption, not a provider signature, payment receipt, custody proof or FinalUse.

This component has no filesystem or networking effects. A caller can write the
returned verified chunk through the existing cache API. After recovering all
chunks, the original complete-Cell verification/materialization path must
still verify TCM1's whole-payload SHA-256. Release closure and model permission
remain separate requirements.

## Fixed code, field and layout

Reed-Solomon erasure coding and its distinction from corruption authentication
are discussed in [RFC5510](https://www.rfc-editor.org/rfc/rfc5510). This is an
independent, fully specified **CRS1** Cell profile, not an RFC5510 FEC wire
encoding or a claim of interoperability with arbitrary RS libraries.

| Parameter | Fixed value |
| --- | --- |
| Profile | `cell-rs46-chunk-v1` |
| Field | GF(256) |
| Polynomial | `x^8 + x^4 + x^3 + x^2 + 1`, hexadecimal `0x11d` |
| Byte basis | Bit `i` is the coefficient of `x^i` |
| Addition | XOR |
| Multiplication | Polynomial product reduced modulo `0x11d` |
| Data/total shards | `k=4`, `n=6` |
| Evaluation points | Field elements `0,1,2,3,4,5` in byte representation |
| Vandermonde | `V[i,j] = i^j`, `j=0..3`, `0^0=1` |
| Generator | `G = V * inverse(V[0..4])` |
| Shard length | `s = ceil(original_chunk_length / 4)` |
| Padding | Append exactly `4s-L` zero bytes; at most three |
| Data order | Four consecutive length-`s` slices of that padded source |

The exact generator, with decimal field-element coefficients, is:

| Shard index | d0 | d1 | d2 | d3 |
| ---: | ---: | ---: | ---: | ---: |
| 0 | 1 | 0 | 0 | 0 |
| 1 | 0 | 1 | 0 | 0 |
| 2 | 0 | 0 | 1 | 0 |
| 3 | 0 | 0 | 0 | 1 |
| 4 | 27 | 28 | 18 | 20 |
| 5 | 28 | 27 | 20 | 18 |

Each byte offset is encoded independently by its row of this matrix. Any four
distinct rows of `V` have nonzero Vandermonde determinant because their field
points are distinct. Multiplying all rows by the same invertible normalization
matrix preserves this rank. Thus any four correct shards reconstruct the four
source shards in the stated field model. This does not establish that four
independent operators store the shards or that a network delivers them.

The decoder uses the first four supplied rows after enforcing strict ascending
shard index. Duplicate or reordered inputs are refused, not reinterpreted by
array position. An eventual network collector may explicitly sort a bounded,
validated set; it must not discard conflicting duplicates or replenish its
reservation in doing so.

The decoder does not search alternate subsets to correct arbitrary corruption.
Fewer than four shards fail. Corruption in selected shards fails padding or the
original chunk hash; inconsistent additional shards also fail. Zero padding
is checked before truncation, preventing noncanonical codewords that preserve
the original prefix and therefore its original hash.

## CRS1 canonical shard encoding

All integers are unsigned big-endian. There is no algorithm, polynomial, k/n,
or padding negotiation; a changed profile needs another namespace and vectors.

| Byte range | Field |
| --- | --- |
| 0..4 | ASCII `CRS1` |
| 4..36 | Original TCM1 manifest ID |
| 36..40 | Original chunk index, at most 16,383 |
| 40..44 | Original chunk length, 1 through 4,194,304 |
| 44..76 | Original TCM1 chunk SHA-256 |
| 76..77 | Shard index, 0 through 5 |
| 77..81 | Exact shard length `ceil(L/4)` |
| 81 onward | Exactly that many shard bytes |

Decoding validates wire length, version, source length, both indices, declared
length and exact byte coverage before allocating the payload vector. It only
establishes shape. `recover_chunk` verifies the fields against the independent
original binding before any matrix/payload reconstruction.

The optional content address is
`SHA256(ASCII("trnm.cell-rs46-shard.v1") || 0x00 || CRS1_bytes)`.
This identifies exact shard bytes. A malicious peer can
compute a content address for malicious bytes; it is not an authenticated
commitment to the source. Original validity is decided by pinned reconstruction.

## Resource contract

| Quantity | Hard per-object bound |
| --- | ---: |
| Source chunk | 4 MiB |
| Shard payload | 1 MiB |
| CRS1 wire object | 1,048,657 bytes |
| Shards supplied to one decoder call | 4 through 6 |
| Codeword payload | `6 * ceil(L/4)` bytes |
| Decoding matrix | Fixed 4 by 4 over GF(256) |
| Row multiplication lookup tables | Four 256-byte tables |
| Extra-shard consistency checks | At most six supplied shards |

Encoding retains six shard payloads, at most 6 MiB, excluding caller input.
Recovery retains four reconstructed data buffers, the output buffer, and at
most one transient parity buffer: at most 9 MiB of their payload capacity,
excluding caller-owned shards and allocator metadata. These are algorithmic
allocation bounds, not measured process RSS or a global CPU/fairness guarantee.
The manifest is checked but is not cloned into each chunk binding.

No unbounded parameter search, corrupt-subset retry, automatic fetch, repair
loop, or background task is started. An eventual service must reserve ingress,
egress, CPU, buffers and storage under its original operation before decoding.
The fixed dimensions do not establish a production hostile-traffic cost bound.

## Exact vectors and controls

For source `01 02 03 04`, the six one-byte shard payloads are:

```text
01, 02, 03, 04, 45, 5e
```

For source ASCII `abcde`, the two-byte shard payloads are:

```text
6162, 6364, 6500, 0000, d67b, 9b69
```

For source bytes 1 through 13, the four-byte payloads are:

```text
01020304, 05060708, 090a0b0c, 0d000000, 11cadf54, 15eaf958
```

The small vectors and CRS1 address were independently calculated using Python
polynomial long division and canonical wire assembly. Native tests compare all
65,536 field products against a separate polynomial reference, recover from all
15 four-shard subsets, test all five/six-shard sets, test partial padding,
corrupt unused extras and a coherent nonzero-padding codeword, reject every
single-byte mutation of a small shard by shape or pinned recovery, and restore
an actual 4 MiB chunk after omitting two systematic shards.

```sh
bash scripts/project-preflight.sh
cargo test --manifest-path trillionnium/Cargo.toml -p trnm-data-availability --lib cell::erasure::tests
cargo run --manifest-path trillionnium/Cargo.toml -p trnm-data-availability --example cell_rs46_cost_v1
```

The cost example uses real deterministic synthetic bytes, fresh native source
and destination caches, and only shards 2,3,4,5. It records every chunk's
binding, encoding, wire roundtrip, valid reconstruction and corrupted-input
refusal wall time. It then writes each recovered chunk to the destination,
verifies the complete TCM1 payload, materializes it, and checks exact original
bytes. It retains all failures and source hashes. The 1 MiB+1 case is exercised
both as 65 small chunks and as one large chunk. Three repeats per case are
local observations, not throughput/tail-latency or population estimates.

## Remaining qualification

This component supplies bounded erasure encoding and reconstruction. It does
not supply DHT routing, distributed placement, independent custody, repair
funding, durable availability, an operator's delivery guarantee, WAN admission,
Hepta model quality, or PQ128. Existing PN5 independent-administrator and fault
campaigns remain required. No production activation or qualification flag is
changed by this profile or its tests.
