# Cell BEP52 Binding V1

Status: portable, offline candidate component for the existing PN5 extension
seam. Production qualification remains `HOLD_NO_GO`. This specification extends
the [Cell storage contract](CELL_MODEL_STORAGE_V1.md) and the
[provider discovery seam](CELL_PROVIDER_DISCOVERY_DEV_V1.md); it does not replace
TCM1, CDP1, the existing cache, or the sole development plan.

## Purpose and authority

`CellBep52BindingV1` derives one exact external descriptor from an independently
pinned TCM1 manifest and its complete `CellContextV1`. The external torrent names
the **raw cell payload**, not the TCM1 wire object, release manifest, closure,
model release, or executable. The owner must supply the expected manifest ID and
context independently of peer data.

The adapter does not perform discovery, announce, dial, write files or cache
objects, allocate a device, select CURRENT, or grant Runtime FinalUse. Returning
a descriptor is not authorization to publish a private manifest or advertise a
private model. The export owner and an eventual network adapter still control
public/private scope and the original operation's remaining resource reservation.

A payload can have the same external infohash in multiple Cell contexts. Each
binding and companion proof also retains the internal manifest ID, which commits
to context and the declared whole-payload SHA-256. Matching a magnet alone does
not establish that a model, release, or context is approved.

## Restricted interoperable descriptor

The external descriptor uses the SHA2-256 tree and canonical bencoding specified
by [BEP52](https://www.bittorrent.org/beps/bep_0052.html). Its leaves hash 16 KiB
blocks; the last block hashes only its actual bytes. Missing leaves are zero
digests. Parent nodes hash the concatenated child digests. The tree is the
smallest complete binary tree covering the file; a one-block file's root is its
single leaf. The v2 infohash hashes the exact encoded info dictionary.

This implementation deliberately fixes the following profile:

| Field | Exact supported value |
| --- | --- |
| Profile | `cell-bep52-binding-v1` |
| External object | One nonempty raw Cell payload |
| File tree | `cell.bin` with one empty-key properties dictionary |
| Display name | `cell.bin` |
| `meta version` | `2` |
| `piece length` | `16384` |
| Hash algorithm | SHA2-256, full 32-byte infohash |
| TCM1 chunk size | Exactly `16384` |
| File length | Exact TCM1 size |
| `pieces root` | Derived from all ordered TCM1 chunk SHA-256 values |
| Piece layers | Present; actual leaf hashes for files larger than one piece |
| Single-piece layers | Present empty dictionary |
| Additional fields | Rejected by exact profile comparison |

A larger TCM1 chunk SHA-256 cannot be interpreted as a BEP52 subtree root.
Larger-chunk manifests are explicitly refused, even if their payload happens
to fit in one short chunk. No repacking or identity migration is implicit.
General BEP52 supports empty files; TCM1 requires a nonempty Cell, so this
adapter does not support that otherwise legitimate torrent case.

`info_bytes()` emits canonical sorted bencoding. `metainfo_bytes()` includes
the complete `piece layers` dictionary, with no balancing leaves in its layer
values. `verify_info_bytes()` and `verify_metainfo_bytes()` compare exact bytes
against the derived profile. They do not decode arbitrary bencoding and then
hash a potentially normalized representation. The full metainfo check also
checks the piece layers, which lie outside the infohash.

The fixed file name is data only; this component never interprets peer-supplied
names as filesystem paths. Supporting another name or torrent layout requires
another explicit profile and vectors, not a permissive fallback.

## Magnet subset

[BEP9](https://www.bittorrent.org/beps/bep_0009.html) defines the v2 exact topic
as a full hexadecimal multihash. The sole accepted URI in this profile is:

```text
magnet:?xt=urn:btmh:1220<64 lowercase hexadecimal SHA2-256 characters>
```

`CellBep52MagnetV1::parse` performs bounded syntax validation only. The `12 20`
multihash prefix denotes SHA2-256 and a 32-byte digest. `verify_magnet()` also
compares that digest to the independently pinned binding.

Duplicate exact topics, SHA-1 `btih`, other multihashes, percent encoding,
fragments, whitespace, display names, trackers, explicit peers and unknown
parameters are rejected. Some are legitimate features of broader BEP9 clients;
they are outside this version's profile. In particular, a URI cannot smuggle
an endpoint or change the current discovery address policy.

This is not a BitTorrent peer, metadata exchange, or DHT implementation. There
is no automatic DHT fallback when a URI contains no tracker. A future adapter
must preserve the PN5 operation identity, original deadline, address/export
policy and shared connection/response-byte/validation/CPU reservation.

## Cell companion proof CBP1

`chunk_proof(index)` produces a bounded local companion proof. It uses BEP52
hash-tree semantics but **is not a BEP52 peer `hashes` message**. The latter's
request correlation, ranges and wire framing still need an independent adapter.

CBP1 integers are unsigned big-endian. There is exactly one encoding:

| Bytes | Field |
| --- | --- |
| 0..4 | ASCII `CBP1` |
| 4..36 | Original TCM1 manifest ID |
| 36..68 | Full v2 infohash |
| 68..72 | Zero-based chunk index |
| 72..76 | Actual, unpadded leaf count |
| 76..77 | Number of sibling digests |
| 77 onward | Bottom-up 32-byte sibling digests |

The sibling count equals `ceil(log2(leaf_count))`, including zero for one leaf.
Index orientation is derived from the index bits; no separately supplied left/
right flags can contradict it. Index must be strictly below actual leaf count.
Proofs cannot address padding leaves. Extra/truncated bytes are rejected before
allocation. A wholly padded sibling subtree has its unique recursively derived
zero-leaf hash, which is checked even before payload verification.

`verify_chunk()` checks proof shape, both internal and external pins, leaf
coverage, the original TCM1 chunk's exact byte length and SHA-256, and the root
reconstructed by the proof. A successful result concerns that one chunk only.
The existing `CellStoreV1::verify_complete` or materialization path must still
check every required byte and the whole-payload digest. Release closure, tensor
layout, owner approval, retention, and FinalUse remain separate obligations.

## Resource bounds

| Input or retained state | Bound |
| --- | ---: |
| Actual leaves | 1 through 16,384 |
| Payload supported by this profile | At most 256 MiB |
| Accepted info dictionary | At most 256 bytes |
| Accepted metainfo | At most 525,312 bytes |
| Proof depth | At most 14 siblings |
| Encoded CBP1 | 77 through 525 bytes |
| One chunk's hash input | 1 through 16,384 bytes |
| Retained tree digests | At most 32,767 (1,048,544 payload bytes) |

These are per-object algorithmic bounds, not RSS, CPU-time reservations or
global hostile-input cost bounds. Construction also clones the bounded TCM1
manifest, and metadata generation allocates its bounded output. Construction
is linear in the number of leaves; each generated or checked proof is
logarithmic, plus the chunk hash for verification. Repeated valid or invalid
requests still need admission and aggregate resource accounting in a future
network owner. This pure component cannot replenish any operation's budget.

## Vectors and verification

The `abc` fixture has one short, unpadded leaf and this exact infohash:

```text
667db46d8af4a61ad7548bd7307f347b27ed3b6e680d92477f6e563a568f5173
```

The fixture `A * 16384 || B * 16384 || C` has three actual leaves and one
zero-digest padding leaf. Its root is:

```text
f3c9ca846350d432de56330cc6375ce0c80a3a2ad81952a20d3771d88f5f1e1f
```

Tests retain exact info bytes and independent Python `hashlib`/sorted-bencoding
reference hashes. They cover five leaves with a fully padded upper subtree,
exact and partial final pieces, altered piece layers outside an unchanged
infohash, noncanonical bencoding, wrong object/context pins, malformed magnets,
proof truncation/overflow, reordered chunks, cross-index replays, every
single-byte mutation of a valid proof, and maximum supported tree size.

```sh
bash scripts/project-preflight.sh
cargo test --manifest-path trillionnium/Cargo.toml -p trnm-data-availability --lib cell::bep52::tests
cargo test --manifest-path trillionnium/Cargo.toml -p trnm-data-availability
cargo clippy --manifest-path trillionnium/Cargo.toml -p trnm-data-availability --all-targets -- -D warnings
cargo run --manifest-path trillionnium/Cargo.toml -p trnm-data-availability --example cell_bep52_cost_v1
```

The example retains three repetitions at each of 3, 16,384, 16,385, 1,048,576
and 1,048,577 synthetic bytes, including non-power-of-two leaf counts. It
separately records native packing with cache writes, binding construction,
descriptor checks, each proof construction/decode, each valid/corrupt chunk
verification, and complete cached-payload verification. It records monotonic
wall time, every failure and source hashes. It does not measure CPU time, WAN
throughput, model latency, VRAM, durable custody, cost recovery or rewards.

## Qualification still open

This component closes only the explicit pinned-object mapping, restricted
magnet parser and bounded Merkle-proof component seam. No DHT/Sybil/eclipse
resistance, independent-administrator swarm, erasure coding, funded retention,
end-to-end model loading, or 72-hour PN5 acceptance follows from these tests.
No full-chain PQ128 conclusion follows from use of SHA2-256; that requires the
separate cryptographic specification and lifetime budget. Production controls
remain unchanged and `HOLD_NO_GO` remains in force.
