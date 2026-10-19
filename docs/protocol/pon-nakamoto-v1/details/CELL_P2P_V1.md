# Configured-peer cell byte distribution v1

This is the M09 native byte-distribution pilot selected by the
[sole development plan](../../../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md).
It is separate from transaction-batch DA, consensus, model quality, CURRENT and
FinalUse. Its native entrypoint is `trnm-cell` in `trnm-data-availability`.

## Authority and exact identity

The caller obtains a pinned manifest digest from its existing model-release
authority. Peers cannot select that digest. The manifest binds the model family,
base, parent, tokenizer, tensor-layout and runtime digests, the complete payload
SHA256, its length, the chunk size, and every ordered chunk length and SHA256.
The manifest ID is SHA256 of `trnm.cell-manifest.v1\0` followed by its canonical
bytes. A different parent or layout yields a different ID even if payload bytes
are identical. No mutable URL or peer advertisement is an authority.

The bytes remain opaque to M09. A successful download must still pass the normal
model loader's format, family, dimensions, artifact identity and publication
checks. In particular a P2P cache hit cannot install a version, change CURRENT,
accept a task, defeat withdrawal, or grant execution. The complete model's
release manifest must identify its required cells and their dependencies; the
union of arbitrary unrelated cached cells does not define a usable model.

## Canonical manifest and bounds

All integers below are unsigned big endian. Unknown versions, truncated fields,
trailing bytes, noncanonical family strings, inconsistent coverage and invalid
dimensions reject before the manifest becomes cached.

| Field | Encoding |
| --- | --- |
| Version | Four bytes `TCM1` |
| Family | One-byte length, then 1–64 ASCII letters, digits, `.`, `_` or `-` |
| Dependencies | Five 32-byte digests: base, parent, tokenizer, layout, runtime |
| Complete payload | Eight-byte size, then 32-byte SHA256 |
| Chunk layout | Four-byte chunk size and four-byte chunk count |
| Ordered chunks | Four-byte size and 32-byte SHA256 per chunk |

Chunk size is a power of two from 16 KiB through 4 MiB. A cell contains at most
16,384 chunks and 64 GiB; the smaller applicable limit wins. Empty cells reject.
Every chunk except the last has the declared chunk size. The final chunk closes
the exact complete payload length. The manifest parser accepts at most 1 MiB;
the maximum canonical list is smaller than that cap. There is no decompressor,
object deserializer, remote code import, path field, or executable weight format.

## Transport and resources

This pilot uses explicitly configured TCP peers, not the BitTorrent wire
protocol or a DHT. A request is `TCQ1`, a one-byte kind (`1` manifest or `2`
chunk), and a 32-byte digest. A response is `TCS1`, a one-byte status (`0`
present or `1` missing), a four-byte length, and that many bytes. Clients reject
unknown status, excessive length and bad hashes before accepting content.
Each connection handles one request.

A client has at most eight distinct peers and four concurrent fetch workers.
The response queue is bounded by the worker count. Each connection has an
absolute deadline of 10 ms through 30 s, covering connect, request and response;
slow byte-by-byte progress does not restart it. The complete operation has an
explicit deadline up to 24 hours, a caller-specified payload-byte budget and at
most 100,000 connection attempts. Failures consume the original budget. No
unbounded discovery, retry, pending-packet or repair queue exists.

Workers rotate the first supplier by chunk index and try the remaining explicit
peers on absence, truncation or corruption. A corrupt supplier cannot alter the
pinned version. Valid chunks already received remain available to a later
explicit retry. The final report counts actual connection attempts, accepted
downloaded bytes, cached/downloaded chunks, rejected responses and suppliers.
It reports successful complete retrieval only after a fresh ordered full-file
hash check. Cache scans and full verification check the operation deadline
between chunks and before successful return. Blocking local filesystem calls
are not forcibly preempted; final local materialization is a separate owner
operation. Reports of end-to-end loading must include these actual disk costs.

The finite server bounds connections and lifetime, reads one connection at a
time and applies an absolute per-connection deadline. This gives bounded memory
and connection occupancy, not a public-service fairness or bandwidth guarantee.
Admission/transport authentication, peer reputation, DHT eclipse resistance,
storage payments, erasure coding, global quotas and long-term replica renewal
remain separate work. These TCP bytes are not encrypted. Private model bytes
need an authorized private transport or an independently specified encrypted
artifact format before public distribution.

## Cache integrity and publication

`CellStoreV1` uses a separate SQLite namespace with application ID `0x54434c31`
and schema version 1. A populated foreign database is refused. New manifests
are persisted only after full decoding and pinned-ID comparison. New chunks
are persisted only after length and SHA256 verification. Each cache read checks
the bytes again. A corrupt disposable chunk is removed and becomes a missing
chunk, allowing the ordinary multi-peer fetch path to repair it. This rule does
not apply to consensus history, signed facts or a model-release journal.

Complete materialization streams the ordered verified chunks into an owned
temporary file in the destination directory, verifies the full hash and length,
syncs the file, then publishes with a no-replace hard link and directory sync.
An existing output is never replaced. A partial download never becomes the
requested output. A crash after publication can leave a complete file whose
caller did not receive success; the caller must inspect and verify that file,
not interpret an error as permission to overwrite or select another version.
The containing directory is an owner-controlled local filesystem; protection
from a hostile process with the same filesystem authority is not claimed.

## Ordinary commands

Build from the repository after the normal project preflight:

```sh
cargo build --locked --release --manifest-path trillionnium/Cargo.toml \
  -p trnm-data-availability --bin trnm-cell
```

`trnm-cell --help` lists the closed argument grammar. `pack` takes a local input,
an explicit family and all five dependency digests, and emits the manifest ID.
`serve` takes an explicit bind address, lifetime and connection budget. `fetch`
takes the pinned ID, explicit peers, byte/time/connection budgets and an absent
output path. `verify` rechecks a complete local version. `manifest` exports the
canonical pinned manifest for the existing release owner. No command implicitly
discovers a model, changes its authority or activates a consensus profile.

## Executable acceptance

`cargo test --locked --manifest-path trillionnium/Cargo.toml -p
trnm-data-availability --lib cell::` contains actual TCP and disk tests for:

- Origin removal followed by a fresh multi-source retrieval from two separate
  caches, with exact payload comparison and no overwrite of an existing output.
- External SQLite chunk corruption followed by ordinary network repair.
- Missing final chunks, absence of a published partial output and retry using
  the previously verified cache.
- Wrong manifest pins, changed parent context, noncanonical encodings and a
  payload exceeding the caller's byte budget.
- A corrupt network supplier, honest fallback and oversized response rejection.
- Exhausted total connection budget, retained verified chunks and a later
  bounded successful retry.
- A real peer dripping response bytes more frequently than the original
  request deadline; it cannot extend that absolute deadline, and an honest
  second peer supplies the same pinned complete bytes. The wide wall-time
  assertion is a liveness regression, not a performance improvement claim.
- Refusal to repurpose an existing foreign database.

Loopback tests establish byte and failure semantics. Cross-host delivery and
actual loader receipts must name their source, model, hosts and failures; neither
case establishes independent operators, arbitrary large-model loading or a
permissionless storage network by itself.
