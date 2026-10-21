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
explicit deadline up to 24 hours, a caller-specified payload-byte budget, a
shared response-byte budget and at most 100,000 connection attempts. Failures
consume the original budgets. No
unbounded discovery, retry, pending-packet or repair queue exists.

`max_response_bytes` limits actual application response bytes returned by socket
reads across the entire fetch, including TCS1 headers, manifests, corrupt bodies
and truncated responses. It is separate from accepted payload bytes. Workers
reserve capacity before each read, limit the read buffer to that reservation,
and refund unread capacity after partial reads, EOF or errors. Concurrent reads
cannot overshoot the budget; workers wait for an in-flight reservation's refund
within their original deadline. Unread socket-buffer data, outgoing requests,
TCP/IP overhead and retransmissions are outside this application counter.
The limit accepts zero for cache-only retrieval and has a hard maximum of
`8 * 64 GiB + 8 * 1 MiB + 9 * 100000` bytes.

Workers rotate the first supplier by chunk index and try the remaining explicit
peers on absence, truncation or corruption. A corrupt supplier cannot alter the
pinned version. Valid chunks already received remain available to a later
explicit retry. The final report counts actual connection attempts, accepted
downloaded bytes, all received response bytes, cached/downloaded chunks,
rejected responses and suppliers. `downloaded_bytes` still counts only verified
payload chunks newly accepted into the cache. `received_response_bytes` also
counts rejected responses and manifests; a complete cache hit needs zero.
When retrieval cannot complete after exhausting the byte budget, the typed
`ResponseByteBudgetExhausted` error and CLI diagnostic
`CELL_RESPONSE_BYTE_BUDGET_EXHAUSTED` retain the actual received count and limit.
Storage errors remain storage errors even if the response budget is fully used.
It reports successful complete retrieval only after a fresh ordered full-file
hash check. Cache scans and full verification check the operation deadline
between chunks and before successful return. The library's `fetch_cell` retrieves
and verifies content into the cache without materializing an output file. The
CLI uses `fetch_cell_to_file`, which passes that same original absolute deadline
through complete verification and final local materialization; it does not start
another time budget after the download.
`CellStoreV1::materialize_until` also accepts an existing caller-owned deadline,
while the original `materialize` API remains explicitly unbounded by time.
Reports of end-to-end loading must include these actual disk costs.

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
The combined fetch checks its original deadline before materialization, while
verifying chunks, after the complete write, and after file synchronization but
before the no-replace hard link. Expiry at that last checkpoint refuses
publication, removes the owned temporary file and retains verified cached chunks
for a later explicit call. These are cooperative checks: blocking filesystem
calls cannot be preempted, and the hard link, directory synchronization or
cleanup can return after the deadline. Once publication begins, the operation
does not remove a complete output merely because time has elapsed. A later
durability or cleanup error can therefore coexist with a complete published
file. This contract is not a hard real-time or model-loading latency guarantee.
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
output path. Its optional `--max-response-bytes N` sets the response budget;
the bounded default is `2 * max-bytes + 2097152 + 9 * max-connections`.
Its successful `trnm.cell.fetch.v1` JSON adds `received_response_bytes` and
`max_response_bytes` without changing existing payload counters. These local
report additions do not change TCM1, TCQ1, TCS1 or the cache schema.
`verify` rechecks a complete local version. `manifest` exports the
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
- Exact response-byte limits across four concurrent socket reads, including a
  limit one byte short; no aggregate overshoot or successful partial response.
- Partial manifest headers/bodies and corrupt responses exhausting the byte
  budget before publication, with exact received counts on the failure.
- Truncated bodies and rejected headers consuming only bytes actually received,
  followed by honest fallback inside an exact remaining byte budget.
- An exact-budget multi-chunk fetch with four workers and a subsequent complete
  cache hit with zero response-byte allowance.
- A real peer dripping response bytes more frequently than the original
  request deadline; it cannot extend that absolute deadline, and an honest
  second peer supplies the same pinned complete bytes. The wide wall-time
  assertion is a liveness regression, not a performance improvement claim.
- Refusal to repurpose an existing foreign database.
- A genuinely expired materialization deadline leaves the output absent while
  the original explicit no-deadline API can still publish the verified payload.
- An actual network fetch, complete write and file synchronization followed by
  a test-only scheduler pause until the original absolute deadline expires.
  The publication checkpoint receives that same `Instant`, refuses the output
  and cleans the temporary file; an explicit later cache-only call can succeed.
- Fresh complete verification rejects corrupted cache bytes and a mismatched
  complete-payload digest before publication, and never replaces an existing
  output. The combined network-to-file success path returns the exact bytes.

Loopback tests establish byte and failure semantics. Cross-host delivery and
actual loader receipts must name their source, model, hosts and failures; neither
case establishes independent operators, arbitrary large-model loading or a
permissionless storage network by itself.

## PN3 release closure and real loader interface

This is I09 of the
[sole plan](../../../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md).
The TCM1 configured-peer pilot above is implemented; the release closure,
ordinary loader integration and public storage duties below are target work.
Reuse the existing chunk/store/fetch owner rather than add another weight store.

M10 and the existing Hepta release/artifact owner must define a bounded,
versioned release manifest before M09 can retrieve a whole compatible model.
Its canonical commitment must bind:

- Release/parent/family, artifact and evaluation-policy identities, and the
  selection/withdrawal context checked by the existing installation owner.
- Exact shared base/Encoder, tokenizer/preprocessing, runtime/loader ABI and
  tensor layout, including dtype, quantization, dimensions and adapter ranks.
- Router/graph identity, ordered required Cells and their pinned TCM1 IDs,
  dependency edges and expected complete payload digests/lengths.
- Mandatory/optional activation sets, maximum active Cells and any permitted
  fallback behavior. A fallback changes no weights/version outside this closure.
- Compatibility and resource ceilings sufficient for safe local loader admission.

These are proposed schema responsibilities, not fields already encoded by TCM1.
Freeze maximum manifest bytes, dependency depth/fanout, number of Cells and total
required bytes. Reject cycles, duplicate/conflicting identities, missing mandatory
dependencies and unsupported runtime/shape before installation. Deduplicate shared
base bytes in storage and cost accounting. A new closure schema needs a new domain
and exact independent vectors; do not reinterpret TCM1 payload hashes or headers.
If a BitTorrent infohash or IPFS CID is exposed, bind its algorithm, codec and
exact byte mapping explicitly. It is not interchangeable with the domain-prefixed
TCM1 manifest ID or the raw full-payload SHA256.

The loader-side request is a trusted selected closure, missing pinned Cells,
finite peer candidates, absolute deadline, connection/byte/CPU/disk reservations
and an owner operation identity. M09 returns only facts about complete verified
bytes, observed suppliers, resource consumption and unresolved dependencies.
The caller still verifies format/compatibility and current release/withdrawal/
generation/resource authority before installing. A timeout keeps verified chunks
for bounded explicit retry; it cannot choose another model or refresh its own
authorization. A verified byte receipt never becomes a final-use token.

Implement local SSD -> RAM -> device-memory staging and bounded prefetch through
the actual neuron runtime. Bind cached tensors/features to exact content and local
generation, and count download, full hash, disk, deserialization and transfer to
device in cold-load latency. For illustration, 200 MB over 100 Mbit/s alone has
a 16-second ideal transfer lower bound before protocol, hash or disk costs.
Per-token WAN loading therefore needs locality, prediction or a declared cold
miss outcome; content addressing cannot remove that delay. An unavailable
required Cell returns Unavailable or a fallback explicitly selected in the same
release, never an arbitrary peer's substitute.

PN3 acceptance uses the ordinary selected release and actual loader: seed a
complete closure across finite providers, remove the origin, retrieve missing
Cells, validate dependencies, install via the existing owners and run a real
next-generation task. Inject shared-base/version mismatch, bad quantization/
shape, malicious loader bytes, partial/corrupt chunks, duplicate output paths,
deadline/storage exhaustion and withdrawal before admission. Retained partial
bytes must not become a selected release. Record cold/warm p50/p95/p99, failures,
peak RSS/device memory and actual loaded hashes; the existing TCP tests alone
do not supply this receipt.

## PN5 swarm discovery, storage and repair target

BitTorrent-style content addressing, multi-source pieces, resumable verified
chunks and bounded rare-piece scheduling are suitable data-plane techniques.
Consensus carries exact release commitments and scoped settlement, while model
bytes stay off the ordering hot path unless the work relation explicitly needs
them. A node may store a subset; a usable distributed model is the selected
release's complete reachable dependency closure, not the union of all cached
Cells in the network. Local inference still needs the active weights and KV/
activation memory. Remote execution of missing layers is a separate compute,
privacy and latency protocol, not implemented by P2P byte fetch.

Deliver discovery after PN3 works with configured providers. Use a separately
versioned peer/provider envelope with bounded TTL, candidate count, lookup hops,
query rate and original operation budgets. Validate every response against the
pinned content identity; DHT/provider advertisements never select releases or
prove durable possession. Implement eclipse/Sybil controls with stated bootstrap/
network assumptions, bounded parallel fetch and peer backoff. A provider
signature alone does not prove independent administration. Keep repair/discovery
traffic inside measured disk, CPU, bandwidth and connection quotas.

For private artifacts, require existing export authorization and an explicitly
specified authenticated encrypted transport or encrypted-artifact format with
separate key/access ownership. Hashes, DHT lookups and public chunks can disclose
content or interest; an authorized private query must not silently enter public
discovery. The present unencrypted TCP pilot does not provide that profile.

The initial PN5 development objective is three complete replicas in three
independent failure domains, actual retrieval after losing the author and one
provider, and repair back to three under frozen byte/time/funding limits. Measure
possession by real byte retrieval and random integrity probes; report unresolved
missing chunks and oldest repair debt. Reserve byte-time and repair resources
before acknowledging storage duties; renewal and payment expiry are explicit.
Do not promise deletion of already exported copies. Disposable cache eviction
must not erase acknowledged storage duties or consensus account history.
Erasure coding needs a versioned shard relation, k/n availability assumptions,
decode/repair verification and resource measurements before selection.

Exit is the PN5 independent WAN campaign, including churn, eclipse attempts,
corrupt/slow providers, replica loss, hot-model flash crowds, budget exhaustion,
restart and repair. Report complete-release availability and loader completion
for every requested release, not just available popular chunks. The 72-hour
minimum and replica objective are development coverage, not current production
guarantees. Long-term durability and permissionless incentives need independent
review and funded sustained observations.
