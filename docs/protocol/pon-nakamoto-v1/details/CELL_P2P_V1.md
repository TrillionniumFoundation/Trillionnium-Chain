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

## Owner-declared release set

`CellReleaseManifestV1` adds a separate TCR1 object supplied by the existing
release owner. Its canonical encoding is four bytes `TCR1`, the same family
and five dependency digests, a four-byte member count, then sorted unique
32-byte TCM1 IDs. All dependency and member digests must be nonzero, including
an explicitly named initial parent/genesis. Parsing is capped at 1 MiB and
32,760 members before allocation. Its ID is SHA256 over
`trnm.cell-release-manifest.v1\0` followed by the complete canonical bytes.
It checks only the declared set; omitted dependencies, safe tensor shapes and
model executability remain the release and loader owners' decisions.

TCM1 carries five opaque dependency digests; TCR1 adds a same-context member
set. Neither format encodes dependency edges, router/activation sets, explicit
quantization/shape/ABI constraints, authority, custody or retention duties. A
dependency digest alone does not make the corresponding bytes retrievable.
The versioned closure target below must enumerate those bytes and semantics;
do not add unversioned fields or reinterpret the existing five digest slots.

`fetch-release` takes the locally supplied TCR1 file and an independently pinned
release ID. It first obtains all member manifests, verifies the exact common
context and checks the aggregate payload bytes and chunk-reference limits before
fetching any payload. Members share the original absolute deadline, connection
counter and actual response-byte budget. Per-member success does not replenish
any resource. Shared chunks count for each actual full-payload verification.

After full cache readback, the command publishes the exact TCR1 bytes as a
create-only completion marker. Pre-publication errors leave no marker; a
post-link durability or cleanup error can coexist with a complete marker and
must be reconciled through the same pinned identity and `verify-release`, not
overwrite or blind resubmission. A marker grants neither a storage lease nor
CURRENT/FinalUse; consumers revalidate bytes and their own authority before use.
The local input and output namespace is owner-controlled. Filesystem checks
are cooperative and do not supply a hard wall-time guarantee against hostile
local filesystem peers or blocking storage.

## Transport and resources

This pilot uses explicitly configured TCP peers, not the BitTorrent wire
protocol or a DHT. A request is `TCQ1`, a one-byte kind (`1` manifest or `2`
chunk), and a 32-byte digest. A response is `TCS1`, a one-byte status (`0`
present or `1` missing), a four-byte length, and that many bytes. Clients reject
unknown status, excessive length and bad hashes before accepting content.
Each connection handles one request.

Serving remains serial by default. The explicit `serve_cells_bounded` API and
`serve --bounded-workers 1..4 --max-served-bytes N` opt into a configured-peer
pilot with at most four active workers and no application waiting queue. Full
slots immediately close the accepted socket; those refusals consume the original
connection limit. Independent read-only cache connections validate the existing
namespace, never create a database or repair corrupt chunks, and hold no database
lock across socket I/O. All workers share the original service deadline and actual
application-write budget, including headers and partial failed responses; socket
overhead and unread peer requests are outside that counter. A request reads at
most 37 application bytes, so the aggregate input bound is 37 times the accepted
connection limit. Shutdown stops intake and joins existing work within its
original deadline; filesystem, SQLite and hashing remain cooperative. Reports
expose accepted/refused connections, completed responses, peak active workers and
actual bytes written. These local controls do not establish fair service when
all slots are occupied, independent custody, discovery or PN5 acceptance.

The explicit development [provider rendezvous](../../../development/specs/pon/CELL_PROVIDER_DISCOVERY_DEV_V1.md)
shares each client's original connection, response-byte and absolute-deadline
reservation with the subsequent pinned fetch. It does not select the bounded
server mode or create a new serving budget. The separate
[native-funded retention owner](../../../development/specs/pon/CELL_RETENTION_V1.md)
stores obligations and arena bytes in its own namespace; ordinary bounded
serving reads only the disposable Cell cache. A discovery or retention database
is rejected as a cache, and a corrupt read-only chunk remains missing without
deleting its stored row. Ordinary writable fetch can subsequently repair it.

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

`CellStoreV1` uses the fresh TCL4 SQLite namespace, application ID `0x54434c34`
and schema version 4. Old TCL1/TCL2/TCL3 and populated foreign databases are refused;
opening never resets or migrates them. Each writable open requires an exact
persisted `CellCacheConfigV4`: finite logical bytes, chunk rows, manifest
rows and main-database image bytes. The last cap is 4096-aligned, from 256KiB
to 2TiB; every writer sets and reads back `max_page_count` at fixed 4096-byte
page size. Cold readers/writers refuse wrong page sizes, excessive page counts
or oversized main-file tails without truncation. This bounds supported SQLite
DB images/file length, not allocated blocks or guaranteed backing capacity. Logical bytes count every live chunk payload, manifest wire and 32-byte
content key. Atomic insert/update/delete triggers enforce that one whole-cache
allowance across pack, direct puts, batch fetch, discovery and retention rehydration.
Same-hash UPSERTs charge only the size difference; a failed eight-chunk transaction
rolls back its rows and allowance together. Reopening checks complete table/trigger
definitions and bounded actual SUM/COUNT against the counters without repairing
them. Catalog validation copies at most the expected object count plus one, guards
string byte lengths before copying and inspects every object regardless of its
name prefix. Only the two exact primary-key automatic indexes are accepted, with
their original type/name/table and genuinely NULL SQL; an oversized non-NULL SQL
value cannot become an accepted NULL. The foreign-database check stops at its
first object, including an internal object left by a previously used database. A failed download keeps its committed verified prefix charged. Read-only
serving loads these persisted limits and holds no query snapshot across socket I/O.
Actual corrupt-cache deletion returns only logical cache allowance. It does not
retire a paid duty, release native funding or prove that filesystem blocks were freed.

The TCL4 writer gate bounds supported cache WAL growth across independent
processes without treating a checkpoint threshold as a quota. Initialization,
manifest/chunk UPSERTs, the original eight-chunk transaction and corrupt-cache
DELETE share one zero-byte, OS-locked `-writer-lock-v4` identity. Canonical parent
paths share the lock; the owner-controlled namespace must not be replaced,
renamed or aliased while open. Unix opens reject observed symlinks and hard links.
Old writers cannot open the new application/schema; there is no in-place TCL3
migration or protection against arbitrary external SQLite writes.

Before every mutation, the owner requires a complete TRUNCATE checkpoint and
an actual zero-length WAL. A pinned reader that prevents that checkpoint returns
`CELL_CACHE_WRITER_BUSY` before the batch changes rows or counters. Releasing the
reader permits the same original batch to retry. The gate shares the existing
five-second writer-contention allowance with SQLite through one absolute budget;
the checkpoint itself refuses immediately on a held reader. Filesystem and SQLite
calls remain cooperative, so this is not a hard elapsed-time guarantee.

Every connection disables close-time checkpoints, every writer disables automatic
checkpoints and dirty-page spill, and `synchronous=FULL` remains required. Only
this writer gate checkpoints. For the locked bundled SQLite 3.46.0 backend, one
transaction from an empty WAL has at most one frame per main-image page plus up
to 16 FULL-sync padding frames. With main cap `C` and 4096-byte pages, the WAL
file-length allowance is `32 + (C/4096 + 16) * 4120` bytes. Its separate SHM
allowance is `32768 * (1 + ceil((C/4096 + 16)/4096))` bytes, conservatively allowing
the shorter first wal-index region. Existing oversized sidecars are refused;
post-write checks are invariant diagnostics, not the preventive limit. Prevention
comes from serialized zero-WAL admission and the spill-free bounded transaction.
A backend-version substitution fails closed pending new qualification.

These are logical file-length bounds, not allocated-block reservation, guaranteed
free space, a filesystem/global quota, or I05 funding. New-cache rollback-journal
creation, SQLite memory/temp peaks, caller temporary/output files, block allocation
and other stores remain separate resource owners and open exits. Materialized
output is bounded only by its caller's declared payload contract. The immutable
TCL3 control still demonstrates WAL 449112 > main cap 262144; its original writes,
retries and greater-than assertion are preserved in a test-only historical owner.

Official SQLite contracts describe [TRUNCATE checkpoint completion](https://sqlite.org/pragma.html#pragma_wal_checkpoint),
[dirty-page spill](https://sqlite.org/pragma.html#pragma_cache_spill) and
[single-transaction WAL behavior](https://sqlite.org/wal.html#avoiding_excessively_large_wal_files).
FULL sector-padding and wal-index capacity are also checked against the exact
locked SQLite amalgamation; no `journal_size_limit` or automatic checkpoint is
used as a hard cap. New manifests
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
report additions do not change TCM1, TCQ1 or TCS1; the separately bounded local
cache uses the fresh TCL4/schema4 namespace described above.
`verify` rechecks a complete local version. `manifest` exports the
canonical pinned manifest for the existing release owner. No command implicitly
discovers a model, changes its authority or activates a consensus profile.

Every writable command (`pack`, `fetch`, `verify`, `prepare-release`,
`fetch-release`, `verify-release`) also requires `--cache-max-bytes N
--cache-max-chunks N --cache-max-manifests N --cache-max-db-bytes N`. Reuse the same exact limits for
that cache on every invocation; a per-member payload budget is not a new cache
allowance. `serve` and `manifest` use only an existing read-only TCL4 cache.

`fetch-release --store DB --release-file ROOT --release HEX --peers IP:PORT,IP:PORT
--output ABSENT_MARKER --max-bytes N --max-chunks N --max-response-bytes N
--max-connections N --seconds N` fetches the owner-declared set. `verify-release`
uses the same store, root, pinned release ID and total byte/chunk/time budgets
without a network call. The new CLI reports have distinct
`trnm.cell.release.fetch.v1` and `trnm.cell.release.verify.v1` identities. TCM1,
TCQ1 and TCS1 are unchanged; only the local cache schema is TCL4. The root is supplied
locally; this increment does not add public root discovery.

## Executable acceptance

The [TCL4 three-host relay](../../../../evidence/pon-upgrade-implementation-20261018/native-rounds/cell-tcl4-release-three-host-20261024/SCOPE.md)
executes the existing configured-peer path with all271,178,816 public model
bytes and266 chunks. The release build completes the two120s fetch windows in
33.255s and38.782s, with the original supplier stopped before the second hop.
The consumer rehashes all eight material files; no loader or model forward runs.
The preceding development-build deadline failure is retained separately. Both
attempts use the same finite TCL4 caps and unchanged27 driver assertions. This
does not close the funded retention, physical/global storage or public-discovery
obligations below.

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

The same existing native suite includes [TCL4 cache admission controls](../../../../trillionnium/crates/trnm-data-availability/src/cell/cache_budget_tests.rs)
and [complete catalog controls](../../../../trillionnium/crates/trnm-data-availability/src/cell/cache_catalog_tests.rs):
exact byte/row boundaries and full-cache dedup, two real concurrent writers,
atomic eight-row rollback, cross-reopen immutable limits, retained verified
prefixes after a later quota refusal, actual corrupt-row deletion, bounded
catalog/counter/trigger validation, reserved-prefix trigger refusal and exact
automatic-index identity/NULL SQL checks.
Writable and read-only cold-open failures preserve the original database.
The existing [CLI controls](../../../../trillionnium/crates/trnm-data-availability/tests/cell_fetch_deadline_cli.rs)
require every writer cap before cache creation and prohibit read-only manifest
export from creating a missing cache. The existing M12 [native paid-storage controls](../../../../trillionnium/crates/trnm-pon-node/src/store/storage_service/cache_quota_tests.rs)
require actual cache deletion and rehydration quota refusal to leave the original
paid obligation, retained-byte target, funding row and budget report unchanged.
These controls execute through the existing workspace matrix; they do not replace
its retained tests or establish hard physical storage bounds.

Loopback tests establish byte and failure semantics. Cross-host delivery and
actual loader receipts must name their source, model, hosts and failures; neither
case establishes independent operators, arbitrary large-model loading or a
permissionless storage network by itself.

The later [controlled original-owner observation](../../../../evidence/pon-upgrade-implementation-20261018/native-rounds/real-model-owner-controlled-20261025/SCOPE.md)
actually loads the eight TCL4 peer-fetched upstream files in Hepta `07731d31`.
Its unchanged signed neural read and verified terminal unload case passes in
17.753s under the original per-operation bounds. The adapter comes from the
separate controlled parameter lineage. This advances configured-peer material
testing from bytes to a real model forward, without qualifying a selected
complete release, CURRENT installation, funded storage or the three-round loop.

## PN3 release closure and real loader interface

This is I09 of the
[sole plan](../../../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md).
The TCM1 configured-peer pilot above and a fixed-profile eleven-material
controlled byte closure are implemented. The latter [source-bound observation](../../../../evidence/pon-upgrade-implementation-20261018/native-rounds/real-model-owner-controlled-20261025/i09-eleven-material-controlled-20261026.json)
on Chain `915f933c` / Hepta `da4a920` passes the original signed native case
using all eleven objects from one loopback peer. Its overall handoff still fails
at I10 selected installation. General selected dependency closure, ordinary
loader/I10 integration, full runtime closure and public storage duties below
remain target work; the target message names are not new exported APIs.
Reuse the existing chunk/store/fetch owner rather than add another weight store.
P1 closure/loader integration is a required delivery for the P0 PN3 full-loop
gate; completing only its P0 interface prerequisites cannot close that gate.

| Priority / existing plan interface | Delivery owner and dependency | Required acceptance |
| --- | --- | --- |
| P0 / I06–I08, PN3 | M10/M11/M14 and Hepta artifact/evaluation/TaskFlow owners | Freeze the selected real-model profile, authorized export, exact task/release/parent bindings and local installation authority before network fetching can support an upgrade. Download success never closes this prerequisite. |
| P1 / I09–I10, PN3 | M10 release owner -> M09 fetch/store -> existing Hepta safe loader | Deliver a versioned complete dependency closure and bounded request/result mapping, then demonstrate origin-loss retrieval, compatible safe installation and actual next-task readback for the three-cycle loop. |
| P1 / I05 PN4 funding; P2 / I09 PN5 public service | M09 retention/discovery with M12 funding, M14 service and M17 evidence | P1 establishes funded duties and reserved capacity before storage acknowledgement. After that and the configured-peer real-loader path, P2 qualifies independent custody, renewal/repair and bounded discovery; a cache marker cannot acknowledge a storage duty. |

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

These are proposed schema responsibilities, not fields already encoded by TCM1/TCR1.
Freeze maximum manifest bytes, dependency depth/fanout, number of Cells and total
required bytes. Reject cycles, duplicate/conflicting identities, missing mandatory
dependencies and unsupported runtime/shape before installation. Deduplicate shared
base bytes in storage and cost accounting. A new closure schema needs a new domain
and exact independent vectors; do not reinterpret TCM1 payload hashes or headers.
Preserve TCM1/TCR1 decoding unchanged and specify explicit old/new caller refusal;
the new closure may reference existing TCM1 objects without claiming TCR1 proves
closure completeness. Bounds cover shared-base and tokenizer bytes as well as
Cells, and bound any parent/delta reconstruction depth and full-checkpoint cost.
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

Specify the versioned target request/result through the existing I09 seam:
request pins the closure/profile, original operation, selected local generation
and total reservations; result names the same identity, verified required-object
set, materialized payload hashes, actual costs and typed incomplete/refused
outcome. Those are target semantics, not claims about current CLI JSON fields.
Missing dependencies never yield a complete result. The release owner validates
closure completeness and the safe loader validates formats/shapes without remote
code import before the existing FinalUse owner can admit the selected generation.

The following **target interface**, still to be implemented and versioned, makes
that seam reviewable. These are semantic message names, not new exported APIs,
current CLI fields or authority owners.

| Message / owner | Required typed contract |
| --- | --- |
| `ResolveReleaseRequest` / M10 -> M09 | Original operation and attempt, closure codec/domain/ID, model profile, selected generation, mandatory object set and a single shared resource reservation. Mutable tags are resolved by M10 before this request. |
| `ResolveReleaseResult` / M09 -> M10/Hepta | Same operation/closure/generation, `Complete`, `Incomplete`, `Refused` or `Unknown`; verified object IDs, absent IDs, actual suppliers/counters, materialization identities and completion/readback status. Only a fresh complete closure may return `Complete`. |
| `AdmitReleaseRequest` / M10 -> existing Hepta owners | Complete byte result plus independently current release/withdrawal, compatibility, resource and installation authority. M09 supplies no authority token. |
| `LoadedReleaseReadback` / actual Hepta runtime -> M17 | Installed closure and generation, actual base/tokenizer/router/Cell hashes, loader/runtime profile, next task identity and its result. A fetch receipt or intended configuration is insufficient. |

Target error categories are `InvalidClosure`, `UnsupportedCodec`,
`IncompatibleProfile`, `MissingDependency`, `Unavailable`, `IntegrityFailure`,
`BudgetExhausted`, `DeadlineExceeded`, `PublicationConflict`, `Withdrawn` and
`UnknownEffect`. Every result preserves the original identity and consumed
reservation; errors do not replenish it. After publication may have begun,
`UnknownEffect` permits only exact-target verification/reconciliation. A new
attempt needs explicit remaining authority and budget; it cannot blindly repeat
the effect, silently replace the output or obtain a fresh reservation by rename.

Before closure implementation, M10/M09 and the Hepta loader owner jointly freeze
the new codec's canonical byte order, hash domain, supported algorithms and
maximum byte/object/depth/fanout/active-set limits. Define independent vectors
for empty/oversized lists, cycles, aliases, conflicting dimensions and duplicate
dependencies. All size arithmetic is checked before allocation. The closure
also freezes reconstruction order and maximum delta depth; loading cannot follow
an unbounded parent chain. Existing TCM1/TCR1 parsers and identities remain exact.

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
Require zero successful completions with missing mandatory objects, zero wrong-
version substitutions, unauthorized CURRENT changes and budget replenishments
in every success/failure cohort. The
original byte/connection/deadline counters must include corrupt providers and
all closure members. Freeze cold/warm latency, memory, sample-count and completion
targets before the run; undersampled p99 remains unknown. Weight MB/s, cache hit
rate and model-load latency are separate from unique client-confirmed chain TPS.

The PN3 freeze record must contain numeric payload/dependency counts, chunk
distribution, total cold bytes, cache state, concurrency, link rate/RTT/loss,
disk/runtime/device profile, deadlines, every resource ceiling and sample count.
Select limits from the intended deployment envelope and an independently retained
baseline, then sign/hash that record before candidate measurement. Lower bounds
such as bytes/link-rate inform the target; a failed run cannot choose its own
new limit. Publish complete and incomplete cohorts separately, with raw duration
samples, quantile method and the preselected confidence interval. Require at
least 100 completed samples before reporting a measured p99; this floor alone
does not establish confidence, and inadequate cohorts keep the target unqualified.
Completed-sample quantiles are conditional on completion: retain all attempted
requests and failure/timeout censoring denominators, never invent a completion
duration for an unresolved attempt or claim an all-attempt p99 from survivors.
This is a target measurement rule, not a new claim about the two existing relay samples.

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

BitTorrent v2 wire compatibility, a DHT and persistent request multiplexing are
**reviewable PN5 adapter options**, not selected replacements for TCQ1/TCS1 or
the development rendezvous. Benchmark them against the current serial and
four-worker configurations using the same release, cached prefix, hosts, network
faults, concurrency and total budgets. Record setup cost, verified useful MB/s,
time to complete the least-available mandatory object, CPU/RSS/disk cost and
honest service under flash crowds; higher raw socket throughput alone fails the
comparison. A rare-piece scheduler must use bounded observations and queues;
untrusted availability claims cannot create unbounded probes or work.

Deliver discovery after PN3 works with configured providers. Use a separately
versioned peer/provider envelope with bounded TTL, candidate count, lookup hops,
query rate and original operation budgets. Validate every response against the
pinned content identity; DHT/provider advertisements never select releases or
prove durable possession. Implement eclipse/Sybil controls with stated bootstrap/
network assumptions, bounded parallel fetch and peer backoff. A provider
signature alone does not prove independent administration. Keep repair/discovery
traffic inside measured disk, CPU, bandwidth and connection quotas.

The serial default and explicit bounded serving pilot do not qualify public
fairness or discovery. The P2 M09/M14 target must freeze per-provider and
aggregate ingress/egress, queue length, service deadlines and slow-peer admission;
discovery and repair consume those same original reservations. A slowloris,
provider-spam or eclipse cohort must meet the preregistered honest complete-release
deadline without unbounded queues, TTL refresh or retries. Test expired/malformed
advertisements, conflicting contacts and bootstrap loss; none may change a pinned
release or advertise private bytes without the existing export owner's permission.

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

The I05 retention interface must bind acknowledged release roots and reachable
object set, provider/failure-domain identity, reserved bytes, start/expiry,
renewal owner, repair deadline/budget and original funding/settlement identity.
This is a versioned target duty, not a cache-schema or TCR1 field. Keep its facts
with the existing retention/funding owners; cache eviction cannot erase them.
GC starts from every retained release and unexpired duty, traverses the complete
closure, and rechecks those roots before deletion. A shared base stays reachable
while any retained version requires it. An expired lease reports loss of the
promise explicitly; it cannot silently claim all historical versions remain.

For every promised version v, require its reachable bytes R(v) to be present,
retrievable and covered by the declared replica threshold, not merely some
network-wide union U of cached Cells. Test at least two retained versions sharing
a base and one distinct dependency, including origin plus one provider loss,
renewal failure, repair interruption and GC. No acknowledged reachable object
may be deleted; repair must restore three independent complete replicas within
the frozen budget/deadline or report a failed duty. Publish coverage per release,
not average cached bytes. An all-versions promise needs explicit retention duration,
growth/funding and archival owners; no infinite-storage guarantee follows here.

Exit is the PN5 independent WAN campaign, including churn, eclipse attempts,
corrupt/slow providers, replica loss, hot-model flash crowds, budget exhaustion,
restart and repair. Report complete-release availability and loader completion
for every requested release, not just available popular chunks. The 72-hour
minimum and replica objective are development coverage, not current production
guarantees. Long-term durability and permissionless incentives need independent
review and funded sustained observations.

## Bounded provider order within one acquisition session

The configured-peer and discovered-peer fetch paths retain at most eight
per-provider failed-attempt counters for the current session. Before fetching
each manifest or chunk, they snapshot those counters and stably prefer fewer
failures; equal counters retain the original cyclic order. Snapshotting before
sorting keeps the comparator stable while concurrent chunk workers finish.
The provider list remains fixed during the session. Bootstrap discovery does
not write these provider counters, and the discovery expiry can only shorten
the original deadline.

This is an ordering hint, not a persisted reputation or an exclusion decision.
Every configured provider remains a fallback for each object, including a
provider that lacked a different object earlier. A local manifest-persistence
failure is returned directly and never treated as a remote failure. Every
object still attempts each provider at most once, and the original connection,
received-byte and absolute-time reservations remain shared across all members.
Canonical manifest, context, chunk and complete-release verification remain
mandatory; neither a successful response nor a preferred position selects a
release or grants installation authority.

The native regression uses an actual empty provider and an actual complete
provider with one worker. Two manifests and four chunks require six successful
requests. Under the unchanged seven-connection reservation, the previous order
spent three connections on the empty provider and failed with only four useful
requests. The session hint completes with six useful requests and one rejection.
The existing disjoint-provider, corrupt-byte, exact aggregate-budget, deadline,
resumption and create-only publication controls remain in the library suite.
This finite control shows avoided repeated failed attempts; general throughput,
independent failure-domain availability and the PN5 WAN target remain unqualified.
