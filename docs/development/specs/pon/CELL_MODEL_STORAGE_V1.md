# Complete model byte storage and admission contracts

This M09 continuation implements the storage work selected by the
[sole development plan](../../TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md).
It composes the existing [TCM1/TCR1 cache and transfer owner](../../../protocol/pon-nakamoto-v1/details/CELL_P2P_V1.md),
[TCD1 dependency closure](CELL_DEPENDENCY_CLOSURE_V1.md),
[native physical retention owner](CELL_RETENTION_V1.md) and
[provider discovery](CELL_PROVIDER_DISCOVERY_DEV_V1.md).
These are local candidate contracts. An integrity check, a completion marker or
a local retention readback cannot select CURRENT or issue FinalUse.

## Implemented boundaries

| Layer | Implemented contract | Separate owner or remaining qualification |
| --- | --- | --- |
| Objects | Canonical TCM1/TCR1/TCD1; TMR1 model root; TMT1 exact dense tensor roster; self-contained TMA1; fixed, versioned SHA256 domains. | Additional codecs, quantization, architecture and model quality require their own profiles. |
| Deduplication | Raw SHA256 chunk CAS, canonical TCX1 chunk reuse, one request per distinct missing chunk, shared retained manifest duties. | Cross-context physical retention aliases and semantic adapter rebasing are not implemented. |
| Dependencies | Complete declared TCD1 graph, exact file mappings, TMR1 router roster and bounded direct parents, independently pinned loader context. | The release owner must enumerate every real dependency; bytes cannot reveal an omitted external requirement. |
| Transfer | Bounded sources, verified-prefix resume, explicit rarest-observed-first inventory, explicit TCQ2/TCS2 sequential connection reuse and aggregate budgets. | Public service fairness, transport confidentiality and WAN performance need separate deployment qualification. |
| Discovery | Existing signed current hints, TTL and replay checks; balanced observed bootstrap contributions and IP-prefix diversity. | This is a rendezvous heuristic, not a DHT implementation or proof of eclipse resistance or operator independence. |
| Retention | TCA2 complete-release catalog over the original physical arena; immutable terms, funding identities, replica declarations, repair owners and deadlines. | M12/payment admission, current chain height and independent replica evidence remain externally supplied. |
| Collection | Every pending, acknowledged or expired-but-unretired root protects its members; physical retirement also refuses unsettled repairs. | A disposable cache eviction is not a paid-duty release or proof of freed filesystem blocks. |
| Use | Fresh complete payload and declared tensor checks before exact create-only TMA1 completion publication. | Ordinary current selection, withdrawal, compatibility, resource admission and FinalUse remain required at actual use. |

## Model roots and canonical byte reuse

TMR1 has a new domain `trnm.cell-model-release-root.v1\0`. Its exact wire is
`TMR1 | closure_length:u32 | complete_TCD1 | router_roster_hash:32 |
parent_count:u8 | parent_root_ids:32[]`. Integers here are big endian. The total
limit is 1,049,129 bytes and there are at most 16 nonzero, strictly increasing
direct parent IDs. The router hash uses
`trnm.cell-model-router-roster.v1\0`, the router count as u16, and each router's
path length/path, manifest ID, payload hash and u64 payload length in the
closure's canonical path order. An empty router roster has an explicit hash.

`CellModelReleaseRootV1::verify_parent_roots` checks each supplied direct parent's
identity, family and strictly older generation. It does not recursively fetch
ancestry. The owner still pins the selected root and the original TCD1 loader
context independently. A parent digest is lineage metadata, not permission to
install its descendant or evidence of measured model improvement.

TCX1 has domain `trnm.cell-chunk-delta.v1\0`. Its wire is
`TCX1 | base_TCM1_id:32 | target_length:u32 | complete_target_TCM1 |
source_count:u32 | source_indices:u32[]`, capped at 1,114,156 bytes. The source
count equals the target chunk count. `0xffffffff` declares a new chunk;
otherwise the index is below 16,384 and must identify the first matching
`(SHA256, length)` chunk in the independently pinned base. Decode alone does
not replace `verify(base)`.

`fetch_delta_to_file` requires the exact base, target and delta identities,
verifies the full available base, fetches missing target chunks and verifies
the ordered full target before publication. Manifest persistence, network,
cache writes and materialization share the original absolute deadline. There
is no executable patch, arithmetic weight transform or unbounded reconstruction
chain. Chunk reuse can cross contexts because the bytes are exactly equal;
that does not prove adapter, tokenizer, layout or runtime compatibility.

TCM1/TCR1 retain their exact common-context rule. Two releases can share the
same base/tokenizer manifest and physical duty when that complete context is
unchanged. A changed context produces a new TCM1 identity; raw cache chunks can
still deduplicate, while the current physical arena may reserve another duty
for that new manifest. The two-version archive control freezes the same
context (including `context.parent`) and changes the TCD1 generation, TMR1
lineage and router. It is not evidence
of cross-context physical deduplication.

TCD1 currently defines Base, Tokenizer, Preprocessor, Adapter, Router and
Configuration data roles. Arbitrary expert payloads can be content addressed,
but this continuation defines no Expert ABI, expert activation policy or safe
architecture conversion. Adding such semantics requires an explicit versioned
loader/closure profile. No existing role or parent slot is repurposed.

## Strict tensor contract and self-contained manifest

TMT1 uses `trnm.cell-tensor-contract.v1\0`, hash-profile tag 1 (SHA256-v1) and
codec tag 1 (dense safetensors-v1). It binds one exact TMR1 digest and an ordered
list of TCD1 file indices, with every expected tensor name, dtype and shape.
All Base and Adapter files must be covered. Additional files may be explicitly
declared; the verifier does not infer their architecture or ABI.

The supported dtype set is F32, F16 and BF16. Rank is at most eight; each
dimension is in `1..=u32::MAX`. Scalars use `[]`; empty tensors and quantized
formats are outside this profile. Names are nonempty UTF-8 strings of at most
255 bytes, without control characters or the reserved `__metadata__` name;
their order is exact and no Unicode normalization is performed. There are at most 16,384 tensors across the contract, at most
256 file entries, at most 1 MiB of contract bytes and at most 64 GiB of declared
dense data per file. Shape products and byte totals use checked arithmetic.
Unknown version, hash profile, codec, dtype or noncanonical ordering rejects.

The container layout follows the
[upstream safetensors format](https://github.com/safetensors/safetensors#format).
The first eight bytes encode a little-endian JSON-header length. Before
allocation the verifier bounds that length to 1 MiB and the actual file size.
It rejects duplicate keys, escaped-name aliases, unknown tensor fields,
duplicate metadata, invalid types and an incomplete or additional tensor
roster. Only bounded unique string-to-string metadata and trailing ASCII-space
header padding are allowed. Every dtype and shape must exactly match TMT1.
Data offsets must cover the data area exactly, without overlap, holes, overflow
or trailing bytes. A correct outer SHA256 does not excuse an invalid container.
Each tensor entry must itself be a named JSON object. A positional array such
as `["F32", [2], [0, 8]]` is rejected even when every value and the full payload
hash match the pinned contract. Legal object-field reordering remains accepted;
the required-field, duplicate-field and bounded-shape checks still apply.

After metadata checks, `verify_reader` streams the entire payload with a 64 KiB
buffer, verifies the complete TCD1 SHA256, checks the final size again and uses
the caller's same absolute deadline for reads and seeks. Cache-backed reading
independently verifies each TCM1 chunk and drops the prior chunk before loading
the next, retaining at most one 4 MiB chunk buffer. These are cooperative
checks; blocking filesystem/SQLite calls and their internal allocations are
not a hard real-time or whole-process RSS guarantee. Tensor numerical quality,
NaN/Inf policy and safe actual model execution are separate loader decisions.

TMA1 uses `trnm.cell-tensor-model-manifest.v1\0` and contains the complete
TMR1 and TMT1 with exact bounded section lengths. Its maximum is
`12 + MAX_MODEL_RELEASE_ROOT_BYTES_V1 + MAX_CELL_TENSOR_CONTRACT_BYTES_V1`
(2,097,717 bytes). Decode validates canonical roundtrip and exact root binding.
It is supplied with an independent owner pin; it is not accepted because a
peer, a rendezvous or its embedded metadata claims that pin.

`prepare-tensor-model` validates independently pinned TMR1 and TMT1 inputs and
publishes TMA1 with create-only output semantics. `fetch-tensor-model` requires
the same explicit authentication policy, original closure ID, context,
generation and loader profile as `fetch-closure`. It validates those inputs
before writable cache open or network dial. CPR2 authenticates its original
embedded TCR1 statement only; the TMA1/closure pins remain independently owned.

Full closure acquisition and fresh cache readback precede tensor verification.
Only after every declared tensor file passes does the existing marker owner
publish the exact TMA1 bytes. Wrong pins, missing members and invalid tensors
leave no completion marker. A later cache-only explicit retry still repeats
the required verification. Post-link errors retain the existing exact-target
reconciliation rules. Every result has no selection or use authority.
After the no-replace link, directory synchronization and owned temporary-file
cleanup finish before the original deadline is checked again. A late completion
returns an error while preserving the exact published marker for reconciliation.
This refuses a late success; it cannot preempt blocking filesystem operations or
undo a completed publication.

## Transfer and discovery budgets

TCQ1/TCS1 remain the default one-request-per-connection profile. Optional
`--scheduling rarest-first-v1` uses TCI1/TIS1 inventory pages of at most 256
positions. The 43-byte query binds the pinned TCM1, start and count. Replies
use a canonical least-significant-bit-first bitfield, with zero unused bits.
Inventory is a hint; every downloaded chunk and the full payload are still
verified. Queries, corrupt/truncated responses, retries and data share the
original connection, byte and time reservations. Unsupported inventory grants
no authority. Its endpoint remains eligible for ordinary retrieval of the same
pin within the remaining original budget; a spent query budget is not renewed.

Repeated positions of the same missing `(hash, size)` schedule only one
payload request. Existing V1 `cached_chunks` and `downloaded_chunks` retain
manifest-position accounting; their sum still covers the ordered manifest.
`downloaded_bytes` counts actual newly committed payload bytes once per
distinct content object. Connection attempts and received-response bytes are
actual transport counters. Three repeated positions can therefore be covered
by one request and one chunk's payload bytes without changing V1 handoff checks.

Explicit `--transport persistent-v2` selects TCQ2/TCS2. A request is 37 bytes:
`TCQ2 | kind:u8 | digest:32`. A response is
`TCS2 | status:u8 | length:u32be | bytes`. The old object bytes and pinned
identities are preserved, while unknown or old protocol magic is refused.
Sequential reuse does not multiplex requests or negotiate an automatic
fallback. It requires explicit `--max-requests` and
`--max-requests-per-connection`, each bounded by 100,000, with the latter no
greater than the total. Serving also requires bounded workers and a byte cap.
Inventory/rarest scheduling is not combined with this profile.

The shared peer pool decrements the connection allowance only on actual dials.
Frame attempts, including bounded pool-lock waits, consume the request
allowance. Each connection receives one fixed deadline at dial/accept, capped
by the original operation deadline and request timeout. A subsequent frame
does not refresh it. A partial or failed frame discards the connection without
an uncharged hidden retry. All frames consume the same response-byte budget.
Server request-attempt reports include reserved idle/EOF/partial frame slots;
completed-request reports count only complete responses. Bounds remain finite
across workers, sessions, shutdown and failed writes.
The persistent server stops new connection and frame admission when actual
written response bytes exhaust the original allowance, including zero and
partial-response allowances. A temporary allowance held by another worker is
not exhaustion: an unused reservation may still be returned. Already admitted
workers retain their original deadlines and accounting. Availability queries
also pass that same request deadline through manifest readback and decoding.

The rendezvous continues to verify its current signed records and TTL under
the existing finite query. Selection first balances the configured bootstrap
sources that actually returned each current statement, then prefers distinct
IPv4 /24 or IPv6 /64 prefixes and IPs. It retains bounded fallback candidates
when no more diverse endpoint exists. A newer sequence does not inherit the
old statement's observed sources. This limits one bootstrap's simple slot
flooding; it does not prove distinct administrators, endpoint control, custody,
Sybil resistance or a public DHT's security.
Both classic and PQ rendezvous exchanges check the enclosing Cell operation's
actual response-byte allowance before consuming another connection slot, dialing
or sending a query/announcement. A zero allowance or a fully consumed response
stops subsequent bootstrap attempts. In-flight byte reservations may refund
unused capacity; they are not treated as actual exhaustion. This does not change
the existing discovery record, TTL, signature or connection-count limits.

Rarest-first and persistent connections are separate explicitly selected
transport profiles; a combined inventory-over-persistent protocol is not
implemented. Likewise, the legacy serial `serve_cells` API is not an aggregate
egress-byte owner. CLI serving selects metered admission with explicit
`--bounded-workers` and `--max-served-bytes`; the serial default must not be
reported as having that egress contract.

## Complete-release retention and collection

TCA2 is a fresh SQLite catalog: application ID `0x54434132`, user_version 2,
wire `TCA2`, contract domain `trnm.cell-release-retention-contract.v2\0` and
versioned row checksums. Archived TCA1 and foreign databases are refused; they
are not migrated or overwritten. The catalog retains at most 128 roots,
including retired history, with a maximum 4 MiB contract per root.

Each contract binds the original operation/funding identities, responsible
owner, failure-domain declaration, replica slot/threshold (1..16), start,
expiry and repair deadline, complete TMR1 and every original per-manifest
physical contract. A shared object must use the exact same immutable original
physical operation and terms. The optional typed TMA1 slot binds that same
TMR1; strict tensor retention preserves the complete validation plan across
cold reopen. `None` explicitly retains an opaque model-byte plan and cannot
be reported as tensor-plan retention. The catalog does not synthesize TMT1
from downloaded bytes or infer an absent owner pin.

Reservation records the complete root before physical reservations. A partial
or failed reservation remains a protected pending root and can resume under
the original identity. ACK requires complete fresh physical readback. Recovery
can repopulate the disposable cache from the retained arena after the original
cache/provider is gone. Recovering TMA1 metadata does not skip a new tensor
verification, CURRENT check or FinalUse.

Before recording a new root, a read-only admission pass rejects permanent
contradictions with this fixed store: the complete aligned member set must fit
the arena, immutable physical history must have enough record identities, and
no retired operation or historical funding identity may be repurposed.
Unmaterialized members of existing pending roots also reserve their original
operation/funding identities and future history slots. This pass does not
allocate bytes, grant funding, or promise that currently occupied or fragmented
slots are immediately available. The physical writer still checks its live
layout. Genuine contention or I/O failure after intent publication preserves
the complete pending root. Previously stored impossible pending intents remain
readable and protected; this admission change does not migrate or erase history.

Catalog mutations use an IMMEDIATE writer transaction and one original
absolute deadline through SQLite writer wait, precommit and postcommit
readback. Physical reservation rechecks the available layout inside its
writer transaction. Deadline exhaustion never manufactures an ACK or refunds
consumed work. After an uncertain committed effect, reconcile the exact
original operation; do not rename it to obtain a fresh allowance.

The Node paid-storage adapter uses the same deadline-aware physical reservation
entry point. An already expired request is rejected before opening a budget or
creating a physical obligation. Checks between original owner calls and around
completion preserve exact same-identity reconciliation after an uncertain
commit; no late outcome grants a refund or a second physical dispatch. The M09
physical writer wait spends the original deadline. M12's existing journal calls
still contain their own cooperative SQLite intervals; these boundary checks do
not make every M12 wait preemptible or replace its internal busy timeout.

Every pending, acknowledged and expired-but-not-explicitly-retired release
protects its complete member set. `retire_object` holds the catalog writer
transaction while auditing every root and checking the exact original physical
contract; only a fully unreferenced object reaches the physical retirement
owner. Expiry alone is not collection permission. Both release retirement and
the physical writer gate reject an unsettled repair, including a healthy
target whose interrupted repair has not yet reconciled. Replay history and
charged repair work remain retained.

A successor release can renew references only while each original physical
term already covers the requested new interval. This implementation refuses
to invent a funded extension, rewrite paid terms or prove a current chain
height. Extending physical leases, funding/price/currency admission, successor
authority and independent replica observations remain their original owners.
The local replica declarations are not proof of the declared complete copies.
No erasure-code threshold, automatic renewal service or infinite retention
promise is implemented.

## Ordinary owner integration still required

The Node's current funded adapter in `store/storage_service.rs` accepts the
per-object `CellRetentionStoreV1` and its original physical contract. It does not
yet select the complete `CellReleaseRetentionStoreV2` catalog for an ordinary
funded release lifecycle. The local catalog's complete-root protection is real,
but it is not a claim that every external payment or release owner has admitted
the complete graph. Existing task-escrow observations do not themselves lock
coins against cancellation/reorganization or pay a provider after ACK.

Similarly, `CellResidencyV1` supplies immutable TCD1 byte views and process-local
selection hints. The ordinary Hepta owner must verify the independently required
material roster and tensor/runtime compatibility on those same bytes, then
enforce current generation/withdrawal, resource admission and FinalUse at actual
use. Neither a TMA1 completion marker nor a local retained root grants this
authority. Independent custody, funded renewals and actual loader integration
retain their original qualification gates.

The [completion-boundary regression record](../../../../evidence/cell-storage-owner-boundaries-20261104/README.md)
keeps the original failed cases and exact-source reproduction entry point.

## Verification and remaining acceptance

The [continuation evidence](../../../../evidence/cell-storage-continuation-20261104/README.md)
records exact source provenance, retained test coverage, failed regression
observations, commands and actual results. TMR1 has an independent Python
oracle and fixed vector. Native controls cover canonical and wrong-domain
inputs, multi-source transfers, shared chunks, original deadlines, interrupted
repairs, concurrent catalog writers, two retained versions, cold recovery,
invalid tensor containers and real CLI publication/refusal. These observations
do not replace the ordinary actual-loader product-loop or PN5 WAN campaigns.

Remaining qualification includes real selected model/runtime profiles,
architecture/expert ABI and quantization admission, complete release-owner
dependency enumeration, CURRENT/withdrawal/FinalUse at actual use, funded
renewal, independent complete replicas or a specified erasure-code scheme,
and repair/loss/eclipsing/hot-model cohorts over the original independently
operated WAN campaign. No component PASS promotes any production, public-WAN,
whole-chain security or model-efficacy flag.
