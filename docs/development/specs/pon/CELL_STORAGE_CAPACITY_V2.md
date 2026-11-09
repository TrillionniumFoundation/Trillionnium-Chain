# Complete model transport and retained-plan capacity V2

Status: implementation candidate; production qualification remains HOLD.
This extends the existing storage convergence candidate at `0746a462e80067b78317597f2fa4bacf5e3db958`.
It does not reinterpret the older BEP52 V1 or CRP1 formats.

## The composed-profile capacity problem

The original direct BEP52 binding requires a 16 KiB TCM1 chunk. TCM1 and that
BEP52 profile allow 16,384 chunks/leaves, so the direct descriptor covers at
most 256 MiB. CRP1 separately limits the complete canonical protected
manifest/chunk union to 128 records. If every protected member uses this direct
16 KiB encoding, that composition covers at most 2 MiB of payload. The latter
is a conditional composition bound, not a general CRP1 payload limit and not
its 2 MiB metadata limit.

The retained model observation contains a 269,060,552-byte weight file:

| Quantity | Exact value |
| --- | ---: |
| Original payload | 269,060,552 bytes |
| Original 4 MiB storage chunks | 65 |
| Underlying 16 KiB transport leaves | 16,423 |
| Excess over 256 MiB | 625,096 bytes |

The [BEP52 specification](https://www.bittorrent.org/beps/bep_0052.html) fixes
the Merkle base block at 16 KiB and permits a larger power-of-two logical
piece length. The 16,384-leaf restriction belongs to our old profile.

## Large storage pieces with standard transport blocks

`CellBep52StorageBindingV2` uses the actual storage-chunk byte stream to derive
the BEP52 subtree for each logical piece. It preserves the original TCM1
manifest, payload hash and larger storage chunks. A 4 MiB piece contains up to
256 transport blocks. Its ordinary storage SHA-256 is never substituted for
the Merkle subtree root.

The independently pinned mapping binds the original manifest to all logical
piece roots. `CBM2` mapping and `CBL2` companion proof have their own namespaces.
Companion proofs are not encoded as standard peer-protocol hash messages.
The TCP profile uses standard handshakes, metadata, bitfields, block requests
and hash messages with 16 KiB blocks and the explicitly declared larger piece
length. Endpoints remain explicit caller inputs; this does not add a DHT,
tracker service, public listener, peer authentication or encryption.

The receiver assembles a logical piece privately. It publishes its original
storage chunk only after both the ordinary TCM1 hash and the BEP52 subtree
check. Partial pieces do not become acknowledged storage chunks. A successful
member fetch re-reads its complete original ordered payload. Consequently,
the sample can retain 65 storage records while transferring 16,423 blocks.

The structural per-object profile remains finite: at most 16,384 storage
pieces, each at most 4 MiB, hence at most 64 GiB. The mapping contains at most
524,340 bytes; metainfo at most 525,312 bytes. Those bounds do not establish a
64 GiB execution or availability observation. Other complete-version, arena,
network, time and task-memory admissions may impose lower limits.

## One complete-version transfer owner

`CellBep52ReleasePlanV2` requires the exact entire TCV1 manifest union and
binds every corresponding mapping and infohash into one independent SHA-512
commitment. Missing, duplicated, foreign or context-mismatched members cannot
form that plan. The current model/environment loader pins are rechecked for
each member call and final observation.

`CellBep52ReleaseSessionV2` holds one non-cloneable accounting owner across
all members, failures and retries. Its original deadline, cancellation latch,
connections, byte/message counters and refusal history do not restart at a
file boundary. Its explicitly admitted V2 caps differ from the old V1
constructor, which continues to reject more than eight connections.

The complete-release profile bounds payload at 16 GiB and the canonical
manifest/chunk inventory at 4,096. Connection, wire-byte and message allowances
are explicit, finite caller inputs. A final whole-release readback reserves
its complete logical bytes/chunks before reading; unsuccessful attempts keep
their reservation. Source preparation and codec CPU are not inferred from
socket byte counters. An end-to-end cost observation must measure them
separately, together with storage, failures and process resource usage.

## Complete catalog with coordinated pages

`CRR2` is one immutable root for the complete current protected catalog union;
`CRG2` pages are exact contiguous partitions of that union. A page is not a
CRP1 complete-catalog plan. The root commits all original catalog anchors,
versions, manifests, funding identities, providers and page identities.

The V2 union admits at most 4,096 chunk records. Pages contain between one and
128 records, with a separate 256-page ceiling; using full 128-record pages
needs at most 32 pages. The original 2 MiB bound remains per page, and the
root itself also has an explicit 2 MiB metadata cap. Serialized page bounds
and total chunk bounds are checked before allocation or native effects.

Whole-plan native preflight checks every page and original funding claim and
accounts for each provider's existing lifetime obligations, including retired
history. It does not grant 4,096 fresh slots for every plan. All original CSP1,
TCR1 and M12 owners and irreversible responsibilities remain authoritative.
Native execution uses one verification budget across pages. Final success
re-reads the actual original targets and the current complete catalog.

The current paged profile uses one fixed roster of six providers. Each provider
must explicitly admit one lifetime obligation for every protected chunk, plus
all of its existing history, and enough physical shard capacity. For example,
95 chunks cannot be admitted by six providers configured for 64 obligations
each. Additional providers are not automatically assigned by this profile.
The small test-provider configuration is not a real-model deployment size.
Capacity and obligation limits are persisted with the provider owner. A
larger deployment needs explicitly sized provider namespaces/generations;
changing a configuration file cannot resize an existing owner or discard
its irreversible obligation history.

The file owner supplies both a lightweight root/catalog observation and an
explicit complete current observation. The latter verifies every page's
actual bytes, global coverage and identities, then rechecks root and catalog;
it is a sequential observation, not an atomic filesystem snapshot.

## Native recovery across pages

`recover_native_cell_paged_shard_plan` uses a dedicated non-cloneable V2
recovery budget. Metadata and native claims for the entire plan are checked
before effects. Repair uses at least four actual original provider shards;
catalog bytes or an old cache are not alternative recovery sources. Original
Pending/Done operations are reconciled without reissuing their effects.

The same budget and admitted execution CPU owner cover all pages and final
readback. After repair, the executor checks all original storage intents,
requires Done, verifies every codeword and checks the complete pages/catalog
again. Its CPU receipt covers admitted execution and final readback; it does
not include metadata/funding preflight CPU. The latter still uses the original
wall deadline. This distinction must remain in cost reports.

## Immutable typed release snapshot

The [CTS1 release snapshot](CELL_RELEASE_SNAPSHOT_V1.md) combines TCV1,
mandatory TMA1 and an actual declared composition configuration file into
one independent pin. Model root, base/adapter/expert dependencies, tokenizer,
environment and declared dense tensor names/shapes/dtypes remain bound to the
same version. The task's immutable resident handle checks the same current
pins, original deadline and cancellation owner on use.

CTS1 admits only the existing dense F32/F16/BF16 safetensors contract.
Quantization or another container/ABI requires a separate implemented and
reviewed profile. A composition-profile digest identifies an interpretation;
it does not prove that arbitrary hashed components are compatible. The real
loader must implement that interpretation. Provider `latest` is never used
to select another task component.

## Acceptance and remaining boundaries

Local tests must distinguish actual bytes from structural boundary fixtures.
Required observations include original-chunk/whole-file readback, truncated
transfers, bounded shared retries, complete inventory pinning, page corruption
before effects, historical provider capacity, cross-page four-shard recovery,
native Pending/Done reconciliation and typed loading of the same snapshot.

A real-model acceptance must execute, on the same committed source and
operation: approved source and release pins, cold BEP52 acquisition, complete
retention, source/cache removal, anchored shard recovery, immutable loading
and a subsequent actual task. The historical 269,060,552-byte model load is
not a V2 transport run. Local synthetic bytes of the same size are useful
capacity controls but must never be reported as that model observation.

The explicit `cell_sealed_research_next_use_v2` research entry exercises
BEP52 acquisition, complete TCA3 copy retention, deletion of both publisher
and received caches, anchored copy recovery, CTS1 admission and two CHB1
sealed-worker forwards in one operation. This entry does not execute the
CRR2/CRG2 native four-of-six shard recovery path or admit M12 funding.
Its observations and the separate native paged-shard tests must remain
distinct; neither is a substitute for the other.

Six local provider directories do not establish independent operators or
failure domains. This work does not establish WAN throughput, continuous paid
custody, general model compatibility, ordinary Hepta FinalUse or production
activation. Original service/campaign qualification conditions remain intact.
