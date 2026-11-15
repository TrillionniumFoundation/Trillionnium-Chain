# Cell branch composition — 2026-11-13 UTC

**HOLD. Local source composition; no production, durability, model-efficacy or
whole-root recovery qualification is granted by this review.**

## Exact inputs

The isolated composition starts from #947
`d5f57aa038b80a29b0f02a8af78ae3b6584666f1`, combines #923
`fea6bcbde02cabab5b624a784ff20e57cac72586`, and compares the 38 Rust paths changed by
#932 `749cf478d5a03f325c2a04ea757d7edeea3285d1`. Between the latter two heads,
8 paths have identical bytes, 21 differ, and 9 original paths are absent.
An absent original path alone does not prove either equivalent replacement or
lost functionality. The #932 head has not been merged as a complete history
parent by this source patch.

## Native BEP52 and historical Cell framing

The current `cell/bep52_storage/peer.rs` uses the native BitTorrent handshake and
extension transport. Its live profile is now
`cell-bep52-storage-native-wire-v2`. The V2 storage binding, CBM2 mapping and CBL2
proof encodings remain unchanged; the independent mapping/proof fixed vectors
from #932 are restored.

The historical `cell/bep52_storage_peer.rs` at #932 used custom Cell TCP framing
under `cell-bep52-storage-pinned-tcp-v2`. That implementation remains in its
original Git history. Its old evidence must continue to cite that exact source;
it is not evidence for native BitTorrent wire execution. The old transport,
session types and overlapping reexports are not activated in this composition.

## Preserved admission controls

`retention/reservation_preflight.rs` and `retention/repair_preflight.rs` retain
#932's read-snapshot schema validation and temporary SQLite busy timeout capped
by the original remaining deadline, followed by restoration of the prior timeout.
The provider exposes the corresponding read-only repair admission component.
These checks create no new reservation, acknowledgement, repair intent or byte
charge; actual effect owners still recheck their own boundaries.

The paged plan again exposes the original catalog operation/funding identities,
and both native paged storage and recovery admission seed their identity sets
from that catalog. #923's complete page readback and controlled repair-layout
rechecks remain in place. These local changes do not replace the later #946
controls that the parent repository integration must retain.

## Reconciled recovery and delivery-cache contracts

Recovery uses the existing three target-observation passes: a read-only census
of the complete root, a bounded repair reread, and the final original-intent
readback. The census replaces the old per-chunk intermediate reconciliation
pass; no fourth complete target pass or larger codec reservation is introduced.
The original numeric read/input/reconstruction/repair allowance formulas and
maximum cache quotas remain unchanged.

The census inspects exact charged target bytes without acknowledging a pending
copy or writing an arena/journal row. It validates the complete codeword,
quorum, and fresh authority for every damaged slot across every page. The
read-only provider/arena repair-capacity checks then cover the entire proposed
set before any new repair effect. Only a bounded slot bitmap survives; payload
buffers are dropped per chunk. A later new target fault cannot expand that
admitted repair set. Observations remain sequential rather than an atomic
snapshot against concurrent external changes.

The shared successful payload/provider read path also fences the original row,
physical arena and descriptor after its final callback, without another payload
pass. This applies to both acknowledged reads and the new pending-target
inspection. It is not a replacement for the separate V2 observation APIs on
the SP27 branch; their source and terminal-fence changes remain an independent
input to the parent integration.

The final pass preserves each original intent's truthful entry replay kind.
A Pending original intent can become Done during its target-only observation;
that row is not relabeled as an earlier Done observation. A separate metadata
check requires all original intents actually be Done before successful return.
This check does not reread target payloads or start another effect.

The explicit `discard_manifest_until` operation is restored with stronger CAS
ownership: it removes only the named manifest and chunks no remaining canonical
cached manifest references. Reference inspection and deletion use one bounded
writer transaction, with schema/quota auditing and the original deadline.
Repeated hashes, missing original residue and retries do not double-decrement
usage. Other manifest owners retain shared chunks, including across cold reopen.
No retained arena, duty, funding, repair or retirement record is removed.

Paged storage and recovery now require a writable delivery cache and discard
each verified codeword's named staging set before continuing, including residue
after a prior Done result. A dedicated six-row cache can therefore be reused
across chunks. A shared cache may legitimately retain other owners' bytes and
must not be treated as an exclusive staging allowance; no quota is increased to
hide that distinction. Existing Default/HOLD/false qualification boundaries are
unchanged.

## Exact source review remains required

The historical seven-route/44-file authority register is retained with its
original source revision and HOLD/false flags. The composed
`cell/discovery/transport.rs` adds failure observations without replenishing the
original transport session, `cell/store.rs` registers bounded cache disposal,
and `trnm-pon-node/src/store.rs` adds grouped-owner exports. Their bytes differ
from the retained authority lock. Its actual
rejection must be preserved until the final integrated source revision receives
an explicit composition review; an uncommitted tree must not be labeled as either
historical source commit.

The corpus membership is the union of both source inputs. Original evidence
files are preserved. Native compilation, selected normal-operation tests and
source checks on this isolated candidate do not establish FinalUse, independent
custody, production activation or successful whole-repository consolidation.
