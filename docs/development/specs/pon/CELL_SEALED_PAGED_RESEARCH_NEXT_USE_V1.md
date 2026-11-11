# Paged sealed research next use V1

This explicit research route composes V2 BEP52 acquisition with CRR2/CRG2
shard retention, complete selected-version consumer restoration and sealed
local execution. It grants no M12 funding, native custody settlement,
installation or ordinary Hepta FinalUse authority.

## Wire and content identity

The outer source schema is `trnm.cell-sealed-paged-research-source.v1`.
It contains the unchanged strict V2 `source`, a strict `custody` profile
and independently supplied `expected` content pins. The source operation
must be fresh and differ from `expected.previous_operation`; its output
directory is create-only. The original V2 input and run remain available.

Expected TCV1, TCV2, CTS1, payload bytes, manifest count and chunk count must
match actual capture before transport. The independently expected BEP52 plan
is checked after actual transfer. Endpoint sessions and CHB1 bind the fresh
operation. A new operation does not remint model/environment contexts or
silently rechunk the original release.

The first real input preserves 280,269,602 bytes, 30 manifests and 95 storage
chunks. Page width 64 yields two committed pages. Synthetic helper tests
are not that model observation.

## One operation and original responsibilities

The original absolute deadline starts before source capture. Catalog ACK,
plan construction, RS encoding, staging, all six provider publications,
cold reopen, four-provider reconstruction, complete readback, typed snapshot
admission and two forwards all consume that same deadline. No plan or shard
precomputation may be moved outside the measured operation.

The original limits remain 300 seconds, 512 MiB payload, 8 GiB worker RSS
and four threads. Logical I/O reservations are distinct from resident payload:

| Consumer reservation | Original-release amount |
| --- | --- |
| Source chunks / potential provider callbacks | 95 / 570 |
| Maximum shard-wire input | 420,450,624 bytes |
| Reconstruction | 700,720,226 bytes |
| Cache write and readback | 560,539,204 bytes |
| Complete final readback | 280,269,602 bytes |

RS staging requires 570 finite manifest records derived from the plan, while
the original source/consumer cache limits remain unchanged. Provider IDs and
funding identities use framed SHA-256 domains and full integer ordinals.
They are local declared research identities, not independent operators or
actual native payment approvals.

Before cold restoration the operation preserves its catalog anchor, plan root,
provider configurations and original obligations. It removes only its new
publisher, transport and staging caches, quarantines two newly created provider
directories and damages only its own catalog payload arena at unchanged length.
The other four providers are reopened with their original configurations.

The catalog fault leaves an original retention responsibility unresolved.
Consumer delivery does not repair that duty or settle any provider. Valid
partial cache entries, original ledgers, failures and cumulative reservations
remain observable. Failure usage and elapsed stages are recorded before errors
propagate. Nothing replenishes a budget at a page boundary.

## Qualification

The original release-profile route has a retained observation on fixed runtime
source `8dee97636e2b6932fb7a22b1b54f2cab09ae8406`, published in
[the original evidence](../../../../evidence/cell-paged-model-release-34e09-20261110/README.md).
That historical execution does not qualify later runtime changes. Tests, model
observations and prior V2 copy-recovery evidence must retain their exact
source/operation identities.
A timeout is an actual failed operation under the original contract; it must
not be converted into a pass by increasing the deadline or reusing hidden work.

Independent domains/WAN, continuous paid custody, real-model native M12
settlement, ordinary FinalUse and production remain **HOLD**.

Provider storage capacity sums one 4096-byte-aligned extent per shard obligation. Wire input and reconstruction reservations remain byte-exact and are reported separately; storage alignment does not enlarge the original transfer or execution budgets.

Staging cache logical occupancy includes the exact encoded shard manifests as well as wire payloads. Both are summed from the committed plan within the original clock, checked against the unchanged 512 MiB bound, and reported separately from transport input usage.

The staging logical total also reserves both 32-byte CAS row keys per slot under Cache V4 accounting. The payload transfer reservations do not include or refund this separately recorded metadata storage.

## Original owner control during consumer restoration

`restore_cell_paged_version_to_cache_controlled_v2` adds a cooperative owner
checkpoint to the existing consumer restoration entry. It uses the same
request, complete-version pins, plan/catalog, original absolute deadline and
whole-attempt reservation. TC/CR wire formats and signed domains are unchanged.
The compatibility entry delegates to the same implementation with no additional
owner callback; it cannot reopen a reservation already stopped by the controlled
entry.

Checkpoints surround provider callbacks, complete plan/page reads, bounded
RS verification/reconstruction/re-encoding, strong content checks, CAS writes
and actual reads, per-chunk complete content scanning and the final plan check.
The original deadline is checked before and after the owner callback. A
checkpoint refusal or observed expiry permanently stops this in-memory restore
reservation, including attempts made through the compatibility entry. Replacing
the callback with a permissive callback cannot resume it.

On any early read/codec/storage error, a final control observation also runs.
The original operation error is retained, while a simultaneous cancellation
still latches the stopped state. Ordinary data/read errors whose owner remains
admissible keep the original bounded retry semantics. Admitted costs and valid
cache entries are never refunded or erased by cancellation. An error after a
successful cache write is not reported as a completed restoration.

The lower-level `repair_chunk_controlled`, `repair_chunk_to_cache_controlled`
and `verify_cached_controlled` carry that owner callback into the actual work;
their standalone callers remain responsible for cancellation state across
separate calls. No callback creates an authority, paid custody record, resource
reservation, durable recovery identity or FinalUse permission. Checks are
cooperative boundaries, not preemption inside a codec, filesystem operation or
provider callback. A resumed process still requires its original durable owner.
