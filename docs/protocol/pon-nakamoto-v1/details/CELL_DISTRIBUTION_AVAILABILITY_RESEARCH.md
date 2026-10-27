# Cell distribution, version availability and PQ authorization: research boundary

This is a read-only architectural finding under the
[sole development plan](../../../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md),
not another implementation plan, protocol activation or storage qualification.
Code locations below refer to Chain source
`9e05ad5d237660fb0ea8b40dd5c29af4225551d3`, tree
`952666bff72a49d8bc7693b27ff747f56a56b240`, inspected on 2026-10-27.
No network experiment, model load or new benchmark was performed for this note.
The existing [Cell contract](CELL_P2P_V1.md),
[discovery contract](../../../development/specs/pon/CELL_PROVIDER_DISCOVERY_DEV_V1.md)
and [retention contract](../../../development/specs/pon/CELL_RETENTION_V1.md)
remain authoritative for their implemented profiles.

## Existing owners and their actual boundaries

| Source at the pinned commit | Implemented behavior | Limit of the result |
| --- | --- | --- |
| [cell/manifest.rs](../../../../trillionnium/crates/trnm-data-availability/src/cell/manifest.rs): `CellManifestV1` at line 47, `validate` at 87, `CellReleaseManifestV1` at 186 | TCM1 binds family, five dependency digests, ordered chunk lengths/hashes and complete payload identity. TCR1 binds a sorted unique set of TCM1 IDs in one common context. Chunk size is 16 KiB–4 MiB; a cell has at most 16,384 chunks and 64 GiB, subject to the smaller limit. | The five dependency digests and member list are opaque. They do not encode the complete executable graph, tensor coordinates, numerical semantics, authority or storage duties. |
| [cell/network.rs](../../../../trillionnium/crates/trnm-data-availability/src/cell/network.rs): `fetch_cell_in_session` at 164, `download_chunk` at 360 | Up to four workers fetch missing chunks from at most eight explicit peers; supplier order rotates by chunk. Corrupt/missing responses consume the original deadline, connection and response-byte budgets. Verified committed prefixes survive failed fetches. Final materialization/full-payload verification uses the same deadline. | This is a bounded TCP byte protocol, not BitTorrent wire compatibility, a DHT, fair public service or guaranteed latency. Hashing, SQLite and filesystem checks are cooperative. |
| [cell/release.rs](../../../../trillionnium/crates/trnm-data-availability/src/cell/release.rs): `fetch_release_to_file` at 83 | All declared member manifests and aggregate limits are checked before payload fetch; members share one transport budget. Fresh complete readback precedes the create-only completion marker. | Completion proves the declared set was readable then. It cannot prove that the owner declared every dependency or that an ordinary model loader accepts the result. |
| [cell/discovery.rs](../../../../trillionnium/crates/trnm-data-availability/src/cell/discovery.rs): constants at 23, `CellProviderRecordV1` at 123, `verify_at` at 219 | Explicit development rendezvous, at most four bootstrap endpoints and eight returned providers; signed records bind pinned context, endpoint, sequence and bounded lifetime. | No referrals, DNS or DHT routing. An advertisement is not endpoint control, independent custody, a retention receipt or release authority. |
| [store/storage_service.rs](../../../../trillionnium/crates/trnm-pon-node/src/store/storage_service.rs): `retain_native_cell` at 161, `repair_native_cell` at 245, `retire_native_cell` at 335 | The Node bridge checks a task funding source, exact subject/effect and byte/byte-block reservations before local retention. Repair has a separate funded operation and original interval. Current native height controls retirement. | A local reservation is not coin finality or proof of future service. Initial/repair readback does not issue a Positive payment or refund unknown cost. |
| [cell/retention.rs](../../../../trillionnium/crates/trnm-data-availability/src/cell/retention.rs): `create` at 140, `populate_cache` at 669, `retire` at 705 | A separate locked, preallocated and fsynced arena holds obligations. Repair/reconciliation retain replay identities and costs. A required successor must be freshly read from the actual successor store before retirement. | Distinct store IDs do not prove distinct administrators or failure domains. Ordinary serving reads the disposable cache; explicit verified rehydration bridges the arena to that cache. Local successor readback is not WAN retrievability. |

These are reusable implementations, including real finite retention and repair,
not just download sketches. They leave continuous independent replication,
renewal funding, globally coordinated version retention and complete executable
release closure unqualified. A per-invocation repair CPU ceiling also does not
bound the lifetime sum of arbitrary readback calls.

## What BT and IPFS contribute

[BEP 52](https://www.bittorrent.org/beps/bep_0052.html) specifies BitTorrent v2
file identity, SHA-256 Merkle trees and authenticated pieces. This supports
retrieving and checking portions without trusting each supplier. Current TCM1
instead carries its bounded ordered hash list; adopting a different tree format
would need its own canonical version and parser limits. Replacing TCP with a BT
transport would not change the independently pinned release owner.

[BEP 9](https://www.bittorrent.org/beps/bep_0009.html) provides peer metadata
exchange used with magnet links. A magnet identifies content and helps obtain
metadata; it does not promise a live seeder. [BEP 5](https://www.bittorrent.org/beps/bep_0005.html)
describes DHT lookup of peer locations. That is a discovery mechanism, not a
storage guarantee. Adding open discovery here would still need bounded lookup,
record freshness and replay rules, address policy, failure handling and evidence
against eclipse/Sybil concentration. Many advertised keys must not count as
independent custodians.

The [IPFS pinning contract](https://docs.ipfs.tech/how-to/pin-files/) distinguishes
direct/recursive retention from a cache that garbage collection may remove.
The architectural inference for this project is that a content identifier and
a provider hint do not supply future availability: operators must keep the
required bytes and remain reachable. Pinning also does not authorize installation
or certify model quality. None of these protocols turns storage payments into
valid PoN work.

## Why the union of every node's cells is insufficient

For a particular version, define its required closure as the exact base,
tokenizer, runtime/ABI, layout, router and activation rules, all reachable cells,
and every dependency of a delta or adapter. The loader additionally needs a
compatible numerical contract and its original release/installation authority.
TCM1/TCR1 do not currently encode this full relation.

Even if the mathematical union of all stored bytes contains that closure, a
version can fail to load when its only supplier is offline, unreachable, has
expired its duty, withholds a chunk or exhausts the caller's resource budget.
A valid list containing an adapter cannot by itself establish that all base and
router dependencies were declared and retained. Conversely, many individually
valid cells can belong to incompatible parents, layouts or numerical contracts.
Hash validity does not choose a compatible subset.

An executable-version claim therefore needs both a complete owner-bound closure
and successful retrieval/load of that closure under stated availability and
resource conditions. A completion marker must not replace either check. The
existing Hepta authorization/CURRENT gates remain separate; the
[public neural-task note](PUBLIC_NEURAL_TASK_CONTRACT_RESEARCH.md) describes the
additional numerical-consumer gap. Distribution cannot make the current FP32
contract accept integer tiles by renaming their format.

Keeping **all versions** also needs an explicit definition of which releases
enter the retained set. The unique bytes of every retained dependency remain
charged until no retained release needs them. A reference-count or reachability
GC owner must account for concurrent reads, repair, pending publication,
rollback/reorganization and local irreversible retirement. Present local
obligations do not implement that global policy. Unbounded new unique versions
require increasing durable capacity and continuing funding; a finite cache
cannot promise permanent retention merely by assigning content hashes.

Independent replicas and erasure coding are possible storage strategies, not
implemented guarantees in this profile. They require actual fault-domain and
retrieval evidence, repair bandwidth/capacity reservations and renewal before
expiry. Erasure fragments need their own authenticated coding parameters and
reconstruction bounds. Neither a paid duty nor a local ACK demonstrates that
enough independent live fragments remain.

## Full checkpoints, adapters and deltas

The following are storage/loader tradeoffs, not measured speedups or changes to
the current model contract. Let `W` be a full checkpoint's bytes and let `V` be
the number of retained versions; exact common chunks can be deduplicated only
when their bytes and chosen chunk boundaries actually match.

| Representation | Storage opportunity | Cold load and dependency cost |
| --- | --- | --- |
| Complete checkpoint per version | Worst case roughly `V * W`, reduced by actual identical chunks. | A selected checkpoint has no reconstruction chain. All missing bytes, disk verification and loader memory still cost time/capacity. |
| Shared base plus LoRA | For one adapted matrix, rank `r` factors contain `r * (d_in + d_out)` scalars rather than a full `d_in * d_out` update; metadata, biases and other tensors are additional. | The exact base is mandatory. Cold loading includes base plus adapter. Pre-merging may avoid extra forward work but incurs merge/materialization and full-weight memory; keeping factors separate changes execution cost. |
| Byte or numerical deltas against parents | Savings depend on the real delta encoding; a dense changed checkpoint need not compress well. | Every required ancestor must be obtained and each patch verified in its declared order. One unavailable ancestor breaks reconstruction. Temporary memory, disk writes, rounding and final identity are part of the contract. |
| Periodic complete checkpoint plus bounded deltas | Trades duplicated checkpoint bytes for a finite reconstruction depth. | A declared maximum of `K - 1` intervening deltas bounds chain depth only; it does not establish download latency or a memory bound by itself. |

The [original LoRA paper](https://arxiv.org/abs/2106.09685) establishes the
low-rank parameterization, and the
[authors' implementation](https://github.com/microsoft/LoRA) documents merging
for inference. Neither result establishes this project's cold-load latency.
Continuing training of one fixed-rank adapter can keep its dimensions fixed;
composing multiple independent updates can instead increase effective rank or
require separately qualified compression. Those operations must not silently
change the selected model's numerical identity. Training-resume checkpoints
may also need optimizer/RNG state that inference-only artifacts omit.

For dynamic cell loading, the meaningful observation is end-to-end time from
the already authorized version selection to the first actual usable output,
including lookup, missed chunks, verification, reconstruction, disk and device
transfer. Sum of peer link speeds is not that latency. The existing code supports
byte retrieval, not transparent swapping of arbitrary cells into an arbitrary
running transformer.

## The current provider authorization is classical

`CellProviderRecordV1::sign` uses `ed25519_dalek::SigningKey`; its CDP1 wire has
a 32-byte owner key and 64-byte signature in a fixed 335-byte record.
`verify_signature` at `discovery.rs:210` calls
[`types::verify_strict`](../../../../trillionnium/crates/trnm-data-availability/src/types.rs)
at line 1756, which constructs the Ed25519 verifying key. This is an actual
verification path, not a conclusion from a dependency list.

The separate native
[`PqAuthorizationOwner`](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/9e05ad5d237660fb0ea8b40dd5c29af4225551d3/trillionnium/crates/trnm-pon-node/src/pq_authority.rs)
uses TPQ1 and durable replay consumption. It is not called by this provider
verifier and does not install itself into legacy Node transactions, release
selection, model installation or chainwork. Its presence cannot make CDP1 or
the complete chain post-quantum secure.

A provider successor would require a fresh signed domain/wire and persisted
namespace, explicit key identity/rotation and generation, replay/expiry rules,
and strict rejection of legacy or wrong-purpose records without fallback.
[FIPS 204, Table 2](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf)
gives ML-DSA-65 a 1,952-byte public key and 3,309-byte signature. Eight records
carrying each full key and signature already require 42,088 bytes before their
statements, exceeding the current 32,768-byte discovery-response cap. A key
registry/reference encoding could change that layout but creates another
authenticated fetch/rotation dependency. Parser, transport, persisted storage
and shared verification budgets need an explicit bounded contract; increasing
one constant is insufficient.

Provider-hint authentication and release authorization must migrate separately.
Forging a hint does not let a peer change bytes under an already trusted pinned
digest, but can redirect or obstruct retrieval. Migrating hints alone leaves
classical release, funding and installation owners unchanged. Hash selection,
collision/preimage security and long-term archival verification also require
their own PQ threat model; no claim of complete PQ security follows here.

## Evidence still needed before stronger claims

- A loader-owned, versioned executable closure must reject omitted dependencies,
  incompatible parents/numerics, cycles and unknown versions; declared TCR1
  success alone must never authorize a load or CURRENT change.
- Cold retrieval and ordinary load must succeed after the original publisher
  disappears, using retained bytes from genuinely independent failure domains.
  Missing mandatory data must fail explicitly, without a substitute model or
  silent local fallback. Existing per-operation budgets must remain shared.
- Renewal and GC must preserve every still-retained version through expiry,
  repair, concurrent use and reorganization, while keeping actual byte/time
  costs and irreversible local histories. A successor receipt alone is not
  enough; the implemented physical readback remains necessary.
- A PQ provider successor must test the actual native verify/replay path,
  wrong purpose/network/generation, key rotation, malformed lengths, expensive
  invalid records and legacy-downgrade attempts. It must not reinterpret CDP1.
- Paid storage remains a service resource. Bytes retained, payments, provider
  identities and replica count grant no chainwork, leader selection or voting
  weight. Pure PoN validity and original model adoption authority remain intact.

These are acceptance boundaries for existing owners and any explicitly versioned
successor. This note implements none of them and changes no readiness claim.
