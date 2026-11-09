# Complete retained-version recovery V1

Status: bounded native candidate component. Independent custody, public WAN,
ordinary loader adoption and production acceptance remain **HOLD_NO_GO**.
This contract implements the Cell continuation of the
[sole development plan](../../TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md).
It builds on [TCV1](CELL_COMPLETE_VERSION_V1.md),
[declared dependency closures](CELL_DEPENDENCY_CLOSURE_V1.md),
[native retention](CELL_RETENTION_V1.md) and
[the fixed CRS1 RS(6,4) codec](CELL_RS46_CHUNK_V1.md).

## 1. What the union must mean

Let `R(owner, epoch, h)` be the exact, independently pinned set of versions that
the current retention owner promises to retain at height `h`. For each version
`v`, let `C(v)` be the manifest/chunk closure of its original complete TCV1.
The engineering invariant is:

> For every version in the current promised set, reconstruct every object in
> that version's complete declared dependency closure, using the original
> selected composition and owner context, within the declared recovery budget.

This is universally quantified over versions and their objects. Successful
retrieval of a chosen subset, aggregate stored byte totals, provider counts or
successful recovery of another version cannot satisfy it.

The archive union `union(C(v), v in historical_versions)` describes an archive.
The active working set is the closure of a specifically selected version.
Combining weights from different tokenizers, tensor layouts, router rosters,
runtime/ABI profiles or generations never creates a new executable composition.
Shared exact content can be stored once while retaining all referencing version
identities. Storage deduplication does not change model semantics.

TCV1 already binds the original TMR1 model graph, router roster, environment
TCD1 and every complete TCM1 in their exact union. Owner-declared inventories
must include base weights, adapters/experts, router, tokenizer, configuration,
tensor schema, environment dependencies, compatibility and composition rules,
and precision/quantization descriptions when required. The loader supplies its
own expected contexts and required roles. A hash cannot discover an omitted
dynamic dependency or prove that a device implements an ABI. Current TMA1's
supported dense tensor formats remain separate; this change adds no quantized
format, dynamic loader or implicit compatibility conversion.

## 2. Exact current-set admission

`CellRetainedVersionSetV1` contains a nonzero epoch and a nonempty canonical
list of complete versions, each with its original inclusive start and exclusive
end height. Entries are strictly ordered by their complete-version commitments.
Duplicates, reordering, invalid intervals and oversized sets are refused.

The set commitment is SHA-512 of:

```text
ASCII("TRNM/Cell/RetainedVersions/v1") || 00
    || u64be(epoch) || u16be(version_count)
    || [TCV1_commitment_64 || u64be(from) || u64be(until)]...
```

`CellRetainedSetOwnerV1` independently supplies that exact commitment, epoch,
current height, required exclusive service horizon and the complete ordered
roster of both model/environment loader contexts. Admission requires exact
equality, an active promise window and coverage of the required horizon for
**every** entry. A smaller convenient set or an old epoch cannot substitute.
An intentionally empty current set requires a separate no-obligation decision;
it is not reported as a successful recovery by this nonempty profile.

These are original owner inputs. The component does not discover the current
ledger, authenticate a freshly supplied height, or prevent an owner from
replaying an entire old view. Durable current-set selection, anti-rollback and
funding remain with their existing owners. No new signed or stored namespace
reinterprets TCV1, CPV3, TCA2 or the native retention journal.

`referenced_objects()` returns the exact unique manifest set, original sizes,
chunk counts and all referencing version commitments. It is an inventory, not
a GC authorization. It does not register or protect these references in TCA2;
the existing catalog roots must be reserved through their normal owner.
Pending and expired-but-unretired catalog roots continue
to protect objects through the existing TCA2 transaction. This module does not
make separate model/environment reservations an atomic durable TCV1 duty.

## 3. Actual complete-byte and network observation

`verify_cached()` rereads every actual unique manifest and every original
complete payload under one `CellRetainedReadBudgetV1`. Shared exact manifests
are scanned once; every version's independent loader context is still checked.
The whole intended read cost is committed before I/O. A missing or corrupt
object, late completion or failed retry retains that reservation. A new call
using the same budget cannot replenish it.

`fetch_complete_version()` acquires a single TCV1, including its environment.
`fetch_retained_version_set()` acquires the exact complete current set. Both use
one original `NetworkFetchSession` per invocation across all their members:

1. Check all owner contexts, every per-file bound and the total payload/chunk
   budget before cache writes or network requests.
2. Fetch/check all original TCM1 metadata before requesting any payload.
3. Reuse the original connection, persistent-request and response-byte quotas,
   absolute deadline and cancellation state across model, environment and
   version boundaries. Failed responses and retry traffic consume that session.
4. Reconstruct actual cache contents and check every complete payload hash
   before returning a private-field successful observation.

Failures retain actual connection/request/response counters. Unknown response
accounting is not zero and cannot produce success. Retained-set member counts
describe completed member calls; partial bytes from a refused member remain in
the session response count. The unchanged disposable cache may contain partial
progress after failure, which grants no release or use authority.

Warm-cache success is explicitly distinguishable from network recovery. It
does not prove that any remote node is currently reachable. A cold-cache native
TCP test can establish recovery from those configured peers during that test;
it is not a public discovery service or an independent WAN SLA. Observations
retain a start/end window. Sequential reads are not simultaneous availability
of all peers at an atomic instant.

Repeated public fetch calls are separate explicit reservations. Their receipts
preserve consumed attempts, but a durable lifetime network budget remains the
outer operation owner's responsibility. No retry deadline or quota is silently
renewed inside an invocation.

## 4. Correct RS shares and exact fault-domain accounting

`CellRecoveryPlacementPolicyV1` pins the full provider roster, operator,
administrator, physical failure-domain and separately retained domain-evidence
identities, plus a typed fault model. Its commitment uses the fresh SHA-512
domain `TRNM/Cell/RecoveryPlacement/v1` and canonical fixed-width identities.
The owner must independently retain the expected policy commitment.

The selected fault axes are `Operator`, `Administrator` and/or `FailureDomain`.
The model states that at most zero, one or two typed events can occur. Choosing
multiple axes means **all mixed combinations** are checked together. Losing two
operators, losing two locations and losing one of each are different models.

For one original chunk and an allowed failure set `F`, define:

```text
I(F) = { shard index i : at least one eligible copy of i survives every event in F }
```

The declared placement survives `F` exactly when a verified original whole-chunk
copy survives or `|I(F)| >= 4`. A provider is removed by any matching selected
operator, administrator or physical-domain event. Every allowed set is checked;
the report retains a worst-case witness. Copies of one index may improve its
survival, but never increase decoder rank. Missing domain evidence, unknown
providers, conflicting identity order and duplicate placement records refuse.

`evaluate_recovery_placement()` is a pure, conditional placement analysis. It
cannot validate bytes, freshness or real independence. The streaming
`CellRetainedRs46RecoveryV1` supplies the byte-verification bridge:

- It admits the exact current retained set and independently pinned placement
  policy, then selects each required manifest/chunk itself in canonical order.
- It reconstructs from four through six distinct CRS1 indices using the original
  TCM1 binding. It does not search around a corrupted share.
- A borrowed `CellRs46ManifestBindingV1` checks each immutable manifest once and
  selects each chunk in constant-size metadata work. The decoder does not
  rehash a potentially long manifest for every chunk.
- Repeated indices at different providers must contain identical original CRS1
  bytes. Every supplied copy is compared with the re-encoded verified codeword,
  including unused extras and replica copies.
- Every reconstructed chunk is added to its original whole-file SHA-256; a
  chunk-list match without the original whole payload hash is insufficient.
- Any refusal latches the session. Missing, repeated, reordered or additional
  chunks cannot be ignored to manufacture a successful `finish()`.
- A complete byte recovery with inadequate fault tolerance returns explicit
  per-chunk deficits. It does not label the topology fault-tolerant.

This streaming API receives bytes; it does not prove that a claimed provider
sent or retained them. Its conditional resilience result requires actual
authenticated, timely provider observations and independently qualified control
domains before it can support a service-level claim. No public `verified: bool`
is accepted in place of reconstruction. Caller-staged output chunks require the
final complete-set observation before being treated as complete version bytes.

## 5. Bounds and costs

| Resource | Bound / accounting |
| --- | --- |
| Retained versions | 1 through 16; exact owner roster |
| Aggregate retained TCV1 metadata | 32 MiB; each original TCV1 bound still applies |
| Recovery providers | 1 through 16 |
| Placement records for one chunk | At most 112 (whole plus six indices per provider) |
| Supplied RS-only copies for one chunk | At most 96 |
| Typed failure events | At most 48 |
| Failure scenarios | At most `1 + 48 + choose(48,2) = 1,177` |
| Placement work units | `events * providers + scenarios * (providers + 1)`; at most 20,777 per chunk |
| Streaming retained RS recovery | At most 65,536 unique manifest/chunk positions |
| Original source chunk | Existing CRS1 4 MiB maximum |
| Recovery reservation | Checked aggregate attempts, source bytes, chunks, evaluation work and all supplied CRS1 wire bytes |

Complete-plan source/chunk/evaluation costs are reserved before decoding, with
checked arithmetic. Supplied wire bytes include bad/duplicate copies and are
charged before share validation. Failed attempts keep those commitments. The
placement validation/policy preview is bounded setup outside a recovery session;
the immutable policy caches its per-chunk work cost. Its work-unit definition
is not a measured instruction count or process CPU budget. Existing absolute
deadlines remain cooperative checkpoints, not kernel preemption.

The ideal RS payload ratio is `6 * ceil(L/4) / L`, approaching 1.5 for large
chunks. Headers, metadata, small-chunk padding, extra replicas, temporary
buffers and repair traffic are additional costs. The code tolerates two absent
**correct share indices** only when four correct indices remain obtainable;
this is not automatically two adversarial operators or two failure domains.

## 6. Qualification and integration boundary

This candidate is based on #807's exact TCV1/Cell source
`0dc13a92cc49e9a751a2b6cf7cc96524f1244a2a`. The separate frozen unified candidate
#812 at `7e044b65454f4c9ea505591727332acffb33e7e5` did not include #807 at the time
of this continuation. Tests on this candidate do not become #812 or main tests.

The production gate still requires the current durable owner to enumerate all
promised versions; an actual restricted loader dependency inventory and
supported execution contract; binding between complete-version, environment and
funded catalog duties; authenticated provider identity and independently
qualified control/failure domains; original-window WAN/churn/cold-recovery
observations; and funded repair/renewal with actual ordinary Hepta adoption.
The existing SHA-256 leaves and their quantum-security qualifications are
unchanged. No content hash, archive union or this component's test result grants
CURRENT, FinalUse, production activation or a whole-chain PQ claim.
