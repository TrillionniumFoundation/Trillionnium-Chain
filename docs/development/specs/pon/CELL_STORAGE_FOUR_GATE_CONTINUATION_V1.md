# Cell storage discovery, selected release, repair and first use

Status: local native execution recorded on C3; production qualification HOLD.
This continuation starts from storage PR #879 at
`30ce6e99c5d0d86e6563a49786e8b1e41b44c6c6`. It preserves that branch's
signed profiles, original budgets, prior failed observations and production
refusal. The sole development plan remains
[TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md](../../TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md).

## 1. Bounded authenticated discovery

The existing [V3 discovery contract](CELL_PROVIDER_DISCOVERY_AUTH_PQ_V3.md)
already supplies four explicitly pinned bootstrap sources, two rounds,
ML-DSA-65 provider statements and query replies, nonce/source binding,
300-second epochs, withdrawal and bounded replay/source quotas. Those
mechanisms do not establish an open-network identity or independence oracle.

Serial requests previously could spend the whole remaining operation window
on early eligible sources which accepted TCP but withheld their replies. Each
source now receives at most the smaller of its original request timeout and
the remaining operation time divided by the number of remaining configured
source positions plus one. The extra share reserves time for downstream
verification and payload work. Skipping ineligible sources can leave unused
shares; it cannot renew the original deadline or refund any connection,
response-byte or signature reservation. Signed query/reply lifetimes retain
their original meaning.

The new native controls use actual TCP peers: three withholding sources
before a fourth honest source and a fully verified cold payload, all sources
withholding, and an exhausted one-connection budget. The honest-source case
retains the original four-second window. Its pre-fix and post-fix observations
must be retained under their respective source identities. A complete refusal
is a failed availability observation, even when every resource bound holds.

This scheduling rule offers conditional progress among the configured
sources. It neither proves permissionless Sybil resistance nor provides a
fresh independent revocation authority. The separate published BEP5 helper
remains caller-directed and one-hop; it does not announce a public swarm.

## 2. One complete local release selection

The [CTS1 snapshot](CELL_RELEASE_SNAPSHOT_V1.md) already binds TCV1 complete
model/environment identity, actual tensor metadata and composition rules.
`CellResidencyV1` now has one tagged selection slot: either its original
single-closure ticket or a complete-release ticket. There are no separately
mutable current model and environment pointers.

`select_local_release_snapshot` requires the caller's exact previous tagged
ticket, validates the existing complete resident CTS1 admission and current
owner contexts under the original deadline/cancellation, then publishes one
ticket. The ticket binds manager identity, increasing revision, CTS1, TCV1,
model closure, environment closure and composition profile. All fallible work
precedes the final checkpoint and assignment. Refusal preserves the previous
selection and resident allocations. A stale A ticket remains stale after
A-to-B-to-A; another manager's same-content ticket is not interchangeable.

An explicit Closure-to-Release upgrade retains the increasing revision.
Legacy selected-closure reads, selected tensor reads and legacy switches
refuse complete-release mode. `local_selection()` exposes the tagged state;
the legacy `selection()` accessor returns only a legacy closure ticket.
Both selected closures are protected from eviction. A staged successor is
not selected until its entire admission succeeds.

`admit_selected_local_release_snapshot` checks the current complete ticket
and pins before returning the existing borrowed CTS1 task handle. Its borrow
prevents a mutable pool switch or eviction while task bytes remain live.
The actual sealed research entry selects and admits this complete release,
seals both original closures while the paired handle remains alive, and
rechecks the handle before handoff construction.

This is process-local routing of verified bytes. A new process has no selected
release until an owner explicitly validates and selects one. It does not
restore durable Hepta CURRENT, acquire revocation freshness, grant execution
resources, authorize installation or create FinalUse authority. The existing
authenticated handoff and actual consumer guards remain required.

## 3. Repair admission and finite retention

The existing [storage convergence](CELL_STORAGE_CONVERGENCE_DEV_V1.md)
already includes complete TCA3 duties, finite CPS1 schedules, physical CSP1
shard owners, original funding-operation bindings, paged restoration and
separately charged repair. Six local slots are one operational failure domain.

Before repair admission and target-only repair reconciliation, the retention
owner now reuses its existing complete schema, arena-layout and repair-ledger
conservation validation under the original `OperationControl`. After a new
durable repair intent, it repeats that validation and checks the exact selected
row before physical copying. A refusal after the durable intent preserves its
debit and unresolved operation. Existing operation IDs, retry behavior, stored
formats and limits are unchanged; the extra checking consumes the same original
deadline and CPU checkpoints.

These are bounded current local observations, not an atomic snapshot against
noncooperating database writers. General acknowledge/verify entry points are
unchanged. The source-review concern is not reported as an executed metadata
corruption exploit. Existing repair, cancellation, deadline, unknown-outcome
and completion tests remain required.

CPS1 opens its policy with `O_NONBLOCK` as well as the existing no-follow and
close-on-exec flags. Existing regular-file, identity, length, pin and deadline
checks remain. The added ordinary test checks valid reopen and a preexisting
FIFO refusal; it is not a concurrent path-substitution reproduction.

Lost-provider migration into a new approved domain still requires an explicit
successor owner: preserve the old duty and content identity, independently
admit placement and funding, publish original recovered shards, verify actual
replacement readback, commit the successor and reconcile uncertain outcomes.
Current same-provider repair does not implement that entire lifecycle. Funding
admission is also not independent-provider escrow, payment or a completed
renewal cycle. No free or permanent retention is inferred from content hashes.

## 4. First usable-byte observation

The existing `cell_residency_observer` gains an additive
`latency_observation_v1` record. An `Instant` clock measures:

- Empty consumer CAS opening, cold acquisition and complete residency.
- Cold request to the first selected callback that rehashes every file in the
  pinned closure.
- Explicit successor prefetch and later selection to verified local use.
- A fresh manager's warm-disk preparation and first verified use.
- An exact resident hit and 1,000 sequential complete-payload hot readbacks.

The provider is stopped and joined before hot/disk-warm observations. The
record retains all hot sample durations, count, enclosing wall interval and
nearest-rank statistics. It verifies that subintervals fit the enclosing
interval and that first verified use follows complete residency. Existing
downloaded/cached chunks, actual bytes, shared buffers and eviction counters
remain. These repeated reads in one process are not independent service-tail
samples. Fixtures are synthetic bytes; host page-cache temperature is
unspecified, and no model inference or WAN performance is claimed.

The actual paged/nonpaged sealed research entry also gains cumulative
monotonic milestones from custody-observation entry, after the input file is
read/parsed and the fresh output directory is created: pinned snapshot ready, transport
complete, cold recovery complete, selected typed release ready, sealed
model/environment ready, and verified two-forward receipt. Unreached stages
remain null on failure. These cumulative values must not be summed.
Selected typed release readiness is a byte/type-admission milestone, not
first-token latency. The original overall operation deadline remains fixed.

## Recorded execution and publication

Runtime C3 `030de92be05bfd4f73e199098c12dfeaedf29b17` passed all 68 candidate
commands and seven observer/build commands. Complete DA execution passed
785 unit, 34 integration and 16 documentation cases. Default and
pq-native-openssl Node storage each passed 44; each sealed example passed 11;
all 24 actual sealed-worker Python controls and strict readbacks passed.
Locked graphs, formatting, original source/CI checks and strict Clippy passed.
These suite counts overlap and are not a count of unique behaviors.

Identical actual TCP tests failed on the test-only #879 predecessor and
passed on C3 under original four-/two-second windows. The before exhausted
budget case fails its deadline assertion before counter assertions and is
not evidence of a refund or overrun. C2's unavailable mkfifo test API caused
real compile failures; C3 uses pinned mkfifoat(CWD, ...), without relaxed gates.

The fresh 30-file, 280,269,602-byte, 95-chunk research operation preserved
all original identities and the 300-second limit. Cold recovery, complete
typed release readiness and the two-forward receipt occurred cumulatively
at 62.318658435, 66.401049437 and 103.736029521 seconds. Native elapsed
was 103.804071986 seconds without timeout/interruption. This local run and
the different historical 36.047064473-second run are not a paired benchmark.
The second numeric probe was wrong; completed execution is not model efficacy.

After all source-after checks, packaging found the original source root
absent, for unknown cause. Raw failure/probe records and recovery of the
exact executed runner from its C3 blob are retained. The independent
publication checkout passed original full physical source verification of
all 27,100 C3 entries. Later local review-environment loss interrupted a
planned space migration; it is not labeled complete. Source receipts remain
point-in-time observations, and native execution remains attributed to C3.

The publication descendant changes only documentation/evidence, two CI
workflow seams, the corresponding strict CI contract and source pins.
It enables the exact stacked PR base in the existing CodeQL local-SARIF
trigger, keeping upload: never, all matrix/permission/source/retention rules.
That does not satisfy the separate unchanged Advanced Security API exporter.
It also normalizes colons only in next-architecture log filename stems and
matching reader paths, preserving exact Rust selectors and acceptance criteria.

Six C3 hosted workflow failures remain separate from the passing continuation:
QROM verifier/frozen-lock bindings, the API exporter, original native campaign,
fresh-challenge service criteria and next-architecture artifact upload.
Final-head source and hosted-CI observations have their own identities.
See the [complete observations](../../../../evidence/cell-storage-four-gates-20261111/README.md)
for raw evidence, original failures and measurement boundaries.

## Acceptance boundaries

| Gate | This continuation can validate | Still requires separate implementation or evidence |
| --- | --- | --- |
| Discovery | Signed V3 regression, bounded source time sharing and actual local cold fetch | Independent bootstrap operation, current authority, open-network Sybil/eclipse and WAN qualification |
| Version consistency | Complete process-local CAS, no partial switch, both-member eviction protection and actual selected research use | Durable original Hepta CURRENT/FinalUse and crash/revocation ownership |
| Retention | Existing bounded layout/accounting checks before repair and normal recovery regressions | New-domain replacement owner, actual remote read challenges, paid renewal and original sustained retention |
| Performance | Raw empty/warm/hot byte-path observations and real-model cumulative milestones | WAN distributions, independent-load trials, full device/inference latency and target service qualification |

The original PN5 independent-domain and 72-hour WAN gates remain in force.
Physical hosts under one administrator do not establish independent
administration, power or network domains. Local passing tests, complete
hash verification and four-of-six reconstruction cannot close those gates.
