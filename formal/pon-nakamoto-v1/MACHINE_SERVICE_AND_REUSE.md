# Metered W1 services and bounded preprocessing reuse

This research component extends the [complete lifecycle envelope](w1_machine_envelope.py)
and the [exact input-scope diagnostic](w1_preprocessing_reuse.py). It provides
explicit alternative service reservations and an executable classical cache
comparison. Hardware calibration, minimum attacker cost, equal total economic
resources and quantum-mining qualification remain **HOLD**.

## Service architectures

The original `trnm-w1-machine-lifecycle-envelope-v1` remains the default. An
explicit `reserved_service_patches_per_processor` argument selects the fresh
`trnm-w1-machine-reserved-service-envelope-v2` namespace, including when the
argument is zero. A v1 record cannot acquire an unaccounted auxiliary allocation
by adding an ignored field.

The [architecture builder](w1_machine_architecture.py) declares these three
service configurations per quantum processor:

| Initialization ports | Terminal readout ports | Auxiliary patches per initialization port | Auxiliary patches per readout port | Controller patches | Total auxiliary patches |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 1 | 2 | 2 | 8 | 12 |
| 1,024 | 8 | 2 | 2 | 8 | 2,072 |
| 65,536 | 64 | 2 | 2 | 8 | 131,208 |

Each configuration also reserves one classical controller core and 1 MiB of
controller memory per processor. That is a declared reservation; no compiled
controller image or measured peak workspace has established that it fits.
Unverified memory fit is an explicit calibration requirement, not an assumed
successful implementation.

For oracle width (L), auxiliary width (A), reset concurrency (J), and the
declared cycles-per-distance (c_I), each trial initializes all (L+A) patches
in

\[
  c_I\left\lceil\frac{L+A}{J}\right\rceil
\]

distance-scaled cycles. The service contract includes bootstrap and routing of
the auxiliary patches themselves. The extra patches remain in the live-patch
error count throughout initialization, gates, factory service, all finite
retry/discard slots, control waits and terminal readout. The code distance is
selected after adding this allocation, using the unchanged whole-plan failure
budget. The physical-qubit ceiling also includes the auxiliary patches.

Increasing ports does not change noise values, the error budget, the deadline,
the serial magic-state service, or the original full-predicate/restricted-predicate
circuit. In particular, reset concurrency grants no extra T-factory throughput.
Every stated history-conditional error and latency bound must hold at the actual
declared concurrency. A calibration of a serial device cannot establish those
bounds for an unmeasured parallel device.

The resource record includes physical qubits, auxiliary patches, both kinds of
service ports, controller core/memory reservation, initialized patches, command
and magic-state counts, transfers, host calls and full-schedule reservation time.
Port code-cycle counts include the unused lanes of a partial last batch. Full
qubit/port/core/memory-time reservations include the complete planned schedule
and the reserved proof/propagation services, even if the search policy stops
earlier. Energy, capital/operating prices and actual compiled-controller memory
remain `None`. These missing dimensions prevent a complete economic comparison.

The [architecture frontier](experiments/w1_service_architecture_frontier.py)
keeps the old serial comparison separate and evaluates a new, predeclared grid:

\[
3\text{ service configurations}\times
2\text{ predicates}\times
P\in\{1,2,4\}\times q\in\{0,1,2\}=54\text{ cells}.
\]

Each cell retains the original two trials, four-second modeled horizon,
physical-qubit ceiling (10^{16}), physical/noise premises and host costs.
Refused cells remain in the denominator. Dominance requires the left success
interval's lower endpoint to exceed or equal the right upper endpoint, all
listed resource dimensions to be no larger, and at least one strict improvement.
Adding ports is therefore a paid tradeoff, even when it reduces modeled latency.
An undominated entry is not a proven cheapest legal implementation.

## Calibration artifact contract

`validate_calibration_manifest` accepts external artifact bytes only after their
record binds the exact current source, circuit construction, architecture,
physical/lifecycle parameters, complete modeled allocation and failure union.
The manifest must be within its declared validity interval and the caller's
maximum age. It must cover all of the following obligations:

- Compiled physical layout and allocation, including service auxiliaries.
- History-conditional physical noise bounds and the complete execution coupling.
- Initialization, terminal readout, input/output transfer and their overruns.
- Controller, decoder and feedforward service at the declared concurrency.
- Factory retries, accepted-state storage, delivery and injection.
- Host preprocessing, setup, candidate checks, proof generation and propagation.
- Complete energy metering and capital/operating cost allocation.

Coverage entries bind actual artifact bytes by SHA256 and size. Missing,
duplicate, unbound, stale, future, mismatched or additional undeclared artifacts
are refused. Qualification fields cannot be smuggled into the strict manifest
schema. Hashes bind supplied bytes; they do not authenticate a lab or prove that
the bytes support their statements.

Even a structurally complete manifest returns
`PROVENANCE_AND_COVERAGE_ONLY`, with physical qualification and conditional-error
claims still false. This reader does not derive a valid upper probability bound
from a marginal infidelity, a sample maximum or a zero-failure experiment. Real
evidence still needs a justified interpretation of the entire service/noise
contract. No such evidence is manufactured by this component.

## Actual classical preprocessing reuse

The [cache producer](w1_preprocessing_cache.py) executes complete candidate
proofs using a deterministic, empty-at-start, linear LRU cache. It has two exact
key namespaces:

| Cached value | Exact key | Changes that can preserve it |
| --- | --- | --- |
| Proof product (AB\bmod q) | Full canonical (A,B) bytes, matrix dimension (N), field modulus (q) | Parent, timestamp, target, nonce, PNH1/PGH2 profile, rank and rejection cap, when matrix/dimension/modulus inputs stay equal |
| SHA chaining state after (j\le5) blocks | Namespace, block count and the actual first (64j) tagged/framed header bytes | Only changes outside those exact prefix bytes |

The task commitment alone is not an AB cache key: it does not encode the field
modulus. SHA reuse compares bytes, not just fingerprints. A changed parent or
target normally retains fewer prefix blocks; the remaining suffix is always
hashed. A PGH2 witness change can preserve the five fixed prefix blocks while
still changing the final challenge.

Every candidate regenerates bounded rejection-sampled noise, both low-rank
offsets, every ordered trace prefix, the trace hash and ticket. The complete
PNW1 proof is serialized for target hits **and target misses**. Exhausted noise
attempts retain the work already performed and produce no fictitious proof.
AB caching affects classical proof-product preparation; it does not prove any
reduction in the current coherent oracle, which does not consume cached AB.

The cache payload limit counts complete keys and values. Lookups, exact byte
comparisons, hits, misses, reads, writes, refusals and evictions are retained.
An oversized value is not inserted and does not evict the existing cache.
Its computation remains paid. Python object overhead and transient producer
workspace are outside that payload limit and require separate process-level
memory observations.

An independent complete-relation check follows every candidate. Native shape
uses `work_oracle.evaluate`, whose product is derived through the low-rank
correction identity, separately from the cache's direct AB multiplication.
Reduced controls use the independently organized macro relation and a separate
product loop. A corrupt cached product or checkpoint is detected rather than
silently counted as reusable work.

## Source-bound native CPU observation

The [cache campaign](experiments/w1_preprocessing_cache_campaign.py) loads the
source-bound native fixture and freezes nonce-major order across all retained
contexts. The cache budgets are 0, 4,096 and 262,144 payload bytes; every budget
starts cold and executes exactly the same candidates. It makes no nonce choice
using known winners. Every generated proof's SHA256, byte length, trace and
target result must match the corresponding complete native fixture packet.
This establishes byte identity with the fixture; the comparison itself does not
execute another Node admission or claim another native block.

Actual producer and independent verifier calls have separate CPU/wall records.
The overall observation also charges time outside those calls, including cache
bookkeeping, input/source checks and journal writes. The recorded function scope
excludes interpreter startup, imports and final report serialization; a process
wrapper is needed for whole-command accounting. The record exposes process-wide
peak RSS before/after, not an isolated cache heap or exclusive-host calibration.

The CLI flushes and fsyncs an `OUTPUT.json.stages.jsonl` sidecar containing the
declaration and each stage's start and terminal event. An interrupted attempt can
leave a start without a terminal record. That partial journal remains evidence
of incomplete work and cannot pass the successful-observation reader. Caught
failures produce a failed report, never a successful reduced denominator.

After the native fixture is generated at the frozen implementation source:

```bash
python3 -B formal/pon-nakamoto-v1/experiments/w1_service_architecture_frontier.py --native-directory /absolute/native-evidence --output /absolute/fresh-service-frontier.json
python3 -B formal/pon-nakamoto-v1/experiments/w1_preprocessing_cache_campaign.py --native-directory /absolute/native-evidence --observe /absolute/fresh-cache-observation.json
python3 -B formal/pon-nakamoto-v1/experiments/w1_preprocessing_cache_campaign.py --native-directory /absolute/native-evidence --verify /absolute/fresh-cache-observation.json
```

The verification command reexecutes cache operations and complete relations,
checks the timing-row bijection and sums, and binds the progress journal. It does
not reproduce or attest historical timing values. CPU observations do not supply
QPU calibration, energy/capital accounting, an exhaustive cache strategy space,
or a minimum cost for generating an independent valid query.

## Numerical calibration admissibility and legal producer portfolio

The [calibration gate](w1_machine_calibration.py) distinguishes provenance/unit
coverage from numerical support. Zero observed faults in a finite sample do
not establish zero risk. Exact rational checks retain confidence allocation,
complete denominators, event multiplicities, freshness and device/configuration
identity. Its [campaign](experiments/w1_machine_calibration_campaign.py)
reconstructs the complete native-sized declared machine and reports every
active missing class. Synthetic acceptance controls are unit tests, not
hardware data. Direct IID zero-fault inference is one possible route; a valid
separately proved error-correction transformation could support rare logical
bounds without directly sampling those failures. No hardware-bound
transformation or physical calibration is supplied.

The [producer portfolio](w1_preprocessing_portfolio.py) compares dense AB,
exact sparse AB, correction after the already-required complete ordered trace,
and verified rank-zero/rank-one factorization with a charged dense fallback.
Every producer still builds full noise, trace, ticket and proof. An independent
verifier recomputes direct AB. Trace recovery uses
AB = C' - (A Fl) Fr - El (Er B'), costing four N-squared-R multiply-accumulate
pairs plus correction, while the complete trace itself remains charged.
This identity is neither a quantum-oracle improvement nor a global lower bound.

The [campaign](experiments/w1_preprocessing_portfolio_campaign.py) freezes four
payload capacities (0, 4096, 65536 and 262144 bytes) and all four strategies.
Each pair runs once fully and once under the original four-second admission
deadline: 32 fresh child processes. The fixed stream has 16 original native
fixture candidates and 12 explicitly relation-only repeat/parent/target/task
controls. Structured controls do not assert native task-supply eligibility.
Censored reports preserve all 28 planned attempts, including never-started
and partial work, full non-preemptive overrun, initialization, key checking,
misses, fallback, evictions, proof checks, journal and outer startup/serialization.
Payload caps and process RSS do not establish equal physical resources.

Portable export first verifies the actual source-bound native fixture and
charges native-host preparation. A remote CPU consumes externally pinned
export bytes and implementation capsule and repeats complete W1 construction
and independent checks. This delegates native provenance; it does not assert
fresh Git/native admission on the remote CPU. Actual remote observation and
verification receipts, allocation lifetime and source boundaries must accompany
claims. No GPU/CPU result supplies QPU calibration, energy/capital cost,
exhaustive algorithm coverage or a global minimum.
