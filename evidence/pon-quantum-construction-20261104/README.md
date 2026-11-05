# Constructive W1 oracle and adversarial DAA continuation

**The enumerated research implementation checks passed. Quantum-mining security,
hardware calibration and production qualification remain open.** This record
does not activate a protocol, demonstrate a real quantum attack, or establish the
cheapest possible attacker.

The immutable research checkpoint is
[ba9cf57c1ff615a854cf93accf4e153614de3548](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/ba9cf57c1ff615a854cf93accf4e153614de3548),
tree d2d470407ee6e9e49b0c6aa72008943608ee1021, parent
33a170e863a413279d6611457d907913a54e9e5a, in the existing integration PR #688.
Concurrent Cell, model and throughput work was preserved. The later evidence
commit adds this record and updates the sole plan. The integration parent already
preserves the reviewed source pin for the four new CI invocations. The evidence
commit does not change the tested research implementation.

## Delivered engineering and boundaries

| Obligation | Implemented and checked | Remaining limit |
| --- | --- | --- |
| Complete fixed-context W1 predicate | PNH1/PGH2 nonce binding, every bounded noise branch, low-rank matrices, ordered transcript, ticket/target, phase and inverse | Eligibility/state execution are classical preconditions; no minimum-cost proof |
| Reversible data access | Concrete clean-XOR leaves, charged copies, static accepted-word selection, explicit register lifetime | No free QRAM; no physical routing implementation |
| Resource-to-clock connection | Rebuilt circuit budgets, all processors, whole-campaign code distance, upward event deadlines, post-winner proof | Hypothetical physical/classical inputs and abstract success law |
| Adversarial strategies | Persistent hidden marked counts, paid refresh, bounded throughput, backward timestamps, delayed-view private release | No BBHT/posterior optimum or global strategy proof |
| Complete bounded comparison | Separately named variable-difficulty OHIE state machine and synthetic ledger | No inherited security theorem or Fast DAA 2026 identity |
| Reproduction | Exact committed inputs, negative controls, seeded replay, compact receipts and CI commands | No native/public-network acceptance inherited from research checks |

The [technical research note](../../formal/pon-nakamoto-v1/QUANTUM_DAA_RESEARCH.md)
explains the wire schedule, selected protocol interpretation and assumptions.
The [reproduction manifest](reproduction.json) preserves commands, source digests,
report hashes, physical premises, failed observations and remaining gates.
Large traces and binaries are regenerated with the source entry points rather
than committed as a second archive. Absolute paths and per-point filenames in
the manifest record original run locations, not permanent download links or
additional files bundled in this directory.

## Exact committed-source checks

| Suite | Passed |
| --- | ---: |
| Retained reversible components | 17 |
| Constructive W1 oracle | 17 |
| Conditional resource accounting | 22 |
| Resource-clock binding | 18 |
| Network event model | 35 |
| Adversarial search/readback | 12 |
| Retained DAA arithmetic | 18 |
| Retained PQ/DAA scenarios | 6 |
| OHIE text-profile state machine | 28 |
| **Distinct tests** | **173** |

The clock suite was checked by two reviewers and is counted once. All declared
research inputs matched their committed Git blobs, with source hashes unchanged
before and after execution. This covers the declared inputs, not every archived
artifact in the repository.

| Experiment | Completed | Trace rows | Verification |
| --- | ---: | ---: | --- |
| Expanded adversarial matrix | 45/45 horizons | 139,936 | Seeded replay and separately transcribed periodic target/work/time arithmetic |
| Retained network matrix | 30/30 horizons | 77,847 | Seeded replay and integer readback |
| OHIE matrix | 18/18 horizons | 21,762 | Model receipt readback and seeded replay |
| Oracle construction | 5/5 cases | Structured results | Three native-size macro cases; two reduced gate cases; full replay |
| Construction-to-clock matrix | 15 admitted event runs | Digests in manifest | Budgets/clocks rederived; two further physical settings refused |

OHIE's reader shares admission predicates with its model. It is not an independent
proof or a native verifier. Execution time and synthetic protocol time are not
measurements of W1 or quantum hardware.

## Concrete construction census

The native shape uses field 2^32-5, N=64, R=8 and a 64-bit nonce. This deliberately
conservative schedule retains all intermediate outputs until the outer inverse.
Every leaf is a concrete X/CNOT/Toffoli circuit; native-size execution uses a
hierarchical scalar interpreter rather than expanding billions of leaf gates.

| Resource | PNH1 | PGH2 |
| --- | ---: | ---: |
| Logical qubits | 22,253,173 | 22,253,429 |
| Forward winner gates | 8,859,008,357 | 8,859,397,919 |
| Full compute–Z–uncompute gates | 17,718,016,715 | 17,718,795,839 |
| Phase-oracle depth upper bound | 1,969,835,151 | 1,969,864,925 |

Diffusion adds 383 gates, including 126 Toffoli, and depth at most 131. Preparation
adds 64 Hadamards. Each forward predicate includes 327,680 field multiplies,
335,872 field additions and 2,097,152 static accepted-word selection calls.
Five fixed header SHA blocks are precomputed classically; coherent compression
totals are 3,076 for PNH1 and 3,077 for PGH2. PGH2's challenge tag has 37 bytes
and the framed challenge input has 407 bytes. The initial test expectation of
405 was corrected; the implementation already used the actual native framing.

The reduced whole-phase controls execute 9,380,775 actual gates per selected
nonce, including outer X/Z operations. A winner and real SHA-derived noise
exhaustion both uncompute cleanly. Native-size macro results match the separate
W1 scalar relation. A historically admitted nonce-6 PNW1 packet also matches
challenge, trace, ticket and winner, retaining its original bd2777f9... source
scope. No current native node was built or run by this campaign.

**A large upper bound does not show that a quantum attacker must pay that cost.**
Space/time tradeoffs, different arithmetic, variable-time search, constant folding,
reusable preprocessing and other legal search variables remain optimization questions.

## Observed behavior

The expanded matrix checked 6,416 abstract blocks, 449 branch retargets and 24
admissible backward adjacent timestamps. With four paid processors and identical
synthetic clocks, first-peak private mining made 18 blocks in each seed;
bounded-throughput mining made 31, 27 and 28. Three persistent sampled N=64
domains had no marked element and stayed unsolved. Fresh domains paid setup
and produced 1, 1 and 0 blocks. No beyond-confirmation-depth reorganization or
probe-confirmation reversal was observed in the finite grid; this is not a safety
threshold or an attack on deployed nodes.

All 15 ordinary OHIE runs confirmed the probe without an observed reversal.
Three diagnostic runs withheld one chain at genesis and blocked the global
confirmation barrier. Ordinary minimum targets were 596–1024, outside the tiny
T<m unreachable-chain region. The explicit T=1 control records finite same-ticket
sortition bias, not a deployed-protocol attack.

## Physical sensitivity and refusals

The coupled matrix reconstructs every stage budget from an oracle specification.
It binds a circuit **cost shape**, not that fixed header's marked set to the
changing network targets. Physical errors 0.0001/0.001/0.003, a 1,000 ns cycle,
maximum distance 101, residual magic-state error 1e-60 and the listed factory and
classical costs are illustrative premises, not calibration.

Five profile/processor/error combinations yielded 15 replayable runs. Both PNH1
settings at physical error 0.003 were refused with NO_DISTANCE_FOR_CAMPAIGN_ENVELOPE.
The maximum distance was not enlarged to turn those settings into successes.
The successful settings completed no quantum block within the modeled 1,200-second
horizon. That cannot establish resistance to a cheaper quantum implementation.

Per-T service includes production, delivery, immediate injection, feedforward and
a paid service/buffer patch. No actual fault-tolerant layout is verified. The
error union covers coherent stages and declared T-service errors; initialization,
reset, readout and classical-controller failures are idealized or outside scope.
This is not an end-to-end machine failure bound.

## Environment and source gates

Preflight, project-boundary controls, PQ claim controls, PQ integration negative
controls, distributed-source inventory, locked offline Cargo metadata and Rust
formatting passed. The graph has 26 workspace members and 175 packages. The direct
current CI contract validator passed, including 22 inline source pins; that
validator explicitly does not execute native test jobs. Six source-only guards also passed after
preserving the 1c885019... integration parent; the 32 declared research inputs
remain byte-identical to ba9cf57c. This does not qualify the incoming native changes.

The first PQ integration readback encountered omitted historical inputs. Nineteen
small artifacts were restored byte-for-byte from their original Git blobs. The
modified CI script then required its normal source-pin update: its reviewed hash
changed and every acceptance assertion stayed false. The 450-blob guard retains
HOLD_NO_GO, with activation and cryptographic acceptance false.

Shared storage exhaustion caused a partial source write and later temporary-output
failures. The network source was restored, parsed and byte-checked before successful
observations. The initial copy-based CI contract run failed in temporary-tree
setup. After storage became available, the unchanged original suite passed all
98 tests with its full copy procedure; the failed attempt and successful retry
are separately recorded in the manifest. No fresh strict
Clippy or native-node test run on the combined native tree is claimed. Historical
native receipts retain their original source scope.

## Reproduction

Use the pinned commit, Python 3.12-compatible standard-library code and fresh
output directories. The [CI script](../../scripts/ci/ci_job.sh) contains the unit
commands. Run and replay entry points are:

- [Oracle construction](../../formal/pon-nakamoto-v1/experiments/w1_quantum_oracle_campaign.py)
- [Expanded adversarial strategies](../../formal/pon-nakamoto-v1/experiments/quantum_adversarial_campaign.py)
- [Retained network matrix](../../formal/pon-nakamoto-v1/experiments/quantum_network_campaign.py)
- [Parallel OHIE profile](../../formal/pon-nakamoto-v1/experiments/parallel_variable_ohie_campaign.py)
- [Construction/resource/event coupling](../../formal/pon-nakamoto-v1/experiments/quantum_resource_clock_campaign.py)
- [Exact seven-point resource matrix recipe](reproduce_resource_matrix.py)

Each has an explicit help interface. Exact executed arguments, seeds, report
digests and physical inputs are in the manifest. The delivered seven-point recipe
was executed from its final path: all 15 runs replayed and both refusals persisted;
the five successful reports differ from the originals only in source-head metadata. The optional historical-native
oracle control requires the original native packet fixture and receipt; it must
not be replaced by a successful stub.

## Scientific exit conditions still open

1. Attacker-minimal W1 cost or an appropriate lower-bound argument.
2. Physically calibrated fault-tolerant execution, routing, data access and reliability.
3. Actual legal-domain probability, correlation, reuse and freshness assumptions.
4. Full Fast DAA 2026 source retrieval and faithful protocol reproduction. The exact
   author-linked slides were located, but the PDF/slides remained unavailable.
5. Reconciliation of OHIE's rank and environment-window text discrepancies before
   claiming literal theorem conformance for this named profile.
6. A mixed classical/quantum common-prefix, growth, quality and transaction-liveness
   argument for a concrete deployed profile, including DAA and fork choice together.

The main engineering line remains pure PoN. These observations do not authorize
sqrt(D) chainweight, arbitrary multi-resource scores, main-branch merging or activation.
