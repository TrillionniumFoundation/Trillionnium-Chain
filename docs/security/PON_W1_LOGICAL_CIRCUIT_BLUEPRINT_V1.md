# Complete W1 logical circuit blueprint

This research construction adds concrete logical-gate templates and two explicit
time/space schedules to the [conditional DAA and static oracle ledger](PQ_NATIVE_TRANSFER_AND_QUANTUM_DAA_V1.md).
It does not change consensus, target calculation, account authority, work bytes,
proof verification, or production activation. It has no additional PoW puzzle.

The [implementation](../../formal/pon-nakamoto-v1/w1_oracle_blueprint.py) pins the
actual native `pon_work.rs` Git blob `edc516a57cd57ecd8a80a059cc5ed98e997b745c`
and the independent scalar oracle blob `9cbfccd2d50af48fc43522b967ffdfb1f45ec098`.
Source drift is an error requiring review, not an automatically refreshed pin.
The native source is available at the parent commit
[`829c5d28ec9a0fc13de2bd098b477cbacacdb4b7`](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/829c5d28ec9a0fc13de2bd098b477cbacacdb4b7).

## What is constructed and what is measured

[The bit-circuit builder](../../formal/pon-nakamoto-v1/reversible_bits.py) emits
actual X, CNOT and exact Toffoli gates, with explicit zero ancillas. Its unsigned
adder, schoolbook multiplier, constant-divisor remainder, SHA-256 compression,
first-valid-word compactor and final predicate all have materialized gate lists.
Every intermediate survives until an explicit adjoint removes it. No relative
phase gate, measurement, reset, free garbage erasure or unpriced QRAM is used.

The complete oracle uses a hierarchical call schedule. The billion-gate expanded
list and a complete quantum-state simulation have **not** been produced. The
whole wiring has **not** been formally verified. The numbers below are
constructive blueprint upper bounds under the stated wiring and connectivity
model, not an independently certified least-cost reversible W1 implementation.
Logical circuit counts are independent of the time taken by the Python tests.
The blueprint assumes the specified little-endian noise words, big-endian ticket
comparison, SHA word order and fixed-header bindings are wired accordingly; the
complete global wire connection is not covered by a full expanded-gate check.

Actual controls run materialized gate sequences and their adjoints, including
SHA-256 messages across padding boundaries, 32-bit arithmetic boundary/random
cases, rejected noise words, exhausted and saturated small compactors, and the
target/nonce/all-noise-flags predicate. The complete 64x64 W1 schedule is checked
through a **classical value interpreter** against the existing independent full
relation for zero and nonzero inputs. That differential is explicitly separate
from the gate-template controls; it is not a full quantum simulation or native
block-admission observation. These fixed matrices carry no task-eligibility claim.

## Fixed context and full coherent control flow

The search register is one 64-bit nonce. The fixed parent, task, matrices, roots,
timestamp, miner and target must already be independently eligible. A different
header context requires new setup and binding. A/B are public fixed constants;
their bits are compiled into input loads. Arbitrary variable task loading and
QRAM construction have no cost estimate here.

All four noise arrays compute all 128 allowed hashes, including eight candidate
words per hash. Each compactor accepts the first 512 words below q and saturates.
It executes the same schedule on every input. A failed array's final ready flag
is false; arithmetic still runs, but that branch is never phase-marked. Later
hashes cannot overwrite an already full array. This covers the NoiseBudget branch
instead of assuming the usual no-rejection path for every superposed nonce.

| Forward stage | Exact scheduled work |
| --- | ---: |
| Header challenge | 1 compression after 5 fixed classical prefix blocks |
| Four complete padded noise streams | 512 hashes / 1,024 compressions |
| Coherent first-valid-word selection | 4,096 compactor calls |
| E and F | 8,192 eight-product reductions |
| A+E and B+F | 8,192 field additions/reductions |
| All ordered transcript prefixes | 32,768 eight-product reductions, 512 tiles |
| One complete streaming trace | 2,049 compressions for 131,120 bytes |
| Ticket | 2 compressions |
| Predicate | Target, nonzero target, four ready flags and signed nonce range |

There are 327,680 multiply-accumulate terms, 49,152 field reductions and 3,076
SHA-256 compressions per fixed-control-flow forward call. The arithmetic template
uses a conservative 70-bit accumulator; it does not interpret Rust's u128 storage
width as a necessary quantum width. The baseline uses an explicit binary
remainder circuit, not an assumed free field operation. Matrix transposition,
SHA rotations and byte order use logical wire names; physical routing is unknown.

The prepared A*B product, task commitment and first five challenge blocks belong
to classical setup. They are not charged again to every query. After a successful
measurement, the full PNW1 witness and ordinary native admission remain separate
required costs. Verifier-only product corrections are not added to every search
query. A STARK certificate, if desired, has its own measured proof costs.

## Two explicit space/time choices

Every macro call gets fresh input ports, loaded by at most one X or CNOT per bit.
This charges constants and coherent copies. The final phase oracle computes F,
applies one Z to the actual predicate and applies the complete adjoint, restoring
nonce inputs and all oracle work bits.

| Complete phase oracle construction | Toffoli | T count at exact 7T/Toffoli | Logical qubit upper bound |
| --- | ---: | ---: | ---: |
| Retain every intermediate until the final adjoint | 2,748,849,006 | 19,241,943,042 | 3,080,564,056 |
| Compute/copy/uncompute every macro, retain only result history | 5,497,698,012 | 38,483,886,084 | 69,637,141 |

The second construction retains 69,514,241 result bits and reuses at most 122,836
scratch qubits. Its large compactor result history is intentional and unoptimized.
An actual compute/copy/adjoint gate control checks that intermediate scratch
returns to zero while inputs and copied results survive. Input-port unloading is
charged as well. This does not erase past result registers for free.

The 7T mapping uses the standard exact Toffoli decomposition, described by
[Selinger, *Quantum circuits of T-depth one*](https://arxiv.org/abs/1210.0974).
It counts T and T-dagger equally and does not imply a physical factory rate.
Clifford counts in the JSON are explicitly **before** Toffoli decomposition.
The first serial logical-depth upper bound uses X/CNOT/Toffoli/Z as elementary
logical gates, not a scheduled fault-tolerant T-depth or wall-clock prediction.

A separate 64-bit diffusion reflection uses a 62-ancilla AND ladder, one CZ and
the inverse ladder: 124 Toffolis, 868 T gates and 257 other Clifford gates. Its
temporary ancillas can reuse clean oracle scratch. The number of Grover steps is
not set by this circuit file: the actual marked fraction and its distribution
are unknown. A 64-bit nonce domain also cannot silently stand in for an unlimited
domain as the target becomes smaller; additional contexts and their setup must
then be counted. New-tip interruption, restart, search variance and winning-proof
latency remain outside this deterministic gate ledger.

## Consequence for DAA research

The existing source-bound experiment reproduces the structural difficulty attack
studied by [Bailey and Sattath](https://arxiv.org/abs/2403.08023): when relative
chain weight scales as c but an idealized search cost scales as sqrt(c), harder
private blocks may have disproportionate weight. Its `r=0.25` is an assumed
isolated rate, **not** a rate inferred from either circuit above. These very loose
upper bounds establish neither attack practicality nor resistance.

For fixed probability p0 and declared work volume m, the corresponding model is

    relative weight rate = m / (Cq(m) / Cq(1)).

If Cq(m) is linear under a fixed physical resource budget, this ratio stays one.
If batching, low rank, reuse or quantum parallelism make Cq(m) proportional to
sqrt(m), the ratio grows as sqrt(m). This is a sensitivity calculation, not a
proved successor protocol. The existing `fresh_work_sensitivity` retains both
cases and all freshness, non-grinding, context-binding and chain-quality
assumptions. No current target/work rule is replaced by it.

The next least-cost comparison must include complete paired multiplication,
periodic maintenance-prefix and rank-bounded producers, fast modular reduction,
in-place reversible compaction, recomputation/pebbling and alternative memory
access schedules. The large naive counts above cannot be used as a quantum
security lower bound. `quantum_resource_estimate_physical` and the calibrated
quantum mining rate remain null. ML-DSA account authentication, classical or
quantum W1 hardness, proof-system soundness and network availability remain
separate whole-chain requirements.

## Reproduction

```sh
python3 -B -m unittest discover -s formal/pon-nakamoto-v1 -p test_w1_oracle_blueprint.py -v
python3 -B formal/pon-nakamoto-v1/w1_oracle_blueprint.py --output /tmp/w1-logical-oracle-new.json
python3 -B formal/pon-nakamoto-v1/quantum_daa.py --output /tmp/w1-daa-conditional-new.json
```

The blueprint refuses an existing output file. The dedicated exact-head research
workflow retains success and failure logs and verifies original source bytes
before and after. Its scope does not replace any native, source-integrity,
signature, activation, model-quality, CodeQL or public-readiness gate.
