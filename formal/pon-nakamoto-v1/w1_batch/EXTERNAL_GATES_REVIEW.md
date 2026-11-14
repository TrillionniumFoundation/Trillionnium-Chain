# Quantum/DAA and independent WAN: remaining closure obligations

This is a source/evidence review alongside the W1 batch experiment. It changes
no consensus or acceptance rule. It records what can be searched or audited,
and what an isolated source-only session cannot honestly declare closed.

## 2C: fixed success probability does not establish work hardness

The existing [conditional model](../quantum_daa_model.py) and
[campaign](../experiments/quantum_daa_campaign.py) implement integer target,
timestamp, work and ASERT arithmetic, but choose work costs as assumptions.
For fixed probability, `cost_ratio` uses either `units/initial_units` or its
square root. Neither is a measured coherent W1 circuit or a lower bound for
the best classical/quantum algorithm. Its flags correctly leave quantum
execution, W1 measurement and a security theorem false.

The [Bailey–Sattath paper](https://arxiv.org/abs/2403.08023v2) shows the
chainweight/cost mismatch mechanism when target changes give linearly more
credited work but ideal quantum search has square-root query scaling. Its
physical feasibility assumptions must stay attached. The original
[BBBV oracle lower-bound result](https://arxiv.org/abs/quant-ph/9701001) and
[Boyer–Brassard–Høyer–Tapp search analysis](https://arxiv.org/abs/quant-ph/9605034)
bound oracle searches; they do not prove the gate count, memory cost,
preprocessing cost, parallel cost or amortized cost of this concrete W1 oracle.

An immediate conditional counterexample family is useful. Let u be work scale
relative to the baseline, let the proposed credited weight grow as u, and
assume an attacker's concrete per-attempt resource cost instead scales as
u^alpha. At fixed success probability, the credited-work rate relative to a
unit-scale reference is r*u^(1-alpha), where r is the baseline resource-rate
ratio. For r=1/4, this exceeds 1 at u>16 if alpha=1/2, u>256 if alpha=3/4,
or u>1,048,576 if alpha=9/10. This algebra is our inference under the explicit
cost premise. It is **not evidence of an implemented attack**, and feasible
DAA/MTP/future-time trajectories and allowed work caps can prevent some scales.
The existing sqrt-work case already tests this kind of mismatch.

Pure PoN is preserved by rejecting unjustified linear work credit, not by
adding a fallback resource. To freeze linear credit, a later claim must bind
the exact work relation and explain why the admitted hardware/preprocessing
model gives an adequate lower bound on *additional* cost for an additional
distinct work. Transparent compression alone does not supply that argument.
SHA-256 oracle query bounds, public output size and measured FLOPs are each
insufficient to establish that full premise.

### Concrete bounded search to add next

The code locations are `Scenario`, `required`, `cost_ratio` and the trajectory
loop in `quantum_daa_model.py`. Preserve the current baseline vectors and
original schedules. An isolated search runner can extend the following state:
full last DAA interval, full last 11 timestamps, fixed ASERT anchor, exact
target, work units, cumulative credited work and paid elapsed resources.
Two states with equal height/work but different timestamp history cannot be
merged as if they had the same legal future.

Before execution, freeze an enumerated grid: all four existing policies;
baseline rates 1/64, 1/16, 1/4; proof delays 0, 1 and 10 seconds; fixed-work
exponents 1/2, 3/4, 9/10 and 1; the existing work cap and both shorter and
extended tails. Enumerate timestamp increments in {1, 5, 10, 20, 40} plus the
exact MTP+1 and future-time boundary choices. Apply the original integer
retarget/MTP rules and charge physical waiting before accepting a future
timestamp. Add explicit one-time preprocessing and amortization parameters,
not an uncharged cache.

First enumerate small horizons exhaustively. For longer horizons, a declared
beam of 1,024 states and a 4,096-block horizon is a bounded *search*, not an
exhaustive proof. Freeze tie-breaking and seed, retain every explored/pruned
count, preserve complete replayable counterexample traces, and cap total CPU
and stored states. Cross-check each reported trace with the independent
reference arithmetic. A timeout, pruning or no found counterexample is
INCONCLUSIVE. A found trace refutes only the declared arithmetic/cost model.
Do not call any of these rows native packets, quantum gates or a real attack.

To move beyond model counterexamples, build the exact reversible oracle for
all W1 components: task/header binding, rejection sampling, transcript
prefixes, arithmetic, output and ticket comparison, including uncomputation.
Record logical qubits, T/Toffoli count and depth, memory accesses, error budget,
parallelism/preprocessing model and a stated fault-tolerant hardware mapping.
Even a constructed circuit is an upper-bound implementation, not an optimal
lower-bound theorem. Full protocol proof-system/QROM soundness and concrete
hash security are separate obligations. Neither an ASERT simulation nor a
successful recursive STARK closes them.

## 5: independent WAN evidence is absent in the reviewed scope

The pre-existing contract is
[WAN evidence accounting v1](../../../docs/protocol/pon-nakamoto-v1/details/WAN_EVIDENCE_ACCOUNTING_V1.md),
with [performance acceptance](../../../docs/protocol/pon-nakamoto-v1/details/PERFORMANCE_ACCEPTANCE.md)
and [Cell repair/availability duties](../../../docs/protocol/pon-nakamoto-v1/details/CELL_P2P_V1.md).
It requires **at least three independent administrators and failure domains,
and at least 72 hours of real operation**. A JSON maximum timestamp is not
physical duration. Different machines, usernames, regions, agents or CI jobs
under one administrator do not satisfy independence.

Read-only inspection of current `config`, `evidence`, `docs`, `scripts` and
`formal` found the preregistration schema / external-attestation field only in
the contract, [arithmetic reader](../../../scripts/pon_wan_evidence.py), and
its [synthetic tests](../../../scripts/ci/test_pon_wan_evidence.py). No actual
campaign preregistration or independent operator attestations were found in
that scope. This is a scoped absence finding, not a claim to have inspected
every external deployment or account.

The retained earlier multi-host reports explicitly deny independence:

| Reviewed report | Relevant retained declaration |
| --- | --- |
| `evidence/pon-v3/multihost/report.json` | Three hosts declare `independent_operator=false`; `same_operator=true`; independent/public acceptance false |
| `evidence/pon-v4/native-hosts/report.json` | Host results declare `independent_operator=false` |
| `evidence/pon-evaluation-bundle-v1/hosts/report.json` | Three results declare false; aggregate independent operators false |
| `evidence/pon-v1/network-report.json` | `independent_operators=false` |

No credentials, login sessions, third-party endpoints or people were probed or
contacted in this review. The current work supplies no independently owned
deployment/monitoring resources. **WAN remains NOT_RUN / HOLD_NO_GO.**

### Executable independent acceptance review contract

Before the first scheduled operation, the real operators must publish a
source-bound signed preregistration and authenticated control attestations,
with their independently controlled endpoint/monitoring evidence. Freeze
Chain/Hepta source and binaries, exact threat model, faults, offered workload,
original operation IDs and nonces, confirmations, all service deadlines,
minimum samples and timely-completion floors, all resource limits,
publisher/replica-loss duties, no-update policy and stopping rule. Use the
existing authorities for thresholds; do not insert favorable new floors after
seeing the measurements. The source-only review does not fabricate operators,
signatures, hashes, deployed endpoints or a future schedule.

Independent collectors retain every original scheduled request, including
client queue time, successful confirmation, timeout, busy, unavailable,
rejection, cancellation and send failure. Retrying/polling an operation retains
its original identity. Missing rows are failures in the scheduled denominator,
not exclusions. Preserve raw authenticated receipts, confirmation depth,
block ID/chainwork, later reorg/loss, CPU/RSS/bytes and resource attribution
gaps, as well as independent real-time monitoring and fault execution records.

Run the current arithmetic reader against the frozen originals:

```sh
python3 scripts/pon_wan_evidence.py frozen-manifest.json original-observations.jsonl
```

Then independently join and verify the originals against these obligations:

| Review gate | Evidence required before acceptance |
| --- | --- |
| Administrative independence | Authenticated ownership/control attestations and genuinely separate operational authority |
| Physical duration | Independent start/end/continuous monitoring proving at least 72 real hours; gaps retained |
| Exact source/state | Binary/source identities, required transport/authorization, canonical state/receipt roots and reorg behavior |
| Every operator/cohort | Original scheduled denominator and its own frozen service floor; aggregate success cannot mask one failed operator |
| Adversarial budgets | Original depleted-budget hostile loads, honest requests, lock/CPU behavior and actual restart/kill cuts |
| Cell/Hepta | Publisher-offline recovery, actual install/inference, future-task comparison, no-update and repair/retention duties |
| Resource completeness | Failed and successful attempts, queueing, all bytes/CPU/RSS and unmeasured gaps |
| Decision | All required gates pass under the predeclared threat model, or retain failure/INCONCLUSIVE/NOT_RUN |

The reader intentionally leaves authentication, independence, physical
duration, state safety and model-quality flags false even if arithmetic exits
zero. Synthetic tests validate the reader only. They must not be uploaded as a
three-admin campaign or substituted for any row in this contract. The external
resources and elapsed observation time are required dependencies, not software
defects that a source patch can erase.
