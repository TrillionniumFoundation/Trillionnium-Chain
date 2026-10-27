# P2 measured-cost admission envelope: conditional analysis only

**Source-only P2 research; no production protocol selection.** Evaluate
the explicitly original development V3 Cookie difficulty choices
8, 12, 16, 20 bits without changing `PublicPolicy`, the Cookie MAC,
the W1 transcript equation, proof/target or chainwork.

## Why one observed ratio is not an economic defense

For per-trial success probability `p=2^-bits` under the
**assumed** independent-uniform SHA-256 search model, unbounded expected
hash trials per successful ticket are `1/p`. Its 95th-percentile trial
count is `ceil(log(0.05)/log(1-p))`; the 95th percentile is about
three times the expected effort at small `p`.

Conditional on a real measured honest CPU hash cost `H`, a real measured
fastest available attacker cost `A` including GPU/ASIC and amortization,
honest *nonhash* cost `N`, available honest deadline `D` and complete
defender invalid-W1 cost `V`, a candidate may be worth **further**
measurement only when both inequalities hold:

- expected attacker expenditure: `2^bits * A >= V`;
- 95th-percentile honest expenditure: `quantile_trials(bits)*H+N <= D`.

These inequalities **cannot prove a lower bound for every attack**:
a lucky attacker may find a winner on its first hash, while another
must spend much more. A global ticket may also be replayed across
multiple receivers unless the actual V3 receiver-bound authenticated
grant and spent-table protections apply. Distinct proof bytes, requests
and identities also consume independent verification CPU.

The Rust public V3 Cookie TTL is only 100–2000ms, with original
absolute request/connection deadlines; CPU time is not the same as
wall time or an admissible lifetime under contention. The model above
only compares *conditional cost indicators*; it is **not** a full
latency, energy, GPU or honest-service acceptance model.

## Executable read-only evaluator

`formal/pon-nakamoto-v1/w2_admission_cost_envelope.py` accepts an
existing UTF-8 JSON file with **exactly** the following fields, using
positive numeric nanoseconds or explicit `null` for unknown:

```json
{
  "honest_hash_cpu_ns": null,
  "attacker_fastest_hash_ns": null,
  "invalid_w1_cpu_ns": null,
  "honest_nonhash_ns": null,
  "honest_deadline_ns": null,
  "observation_scope": "synthetic"
}
```

For actual, unattested local measurements, set scope to
`measured_unattested`. The program cannot verify the physical provenance
of a caller-supplied number. A complete real measurement package must
independently bind exact source, binaries, target, CPU/GPU, watt/energy,
time windows, request bytes, failed trials, producer setup and full
honest/attacker denominator. Without that data the research verdict is
`UNKNOWN_INCOMPLETE_MEASUREMENTS`, **not** PASS.

```sh
python3 formal/pon-nakamoto-v1/w2_admission_cost_envelope.py --input /unique/measured.json --out /new/unique/conditional-result.json
python3 formal/pon-nakamoto-v1/test_w2_admission_cost_envelope.py -v
```

The evaluator produces four fixed-bit conditional rows, each with
expected attacker ticket CPU cost, honest 95th-percentile cost, ratio
to defender W1 rejection CPU, an explicit `null` when necessary data
are missing, and permanent `production_consensus_activation=false`.
Its four deterministic tests deliberately include an extremely fast
attacker, the 16-bit vs 20-bit honest deadline tradeoff, unknown GPU
data and invalid numeric inputs.

The reader rejects duplicate JSON object keys and nonfinite JSON
constants rather than silently overriding an attacker-cost input. With all
five required numeric inputs present, it returns one of two *conditional*
research states: `SOME_BITS_EXPECTED_COST_ONLY` or
`NO_BIT_FEASIBLE_UNDER_DECLARED_COSTS`. Missing GPU or other inputs returns
`UNKNOWN_INCOMPLETE_MEASUREMENTS`. None of these three states can set a
public-readiness or production activation flag.

No amount of this CPU-only arithmetic demonstrates Sybil-safe admission,
valid neural-work mining hardness, true GPU/ASIC economics or the full
A03 three-mode three-run three-timely-confirmation safety criterion.
Until actual physical evidence and external review arrive, P2/P4/P5/P6
remain OPEN, and W1 production activation remains HOLD_NO_GO.
