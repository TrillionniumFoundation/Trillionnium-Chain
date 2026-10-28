# PoN DAA and reversible confirmation experiment

This executable experiment extends the obligations in the
[sole development plan](../../../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md)
and the [work-cost and DAA boundary evidence](WORK_COST_DAA_BOUNDARIES.md).
It changes no consensus target, timestamp rule, required-work formula,
confirmation threshold, proof relation, request budget or activation gate.
It adds no Hashcash, alternate work lottery or production DAA profile.

There are two different kinds of evidence. The native test constructs and
admits real PNW1 packets with authenticated State. The Python experiment uses
explicit synthetic costs and a valid-proof premise to explore consequences.
Its simulated success frequencies are not measured network attack risks.

## Executable evidence

| Component | What it checks |
| --- | --- |
| [Native confirmation test](../../../../trillionnium/crates/trnm-pon-node/tests/pon_confirmation_risk_v1.rs) | A real transfer reaches the unchanged depth and required-work confirmation threshold. A separate producer withholds a real competing history. Equal cumulative work retains the current tip; a subsequently delivered, strictly heavier history reorganizes the transaction. Authenticated State and the `reorged` observation agree after reopening. |
| [Shared arithmetic vectors](../../../../formal/pon-nakamoto-v1/vectors/pon-risk-native-vectors-v1.json) | Fifteen retarget cases and eight clock cases are checked independently by native Rust and Python. They cover `interval - 1` time gaps, ceiling of the lower clamp, reversed endpoints, upper clamp, target clipping, full-width arithmetic, overflow rejection, parent-first MTP and deferred-future retry. |
| [Conditional risk model](../../../../formal/pon-nakamoto-v1/pon_risk_model_v1.py) | Two branch-local histories, complete producer costs, task changes, proof/publication latency, worker arrival/departure, withholding, exact DAA and reversible depth/work observations. |
| [Frozen synthetic inputs](../../../../formal/pon-nakamoto-v1/vectors/pon-risk-scenarios-v1.json) | Eight explicit scenarios, a seed, a finite horizon and declared complete costs. Each runs with native DAA and a fixed-target counterfactual. |
| [Model counterexamples](../../../../formal/pon-nakamoto-v1/test_pon_risk_model_v1.py) | Complete-cost accounting, invalid-input exclusion, phase exit, quantum overshoot and empty domains, strict heavier-work replacement, frozen in-flight offers, repeatability and retained censoring. |

The native observation is an expected property of probabilistic chain selection,
not evidence that an attacker can afford the competing history. It proves that
an installed-depth-and-work confirmation is reversible. It does not measure
the attacker's resource fraction, economic profitability or elapsed WAN time.
The test's development signatures and locally scheduled clocks do not certify
quantum-safe authorization or live-network service.

Run the checks from the repository root using the installed, locked toolchain:

```sh
bash scripts/project-preflight.sh --dev
python3 formal/pon-nakamoto-v1/test_pon_risk_model_v1.py -v
python3 formal/pon-nakamoto-v1/pon_risk_model_v1.py > /absolute/new-risk-report.json
cargo +1.95.0 test --manifest-path trillionnium/Cargo.toml --offline --locked \
  -p trnm-pon-node --test pon_confirmation_risk_v1 -- --nocapture
```

The existing `daa_adversarial_schedule` native test and its independent packet
reader remain separate evidence. They check actual legal endpoint schedules
and full PNW1 replay; no synthetic trace substitutes for those packets.

## Model and cost meanings

The model loads the existing development parameters. Targets use exact 256-bit
integers, accumulated work is checked against 512 bits, and clock arithmetic
matches native u64 inputs and its wider future bound. Each branch retargets
from its own actual simulated ancestry. Required work remains
`floor(2^256 / (target + 1))`; a faster legal algorithm receives no special
per-block credit. A fabricated transcript has no admissible producer kind.

An input cost describes one fixed complete producer strategy and task class.
`full_attempt_ns` includes all work needed for a legal attempted statement,
including failed target trials. `context_setup_ns` is separate preparation
charged for the slot. `winning_witness_ns` and `publication_ns` reserve extra
winning-candidate work and delivery time. Nested setup/search timings must not
be added a second time to an already inclusive measured attempt cost. The
shipped values are invented sensitivity inputs; they are not copied from a
partial verifier timer or represented as current hardware observations.

For a classical group with `w` workers, slot duration `S`, setup `c`, complete
attempt cost `a`, winning-witness time `v` and publication time `d`, the model
permits `n = w * floor(max(0, S-c-v-d)/a)` complete attempts. Under its explicit
independent, uniform-ticket premise, one attempt succeeds with probability
`p = (target + 1) / 2^256`, so the group's chance is `1-(1-p)^n`.
Only one block per group per slot can count. Unused capacity and unfinished
work do not carry forward. `reserved_worker_wall_ns` is an opportunity budget,
not measured consumed CPU or a claim of perfect parallel scaling.

These slot assumptions are material. A job that cannot finish inside a slot
gets no opportunity in this experiment; that result does not mean a real
miner cannot finish the job across slots. Startup at an easy target and large
worker groups can hit the one-block cap. A continuous event model, slot-size
sensitivity, measured hardware costs and realistic queue/propagation traces
are needed before calibrating an actual deployment. The model emits these
limits and refuses an input that labels its costs as certified measurements.

## Withholding and confirmation

The public branch includes the observed transaction in its first block. Both
branches start at genesis. The private producer uses a declared wall-clock,
minimum-median, future-boundary or period-endpoint timestamp policy. Every
accepted synthetic header must satisfy the same MTP and future constraints.
The private history cannot affect public confirmation before delivery.

An offer can start only after the public transaction has met both installed
confirmation conditions and the private branch is strictly heavier. The
offered prefix is frozen for the declared release delay. Blocks mined during
download are not silently appended or credited before delivery. When it
arrives, that exact prefix must still be strictly heavier than the current
public branch. A tied or overtaken offer fails. Both groups continue mining
during delivery. The tests include a case where later private work would win
if it were improperly credited to an older in-flight offer.

The report retains all trials. It distinguishes no confirmation before the
horizon, confirmation followed by reorganization, confirmation surviving only
until the horizon, and an offer still in flight. It provides both the all-trial
denominator and the denominator conditioned on an observed confirmation. A
missing conditional denominator is `null`. Zero observed reorganizations do
not become zero risk: the finite-sample Wilson upper interval remains positive.
These intervals describe Monte Carlo sampling inside the declared model;
they exclude uncertainty in the work primitive, costs, occupancy and network.

All scenarios and their fixed-target arms use the same uniform samples for
each trial, so changing a scenario label cannot create a sampled effect. The
fixed-target arm is a research counterfactual, not a proposed activation. An increase or decrease in its
sampled failure frequency is not proof that a DAA is secure or insecure.

## Quantum search is costed as a complete PoN oracle

The quantum arm fixes its iteration count in the input and never optimizes it
using the marked count. Each attempt charges that count times a declared
complete clean W1 oracle plus diffusion cost, then measurement, a complete
check and restart. A nonzero classical winning-witness cost is mandatory.
The model does not replace neural work with a free hash oracle or add a new
external work gate.

For an explicitly hypothesized domain of `N = 2^nonce_bits` candidates and
`M` marked candidates, the ideal conditional success expression is
`sin^2((2k+1) asin(sqrt(M/N)))`. The shipped hypothesis obtains `M` by the
declared floor or ceiling of `N*p`. This is a sensitivity premise, not the
unknown actual occupancy of W1's nonce domain, a bound on that occupancy or
knowledge available to a miner. The program separately exposes `(1-p)^N`
under an independent Bernoulli-domain assumption. It does not multiply that
diagnostic into the fixed-M expression and call the result a marginal risk.

Tests cover empty and fully marked domains, classical sampling at zero
iterations, overshooting an optimum, unchanged iteration policy across
occupancy hypotheses, and the loss of opportunity when complete oracle cost
increases. The current experiment does not integrate an unknown-M distribution,
model quantum circuit faults, establish a minimal reversible W1 oracle or
measure physical quantum throughput. It consequently cannot establish that
the chain is quantum safe or predict a quantum attack date.

## Interpretation and remaining boundary

The executable result closes a reproducibility gap: complete-cost hypotheses
can now be run through branch-local native DAA arithmetic, a real confirmation
counterexample, explicit withholding delays and finite-horizon observations.
It supplies no automatic reward, work-profile qualification or production
activation. Selecting production parameters still requires measured complete
legal strategy costs over task distributions, realistic propagation and
queue behavior, independent chain-quality analysis, and explicit acceptable
loss probabilities for the actions that consume confirmations.
