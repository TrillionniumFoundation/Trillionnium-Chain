# Conditional unknown-marked-count search cost

The [finite stopping model](PON_FINITE_NONCE_STOPPING_MODEL_V1.md) assumes the
searcher knows the actual number of winning nonces, M. This continuation adds
an explicit policy that does not read M and does not perform uncharged quantum
counting. The evaluator still conditions on a supplied M to calculate results.
The actual W1 marked distribution and physical quantum costs remain unknown.

The policy and cost evaluator are in
[quantum_unknown_marked.py](../../formal/pon-nakamoto-v1/quantum_unknown_marked.py);
[independent controls](../../formal/pon-nakamoto-v1/test_quantum_unknown_marked.py)
check its probability and cost calculations. Existing native W1, target,
chainwork, DAA and all prior model source files remain unchanged. No additional
PoW, activation, production miner or quantum security conclusion is introduced.

## Declared policy

[Boyer, Brassard, Hoyer and Tapp, section 4](https://arxiv.org/html/quant-ph/9605034v1)
describe a randomized iteration policy for an unknown number of solutions.
Our implementation starts with rational m=1, draws j uniformly from the
nonnegative integers below m, performs j Grover iterations, measures and checks
the result. A failure resets the state and replaces m by min(6m/5, cap).
The integer support therefore has ceil(m) choices; rational growth is exact.
The last window repeats. The policy interface accepts domain size and an
explicit cap; it has no M argument. A full quantum reset may revisit a nonce.

The cap cannot exceed floor(sqrt(N)) or the evaluator's declared 10,000-choice
numerical limit. The 64-bit examples explicitly select cap=256. This is a
restricted policy, not the full sqrt(N) search or a universal optimum. Its
additional cost when only a few nonces win is retained. A finite attempt limit
returns an exhaustion outcome; it does not certify that the domain is empty.
An empty domain without an attempt limit or external tip is nonterminating.

For each j the evaluator computes the ideal success probability with an
80-digit Decimal cosine recurrence. With p=M/N and x0=1-2p, it uses
x1=4*x0^3-3*x0 and x[j+1]=2*(2*x0^2-1)*x[j]-x[j-1], then P[j]=(1-x[j])/2.
This avoids amplifying a binary64 arcsine error through a large phase and
retains very sparse and nearly full 64-bit domains. Success and failure
probabilities are converted separately, preserving a failed-draw probability
of 2^-64 even when success rounds to one. Values outside [0,1] are
rejected. It remains a numerical evaluation, not a certified interval proof.

## Complete timing and interruption accounting

The prior four timing inputs remain: full clean W1 oracle plus diffusion,
per-attempt preparation/measurement/classical check, initial context setup,
and the winning witness/publication tail. A fifth strictly positive input
charges every random policy draw and its control work. No timing is inferred
from a gate count. All example times are declared assumptions.

For one stage let p_j be the ideal success probability, s_j the draw plus
iterations plus check duration, v the winning tail, and lambda an assumed
independent Poisson rate of external tips. Define
J(t)=(1-exp(-lambda*t))/lambda, with J(t)=t when lambda=0. Averaging uniformly
over the stage's iteration window gives:

| Quantity | Stage calculation |
| --- | --- |
| Delivered win before an external tip | mean(p_j * exp(-lambda*(s_j+v))) |
| Failed check with no external tip | mean((1-p_j) * exp(-lambda*s_j)) |
| Expected elapsed time until any stage outcome | mean(J(s_j) + p_j*exp(-lambda*s_j)*J(v)) |

The evaluator composes failure transitions, separately charges initial setup,
and sums the repeating final window as a geometric tail. It computes the
tail's exit probability directly, preserving probabilities as small as 2^-64;
subtracting a rounded failure probability from one would lose those exits.
External interruption applies during setup, policy draw, computation, checking
and successful publication. The model abandons on a tip and excludes strategic
salvage measurements, network latency distributions and equilibrium behavior.

Without interruption, it also reports expected complete Grover iterations and
measurement/check attempts. These independently reconcile elapsed time with
all five costs. With interruption these counters are null: charging a complete
oracle to every interrupted attempt would misrepresent work actually executed.
Out-of-range finite means are explicitly refused, preserving finite JSON.

## W1 and DAA binding

The report obtains the original
[full W1 blueprint](PON_W1_LOGICAL_CIRCUIT_BLUEPRINT_V1.md) and checks its original
native/reference source bindings. Its retained-history phase-oracle upper
bound is 2,748,849,006 Toffolis; the 64-bit diffusion adds 124. For uninterrupted
64-bit scenarios only, multiplying expected iterations by 2,748,849,130 gives
the conditional expected Toffoli count for that particular construction.
This is neither a least-cost oracle nor a physical gate rate, memory budget,
fault-tolerance estimate or actual quantum run. Setup/check/publication costs
remain explicitly separate rather than disappearing from the total time.

The report also compares the same three declared DAA cost laws as the existing
model: reducing the marked fraction, fixed probability with linear oracle
cost, and fixed probability with square-root oracle cost. It repeats the
comparison at external rates 0, 0.1 and 1 per assumed second. In the variable
work cases, setup, check, random draw and winning tail all grow linearly with
the work multiplier. These are sensitivity calculations. The original
[difficulty manipulation reproduction](PQ_NATIVE_TRANSFER_AND_QUANTUM_DAA_V1.md)
and the attack's full native timestamp/target checks remain separate.

Unknown M is now a costed policy choice in this model; its real distribution,
optimal search policy, cheapest legal oracle, physical resources, strategic
miners and chain quality under a candidate DAA remain unresolved. The report
keeps every production/security qualification false.

## Reproduction and checks

```sh
bash scripts/project-preflight.sh
python3 -B -m unittest discover -s formal/pon-nakamoto-v1 -p test_quantum_unknown_marked.py -v
python3 -B formal/pon-nakamoto-v1/quantum_unknown_marked.py --output /tmp/unknown-marked-new.json
```

The new output path must not exist. Independent controls compare 8,576 dense
state-vector probabilities, including overshoot, and 120 finite terminal-path
enumerations using the random iteration choices. They also check exact
rational windows, quarter-fraction and nearly full 64-bit endpoints, empty
domains, actual draw/check/tail costs, interruption during successful delivery,
geometric-tail convergence and explicit numerical/operation limits. The
existing 21 stopping, 11 reversible-template and 7 native DAA controls are
retained in the unchanged dedicated workflow alongside these new controls.
Full Cargo, security and whole-repository gates retain their own outcomes.
