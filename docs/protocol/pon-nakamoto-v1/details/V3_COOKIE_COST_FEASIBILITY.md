# P2: V3 Cookie ticket economic-feasibility screen (research only)

Source implementation: 'scripts/pon_admission_price_model.py'.
Test selector: 'python3 scripts/ci/test_pon_admission_price_model.py'.
This is not V3 public-service integration and changes no signed Cookie profile,
W1 proof, target, Chainwork, ledger authority or release/production flag.

## Why a single bit value is not sufficient

A false W1 transcript can satisfy the existing cheap claimed-ticket check
without computing the real transcript, triggering expensive full rejection.
Adding a front-door Hashcash raises client work, but:
- The fastest hostile GPU/ASIC can hash far more cheaply than a CPU miner or
  interactive honest client.
- A legit client must finish the *actual receiver-bound* short-lived Cookie
  challenge and body exchange within its retained deadline. More bits can
  exclude the honest client before pricing out attacker validation cost.
- Hashcash expected tickets use the **geometric distribution**. In this
  model, a b-bit ticket has expected 2^b hashes, and the 95th-percentile
  number of attempts is ceil(log(0.05)/log(1-2^-b)). Neither is a worst-case
  computational lower bound for an individual winning ticket.
- Real GPU equipment cost and receiver energy/resource cost may be incomparable
  even when both are converted to dollars. One observed cost is not a theorem
  of independent identities, sustained WAN fairness or every possible ASIC.

## Strict input and output

The machine input uses exact schema
'trnm-v3-cost-feasibility-research-v1' and explicitly supplied measurement
identities: honest hashes per second, honest fixed handshake overhead,
original Cookie validity milliseconds and honest 95th-percentile budget;
cost in USD per complete invalid W1 receiver validation; 1..12 labelled CPU,
GPU or ASIC adversarial arms with hashes/second, USD/second and a source digest.
All fractional costs are **finite positive decimal strings**, not silent
float defaults. The source commit must be a lowercase 40-digit hex identifier,
but a self-declared source hash is not independently authenticated.

For each of the existing V3 bits 8..20, the model computes:
1. Expected cheapest attacker ticket cost across the supplied arms;
2. Measured-cost proxy for the receiver W1 rejection;
3. Expected receiver/attacker spending ratio;
4. Honest client's 95th-percentile full ticket time under the exact
   supplied CPU speed and fixed overhead;
5. Whether BOTH operator-declared economics and honest latency constraints
   can be satisfied. Empty model-feasible bits is an explicit failed result,
   not permission to guess a production price.

The returned booleans
'hardware_rates_observed_by_this_model=false',
'source_identity_verified_by_this_model=false',
'independent_security_accepted=false', and
'production_activation=false' are **immutable**. Even a hypothetical
successful cost model cannot activate or certify a signed V3 Cookie policy.
The program never writes back to source/config; --out is create-only.

## Worked negative fixture (synthetic; NOT a GPU benchmark)

The test supplies a hypothetical honest CPU able to try 1,000,000 SHA
tickets/s, a receiver costing $0.000001 per false W1 rejection, and a
hypothetical hostile GPU doing 10,000,000,000 hashes/s at $0.01/s.
Cookie lifetime and honest p95 upper bound are both 2000ms; assumed fixed
honest overhead is 5ms and required attack-cost margin is 1x.

No bit setting from 8 through 20 satisfies both constraints: 20 bits are
approximately the first to cover the assumed receiver dollar cost, but
honest p95 requires more than 2000ms. This is a counterexample to the
claim that raising bits always repairs the public admission asymmetry.
The fixture is declared synthetic, not mislabelled as measured physical
GPU power/rental costs.

## Remaining evidence before P2 can close

Real signed V3 Cookie traces, actual W1 from-zero false rejection, CPU/GPU/ASIC
hash cost, network receive/canonical decode costs, payment/energy price
assumptions, miner chance/preprocessing and honest p95 under saturation must
be measured at frozen source/tree/hardware/independent fault domains.
Attacker identity rotation and one-use receiver binding must be evaluated
with P1 shared Host limits and P3 honest mixed traffic. Failed, Busy,
deadline and exhausted cohorts remain in denominators, not omitted.
The original A03 3x3x3 attack/honest confirmation matrix and P6 independent
cryptographic review still apply. All production activation stays DENY_ALL /
HOLD_NO_GO regardless of this utility's model-feasible result.
