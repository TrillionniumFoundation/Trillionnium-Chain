# Source incentive research contract — 2026-11-12

## Status and ownership

This is a finite research and verification contract within PN0/PN3/PN4 of the
[sole development plan](TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md), under the
existing M10/M11/M12 and M07/M08 owners. It adds no activation decision, identity
authority, alternative roadmap, or production acceptance flag.

The [independent reference tool](../../scripts/experiments/source_incentive_reference_v6.py)
uses only the Python standard library. Its exact-integer toy utility, digest
namespace, and collateral accounting model do not import or duplicate Rust
implementation results. Every ordinary result declares:

- model_only = true;
- native_payment_executed = false;
- market_test = false;
- native_acceptance_granted = false.

A passing mathematical model, a passing arithmetic check of a supplied receipt,
an executed native payment regression, and observed real-market incentive
compatibility are four different claims. The tool supplies only the first two.
A receipt is untrusted input; a successful check does not authenticate its origin.

The historical
[source-split receipt](../../evidence/chain-incentive-counterexamples-20261112/node-genesis-split/native.json)
must remain unchanged. It records the original same-source manipulation and its
original implementation identity. New candidate results cannot rewrite that
observation or qualify unrelated branches.

## 1. Frozen source game

For a registered additive profile, freeze a parent, the source registry G, exact
source-relative updates, an evaluation plan, an evaluation-randomness plan, a
funded model budget B, source caps, and source-internal authorization rules.

For each source s, first compute its complete signed update:

    D_s = CanonicalAggregate(parent, profile, all components assigned to s)

Construct the value game from these complete source updates. Only afterwards
apply the specified value transformation, positive part, source cap, and monetary
rounding. Adding old component-omission scores after they were clipped does not
implement source-level valuation.

The limited invariant is:

> If an admitted transformation preserves the frozen source registry, every
> canonical source update, evaluation plan and randomness, eligibility decision,
> budget, caps, and internal authorization totals, it preserves every source's
> entitlement and the refund.

The transformation class includes signed splitting, permutation, and authorized
payout-alias changes within one known source. It does not include an attacker
claiming a new unknown source or changing ownership evidence.

The proof is direct: all inputs of the deterministic valuation and settlement
functions are unchanged. It is not a theorem about truthful bidding, unknown
Sybil identities, collusion, or global fairness. The valuation need not be a
Shapley value to possess this restricted invariant.

### Exact arithmetic and source identity

The reference profile is explicitly
reference.signed-i64-vector-addition.v6. Every component is a signed 64-bit
integer vector with a matching parent and profile. Accumulation is performed
with exact unbounded intermediate integers, then the complete source vector is
range-checked once. Input shape, component count, and source count are bounded.
An invalid final aggregate is rejected; no saturation or intermediate positive
part is used. This makes cancellation independent of component ordering.

This reference registration does not register a new Chain production profile.
Its limits are an executable mathematical domain, not an assertion about Rust
storage widths or accepted on-chain bytes.

The source registry is frozen independently of payout aliases. A source with
zero net update remains a named member of this frozen game. Unknown sources,
mixed parents, mixed profiles, non-integer values, and shape mismatches are
rejected. Known attribution is an input assumption; the program does not prove
that two authors have the same real-world controller.

Floating-point accumulation, LoRA factor equivalence, changed base models, and
non-additive Cell graphs need their own canonicalization contracts and negative
tests. They receive no guarantee from this reference profile.

### Digest and randomness separation

The independent digest uses:

    SHA-512(
        b"TRNM_SOURCE_INCENTIVE_INDEPENDENT_REFERENCE_V6\0"
        || ASCII(kind)
        || b"\0"
        || canonical_json
    )

The JSON is ASCII with sorted object keys, compact separators, exact integer
fields, and no non-finite numbers. The game object contains the parent identity
and vector, target vector, profile, evaluation plan, and source-sorted aggregate
updates. Payout aliases and original component packaging are absent. A separate
contract digest also binds the budget, caps, adoption flag, and
counterfactual-validity inputs.

This is an independent reference namespace. It must not be compared to a native
game digest without specifying and implementing the native preimage separately.
The receipt reader currently reports native_game_digest_recomputed = false.

Evaluation randomness must be a function of the frozen canonical game and
committed plan, not a manipulable component ID, payout address, or packaging
digest. Otherwise a representation change can produce a new estimator sample
and a new payment even when the exact game has not changed. Retain both raw
release identity and canonical game identity when they serve different purposes.

## 2. Finite-budget settlement

For nonnegative conservative source values v_s, define V as their sum:

    R_s = min(cap_s, floor(B * v_s / V))  if Adopted and V > 0
          0                             otherwise

    refund = B - sum(R_s)

All quantities in the reference payment formula are exact integers. Each source
is rounded and capped once. Since R_s is at most B*v_s/V, total rewards cannot
exceed B. Any remainder is refunded; this contract does not redistribute it by
component count or address ordering.

Source-internal payments must sum to the source entitlement without creating
additional caps or claims. Fees are accounted for separately. Equal gross
entitlement does not prove equal net balance under an arbitrary fee schedule.
Do not describe a conservation result as proof of resistance to manipulation.

The receipt check accepts an object with:

- sources: rows containing source, delta_hash, without_correct, weight, cap,
  and reward; standalone_correct is checked when retained by the bounded receipt;
- payments: rows containing contribution, source, payee, marker: 1, and amount;
- game_digest, total_weight, budget, allocated, and refund.

It independently checks unique source rows, exact integer financial fields,
the total weight, the source-level floor/cap formula, aggregate payments by
source, and budget conservation. It rejects duplicate payment identities and
payments to sources absent from the frozen source rows. It does not establish
that the reported weights are correct, that adoption was authorized, that funds
were actually locked, that signatures are authentic, or that native execution
occurred. The formula check is conditional on an eligible settlement.

## 3. Valid counterfactuals

The toy game defines the actual composed vector for a coalition Q as:

    M(Q) = parent + sum(D_s for s in Q)

Its deterministic utility is the negative sum of squared integer errors against
a fixed target. Source value is the nonnegative full-minus-source-omitted
difference. This is an independently specified toy LOO game, not a claim about
the native evaluator's scientific usefulness or its precise weight formula.

Every required counterfactual must be well defined and in the registered domain.
A full model or omitted-source model that cannot be formed yields
InsufficientEvidence. The program returns source_values = null, zero allocation,
and the full budget as unallocated/refundable in the model. It does not invent a
numerical zero utility and reward an artificially indispensable source.

For a real Cell graph, the frozen evaluation contract must additionally specify
baseline replacements, dependency closure, feasible coalitions, and composition
and loading rules. A dependency declaration is not itself evidence that the
dependency is necessary or legitimate. An unavailable or invalid counterfactual
must not be silently replaced by zero.

## 4. Concurrent responsibility and payment order

For attack strategy alpha and history h, the economic target is a bound on:

    expected cheating gain
        <= cost-saving upper bound + extra-revenue upper bound
           - effective probability * executable-loss lower bound

The effective probability concerns actual audit, adjudication, and execution
under that strategy. A valid decomposition uses conditional probabilities:

    P(audit | h, alpha)
    * P(adverse decision | audit, h, alpha)
    * P(executed loss | audit, adverse decision, h, alpha)

Multiplying unrelated marginal probabilities is not justified.

### One shared slash is insufficient

The explicitly mathematical shared-collateral example assumes cost saving c=1
per task, independent detection p=1/20, one stake S=25 that can be slashed at
most once, final unrecoverable rewards, and no other recourse:

    G(k) = k*c - (1 - (1-p)^k)*S

The reference computes this with rational arithmetic:

| k | Expected gain, decimal approximation |
| --- | ---: |
| 1 | -0.25 |
| 10 | -0.0315765190 |
| 11 | +0.2200023069 |
| 100 | +75.1480132305 |

The first profitable integer k in 1..100 is 11. These are calculated model
outputs, not observed market behavior.

If every obligation has separately executable stake 25 and conditional
effective punishment probability at least 1/20, with savings at most 1 and no
extra gain, expectation linearity gives a per-obligation upper bound of -0.25.
This expectation bound does not require independence across obligations. It
does require that each promised loss can actually be executed, rather than
sharing a single aggregate slash limit.

The finite ReservationModel checks accounting exclusion, unchanged retries,
unresolved-exit refusal, distinct liability consumption, and terminal
idempotency. Its invariant is:

    available + reserved + withdrawn + slashed = deposited

It does not create actual deposits, implement persistent locking, certify
concurrent database transactions, reserve real audit capacity, or execute
slashing. Those remain native-owner obligations.

### Maturity and cancellation change the model

If any detection also cancels an entire batch of still-unmatured, enforceably
recoverable rewards R_batch, the corresponding simplified model becomes:

    G(k) = k*c - (1-(1-p)^k)*(S + R_batch)

Already final, unrecoverable rewards cannot be included in R_batch. The same
asset cannot count as both stake and recoverable reward. Auditing capacity,
dispute service, funding, maturity, final payment, exit, and restart/reorg order
must be analyzed as part of the actual payment state machine.

Required native evidence includes atomic funded reservations; no duplicate
collateral use; unavailable audits preventing premature maturity; responsibility
surviving selective exit; idempotent payout/penalty; and recovery preserving the
joint funding, obligation, sampling, and payment identities.

## 5. Random audit threat matrix

Materials and liabilities must be committed before the designated random
observation becomes available. Freeze the beacon scheme, chain/key identity,
exact future round, verification rule, and unavailable-round behavior.

| Adversary freedom | Failure to test | Required bound or behavior |
| --- | --- | --- |
| Proposer withholding or block filtering | Submit only a favorable seed | Bound seed choice and its cost; do not use nominal sampling probability unmodified |
| Reorganization | Reroll a seed or erase liability after learning it | Bind the obligation to the defined finality/seed policy; reconcile liability and payment together |
| Last revealer withholds | Delay publication until an advantageous decision | Explicit availability and abort policy; no free user-selected replacement round |
| Selective task exit | Withdraw after learning that audit was selected | Committed responsibility and funds remain enforceable |
| Many source/address/task claims | Gain multiple chances to choose an unaudited task | Freeze admission and quantify opportunity count; aliases do not reset obligations |
| Beacon compromise or early observation | Learn selection before honest participants | Preserve timing assumptions and the threshold/corruption model |
| Audit or dispute resource exhaustion | Nominal sampling survives but enforcement fails | Reserve actual service capacity before paying; estimate effective execution probability |

The seed-choice pressure example assumes m independent candidate seeds are all
known and the attacker may pick any one. If each seed selects audit with
probability p, unavoidable detection has probability p^m. This is an explicit
worst-choice toy model. It is not a measured distribution of any real consensus
protocol.

Unavailable or unqualified randomness is not a successful audit outcome.
Cryptographic uniqueness, unpredictability, resistance to economic bias,
availability, and post-quantum security are separate properties.

## 6. Primary research evidence and limits

These sources were checked on 2026-11-12. Their guarantees are not automatically
properties of this settlement code.

- [Quotient Semivalues, arXiv:2605.07663v2](https://arxiv.org/html/2605.07663v2),
  revised 2026-07-31. Theorem 6.2 requires quotient-stable representatives and
  false-name-neutral within-cluster allocation. Theorem 6.3 needs an admissible
  matching and bounds allocation leakage, escaped mass, matched-cluster value
  drift, and estimation error. Pure disjoint splits require evidence beyond
  example similarity. Section 5.1 distinguishes payment experiments from final
  deployed-model behavior. Lemma A.1 requires additional total-score and value
  stability bounds for normalized payments. These results neither prove source
  identity nor justify a generic normalized-budget fairness claim.
- [Faithful Group Shapley Value, NeurIPS 2025](https://proceedings.nips.cc/paper_files/paper/2025/hash/ee5acc38c2185587ed31de407e1722ad-Abstract-Conference.html).
  Definition 1 fixes the atomic dataset and its utility; Theorem 1 characterizes
  group value as the sum of those individual Shapley values. The grouping
  invariant does not prove arbitrary parameter-component equivalence, source
  ownership, or invariance when the atomic game changes.
- [Priority-Aware Shapley Value, ICML 2026](https://proceedings.mlr.press/v306/lee26at.html)
  and [arXiv v2](https://arxiv.org/html/2602.09326v2), revised 2026-06-14.
  The method incorporates supplied precedence constraints and priority weights.
  Definition 2.4 requires feasible coalitions to contain their predecessors.
  This supports an explicit dependency-aware game, but does not validate real
  model loading, prove the supplied dependency graph, or prevent fabricated
  dependency incentives.
- [drand cryptography](https://docs.drand.love/docs/cryptography/) and
  [security model](https://docs.drand.love/docs/security-model/).
  drand uses threshold BLS with pairing-based cryptography. Its documented
  assumptions distinguish output uniqueness, threshold compromise,
  front-running, and DoS-induced unavailability. Its
  [timelock security discussion](https://docs.drand.love/docs/timelock-encryption/)
  explicitly states that its cryptography is not quantum resistant. Treating it
  as an external research beacon does not establish Chain end-to-end PQ
  randomness or unconditional availability.
- [EIP-8321: Hash-Chain RANDAO](https://eips.ethereum.org/EIPS/eip-8321),
  created 2026-07-05, is Draft at inspection. The proposal retains reveal-or-
  withhold bias and says it does not make beacon randomness post-quantum secure
  end to end while registration and block-signature paths still use BLS.
  Transition timing and orphaned-reveal exposure have their own documented
  assumptions. A draft construction is not a deployed Chain qualification.

## 7. Reproduction and interpretation

From the repository root:

    python3 scripts/experiments/source_incentive_reference_v6.py --self-test

Print the exact independent input schema:

    python3 scripts/experiments/source_incentive_reference_v6.py --print-example-input

Run a supplied toy input:

    python3 scripts/experiments/source_incentive_reference_v6.py --input input.json

Check an already retained native settlement object's arithmetic:

    python3 scripts/experiments/source_incentive_reference_v6.py --receipt native.json

If that object is nested, pass its explicit RFC 6901 location using
--receipt-pointer /path/to/object. Do not point the checker at a hand-written
model result and label it native evidence.

The output includes exact rational numerators/denominators, decimal
approximations, file-input hashes, the reference script hash, and explicit
non-qualification flags. Self-tests cover known arithmetic vectors, signed
cancellation, all permutations of the three-component example, alias changes,
range/shape/profile rejection, invalid counterfactuals, receipt mutations,
shared collateral, independent reservations, and seed-choice assumptions.

A failing or insufficient-evidence result returns nonzero. A passing tool result
does not close actual source provenance, independent scientific evaluation,
native funding/slashing integration, real-market behavior, general Sybil
resistance, or a qualified post-quantum randomness source.

## Independent retained-byte readback

The [native receipt reader](../../scripts/experiments/read_source_incentive_native_v6.py)
reads actual PNX1/ILF2 bytes, ignores fixture author ordinals, binds actual component
senders to the installed source map, reconstructs all 3,855 ILM2 coefficients,
materializes valid source-alone and source-omission models, and recomputes the
installed 25-row evaluations. It checks source delta hashes, function/contribution
IDs, the fixed-marker allocation Merkle root, the fresh V6 release ID, source
record and complete game digests, reported caps, once-only floors, internal payouts,
and the budget remainder. Reproduce after an actual native run with:

    python3 scripts/experiments/read_source_incentive_native_v6.py --self-test --repo . --log /absolute/path/to/native-v6.log

A positive readback is limited to retained bytes and reported payment arithmetic.
It does not verify Ed25519 signatures, PoN work, ledger roots, actual funding,
prepublication reservation authority, underlying source-control truth, actual
claim-account execution, or prospective efficacy. Native execution receipts own
those separately tested transition claims. A reader PASS cannot turn a failed
native suite into a passing one. The historical-domain reader refusal and its
corrected fresh-domain rerun are retained; no check was removed or relaxed.
