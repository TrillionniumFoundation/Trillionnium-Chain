# Neural work: concrete experimental relation and security boundary

Owners M01/M02/M03, with M04/M15 ingress and M17 qualification; model input owners
M10/M11 and Hepta. The selected architecture remains Nakamoto-style useful neural
work. Production work qualification is false.

## Defined and implemented profile

[W1 — WORK_PROFILE](details/WORK_PROFILE.md) specifies n=64, rank8, q=4294967291,
canonical u32 arithmetic, all transcript steps, exact49188-byte certificate, challenge,
ticket and decoded useful result. Rust and separately coded Python implementations
produce identical vectors. The profile configuration is part of the genesis parameter
hash; there is no floating-point tolerance, proof-randomness nonce or output/template cycle.

A complete work certificate contains historical verification inputs. The signed integer
bridge is demonstrated on a real trained model's partial inference contraction, not a
made-up score or a claim that old fine-tuning itself secures a new parent block.
Model quality and local authority are separate proofs. New learned output enters later
transactions, never the current header's post-state calculation.

## What remains unqualified

The candidate uses full recomputation and is not succinct. Measured cheap forged
transcripts can pass its preliminary ticket predicate while rejection costs a full
verification. Worst-case adversarial computation, cross-attempt precomputation, low-rank
shortcuts, hardware advantage, uniform independent lottery assumptions and public-network
DoS remain security work, not an activated profile. Native and Python parity is not an
independent external review. The configuration distinguishes executable candidate from
production-eligible work rather than saying every implementation must forever be absent.

[Performance and acceptance](details/PERFORMANCE_ACCEPTANCE.md) binds raw cost samples,
negative observations and external obligations. The peer-facing production verifier
must not accept a JSON boolean, TEE quote or evaluator vote as work. No old BFT or
hash-only fallback is provided. The real experiments use the defined transcript check;
they do not replace it with a successful stub.

## PN1 work-safety delivery contract

This is I01/I02 in the [sole plan](../../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md).
Audit baseline: PR #323 source `8d56f2f173d3e870846cf1129d48647f2b84540a`.
It specifies remaining work, not an accepted security result. Preserve the
existing W1 relation and all historical profile bytes while qualifying it.

Three independent verdicts are required:

| Verdict | Owner and evidence | Cannot substitute for it |
| --- | --- | --- |
| Statement correctness | M00/M01 canonical bytes, actual parent/header/task/payout/body binding, full transcript/product checks and private verified-work construction | Preliminary ticket, evaluator signature, model score, declared CPU or a valid result for another statement |
| Computational qualification | M01/M02/M17 same-target adversarial costs, explicit amortization/hardware/task assumptions and independent review of the resulting effective-work security model | Bounded queue, equal machine count, finite timing parity or an unproved cheapest-producer assertion |
| Honest service availability | M04/M15 actual sockets, shared CPU/worker/state ownership, paid honest cohorts and complete confirmation results under a frozen attack envelope | Valid-work correctness, permit cleanup, recovery-only progress or Submit ACK |

The qualification artifact must freeze profile and parameter hashes, target,
task distribution/choice authority, complete maintenance material, compiler and
hardware, cache state, preparation lifetime and challenge horizon before
sampling. Record attempts and total resources for general, zero, low-rank,
sparse, paired/blocked, preprocessed and false-transcript strategies. Include
all unsuccessful trials and actual receiver acquisition/rejection; separate
existing-proof mutation from constructing a new forgery. Raw samples retain
paired order and failures. Ratios from different sources or cost denominators
must not be combined into a security claim.

Use effective qualified work for the adversary assumption. Count any permitted
structured-instance advantage, amortized setup, acceleration, task withholding
and mining concentration. State the honest-work availability and propagation
assumptions needed by the Nakamoto confirmation argument. A configured evaluator
quorum cannot cap an attacker's work fraction; a node count does not establish
that fraction. If no defensible cost/lottery assumption is available, leave the
work gate open and publish the counterexample rather than select a convenient
measured ratio as a consensus lower bound.

The I01 verifier consumes exact statement bytes and returns a private checked
work fact only after every required check. Transport may reject bounded syntax
early; resource exhaustion yields Busy/Unavailable, never an invalid-work cache
entry. Accepted work credit follows the existing required-target arithmetic,
not reported effort or useful-model gain. The challenge remains bound before
search; no free randomness or alternate serialization is added to repair cost.

If W1 cannot meet the declared assumptions or receiver budget, the owner must
propose an explicit successor with a new relation, parameters, genesis/domain
and storage context, independent vectors, adversarial analysis, migration and
review. A succinct proof is a possible research direction, not a property of
the present 49,188-byte replay certificate. Its setup/trust, prover costs,
invalid-input costs and statement completeness need separate acceptance.

Exit requires all three verdicts above and the PN1 original-budget campaign in
[admission security](details/ADMISSION_SECURITY.md). A finite campaign can close
its declared availability regression while computational qualification remains
open. The current revision does not set either verdict to accepted.

### P0 responsibilities and acceptance within PN1

I01 correctness, computational qualification and I02 honest service are three
separate P0 results. M01 owns private `VerifiedWork` construction; M02 consumes
only that checked fact and the existing required-work increment. M03 supplies
the exact producer statement and all search/setup attempts. M04/M15 own shared
operation admission, sockets, workers, cancellation and final settlement; M17
binds source/configuration, preserves failures and independently reproduces
each verdict. No single verdict substitutes for another.

An I02 admission permit authorizes bounded local work only. It cannot construct
`VerifiedWork`, change block validity/chainwork, issue local installation or
FinalUse authority, or treat overload as invalid content. I01 verification
cannot grant a new queue/CPU budget or bypass M04/M15 admission. Duplicate,
cancelled, late and unknown outcomes retain their original operation/deadline
and consumed-resource identity under
[the shared-operation contract](details/ADMISSION_SECURITY.md#pn1-shared-operation-admission-target).

Dependency order is PN0 source/profile freeze -> I01 statement and negative
vectors -> same-target adversarial cost and I02 complete-path measurements ->
independent verdicts. Cost research and ingress repair may run concurrently;
public acceptance needs both. Freeze numerical target, setup horizon, shared
CPU/worker/byte limits, honest load, attack envelope, confirmation deadline and
depletion requirement before running the existing original-budget campaign.
Every planned honest round must complete and the hostile cohorts must actually
reach the required depletion; absent pressure cannot qualify attack resilience.

At this baseline the three complete campaign runs retained 27/27 honest
confirmations with matching imported states, but all six hostile stages missed
the required genuine CPU depletion. Thus the original attack-envelope gate
remains failed. Do not inherit the older 6/18-depletion result or claim observed
honest interruption from this failure. Correctness, work cost and public-service
acceptance remain independently open as specified above.

Any change to the work relation, accepted statement or lottery needs a fresh
profile/domain, parameter/genesis and storage context, old/new independent
vectors and explicit migration/replay review. Byte-equivalent P2 verifier
optimization must retain the existing relation, error/cancellation order and
full checks; throughput gains cannot replace P0 security qualification.
