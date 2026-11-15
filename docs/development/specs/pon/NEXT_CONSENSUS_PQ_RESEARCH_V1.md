# Next architecture: consensus and PQ qualification research V1

## Status and scope

**HOLD_NO_GO.** This is a subordinate research specification for the sole
[development plan](../../TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md).
It adds two exact finite counterexample exercises. It changes no consensus
weight, target, proof profile, runtime admission, reward or production flag.
The generator executes no native node, proof verifier or payment system.

The implementation is
[counterexamples.py](../../../../formal/next-architecture-security/counterexamples.py),
with [independent controls](../../../../formal/next-architecture-security/test_counterexamples.py)
and a deterministic, source-digest-bound
[result fixture](../../../../formal/next-architecture-security/fixtures/research-counterexamples-v1.json).
From the repository root:

```bash
python3 -B -m unittest discover -s formal/next-architecture-security -p test_counterexamples.py -v
python3 -B formal/next-architecture-security/counterexamples.py --check-fixture
```

The default generator command writes the complete deterministic JSON to stdout.
Fixture equality is a reproducibility check. Neither equality nor successful
unit tests certify a cryptographic theorem or a production system.

## A. Mixed-resource weight: exact finite refutations

Let `S` denote hypothetical static capacity, and `W,U` two hypothetical timed
resource quantities. Only the timed quantities scale with the time factor:

\[
\Gamma(S,\alpha W,\alpha U)=\alpha\Gamma(S,W,U),\qquad \alpha>0.
\]

[Baig, Guenther and Pietrzak, AFT 2025](https://doi.org/10.4230/LIPIcs.AFT.2025.16)
classify weight functions against private double spending in an ideal continuous
resource model using degree-one homogeneity in timed resources. Their discrete
model needs additional assumptions. Applying that result here first requires
an actual resource interpretation and the paper's other model conditions;
the equation alone is not a complete Nakamoto safety theorem.

The checker fixes seven formulas, 125 resource states and three positive rational
scales. Each formula receives 375 exact homogeneity comparisons and 375
coordinatewise monotonicity comparisons. No expression parser, floating-point
probability or caller-selected formula is used. All formulas are unrefuted on
the finite monotonicity comparisons; that outcome supplies no universal proof.

| Fixed formula | Homogeneity result on this grid | First exact witness, `S=2,W=2,U=3,alpha=2` |
|---|---|---|
| `W` | `NOT_REFUTED_ON_FINITE_GRID` | No counterexample in the enumerated grid |
| `W + U` | `NOT_REFUTED_ON_FINITE_GRID` | No counterexample in the enumerated grid |
| `W * U` | `COUNTEREXAMPLE_FOUND` | Scaled result 24; linear expectation 12 |
| `W^2 + U^2` | `COUNTEREXAMPLE_FOUND` | Scaled result 52; linear expectation 26 |
| `min(W,U)` | `NOT_REFUTED_ON_FINITE_GRID` | No counterexample in the enumerated grid |
| `S * W` | `NOT_REFUTED_ON_FINITE_GRID` | `S` is held fixed; both sides are 8 |
| `W + S` | `COUNTEREXAMPLE_FOUND` | Scaled result 6; linear expectation 8 |

A witness refutes the stated homogeneity identity for its exact auxiliary
formula. Absence of a witness on this grid proves neither a necessary nor a
sufficient condition for the implemented chain. In particular, the checker
does not show that any formula meets a complete security characterization.

The contrast between `W*U` and `S*W` is intentional: the designation of a
resource as timed or static matters. Reusable matrix products, saved Cell
artifacts, model-quality scores, staking balances and external task prices
cannot silently be relabeled as fresh timed work. Static capacity also needs
its own enforceable resource model. For sums or minima, the units, calibration,
shared hardware constraints and double-counting rules remain unknown here.
All seven candidate rows therefore retain `real_resource_interpretation=UNKNOWN`
and `security_qualification=HOLD_NO_GO`.

## B. Sampling-rule substitution: an exact finite counterexample

For a fixed subset of `B` points in a population of `N`, `q` independent uniform
draws with replacement all hit the subset with probability `(B/N)^q`.
A uniform sample of `q` distinct points has probability
`(B)_q/(N)_q`, when `q<=N`. The latter sampling model refuses `q>N`; it does
not turn an undefined sampling operation into probability zero.

| Toy model | With replacement | Without replacement | Understatement from substituting the latter |
|---|---:|---:|---:|
| `N=8,B=4,q=3` | `1/8` | `1/14` | `3/56` |
| `N=8,B=2,q=3` | `1/64` | `0` | `1/64` |

Tests independently enumerate ordered toy samples; the retained results use
exact reduced fractions. These are sampling-model counterexamples, not FRI
attacks. No toy probability is assigned to a real W1 proof.

The existing
[RISC0 transcript audit at #778's pinned source](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/0c830e0be8939ce80c8443c9ad68021b87343a00/scripts/w1_fri_transcript_audit.py)
already records 50 queries with replacement. Each position consumes four base
draws, chooses the first nonzero decoded word or zero, and masks low bits.
Under its explicitly conditional independent uniform-field model, the per-query
TV deviation is `(1-2^-k)/p^4` for `k<=27`, with a fifty-query upper bound
`50/p^4`. That audit does not prove the actual Poseidon2 QROM distribution.
The actual reachable outer seal domain is also not supplied by this exercise.
The new code retains those limitations and does not duplicate the transcript
auditor, import its proof qualification or assume without-replacement queries.

## Consensus research choices and the cheapest legal cost

The existing
[work-expensive research specification](WORK_EXPENSIVE_RESEARCH_V1.md)
continues to own the legal-algorithm and cost-census scope. Faster legal
implementations remain legal competitors; the honest reference cannot be fixed
to an unnecessarily expensive algorithm to manufacture a security margin.

| Architecture candidate | Evidence to retain | Unresolved decision |
|---|---|---|
| Existing PoN/W1 | Exact native relation, cheaper lawful algorithms, losing attempts and actual reuse | A universal cheapest-legal-work model and quantum chain-weight argument |
| Separated security PoW plus useful work | Existing isolated [W2-C prototype](../../../../formal/pon-nakamoto-v1/w2c_separated_security_pow.py), independent security and useful-work verification | Real context/profile binding, extra security cost, receiver budget, quantum model and economics |
| MatMul-derived useful PoW | Fresh challenge, arbitrary task choice, preprocessing and streaming/adaptive opportunities | Finite-parameter hardness and mapping to actual native arithmetic and hardware |
| Multiple calibrated resources | Candidate weight, timed/static classification and resource enforcement | Complete model conditions, no double counting, discrete/network behavior and real physical prices |

The [ESA 2026 MatMul PoUW publication](https://doi.org/10.4230/LIPIcs.ESA.2026.2)
is the current reviewed primary version, published 2026-08-25. Definition 3
allows polynomial-time preprocessing, and the text separately identifies
streaming challenges as relevant to Bitcoin-style use. Its optimal construction
depends on a new algorithmic conjecture. It is not a finite `N=64/R=8` physical
lower bound or a theorem about the deployed chain.

For a fixed context and success requirement, a measured lawful strategy gives
an achievable cost, hence an upper bound on the minimum over legal strategies.
Even a rigorous optimum in a closed strategy class is not a lower bound over
all legal algorithms. CPU time, device energy, memory, storage, network and
elapsed time form a resource vector; scalar comparisons require a declared
price/budget model. Preparation, cache lifetime, cross-task reuse, losing
attempts, cancellation and cleanup must stay inside the chosen accounting scope.
Neither target-derived chainweight nor a model-quality score supplies those
physical prices. This increment adds no new physical measurements.

## Latest independent W1 STARK evidence: #783 round 3

The following are reviewed upstream observations at exact source
`cc836dfc13ef0006eb0878abd8cb5eca9a76bec0`, not executions by this increment.
The [complete round-3 report](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/cc836dfc13ef0006eb0878abd8cb5eca9a76bec0/formal/pon-nakamoto-v1/w1_public_stark_research/ROUND3_REPORT.md)
supersedes using only the earlier 21.196110-second proof-generation result as
the latest backend observation.

| Final guarded ABBA median | Original research AIR | Packed carry AIR |
|---|---:|---:|
| Complete pipeline | 23.961509 s | 13.764899 s |
| Proving process | 22.936896 s | 12.833666 s |
| Independent verifier | 0.943004 s | 0.887252 s |
| Prover peak RSS | 2,383,922 KiB | 2,037,316 KiB |
| Statement plus both proof envelopes | 5,264,276 bytes | 5,187,252 bytes |

This four-run comparison used a shared host, one retained independent input,
the same eight CPU affinities/Rayon 8, an observed eight-CPU quota and an 80 GiB
cap. Both actual proof components, persistence and an independent verifier are
included. It demonstrates an improvement over the prior research backend.
It does not establish a population or worst-case performance bound. The packed
payload is still 104.780269 times the 49,506-byte native candidate; the public
statement alone is 377,290 bytes. The historical 1.913279 ms native warm median
was not rerun contemporaneously. No native-benefit claim follows.

The same report retains two four-second, sixteen-verifier pressure batches
under 0.25 CPU and 2 GiB: each had zero completed cryptographic rejections and
sixteen incomplete SIGKILL exits. Exit collection and cleanup took about
4.36 seconds in total. These different case mixes are not an A/B performance
comparison; the owner, observer, queue and benign-service boundaries are
explicit. Cancellation is not a successful rejection. Global malicious cost
and production service acceptance remain open.

The [lawful affine implementation](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/cc836dfc13ef0006eb0878abd8cb5eca9a76bec0/formal/pon-nakamoto-v1/physical_strategy_frontier_research/README.md)
uses 5 field multiplications and 71 additions per useful block product versus
the dense 512 and 448, with recognition/preparation charged separately. It is
an achieved algorithm for an exact input family. Its closed-class Bellman
bounds are not universal physical-work lower bounds. These results strengthen
the requirement to test cheaper legal implementations rather than assume
dense multiplication establishes work cost.

## PQ claims remain profile-specific and separate

### RISC0 join-v2: all fifteen inherited obligations stay OPEN

The exact registry is
[the #778 contract at 0c830e0](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/0c830e0be8939ce80c8443c9ad68021b87343a00/config/pon/w1-qrom-implementation-v1.json),
profile `trnm-w1-risc0-3.0.6-poseidon2-join-v2`. The new fixture copies its
identifiers for scope retention; this exercise closes none of them.

1. `latest_theorem_version_equivalence`
2. `complete_relation_and_compiler`
3. `all_27_recursion_program_semantics`
4. `control_padding_and_recursive_trace_size_reachability`
5. `relaxed_rbr_knowledge_soundness`
6. `committed_relation_monotonicity`
7. `merkle_multi_extractability`
8. `sponge_and_domain_separation_mapping`
9. `fiat_shamir_challenge_and_salt_mapping`
10. `finite_field_sampling_and_challenge_length`
11. `sequential_adaptive_composition`
12. `lifetime_global_quantum_budget`
13. `concrete_enabled_features_and_debug_exclusion`
14. `quantum_work_and_chainweight`
15. `pq_signature_owner_authorization`

The [CDHZ ePrint landing page](https://eprint.iacr.org/2025/2166) records a
2026-03-02 last revision and a EUROCRYPT 2026 publication. Its theorem framework
uses post-quantum state-restoration security and quantum commitment extraction.
This review did not retrieve and digest the current full PDF. Equivalence
with the earlier manuscript and exact instantiated theorem constants remain
unresolved; landing-page metadata is not a proof-text audit. Existing source,
joint-oracle, conditional-composition and lifecycle tools keep their original
scope rather than being replaced by this small exercise.

### Plonky3 0.8.0: its own primitive and composition obligations

The [native shared-primitive audit](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/cc836dfc13ef0006eb0878abd8cb5eca9a76bec0/formal/pon-nakamoto-v1/w1_public_stark_research/security_model_audit/INTEGRATION.md)
confirms explicit inverse witnesses for the raw truncated public permutation
compressor and overlaps between fixed-width leaf/branch roles. It refutes an
arbitrary-input collision-resistant interpretation of that raw compressor.
It does not establish a restricted Merkle collision or a W1 forgery. A union
bound itself does not require event independence.

This profile independently needs a restricted commitment/tree statement for
the actual shared permutation, adaptive forward/inverse queries, actual
AIR/PCS/FRI and challenge sampling, Fiat-Shamir compilation, both components,
and lifetime/adaptive classical and quantum budgets. The roughly
63.95384529640614-bit RBR estimator is conditional; its input 128 is not a
raw-compressor security result. Restricted-tree, complete noninteractive,
quantum and lifecycle bits remain `null`. The RISC0-specific count of 27
recursive programs is not transplanted into this profile.

Signature authorization, computation soundness and quantum work/chainweight
are separate claims. [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final),
[FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) and
[FIPS 205](https://csrc.nist.gov/pubs/fips/205/final) standardize cryptographic
components. The current FIPS 204 page also has a 2026-07-31 potential-errata
note. None of these standards grants whole-chain PQ128 or authorizes a role,
key lifecycle, proof backend or consensus profile by itself.

## Validation latency is an architecture input

The primary abstract of the September 2026 preprint
[Security Limits of Mining Before Validation in Nakamoto Consensus](https://arxiv.org/abs/2609.29222)
studies security dependence on allowed validation time. Full-text retrieval
was unavailable in this review, so no detailed theorem is imported here.
The qualification question remains concrete: at which verified state may a
candidate become a mining parent, and do receipt, queues, full verification,
cancellation and cleanup fit the aggregate service budget? Median honest
verification time and a successful structural precheck do not answer it.

All research output retains no admission, no production qualification and
unknown quantum security bits. Complete native/runtime, P2P, Hepta-owner,
performance/economics and independent acceptance obligations remain with their
existing owners in the sole plan.
