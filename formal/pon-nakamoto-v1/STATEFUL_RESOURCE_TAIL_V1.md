# Residual-state resource-to-weight tails: audited continuation

This note extends the previously published `WORK_SCALE_SECURITY_CONTRACT_V1.md`; it does not establish a W1 cost lower bound or change native consensus.

## 1. A compositional theorem that does not erase hidden progress

Let the classical filtration record measured execution outcomes and public control information. Let `rho_i` denote the normalized *conditional joint density operator*, including the adversary's private registers and the purified random-oracle reference registers used by the proof. A quantum register is not a classical random variable whose full contents can simply be inserted into a sigma-algebra.

Let `W_n` be newly extracted, distinct, fully valid credited work; every eligible credit identity is counted at most once. All classical and quantum preprocessing, retained states, proof-generation work, alternative branches and public auxiliary information belong to the initial state or the transition model. Merely releasing a previously counted item adds no new extraction credit. If a different accounting convention counts on release instead, its latent inventory must remain in the state potential, as in the finite toy below.

Use incremental accounting W_0=R_0=0 at the chosen start; any pre-existing completed work and retained correlations follow the declared inventory/potential convention. For fixed theta > 0 and a nonnegative resource-price vector kappa, suppose each reachable classical control state h has a positive operator K_h >= I. For **every permitted action**, including adaptive task selection, batching, restart, measurement, release and stopping, let E_o be its completely positive instrument branches. Each branch o records resource r_o >= 0, newly credited weight w_o >= 0 and next public state h_o. Require the operator certificate

    sum_o exp(theta*w_o - kappa dot r_o) E_o^*(K_{h_o}) <= K_h.       (A)

The inequality is in positive-semidefinite order. It is a sufficient proof obligation for the actual allowed action class, not a property inferred from testing one implemented algorithm. The resource units must be explicitly fixed; gates, oracle queries, depth, memory and seconds cannot be added without specified prices and physical assumptions.

Define V_i = Tr(K_{h_i} rho_i) >= 1 and M_i = exp(theta*W_i - kappa dot R_i) V_i. Conditional on the observed history, branch o has probability p_o = Tr(E_o(rho_i)) and successor state rho_{i+1,o} = E_o(rho_i)/p_o. Multiplying by p_o, summing, and using the adjoint identity gives

    E[M_{i+1} | F_i] <= M_i.

Thus M is a nonnegative supermartingale. Ville's inequality implies, for deterministic componentwise resource budget B and threshold x,

    P[exists n: W_n >= x and R_n <= B]
      <= min(1, V_0 exp(kappa dot B - theta*x)).                    (B)

For random initial states, read the bound conditionally on the same start history, or take a proved upper bound/conditional expectation of V_0. An adaptively selected start must carry its actual residual potential and conditional failure bounds. The proof applies to arbitrary stopping and an unbounded countable horizon. Nonnegative cumulative resources make killing the process after budget exhaustion legitimate. The scalar finite-state version replaces Tr(K rho) with V(state) and (A) with a conditional weighted sum.

A cryptographic failure probability can be added through a formally defined ideal-real coupling, or a process killed at an adapted first failure time. Do not silently condition the transition law on the future event “no cryptographic failure”: that conditioning can change the law and invalidate the supermartingale premise.

For a deterministic threshold and budget one may optimize the resulting valid bound over theta. A theta chosen retrospectively to obtain an anytime *curved* boundary needs a prior mixture, a union bound, or another explicit time-uniform construction.

## 2. Why a state potential is substantive rather than a renamed inventory count

Take the four-element search problem with exactly one uniformly random marked address. Starting in the uniform superposition, one Grover iterate gives the marked basis vector exactly. Cut the resource window immediately before measurement. There is no measured classical winning-address record, yet measuring the retained state produces a winner with probability one and zero new oracle queries. Consequently a uniform fresh-start tail based only on queries since the cut and a count of measured hidden winners is false. This is an exact small-oracle counterexample, not an implemented attack against W1.

At that state, any certificate permitting a probability-one zero-cost release of weight w must satisfy V(state) >= exp(theta*w). The same conclusion holds for an already constructed valid proof. The potential must price *extractable future credit*, including coherent progress and all correlated side information; counting stored blocks alone is insufficient.

An initial-memory size bound also requires a theorem relating the chosen information measure to V. A short register containing a winning address can carry one full high-weight credit. A memory limit alone does not establish the unit-count scaling required by W1.

## 3. Minimal-potential interpretation and a useful rejection test

For a fully specified state model define

    V*(state) = sup_policy E_state[exp(theta*future_credit
                                    - kappa dot future_resource)],

where stopping immediately is permitted and policies may concatenate. Whenever finite, this value is at least one and obeys the Bellman supersolution inequalities. Every valid nonnegative potential dominating one upper-bounds finite-horizon values; under the usual monotone horizon construction V* is the minimal such potential. This characterization identifies the mathematical gap, but defining V* does not compute it or prove it finite for W1.

A regenerative action sequence that returns to the same accounting state with multiplicative exponential payoff exceeding one refutes any finite potential at that state: repeating it makes the value diverge. Deterministic duplicate-credit cycles are the simplest example. A finite table certificate must check every legal action, and state abstraction must be proved to simulate all real policies. A certificate over selected attacks does not establish completeness.

## 4. Executable exact toy and independent policy maximization

`stateful_tail.py` uses exact `Fraction` arithmetic. It has stash states 0 through 3, generation probability p=1/4 costing one unit, and deterministic release costing zero. Set z=2, gamma=1+p(z-1)=5/4 and V(stash)=z^stash. For every generate action,

    E[gamma^(-1) V(next)] = V(stash),

and for every release action,

    z V(stash-1) = V(stash).

Both are exact equalities. Removing the potential rejects all three release actions. The component refuses to issue a bound from an invalid certificate.

An independent Bellman dynamic program maximizes crossing probability over every adaptive policy in the declared finite model. It checks 6,156 state/budget/horizon/threshold cases against the potential bound. Separately, 324 cases with sufficient horizon equal a closed-form binomial tail exactly. This independently checks the DP beyond re-evaluating the certificate itself. In the zero-budget example, initial stash=1 and target=1 give success probability 1, the potential-aware bound 1, and the invalid reset-to-one bound 1/2.

The script is a reproducible abstract certificate exercise. Every actual W1, quantum-resource, native-consensus and six-successor-security claim remains false in its machine-readable output.

## 5. What current primary results do and do not resolve

Cojocaru, Garay, Kiayias, Song and Wallden, *Quantum Multi-Solution Bernoulli Search with Applications to Bitcoin's Post-Quantum Security*, Quantum 7:944 (2023), proves fixed-density multi-solution quantum query bounds and a fixed-difficulty backbone result. It is relevant to total query histories, but does not turn a constructed W1 oracle's gate count into a minimum cost, or justify fresh-start bounds after arbitrary residual-state cuts.

- https://arxiv.org/html/2012.15254v4
- https://doi.org/10.22331/q-2023-03-09-944

Cojocaru, Garay and Song, *Generalized Hybrid Search and Applications*, ePrint 2023/798, gives a hybrid search success bound in terms of classical and quantum queries and a distribution parameter. The abstract states nu_D(2 sqrt(tau_c)+2 tau_q+1)^2. This is a query-model theorem, not an accepted-work, variable-unit or physical-resource theorem.

- https://eprint.iacr.org/2023/798

Chung, Guo, Liu and Qian, *Tight Quantum Time-Space Tradeoffs for Function Inversion* (FOCS 2020), establishes random-function inversion tradeoffs including quantum advice and develops results for salted primitives. Its explicit preprocessing/advice treatment is relevant. Neither arbitrary parent hashes nor an implementation's task commitment automatically meet its salted-game hypotheses.

- https://arxiv.org/abs/2006.05650

Jeffery and Zur, *The Compressed Oracle Is A Worthy (Multiplicative) Adversary*, ICALP 2026, relates compressed-oracle arguments to a multiplicative ladder adversary method and proves a direct-product property. This is a concrete proof-method candidate for constructing a quantum progress operator. The paper's stated reduction uses sequential queries; its Remark 15 explicitly distinguishes the parallel framework of earlier work. It does not supply a W1 operator certificate or actual gate-cost theorem.

- https://doi.org/10.4230/LIPIcs.ICALP.2026.118
- https://drops.dagstuhl.de/storage/00lipics/lipics-vol374-icalp2026/html/LIPIcs.ICALP.2026.118/LIPIcs.ICALP.2026.118.html

## 6. Actual-relation qualifications that remain mandatory

1. Supply the exact mandatory-u validity relation and credit identity. Existing fixed W1 constants and a future counterfactual u are different objects.
2. Prove that the physical/algorithmic transition model includes every legal structured-matrix shortcut, shared setup, batch search, proof backend and output schedule. A full transcript proves correctness; it does not by itself prove computational irreducibility.
3. Establish the oracle abstraction and any coupling error for the actual SHA construction. Domain tags improve binding, but do not prove SHA is a random oracle.
4. Include both quantum and classical preprocessing and retained correlation, or prove a fresh-context reduction with quantified side-information leakage.
5. Account for public help. Honest published artifacts are free side information to the adversary. A raw multi-solution theorem cannot automatically be applied to “adversarial new weight” after excluding all honest query costs; the reduction must show which already public winning points cannot earn new adversarial credit.
6. Prove the effect inequality for the complete legal action class and connect the resource vector to the adversary's allowed time-varying resource budget. Benchmark measurements provide upper bounds for specific strategies, not this lower-bound interface.

The useful new result is the stateful composition theorem and its exact independent toy check. The actual W1 premise remains an explicit scientific gate.
