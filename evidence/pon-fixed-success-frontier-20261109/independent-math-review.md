# Independent review of the free-final-output query frontier

Reviewer notes, 2026-11-09. This reviews an idealized classical query game, not the actual W1 cost contract.

## Mathematical derivation

Let r=1-p with 0<p<1. Distinct oracle membership bits are iid Bernoulli(p), initially independent of the complete algorithm state. The domain has d available addresses, the hard paid point-query cap is n, and at termination the algorithm may output at most m distinct unqueried addresses without feedback. A known queried winner may also be output. Put g=min(m,d), k=min(n,d-g), and b=1-r^g.

When at most m unqueried addresses remain, outputting all of them immediately is, for every fixed oracle assignment, at least as successful as continuing to query. It costs no more. Thus an optimal policy can be chosen to reserve g addresses and use at most k distinct paid queries. Repeated paid queries and queries after discovering a winner cannot improve the optimum.

For any policy, let W be the event that a paid query sees a marked point and Q be its paid query count. Conditional on the final paid history without W, an unqueried output list has success at most b. Predictability of each fresh query gives E[number of fresh paid marks]=p E[Q_fresh], so Pr(W)<=p E[Q_fresh]<=p E[Q]. Consequently:

    Pr(success) <= b + (1-b) Pr(W) <= b + p r^g E[Q].

The hard-cap maximum is 1-r^(k+g), achieved by querying fresh points until the first hit or k queries, then outputting g reserved fresh points if necessary. There is no feasible policy above this maximum. For alpha above b but at most that maximum, mix that paid policy with the immediate-g-output policy using probability

    t=(alpha-b)/(r^g (1-r^k)).

This gives E[Q]=(alpha-b)/(p r^g) and exact success alpha under ideal independent randomization. Alpha<=b needs no paid queries. Endpoints p=0 and p=1 must be handled separately; the implementation does so.

## Necessary qualifications

- "Density p" alone is insufficient: with d=2 and exactly one marked point, n=m=1, target 3/4 is attainable at mean paid cost 1/2, while the iid formula gives 1. The oracle law must be explicitly iid, not a fixed number of marks.
- Arbitrary rational ideal randomization makes the minimum attainable. A fixed finite uniformly random bit seed need not attain it. A decisive example is p=1/16, m=1, alpha=1/2: the optimum is 112/15, whereas bounded-query finite-seed Bernoulli-bit algorithms have dyadic expected query counts. Arbitrarily long finite seeds can approximate the infimum from above. Failure of one two-policy mixture to have dyadic weight alone does not prove all other mixtures fail.
- The query cap is not an actual wall-clock deadline; exact coin sampling, proof generation and final output validation have not been priced.
- The m free candidates must be distinct, fresh, and jointly independent of their unseen marks conditional on the complete charged history. Correlated public help, hidden inventory, oracle-dependent program code, or feedback through another channel invalidates this premise unless modeled separately.
- If only one final candidate can be accepted, one cannot choose a larger m without changing the experiment. If verifier tests are counted in the global resource metric, they cannot simultaneously remain free producer queries in that same metric.
- The game is classical. Superposition queries and coherent variable-time resource counts are not covered by the optional-stopping identity.
- The exact arithmetic verifier checks theorem substitution and the attaining finite distribution. The all-policy lower bound is the mathematical argument, not a finite enumeration or a mechanized verification of arbitrary programs.

## Independent numerical check

An in-memory check explicitly enumerated every oracle truth assignment for d=0..6, p in {0,1/4,1/2,3/4,1}, n,m in 0..d+2, and alpha in {0,1/8,...,1}. It computed each non-dominated first-hit threshold policy's probability and unconditional mean directly from the weighted truth table, then minimized on the convex hull. All 12,600 comparisons matched `analyze`, and each produced certificate passed `verify`.

Reviewed numerical implementation SHA-256 before and after that run:

    046e7b6d741d246e8f617456035200685851cf6f617e857055c591905ed3b295

This count is not a count of independent training runs or unit-test methods and must not be added to such counts. It does not verify a W1 reduction or quantum coverage. A later scope-only edit requires a separate source identity.

The separate committed test enumerator was also read: it enumerates all tiny deterministic address/query/repeat/stop/output-subset decision trees, and computes their lower convex hull independently. Its current scope wording is accurate.

