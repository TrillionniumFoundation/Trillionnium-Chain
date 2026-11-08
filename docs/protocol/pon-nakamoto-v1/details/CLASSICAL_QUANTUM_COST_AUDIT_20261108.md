# Classical and quantum cost: executable credit acceptance contract

Date: 2026-11-08, UTC. Status: **finite mathematical component;
whole-work and mixed-consensus qualification HOLD**.

This continues the [work-scale contract](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/b66e66d2465258d808c0f56ff851123306d4bdb4/formal/pon-nakamoto-v1/WORK_SCALE_SECURITY_CONTRACT_V1.md)
and [stateful resource-tail contract](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/b66e66d2465258d808c0f56ff851123306d4bdb4/formal/pon-nakamoto-v1/STATEFUL_RESOURCE_TAIL_V1.md).
These are immutable references to a separate published research branch; neither
contract is present in integration base `8d5389748873dad6e296d17f2ff20483b5afa5bc`.
The detailed new theorems and examples are in the
[credit-envelope contract](../../../../formal/pon-nakamoto-v1/CREDIT_ENVELOPE_CONTRACT_V1.md).
No native lottery, target, required work, fork choice, timestamp rule or
confirmation rule changes in this continuation.

## 1. The new result and the inherited results

The previous work already proved that common credit cancels from the
same-scale quantum/classical efficiency ratio, represented fixed target and
fixed-probability/variable-unit models, rejected moving anchors, and supplied
multi-winner and stateful counterexamples. It also already contained a full
reversible W1 relation and a restricted legal-winner predicate. Those are not
new accomplishments of this continuation.

The new component decides whether a positive common credit vector exists for
a declared finite rectangle of classical and quantum cost intervals. It
returns either exact rational credits or a closed constraint cycle whose
product is strictly below one. A separate verifier recomputes every necessary
inequality or every cycle edge from the original input. It does not call the
solver. Tests compare the solver with exhaustive simple-cycle enumeration on
small graphs and independently check cost-box endpoints.

The normalized-search component separately computes success mass from the
actual declared probability distribution, itemizes repeated search-unit costs,
and sums all stationary attempts until success. It rejects mismatched success
contracts, mixed resource units and unnormalized probability partitions. These
are mathematical diagnostics on supplied premises, not an implemented quantum
attack or evidence that every legal W1 strategy has been covered.

## 2. What a useful cost submission must contain

For each profile and work scale, a future cost submission must bind all of:

| Contract | Required evidence |
| --- | --- |
| Successful event | Complete valid and available accepted work, probability target, deadlines, and exact behavior on failure and abandonment |
| Resource model | Named additive accounting unit or an explicitly priced resource vector; queries, gates, depth, width, memory, elapsed time and money are distinct |
| Competing contexts | Every still-competitive parent, profile, scale and historical version; no window retirement solely from a moving anchor |
| Initial state | Preprocessing, caches, nonce inventory, advice, public help and residual quantum state; provenance and an actual charge or bounded initial potential |
| Search implementation | State preparation, inverse operations, membership, reflection, predicate, candidate checking, measurement and uncomputation |
| After success | Proof generation, full verification, propagation, availability, cancellation and recovery, with success-only cost charged at its actual frequency |
| Lower bound | A theorem over the complete allowed classical or quantum strategy class, including batching, sharing, adaptive selection and variable-time algorithms |
| Upper bound | An explicit legal algorithm/circuit and its complete execution or resource derivation under the same successful-event contract |
| Composition | A stateful bound for multiple winners and adaptive portfolios, with no reset of paid inventory across epochs, restarts or upgrades |

The finite solver checks equal labels and arithmetic. Labels do not authenticate
these facts. A missing lower bound is unknown, never the observed cost of the
best measured miner. A feasible interval table cannot manufacture these proofs.

## 3. Reproducible refusal examples

For exact classical costs `(1,16)` and quantum costs `(1,4)`, no common credit
keeps both efficiency spreads below `3/2`: an exact cycle has product `9/16`.
At spread `2`, credit `(1,8)` is feasible and tight. This does not change the
quantum/classical advantage at either scale.

For the three-scale rectangle

```text
rho = 2
classical lower = (1,1,4), upper = (1,3,4)
quantum   lower = (3,4,4), upper = (3,4,8)
```

all two-scale cycles pass, but the three-scale cycle has product `8/9`.
Checking scale pairs for isolated contradictions is therefore insufficient.
The full constraint graph is necessary even for this small input.

If a uniform subset retains `1/4` of the domain and `1/4` of all successful
points, conditioning on that subset leaves success density unchanged. Its
normalized success ratio is `1`, not `1/4`. If the original domain is retained
and everything outside the subset is rejected, the ratio is `1/4` instead.
Finding or preparing either subset is a separate cost obligation.

The ideal comparison `f=1/4, a_C=a_Q=2/5` gives classical cost ratio `8/5` and
quantum ratio `4/5`. In a separate supplied-cost example, counting additional
preparation and uncomputation increases the quantum ratio to `6/5`. Both are
conditional arithmetic; neither is an observed W1 shortcut.

The stationary renewal equation is `P + E[C]/q + H`, where all failed and
abandoned attempts are included in `E[C]`, shared preprocessing `P` is paid
once, and the guaranteed success-only proof `H` is paid once. For
`P=7, E[C]=7, q=1/4, H=11`, the result is `46`. Two tasks sharing the same
preparation cost `85`; separately cold-starting them costs `92`. A successful
cold-start envelope cannot be multiplied into a warm multi-task lower bound.

## 4. Literature review and exact applicability

The following are primary sources inspected for this continuation. The review
depth is explicit because an abstract cannot qualify a full implementation.

| Source and version | Reviewed support | Missing W1 bridge |
| --- | --- | --- |
| [Bailey and Sattath, 2403.08023v2, 2024-09-30](https://arxiv.org/html/2403.08023v2) | Full text: cumulative difficulty/credit mismatch and permitted multi-epoch changes; fixed-difficulty limitation is explicit | Actual W1 oracle costs, native timestamp reachability, mixed-network attack probability |
| [Cojocaru et al., 2012.15254v4, Quantum 7:944, 2023](https://arxiv.org/html/2012.15254v4) | Full text: multi-solution and Chain-of-PoWs query tails; honest classical parties, quantum adversary, fixed-density oracle and synchronous rounds | W1-to-query reduction, variable scale/DAA, honest quantum progress and native fork accounting |
| [Nerem and Gaur, 2110.00878v1](https://arxiv.org/html/2110.00878v1) | Full text: single weak quantum miner, measurement timing and declared restart process | General collusion, adaptive portfolios, W1 proof delays and difficulty adjustment |
| [Manson and Sanders, 2607.23952, 2026](https://arxiv.org/abs/2607.23952) | Abstract only: two non-colluding aggressive quantum miners, payoff optimization and repeated measurement opportunities | Full manuscript details were not obtained; no arbitrary collusion, W1 or DAA conclusion follows |
| [Brassard et al., quant-ph/0005055](https://arxiv.org/abs/quant-ph/0005055) | Abstract and stated amplitude-amplification setup: normalized success mass, coherent algorithm and inverse calls | Actual preparation/reflection costs and cheapest structured W1 predicate |
| [Ambainis, 1010.4458v2](https://arxiv.org/html/1010.4458v2) | Full text, Theorem 1: variable stopping times and amplification using their squared-time average | Whether W1 admits such a circuit and a complete physical-resource model |
| [Ambainis, Kokainis and Vihrovs, TQC 2023](https://drops.dagstuhl.de/entities/document/10.4230/LIPIcs.TQC.2023.7) | Published abstract and paper model: improved variable-time search algorithm and lower bound | The query/time model is not a general physical W1 lower bound |
| [Chung et al., 2006.05650](https://arxiv.org/abs/2006.05650) | Abstract: random-function inversion with quantum advice has a time-space tradeoff | W1 is not automatically random-function inversion; salt/advice assumptions and reduction loss must be established |

The 2023 published Quantum Backbone version states settlement waiting time of
the same order as its classical comparison, up to a constant, under its own
model. The older `p^(-1/6)` waiting-factor claim is not the result of this
version. Neither version licenses replacing a quantum mining process by a
constant measured hash rate. The 2026 two-miner equilibrium result does not
bound a colluding adaptive adversary.

## 5. Connection to the full mixed-mining goal

A future accepted resource envelope must be uniform over the allowed histories
and actions. The existing stateful certificate treats a state-dependent
potential and a conditional exponential moment; it is a stronger bridge than
a cold single-winner mean. The relevant process must include search age,
measurement, unsuccessful restart, honest-block interruption, continued old
search, parallel devices, withheld branches and release policy.

For W1, the remaining composition is:

1. Prove a lower bound or a resource-to-query reduction for all legal algorithms,
   with actual challenge dependence and complete joint initial-state accounting.
2. Prove a stateful accepted-work tail, including inherited private inventory,
   all competitive scales and shared work across them.
3. Establish honest classical/quantum progress under the actual validation,
   availability and network-delay rules.
4. Prove that every relevant native common-prefix failure produces a witness in
   that dominated process. Establish weighted chain growth and quality in the
   same model, and distinguish weight guarantees from block-count guarantees.
5. Compose cryptographic, resource, availability and repeated-start failures
   across the stated system lifetime. Derive confirmation policy from this bound.

The public-credit feasibility decision is necessary for the selected calibration
objective; it is not sufficient for any of these five steps. Local telemetry
does not supply a hidden attacker's resource bound. Fixed confirmations do not
provide a failure probability when the underlying model is unknown.

## 6. Execution and review entry points

- [Exact envelope solver and independent witness verifier](../../../../formal/pon-nakamoto-v1/credit_envelope_contract.py)
- [Normalized sampling and complete stationary renewal costs](../../../../formal/pon-nakamoto-v1/normalized_search_cost.py)
- [Pinned named-test runner](../../../../scripts/ci/run_credit_envelope_checks.py)
- [Exact head and prospective-merge workflow](../../../../.github/workflows/pon-credit-envelope.yml)
- [Retained execution evidence](../../../../evidence/pon-credit-envelope-20261108/README.md)

The existing required `repository-truth` lane also registers both new test
suites. The shared CI contract's omission/duplication/relocation negative tests
cover those commands. Its new frozen three-command prefix also rejects shell
conditions that skip either new suite or swallow its failure; this is not a
claim that every inherited command has an equivalent execution proof.
A separate exact-source workflow preserves failures and
requires completion of all its stages. Finite arithmetic PASS and overall HOLD
are intentionally distinct outcomes.
