# Classical/quantum cost contract evidence

Date: 2026-11-08, UTC. Overall qualification: **HOLD**.

This packet records the finite public-credit decision, normalized probability
and complete stationary-renewal cost checks. All numerical cost inputs are
declared mathematical examples. None is a measured or proved minimum W1 cost.

## Source and scope

Development began from `b66e66d2465258d808c0f56ff851123306d4bdb4` in a separate
checkout. Publication is prepared against the current integration candidate
`8d5389748873dad6e296d17f2ff20483b5afa5bc` on
`fix/chain-six-axis-performance-20261103`. Final retained runtime and hosted
observations must identify the exact source they actually executed. Tests on
the development checkout do not establish the integrated checkout's result.

The earlier work-scale and stateful-tail contracts belong to a separate published
research branch. They are cited by immutable links, not imported into this
integration. Retained commands below name suites actually present in the
integration base.

The source-first candidate contains this initial receipt index. Completed
execution observations are appended only after the isolated runtime has
actually run them. A pending check is not a PASS.

## Reproduction

Run from a complete checkout, with a new output directory outside that checkout:

```bash
bash scripts/project-preflight.sh --audit
python3 scripts/ci/run_credit_envelope_checks.py --output-dir /tmp/pon-credit-envelope-new-run
python3 -m unittest discover -s formal/pon-nakamoto-v1 -p 'test_quantum_candidate_check_clock.py' -v
python3 -m unittest discover -s formal/pon-nakamoto-v1 -p 'test_w1_quantum_restricted_oracle.py' -v
python3 scripts/ci/test_ci_source_integrity.py
python3 scripts/ci/test_ci_contract.py
```

The [pinned roster](../../formal/pon-nakamoto-v1/credit_envelope_test_roster_v1.json)
contains named methods, not an inflated count of loop iterations. The runner
requires registered, started and successful names to agree; skips and expected
failures are rejected. Its reports identify the exact selected file bytes.
The [hosted workflow](../../.github/workflows/pon-credit-envelope.yml) additionally
verifies every tracked source entry before and after execution for both the
head and GitHub's prospective merge, including its ordered parents and tree.

## Established finite mathematics

- Cost curves admit exact simultaneous scale neutrality iff their ratio is
  constant over the complete compared scale set.
- With two exact cost curves, the smallest worst efficiency spread is the
  square root of the range ratio of the two costs. The geometric-mean credit
  attains it as a mathematical diagnostic; it is not a native chainwork change.
- A finite rectangular envelope has a robust credit at tolerance rho iff its
  multiplicative constraint graph has no cycle with product below one.
- Exact negative-cycle examples include `9/16` and the three-scale `8/9`;
  the latter is not detected by checking two-scale cycles alone.
- Normalized sampling distinguishes domain retention from success density.
  Repeated-unit, setup, failure, restart and success-only costs stay separate.

## Gates that remain open

Actual W1 bounds covering all legal classical and quantum strategies, warm
adaptive portfolios, complete joint initial state, a mixed honest/attacker
process, native fork-failure reduction, lifetime budgets and original resource/
WAN acceptance remain unproved or unqualified. Honest-node observations do not
bound hidden adversarial resources. Finite tests and a verified cost table do
not set work, consensus, post-quantum or production qualification to true.

See the [project audit](../../docs/protocol/pon-nakamoto-v1/details/CLASSICAL_QUANTUM_COST_AUDIT_20261108.md)
and [full theorem contract](../../formal/pon-nakamoto-v1/CREDIT_ENVELOPE_CONTRACT_V1.md).
