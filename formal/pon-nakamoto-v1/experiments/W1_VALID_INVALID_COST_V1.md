# W1 structured valid-versus-forged-ticket cost control (research only)

**Source base**: Chain `main` `dd6e1c3cbeacbdc532b0679297835b3a0aac78f0`.
This control does not change W1 work, consensus, tickets, DAA, rewards,
signatures, public RPC, native node, PQ security, or deployment activation.

The runner `w1_valid_invalid_cost_v1.py` uses the independently coded Python
W1 scalar oracle and the **existing devnet target** on four deterministic
eligible matrix structures (zero, diagonal, rank one, dense). For each:
- derive the complete exact challenge/task;
- compute a real valid 49,188-byte work certificate and verify its full trace;
- spot-check output against independently evaluated scalar dot products;
- cheaply vary an **untrusted transcript digest** until its ticket passes the
  exact devnet filter;
- show the full W1 replay rejects that ticket-qualified forged digest with
  `TRANSCRIPT`; measure CPU for generation, valid verification, invalid
  rejection and cheap forgery separately.

Reproduce from a checkout with original profile files intact:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 research/pon-w1-cost/test_w1_structured_cost.py
PYTHONDONTWRITEBYTECODE=1 python3 research/pon-w1-cost/w1_valid_invalid_cost_v1.py --output /new/empty/output
```

The output path must **not exist**. The report now **requires** a clean, exact Git HEAD/tree rather than an optional
HEAD. It validates byte-for-byte equality with every committed input source,
including both transitive ledger and model-family configs actually imported by
`contract_wire.py`; no missing-Git fallback is accepted. It repeats this
source check **after** the measured observations. Even a tracked mutation
hidden by `git update-index --assume-unchanged`, an untracked checkout file,
or a substituted symlink is refused. This hardens experiment provenance, not
proof-cost security or independent acceptance.

The report includes SHA-256 of all seven source/config inputs, exact HEAD/tree,
profile, target, Python environment and the original positive/negative observations.
It explicitly marks fastest valid adversarial solver, lower-bound hardness,
quantum/PQ128, public Sybil fairness and production as **false**.

**Crucial limitation:** This is a reproducible scalar-reference cost and
bad-ticket differential, **not** a search over the best CPU/GPU/ASIC/quantum
solver or an independent cryptographic review. Low-rank useful output is not
proof of low-cost valid transcript: W1 challenge-noised trace work still runs.
No sampled timing ratio can establish security, proof succinctness, actual
native resource limits, quantum mining parity or a safe public work predicate.

Original security obligations from the PoN specification and Issue #562
remain open. Existing failed independent tests must not be erased, and this
research-only control must not be used to assert work-profile qualification.

## Source-bound legal structured prover reconciliation (P0 research only)

This isolated child combines the distinct unmerged research experiments:
[#606](https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/606)
computed legitimate structured W1 witnesses, while
[#607](https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/607)
closed the original source-identity gap. Neither parent branch is rewritten.
The source audit remains mandatory both **before and after** all measurements.

For exactly the original zero, diagonal, and rank-one eligible matrix
families, the secondary prover derives the true `C=A*B` by a verified
algebraic identity but still performs fresh challenge-dependent noise
expansion and all 512 transcript tile updates. The complete 49,188-byte
proof must equal the original independent scalar oracle byte-for-byte and
be accepted by the unchanged full verifier. Dense inputs have no asserted
shortcut. The input family is checked against the exact eligible matrices;
changing the name cannot authorize an altered input.

The report retains both valid-prover CPU samples and invalid Ticket-only
rejection costs separately. It additionally records the **actual denominators**
`sampled_valid_proof_attempts` and `sampled_valid_devnet_winners`, plus
`sampled_structured_proof_attempts` and
`sampled_structured_devnet_winners`. These are *bounded experimental
attempt counts*, not a success-probability estimate or projected TPS.
A cheap fabricated digest may satisfy the Ticket filter but NEVER counts
as a legal winning attempt, model improvement or verified work.

Required source-precise tests cover two different challenges for each
structured family, byte-identity, actual full-verifier acceptance,
mislabeled input and incorrect challenge refusal, invalid Ticket-only
rejection and source alteration hidden by Git assume-unchanged. Tests
must run on the complete exact HEAD with required original checks; the
presence of these test methods alone is not a PASS.

**Still unqualified:** fastest adversarial valid solver, GPU/ASIC and
precomputation, finite quantum cost, real task eligibility, the ratio
between effective winning work and verifier cost under hostile ingress,
W1/PQ128 security, Sybil-safe admission, ordinary Hepta activation, and
public/production acceptance. Issue #562 A–F and #596 remain open.
