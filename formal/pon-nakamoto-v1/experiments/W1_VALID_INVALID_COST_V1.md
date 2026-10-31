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
PYTHONDONTWRITEBYTECODE=1 python3 formal/pon-nakamoto-v1/test_w1_structured_cost.py
PYTHONDONTWRITEBYTECODE=1 python3 formal/pon-nakamoto-v1/experiments/w1_valid_invalid_cost_v1.py --output /new/empty/output
```

The output path must **not exist**. The report binds source SHA-256, git HEAD
when available, profile, target, Python environment and original observations.
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

## Second cost candidate: algebraically structured, genuinely legal W1 proofs

For the exact zero, diagonal and rank-one input families, the prover can
derive the true output C=A×B algebraically instead of executing the generic
W1 decoding correction. **The challenge-dependent noise and all 512
cumulative transcript tiles still run.** The emitted 49,188-byte full proof
must match the original scalar prover byte-for-byte on the same task/challenge,
and it still passes the full reference verifier. The dense family retains
its unmodified original path.

The runner now reports a separate \`legal_structured_prover_cpu_ns\` sample
and byte-identity check only for eligible families; ticket-only forged digests
continue to be measured separately and rejected by the full oracle. CPU
ratios are not pass thresholds, lower bounds, or estimates of GPU/ASIC/quantum
speedups. Task provenance, cheapest *legal* miner, difficulty-adjustment attack,
real node intake, independent witness and PQ128 remain NO_GO.
