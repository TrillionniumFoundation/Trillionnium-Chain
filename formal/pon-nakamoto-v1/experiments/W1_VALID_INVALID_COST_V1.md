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

The output path must **not exist**. The report now **requires** a clean, exact Git HEAD/tree rather than an optional\nHEAD. It validates byte-for-byte equality with every committed input source,\nincluding both transitive ledger and model-family configs actually imported by\n`contract_wire.py`; no missing-Git fallback is accepted. It repeats this\nsource check **after** the measured observations. Even a tracked mutation\nhidden by `git update-index --assume-unchanged`, an untracked checkout file,\nor a substituted symlink is refused. This hardens experiment provenance, not\nproof-cost security or independent acceptance.\n\nThe report includes SHA-256 of all seven source/config inputs, exact HEAD/tree,\nprofile, target, Python environment and the original positive/negative observations.
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
