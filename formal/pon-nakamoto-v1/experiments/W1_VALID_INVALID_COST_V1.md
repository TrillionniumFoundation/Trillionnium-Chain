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

The output path must **not exist**. The report now **requires** a clean, exact Git HEAD/tree rather than an optional
HEAD. It validates byte-for-byte equality with every committed input source,
including both transitive ledger and model-family configs actually imported by
`contract_wire.py`; no missing-Git fallback is accepted. It repeats this
source check **after** the measured observations. Even a tracked mutation
hidden by `git update-index --assume-unchanged`, an untracked checkout file,
or a substituted symlink is refused. This hardens experiment provenance, not
proof-cost security or independent acceptance.

The report includes SHA-256 of all eight source/config inputs, exact HEAD/tree,
profile, target, Python environment and the original positive/negative observations.
It explicitly marks fastest valid adversarial solver, lower-bound hardness,
quantum/PQ128, public Sybil fairness and production as **false**.

## Complete legal CPU vectorization counterexample (optional NumPy)

The separate `w1_numpy_valid_solver_v1.py` builds a **legitimate complete**
W1 PNW1 proof for **every** canonical matrix pair, not a forged ticket.
It recomputes all challenge-dependent noise, true C=A*B, and all **512**
ordered cumulative trace tiles. Each uint64 multiplication is reduced modulo
q **before addition**: a naive unsigned 64-bit NumPy dot can silently overflow
when W1 field values approach q=2^32-5. The resulting 49,188 bytes must be
exactly identical to the independent original scalar prover, and they are
checked by the original full verifier.

Only if NumPy is actually installed does the regular runner execute and time
this legal CPU candidate; it records `numpy_legal_prover_cpu_ns`,
`numpy_legal_proof_byte_identical=true`, and the exact NumPy version.
Without NumPy, the cost is explicitly `null`; no missing observation can be
counted as zero. The additional source is included in the exact-Git
byte-closure and pre/post-run audit. The optional tests include two challenges
per four legal input families, genuine full verification and forged-transcript
refusal, invalid domain inputs, and a high-field overflow counterexample.

To run the optional legal-solver comparison in an isolated controlled
environment (NumPy installation itself must be source/version pinned for
qualification):

```sh
python3 -m pip show numpy
PYTHONDONTWRITEBYTECODE=1 python3 formal/pon-nakamoto-v1/test_w1_structured_cost.py
```

An initial local mirror of the frozen scalar oracle and its H domain passed
ten byte-exact comparisons including high-field matrices; observed CPU time
was about 20–24 ms for vectorized generation versus 76–83 ms for scalar
generation on that one Python host. Those are **unqualified local samples**,
not exact original-checkout/CI receipts, not a measured winning-ticket
denominator, not the cheapest legal solver, and certainly not a quantum
attack-cost bound. CPU, NumPy version, original SHA and native parity still
need fresh independent qualification.

**Crucial limitation:** This is a reproducible scalar-reference cost and
bad-ticket differential, **not** a search over the best CPU/GPU/ASIC/quantum
solver or an independent cryptographic review. Low-rank useful output is not
proof of low-cost valid transcript: W1 challenge-noised trace work still runs.
No sampled timing ratio can establish security, proof succinctness, actual
native resource limits, quantum mining parity or a safe public work predicate.

Original security obligations from the PoN specification and Issue #562
remain open. Existing failed independent tests must not be erased, and this
research-only control must not be used to assert work-profile qualification.
