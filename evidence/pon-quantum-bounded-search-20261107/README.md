# Constructed W1 search under a finite deadline

Status: **Draft / HOLD**. Base source:
`7a98f27f99abccc28da2f1f3cc60bdaa2eca4890` (PR #755).
This is a research continuation on the existing integration lineage.

## Scope of this source change

- Repair zero-iteration identity and the exact `1/4`, `1/2` and `3/4` Grover
  probability periods. The original
  floating-point implementation could assign a positive probability to an
  impossible measurement; exact rational reference controls retain that failure.
- Reject physical decompositions claiming more nonempty T layers than T gates;
  this is input coherence, not a universal minimum implementation cost.
- Add a literal-domain finite-horizon executor that retains partial preparation,
  iterations, readout, full candidate checks, proof and propagation costs.
  Completion at the deadline is inclusive; incomplete delivery earns no success.
- Bind actual full and restricted W1 constructions to the same declared
  physical-model envelope, all processors and predeclared schedule. Restricted
  phase membership and full legal acceptance remain separate. A measured legal
  winner may pass the full checker even when its phase was unmarked.
- Preserve source identities, complete scenario inventories, exact resource
  inputs, deterministic replay and refusal controls. Register the new tests in
  the existing repository-truth job without weakening its original commands.

The complete mathematical and cost contract is in
[QUANTUM_DAA_RESEARCH.md](../../formal/pon-nakamoto-v1/QUANTUM_DAA_RESEARCH.md).

## Frozen validation

The implementation will be frozen before campaign generation and final
validation. Exact command records and original failures will be appended in an
evidence-only continuation. Development checks do not qualify this not-yet-frozen
source, a later composition or an actual quantum machine.

## Reproduction

Run from the repository root; output paths must not already exist:

```sh
python3 formal/pon-nakamoto-v1/experiments/w1_bounded_search_campaign.py --observe /tmp/w1-bounded.json
python3 formal/pon-nakamoto-v1/experiments/w1_bounded_search_campaign.py --verify /tmp/w1-bounded.json
python3 -m unittest discover -s formal/pon-nakamoto-v1 -p 'test_w1_*search.py' -v
python3 -m unittest discover -s formal/pon-nakamoto-v1/experiments -p 'test_w1_bounded_search_campaign.py' -v
```

The campaign uses explicit illustrative classical and physical inputs, not
measurements. Its four-second analysis horizon is not native service acceptance;
its qubit cap does not represent available hardware. Source-bound replay is not
external execution attestation or a proof of schedule precommitment. Online
proofs generated and native blocks admitted are both zero.

## Remaining qualification gates

The original `quantum_oracle_resources.py` incomplete-input demonstration keeps
`complete_quantum_cost=null`. A separate constructed, fixed-context upper-bound
budget does not justify filling an unknown generic W1 input or setting an
attacker lower-bound flag. The most economical legal implementation remains an
independent research problem.

The current experiment still lacks calibrated fault-tolerant hardware,
end-to-end machine error accounting, measured preprocessing/reuse economics,
accepted native work under equal real budgets, a profitable executable
Bailey–Sattath-style W1 fork attack and a mixed quantum/classical consensus
security proof. Native target, accumulated work and fork choice are unchanged.
All quantum-mining and activation qualification flags remain false.
