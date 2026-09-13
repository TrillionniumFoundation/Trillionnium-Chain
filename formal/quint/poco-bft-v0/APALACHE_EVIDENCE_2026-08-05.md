# PoCO-BFT v0 Apalache evidence — 2026-08-05

Status: **bounded, mutation-calibrated evidence; not an unbounded proof**

This record covers `noConflictingFinality` in
[`poco_bft.qnt`](poco_bft.qnt). The model has four equal-power validators,
one Byzantine validator, two conflicting direct three-block branches,
durable vote-view watermarks, the v0 safe-vote/lock rule, and direct
three-certified-block finality.

The normal transition admits every nonempty vote batch, including every
singleton, and forms a QC only once cumulative votes reach an exact 3-of-4
quorum. Exact-quorum batches therefore keep a legal three-chain reachable in
four transitions without deleting fine-grained vote paths. A retained
in-model mutation removes the safe-vote/lock gate and reaches conflicting
finality in eight transitions. This calibration makes the normal depth-10
symbolic result non-vacuous with respect to the modeled failure: the same
finite model contains an eight-step counterexample when the safety gate is
disabled.

## Frozen inputs and toolchain

- `poco_bft.qnt` SHA-256:
  `fd599110e25ea01375d4d1d6023bfcff38471c7b3b103642e05c5a566b086569`
- Quint: `0.32.0`
- Apalache: `0.56.1`, build `70cdaf4`
- Apalache JAR SHA-256:
  `4753c0ebb2cbb266e2c6ac19ab5ca3827d726cc80fd1fc5d7c1eeb64736cd60b`
- Java: Temurin OpenJDK JRE `17.0.20+8`
- JRE archive SHA-256:
  `ef491a51a46ef90cc47fbc4abb219fde32483ff91be5ec66ddc896df43524b27`

Apalache and Java were run from user-local and isolated temporary paths. They
were not installed system-wide and are not repository dependencies.

## Results

| Lane | Bound | Expected outcome | Observed outcome |
| --- | ---: | --- | --- |
| Normal nondeterministic `step` / `noConflictingFinality` | 10 | invariant holds | **PASS**, `NoError`; state 10 holds |
| Deterministic `legalFinalityStep` / `legalFinalityNotReached` | 4 | witness violates “not reached” | **PASS as reachability witness**; counterexample found at the bound |
| Deterministic `unsafeForkStep` / `noConflictingFinality` | 8 | retained mutation violates safety | **PASS as mutation gate**; state 8 finalizes conflicting blocks `1` and `2` |

Checker times were approximately 557.5 seconds, 4.7 seconds, and 5.4 seconds,
respectively. The generated detailed-log SHA-256 values were:

- normal depth-10 pass:
  `3f78e714fa45db98332ba219be43e21588b67c3c4450c5caaee85e3c7e1b21cd`;
- legal-finality reachability witness:
  `24f288fe0382ff7d205080d12d8883ff0284538049e16f39bf2b3747c07be0d6`;
- unsafe lock-bypass counterexample:
  `eb3cd47e4df2a59baea077fb8b48d1849d3795bf0236e705c0e6e1e9c6e7ef43`.

The normal run ended with:

```text
State 10: state invariant 0 holds.
The outcome is: NoError
[ok] No violation found
```

The mutation run ended with:

```text
State 8: state invariant 0 violated.
The outcome is: Error
finalized: Set(1, 2)
```

The fast Quint gate also typechecked the revised model, explored all five
named invariants over 10,000 seeded traces of up to 30 steps, reached legal
finality in four deterministic steps, and rejected the lock-bypass mutation
in eight deterministic steps.

## Interpretation and limits

The normal result checks every symbolic execution represented by this finite
model through depth 10. The positive witness proves that the legal finality
path is not dead, while the retained mutation proves that the bounded checker
can expose the modeled conflicting-finality failure inside that same depth.

This is not an unbounded protocol proof. It does not establish cryptographic
security, data availability, asynchronous liveness, production networking,
storage durability, epoch handoff, heterogeneous-weight safety, or multi-hop
light-client safety. Those concerns have separate bounded models and runtime
tests, and deeper or inductive proof remains an open P0 obligation.
