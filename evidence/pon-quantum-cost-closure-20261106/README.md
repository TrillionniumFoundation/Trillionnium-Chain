# Quantum cost and preprocessing boundary followthrough

Status: **Draft / HOLD**. This continuation starts from
`2d4ff4b6c0af18f324e056b4e0d5343c97850b85` (PR #750). It changes research
diagnostics and their tests; it does not qualify quantum mining or consensus.

## Source changes

- The adaptive private-branch publication timer now schedules and tests the
  same upward-rounded exact deadline. In the retained conditional scenario,
  a block completed at `0.5` and a wait of `0.1` previously lost the timer
  because `0.6 - 0.5 < 0.1`. The fixed publication time is
  `0.6000000000000001`. Partial-prefix release resets the deadline; timestamp
  admission and duplicate-event controls remain covered.
- The network model uses the shared finite Grover probability kernel, including
  exact empty/full marked-set endpoints at large iteration counts.
- Direct physical estimation now checks count/depth consistency as stage
  validation already did. The retained direct-call counterexample accepted
  100 gates at zero depth and reported zero runtime. This bypass was not a
  JSON-path defect. Both entry paths now also reject impossible width/depth
  combinations. The necessary capacity inequalities do not verify a netlist,
  routing, error correction or hardware. Counts and depths refer to one
  declared schedule; unrelated loose ceilings are outside that contract.
- `w1_preprocessing_reuse.py` compares canonical templates using exact framed
  bytes. It separately reports AB input identity, task-hash input identity,
  the common fixed SHA prefix, and complete challenge-input identity. It
  resumes real SHA compression from the shared checkpoint and checks the
  result against independent `hashlib.sha256` computation. Its tests are
  included in the existing repository-truth CI job.

## Preprocessing observations

The following are specific retained reduced-fixture changes, not universal
per-field rules. Every row changes the complete challenge input. Input
inequality is not a proof that all other caches or algorithms must recompute.

| Changed input | AB input identical | Task-hash input identical | Reusable consecutive fixed SHA blocks |
| --- | --- | --- | ---: |
| Nonce | yes | yes | 5 |
| Parent | yes | yes | 1 |
| Target | yes | yes | 2 |
| Timestamp | yes | yes | 2 |
| PNH1 to PGH2 | yes | yes | 0 |
| PGH2 witness | yes | yes | 5 |
| PNH1 task and legal matrices | no | no | 4 |
| PGH2 task and legal matrices | no | no | 5 |

PGH2 task and witness bytes occur after the five precomputed blocks. Reusing
those blocks therefore does not reuse the entire challenge. AB depends on
`A, B, N, q`; the task commitment hashes matrix bytes and does not include the
modulus. Challenge identity alone does not imply identical later relation
intermediates if other relation parameters differ.

Five intentionally stale-checkpoint controls produce the wrong hash. They
demonstrate why unconditional checkpoint reuse is invalid, not a discovered
bug in the existing full/restricted oracle implementations.

## Validation and retained limitations

The source commit is frozen before the final validation batch. A subsequent
evidence-only commit records the exact tested commit/tree, logs, original
failures, portable replay drivers and independent review. Working-tree runs
are kept distinct from that frozen batch; repeated runs are not independent
replications.

The existing full and prefix-restricted W1 constructions, reduced gate
controls and native-shape symbolic/macro controls remain research evidence.
This followthrough does not execute a native-size quantum gate circuit or a
fault-tolerant quantum device. It measures no CPU/QPU energy or time saving.
The literal accounting audit checks 32 exact rational schedule calculations;
its API has no finite-horizon parameter and is not equal-budget work
production. Native DAA reader and cost-binding work in other continuations
must be qualified on their own source identities.

Hardware calibration, physical resource feasibility, preprocessing frequency,
same-real-budget accepted-work production, profitable executable fork attacks,
whole-chain quantum security and activation all remain unqualified. The
linear consensus chainwork rule is unchanged.

Bailey and Sattath analyze an idealized mismatch between quantum search cost
and accumulated-work scoring, including bounded-retarget adaptations. Their
paper does not instantiate a full Trillionnium W1 attack:
<https://arxiv.org/abs/2403.08023>.
