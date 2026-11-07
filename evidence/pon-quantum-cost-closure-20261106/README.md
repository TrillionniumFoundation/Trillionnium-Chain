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

Final validation ran against source commit
`acafa39a507632b6a8947915124a5e9f680f3448`, tree
`03c13a4c900b379a87a1fc359d1a82f093218c8e`. Every group verified all tracked
source bytes before and after execution. This evidence-only successor records
those results; it does not relabel the tests as having run on a later commit.

| Final frozen check | Result |
| --- | --- |
| Quantum/W1/DAA retained unit tests, including the seven new preprocessing tests | 210 PASS |
| Independent network controls | 7 PASS |
| Negative source-integrity tests | 43 PASS |
| CI contract tests | 105 PASS |
| PQ research integration tests | 38 PASS |
| Exact rational literal schedule controls | 32 PASS |
| Malformed direct-count and width/depth controls | 10 rejected as required |
| Preprocessing byte-change controls | 8 checked, including corrected parent coverage |
| Source pins, inventory, repository/Markdown links | PASS |
| Locked offline main/fuzz dependency graphs, Rust format, strict all-target/all-feature Clippy | PASS |

The first frozen batch at `c7f0918da82041de62e693b4e6a814b4ca16fe4c`
correctly failed the source-pin guard: adding the new CI invocation also
required updating the existing CI-script pin. That failed batch is retained
unaltered under `attempt-c7f0918` in the historical archive. The next source
commit changes only that pin; the complete final batch was rerun.

The independent review also caught a fixture mislabeled as a parent change:
offset 66 changes `parameters`, whereas parent starts at offset 70. The same
prefix block count had concealed the missing field coverage. The corrected
test independently decodes wire fields. Nine original files and the failing
label assertion are preserved with hashes. The initial two mistyped unittest
selectors are retained as harness errors, not counted as discovered defects.
Intentional stale-checkpoint and negative source-integrity failures are not
mistaken for final validation failures.

The local lint run used OpenSSL 3.5.7 (CI pins 3.5.9) and retained Cargo's
SQLite bounded-I/O loader UNQUALIFIED warning. It disabled debug symbols and
incremental compilation to bound storage. These checks establish no provider
parity, native runtime performance or bounded-I/O qualification.
The source-pin checker exits successfully while retaining its semantic
`HOLD_NO_GO` status and false cryptographic/activation acceptance flags.

### Evidence files

- [Qualification and source manifest](qualification.json): exact source/tree,
  final counts, environment and false qualification flags.
- [Frozen validation archive](frozen-validation.tar.xz): command receipts,
  raw logs, source checks and a parameterized replay driver.
- [Historical observations archive](historical-observations.tar.xz): original
  failures, portable controls, corrected-label lineage and the first freeze.
- [Independent source review](final-independent-review.md) and
  [evidence lineage review](evidence-lineage-review.md).
- [Evidence manifest](evidence-manifest.json): SHA-256 of every delivered file
  except the manifest itself, and every file inside both archives.

Extract the archives into a temporary directory. The retained control drivers
accept `--repo /path/to/checkout`. `run_frozen_validation.py --help` describes
its repository, exact-head, evidence-root, Cargo cache/target and toolchain
arguments. A group refuses to overwrite an existing result directory. Earlier
passes and replayed cases are not added to the final independent-test counts.

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
