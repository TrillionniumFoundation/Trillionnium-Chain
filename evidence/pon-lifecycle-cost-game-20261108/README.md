# Lifecycle legal-cost accounting and service separation — 2026-11-08

Status: **scoped local validation PASS; actual-work qualification HOLD_NO_GO**.

This record belongs to executable source `2d71bd943e88fb25d19c2d86feb09b86657a87d3`, tree
`4f0f951023b63bb1a27b63a76cd489da20538db0`, continuing integration source
`8d5389748873dad6e296d17f2ff20483b5afa5bc`. The publication child adds evidence
only. Its source identity is checked separately; these runtime observations bind
the executable source above. No merge, main activation, native payment or work
qualification is performed by this evidence package.

## 1. Delivered changes

- [Finite lifecycle cost game](../../formal/pon-nakamoto-v1/LIFECYCLE_COST_GAME_V1.md):
  exact rational potential certificates, independent finite-policy refutations,
  deterministic cycles, stochastic occupation witnesses and finite-horizon tails.
- [Cell cost conformance](../../docs/development/specs/pon/CELL_LOTTERY_COST_AUDIT_V1.md):
  unchanged complete V2 relation at two fixed nonces, with original refusals and
  six explicit remaining cost obligations.
- [Service and work settlement](../../docs/development/specs/pon/SERVICE_WORK_SETTLEMENT_V1.md):
  complete frozen evaluation earns its contracted base fee independently of the
  improvement decision. The separate bonus retains four controls and retention.
  Additional consensus credit is always zero.
- [Combined reproduction driver](../../formal/pon-nakamoto-v1/experiments/lifecycle_cost_game_v1.py):
  clean committed whole-source checks before and after; a new output directory
  outside the source tree; complete JSON reports with hashes and refusal status.

The three new test commands are mandatory in the existing protocol-contract lane.
The CI contract's original removal, duplication, relocation, failure-swallowing
and missing-source controls now include them. No existing test was removed.
The inherited embedded source inventory omitted the already tracked
`history_stage_diagnostic.rs`; the original generator added that one source
entry and the original checker now passes. This is not a native algorithm change.

## 2. Exact finite-model results

The [complete serialized games and certificates](validation/reproduction/finite-lifecycle.json)
are scoped to a declared finite classical MDP. Atomic costs and conditional
probabilities are assumptions of that model, not measured W1 implementation costs.

| Declared experiment | Checked result |
| --- | --- |
| Cold two-selector bank | 216 states, 1,848 actions, kappa=1/8, initial expected potential 0; exact fixed point after five iterations |
| Warm prepaid bank | Zero initial budget is refuted; the full original initial allowance 1/4 is certified |
| Sharing two continuations at one declared cost | Three-step strategy achieves 3/8; all-action upper certificate also gives 3/8; strict gap over 1/4 is 1/8 |
| Incorrect restart restoring redeemed credit | Two-edge positive cycle has net credit 1; no finite stationary potential for that modified game |
| Paid fair coin, horizon 10, excess threshold 4 | Exact exponential upper bound 9765625/268435456; independent test enumeration gives actual crossing probability 3/256 |

The tail JSON stores the upper bound. The value `3/256` is obtained by the
[independent 1,024-path enumeration test](validation/test_lifecycle_cost_v1.log),
not by an additional probability field in that JSON. A separate readback of its
serialized fair-coin law found the same 12 crossing paths. The potential checker
does not recognize real credit identities; deduplication and complete state are
model premises. The initial cap is an expectation under the declared law, not
an adversarial-choice or pathwise cap. Only bounded stopping and a finite horizon
are claimed. The occupation witness's stationary net rate is not an initial-state
economic profit rate.

## 3. Complete Cell relation observation

[Cell conformance JSON](validation/reproduction/cell-conformance.json) records
two complete witnesses at fixed nonces 0 and 1, plus one ordinary revalidation
of the first witness. The all-ones target removes mining search from this
conformance experiment. All five complete useful product tiles agree, and all
five nonce-dependent transcripts change. The accepted paths execute 15 complete
W1 verifications in total. No optimized nonce search or physical cost measurement
was performed.

Original refusal codes remain `TRANSCRIPT` for a nonce change without the new
execution transcript, `V2_WITNESS_CANONICAL` for noncanonical witness whitespace,
and `EXPECTED_PARENT_CONTEXT` for an independently held parent mismatch.
Revalidation by a pure verifier is not another owner credit grant. The report
keeps native admission false and additional chainwork zero.

The 7,710 useful dense positions and 1,310,720 padded dense product positions are
shape descriptions only. They are not a speedup, resource ratio or lower bound.
The retained public-source model is bound to `9fedf7ecbbe07177069c030592b4e03dcffebb81`;
it is not claimed to be a deployed trained Hepta encoder.

## 4. Service, improvement and work remain separate

[Service JSON](validation/reproduction/service-separation.json) contains synthetic
integer evaluation controls, not customer demand, actual transfers or training.

| Complete reference scenario | Conditional base fee | Conditional bonus | Additional consensus credit |
| --- | ---: | ---: | ---: |
| Correct NoUpdate | 7 | 0 | 0 |
| Frozen improvement and retention pass | 7 | 11 | 0 |
| Gain with retention regression | 7 | 0 | 0 |
| Invalid service | 0 | 0 | 0 |
| UNKNOWN | 0, original 7 remains reserved | 0, original 11 remains reserved | 0 |

Failed and cancelled work retain supplied resource consumption. UNKNOWN is
nonterminal and refunds neither lane. The empty supplied pool remains empty,
authorizes no synthetic fill and has no liveness qualification. Real funding,
independent evaluation, physical costs, external payments, adoption and native
owner settlement are unverified and explicitly false.

Review closed two executable defects before source freeze: both original budgets
must mature by the start of the service window, and material binding/execution
must use the same private snapshot. A third correction narrowed height wording:
only successfully returned and retained successor states record an observation;
failed calls and read-only supply queries do not persist new observations.
Double-lane atomicity remains a reference state transition, not a concurrent or
durable native transaction. Existing resource-job pins survive branch rewind in
the retained process; whole-process recovery remains open.

## 5. Exact-source validation and denominators

[Main command manifest](validation/validation-manifest.json): **29/29 commands
exit zero** on the frozen source. [Source before](validation/source-before.json)
and [source after](validation/source-after.json) match exactly: **15,000 tracked
entries, 1,652,474,709 bytes**, actual raw worktree hashes checked.
The [combined reproduction manifest](validation/reproduction/manifest.json)
also has matching original before/after checks and `driver_status=PASS` while
retaining `qualification=HOLD_NO_GO`.

| Unittest suite | Invocations | Initial skips | Exit |
| --- | ---: | ---: | ---: |
| [test_lifecycle_cost_v1](validation/test_lifecycle_cost_v1.log) | 31 | 0 | 0 |
| [test_ci_source_integrity](validation/test_ci_source_integrity.log) | 43 | 0 | 0 |
| [test_cell_lottery_cost_audit_v1](validation/test_cell_lottery_cost_audit_v1.log) | 3 | 0 | 0 |
| [test_service_work_settlement_v1](validation/test_service_work_settlement_v1.log) | 25 | 0 | 0 |
| [test_reward_budget_oracle](validation/test_reward_budget_oracle.log) | 23 | 0 | 0 |
| [test_useful_cell_numeric_v1](validation/test_useful_cell_numeric_v1.log) | 20 | 0 | 0 |
| [test_grouped_cell_operator_v0](validation/test_grouped_cell_operator_v0.log) | 11 | 2 | 0 |
| [test_ci_execution](validation/test_ci_execution.log) | 77 | 0 | 0 |
| [test_useful_cell_relation_v1](validation/test_useful_cell_relation_v1.log) | 47 | 0 | 0 |
| [test_useful_cell_execution_v2](validation/test_useful_cell_execution_v2.log) | 34 | 0 | 0 |
| [test_ci_contract](validation/test_ci_contract.log) | 103 | 0 | 0 |
| [test_useful_cell_relation_v2](validation/test_useful_cell_relation_v2.log) | 11 | 0 | 0 |
| [test_useful_cell_relation_v2_adversarial](validation/test_useful_cell_relation_v2_adversarial.log) | 11 | 0 | 0 |
| [test_useful_cell_source_guard_v2](validation/test_useful_cell_source_guard_v2.log) | 20 | 0 | 0 |
| [test_useful_cell_multimodal_execution_v3](validation/test_useful_cell_multimodal_execution_v3.log) | 34 | 0 | 0 |
| [test_useful_cell_multimodal_relation_v3](validation/test_useful_cell_multimodal_relation_v3.log) | 25 | 0 | 0 |

The main run has **518 unittest invocations: 516 pass, two explicit skips**.
These are invocation counts, not 518 unique methods: `test_ci_execution` imports
the 43 raw-source controls. The three newly implemented suites contain **59
methods, all passed** (31 lifecycle, three Cell conformance, 25 settlement).

The two initial skips say `TRNM_GROUPED_NATIVE is unset`. They are retained in
the original log. The [native supplement](grouped-native-supplement/manifest.json)
then built the real `pon_routed_int257_grouped` Rust example from the same frozen
source and reran the unchanged complete grouped suite: **11 pass, zero skips**.
It performs real-process shape/differential and malformed-frame checks; the
binary's before/after SHA256 and whole-source checks match. The nine repeated
Python checks are not counted as nine new unique tests.

Rust validation on the same executable source:

- [Locked offline Cargo graph](validation/cargo-metadata.log): 175
  resolved packages, 26 workspace members; lockfile unchanged.
- [Formatting](validation/cargo-format.log): `cargo fmt --all -- --check` passed.
- [Strict Clippy](validation/cargo-clippy.log): all workspace packages, all targets,
  all features, `-D warnings` passed.
- [Crypto library](validation/crypto-native.log): **158 pass, zero failures/ignored**.
- [Native Cell suite](validation/cell-native.log): **12 pass, zero failures/ignored**,
  including complete five-tile verification, independent owner input and real
  store/cold recovery controls.
- [Original repository/Markdown check](validation/repository.log),
  [CI contract](validation/ci-contract-static.log),
  [embedded source inventory](validation/distributed-source-inventory.log),
  whitespace and project boundary passed.

[Runtime identity](validation/runtime.json) records Python 3.12.14,
NumPy 2.3.5 and cryptography 50.0.0.
The repository CI pins NumPy 1.26.4 and cryptography 50.0.2; this local environment
does **not** reproduce those two pinned versions. Rustc/Cargo versions and all
explicit build flags, including disabled incremental builds and debug information,
are recorded. These are correctness checks, not a production cost comparison.
The full GitHub/native Host/History/pressure matrix was not executed locally and
is not represented by this scoped PASS.

The publication preserves raw test-log whitespace. A later whole staged-evidence
`git diff --cached --check` returned 2 for one original unittest trailing space
and two Cargo logs ending in a blank line; the [exact refusal](raw-evidence-whitespace-check.json)
is retained. The executable-source whitespace command above passed. No raw log
was normalized and no checker was relaxed to hide this publication observation.

## 6. Preserved failures and preparation observations

| Observation | Retained record and disposition |
| --- | --- |
| First Cell setup refused historical source replay | [Original refusal](development-observations/cell-initial-unavailable-source.log); zero tests ran. Fifteen historical blobs were absent locally; [exact blob recovery verification](development-observations/source-recovery-verification.json) checked their Git identities. No retired source tree or weakened source guard was introduced. |
| First lifecycle fixture expected a cold-start violation from a warm-only shortcut | [Transcribed original tool output](development-observations/lifecycle-first-run.log) explicitly labels its provenance. The solver was correct; the test was corrected to hold the specified warm state and original cap fixed. |
| Service window before funding maturity | [Four original failing subtests](development-observations/service-maturity-before-fix.log), explicitly a tool-output transcription; strict two-lane maturity admission added. |
| Bound material changed between two reads | [Original redirected failure log](development-observations/service-material-before-fix.log) and [metadata](development-observations/service-material-before-fix-metadata.json); complete computation changed decision under old code. One private snapshot now binds the computation. |
| Inherited embedded inventory omitted an existing test file | [Original inventory refusal](development-observations/inventory-initial-refusal.json); regenerated the missing include with the unchanged generator/checker. |
| Preliminary repository check while a new document was still being written | [Original missing-link refusal](development-observations/repository-current.log); completed document resolves the link. |
| First local source-identity orchestration started before the remote commit was materialized locally | [Original clean-source refusal](development-observations/initial-source-identity-refusal/source-before.log), [actual runtime identity](development-observations/initial-source-identity-refusal/runtime.json) and [attempted command](development-observations/initial-source-identity-refusal/commands-in-progress.json). Actual HEAD was still the old integration base and the candidate was dirty. No test suite ran. Remote commit bytes were then imported only after matching the exact Git object SHA, and the final source run above passed. |
| Initial optional native runner absent | Two explicit skips in the original grouped log; real runner supplement above executes both and retains the original skipped observation. |

The [working-tree service follow-up](development-observations/service-after-review-fixes.log)
is separate from the 25-method final committed-source run. Early logs are not
silently relabeled as final-source evidence. Numeric potential checks, source
integrity checks and static parallel review are not independent security or
economic acceptance.

## 7. Reproduction and remaining qualification obligations

From a clean checkout of the frozen executable source, with the declared Python
runtime and original model-source Git objects available, run:

```sh
python3 formal/pon-nakamoto-v1/experiments/lifecycle_cost_game_v1.py --output /absolute/new/output-directory
```

The output must be new and outside the source tree. The captured local
[main orchestration](local-orchestration/run_lifecycle_validation.py) and
[native supplement orchestration](local-orchestration/run_grouped_supplement.py)
document the exact local commands and path-specific environment; they are
observation records rather than portable CI replacements.

Outstanding: every legal classical and quantum implementation and prehistory;
resource-model simulation/reduction with accumulated deficit and initialization
bounds; authenticated deduplication across real parent/profile/version changes;
joint execution soundness and late witness search; real trained Hepta inputs,
numerical fidelity, retention and local owner adoption; durable native funding
and payment integration; genuine task demand and long-run supply; and the joint
honest/adversarial process needed for an actual chain-safety probability.
No finite-model expectation or finite-horizon tail is promoted to these claims.
