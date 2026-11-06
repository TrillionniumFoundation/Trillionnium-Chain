# Work, knowledge and settlement evidence boundary

This continuation composes #688 at `513e92dfc27044ef3e0c9d62e7ae504fa5bea38f`
with #717 at `6dd21c7b35fa085f84b8280495b2583c67023fad`. The composition before
the new repairs is `6e47258cf9e87a2f0993aa675cb08f8a74de256c`, tree
`8454037b68ff047794184bb814a515e0da9027c6`. The merged histories and the original
work-value implementation remain separate from the new source-bound checks.

The published, executed source is
`873d33aefd33828842c1f1420382b77c15396d74`, tree
`ac292aed065cef38686c099496fff0f2712a2e30`. Its complete tree equals the local
implementation commit `0f8e870da57f1bb928e7644ab4a10c834df41821` byte for byte.
Publication used the connected GitHub API after terminal Git authentication
became unavailable, so commit metadata changed. Both original #688/#717 parents
remain in the published commit. The three local implementation/merge commits
are retained in `local-source-history.bundle` inside the observation archive.
The final evidence-only publication adds these records without changing runtime,
test, CI, configuration or lockfile bytes.

**Production activation, independent model benefit and work hardness remain
unqualified.** The new controls repair existing local evidence consumers. They
do not train a new model or turn a development test-unit payment into a public
model-improvement reward.

## Concrete findings and repairs

### Complete partition replay

The producer rejected cross-partition task IDs, source groups and normalized
content hashes. The old settlement consumer only loaded calibration and its two
evaluation partitions. A self-consistent bundle, fixed by a caller, could thus
commit overlapping train/evaluation IDs or content and pass that consumer.
Missing train and committed consumer files also passed. Source-group overlap
was already rejected and is not presented as a new finding.

`verify_partition_set` now checks exactly all committed partition names,
recomputes every manifest from actual rows, and rejects the three intersection
types. `settle_model` runs it before evaluation replay and before creating its
experimental ledger. A producer-side constructor is no longer the only place
that enforces those checkable conditions.

The red fixture does not counterfeit an independent owner's digest and never
sets `public_reward_eligible`. It demonstrates a producer/consumer validation
gap in a controlled experiment. Complete committed-row separation still cannot
prove actual training exposure, honest source-content labels, data rights,
semantic decontamination or evaluator independence.

### One verified input snapshot through settlement

The previous positive settlement path reopened model and evaluation files after
checking them. The new path owns the original verified bytes, persists a
versioned digest manifest and uses the same bytes for model contributions,
evaluation evidence, replicas and consumer input. It leaves the original input
directory unchanged. The local author-offline control withdraws only the frozen
author copy; it makes no remote custody or independent-provider claim.

Before the ledger is created, the supplied `model-work.bin` must match the
original producer's exact A/B construction, its model/complete-consumer challenge,
the full W1 transcript and the signed integer result. This is the existing
first-64-feature, expert-zero partial contraction. It is not full model inference
or a proof of fresh training. New challenges on the same A/B still decode to
the same useful product.

The inference worker also read a model once for prediction and again for its
reported artifact hash. A path replacement between those reads could attach the
replacement's hash to the earlier model's predictions. It now parses, uses and
hashes the same bounded byte read. This has a separate exact red/green fault
injection, including replacement models whose observed predictions are equal.

### Completed fees and model-improvement rewards

The existing #717 M12 implementation is retained. `NoGain` can observe an already
executed fee only for completed Task/Contribution, Task/Evaluation or
Quota/Serving work, after its exact original effect, resource and native-payment
checks. Release/Contribution and Reward/Mining still reject `NoGain`.

The expanded existing negative test explicitly covers seven source/lane pairs,
including the previously untested Task/Contribution failure path. It has 25
ineligible payment cases and 42 attempts to relabel 21 Invalid/Unknown/Cancelled
records as NoGain or Positive, retaining the same charged resources and exact
journal report. These are cases within one registered test, not 67 independent
new test executions.

The retained native funding controls are designed to exercise actual signed escrow/payment,
three storage backends, reorganization and cold reopen. Paid and unpaid siblings
at the same target retain equal chainwork. Native development evaluation and
composition retain their own existing score, parent, allocation and no-gain
checks. Neither signatures nor correct matrix arithmetic bypass those owners.

### Fresh-ledger settlement context

The controlled settlement harness always creates a new ledger and submits its
contributions under the zero parent at chain submission round 0. The old reader
accepted a valid bundle declaring a nonzero parent release or later evaluation
round. A self-consistent positive fixture with parent `a1` repeated 32 times and
evaluation round 7 passed full partition replay and scalar W1 and reached the
actual Ledger constructor. The red control stopped there with an exception;
it did not fake a successful ledger or claim an executed reward.

The reader now accepts only the zero parent and evaluation-bundle round 1 before
evaluation replay or ledger creation. Evaluation rounds are positive and are a
different namespace from the chain's height-derived submission round. Generic
bundle construction and multi-round evaluation are unchanged. This narrow
harness cannot silently reinterpret their later contexts as an initial release.

## Reproduction

Use the committed source identities and exact environment from the accompanying
validation records. Run the repository preflight before building or editing.

```bash
bash scripts/project-preflight.sh
python3 -B formal/pon-nakamoto-v1/test_evaluation_bundle.py -v
python3 -B formal/pon-nakamoto-v1/test_settlement_inputs.py -v
python3 -B formal/pon-nakamoto-v1/test_work_utility.py -v
cargo test --offline --locked --manifest-path trillionnium/Cargo.toml \
  -p trnm-service-settlement --all-targets --all-features
cargo test --offline --locked --manifest-path trillionnium/Cargo.toml \
  -p trnm-pon-node --lib --all-features store::funding::tests:: -- --test-threads=1
```

Positive model fixtures in the adversarial tests are deliberately controlled
mechanical inputs. A complete local ledger execution of one such fixture is a
boundary test, not scientific benefit, fresh data, independent administration or
ordinary Hepta adoption. Historical real-model replay retains its original
not-adopted/zero-reward outcome. No original campaign result, deadline or resource
budget is rewritten by this continuation.

## Remaining qualification

The global cheapest legal W1 strategy and effective-work assumptions remain
open. So do lawful fresh training inputs, independent unseen evaluation,
full-release cost and negative-transfer testing, actual current-owner adoption,
next-task readback and original hostile public-service acceptance. The existing
HOLD/NO-GO gates remain authoritative. New local observations cannot close them
by renaming a matrix product, fee, report digest or repeated output as knowledge.

## Executed validation on the published source

All rows below executed on clean commit `873d33aefd33828842c1f1420382b77c15396d74`,
before this evidence-only addition. [validation-summary.json](validation-summary.json)
records exact commands, source identities, profiles, exits and log hashes.

| Check | Actual result | Scope |
| --- | --- | --- |
| Python boundary suites | 104 passed | Seven modules; includes 49 evaluation-bundle and 18 settlement-input tests |
| M12 all targets/all features | 48 passed | Unchanged Cargo profile; source/lane and immutable failed-outcome controls |
| Native funding suite | 6 passed, 0 ignored | Actual signed payment/reorg/reopen checks; 1169 other Node lib tests filtered out |
| CI contract suite | 101 passed | Existing job contract plus the new retained input-substitution suite |
| Negative source-integrity controls | 44 passed | Source and roster substitutions refuse |
| Strict Clippy | exit 0 | Workspace, all targets, all features, `-D warnings` |
| Formatting | exit 0 | Workspace `cargo fmt --check` |
| Current source pins | 542 blobs match | Original `HOLD_NO_GO` qualification disposition retained |
| Repository contract | exit 0 | 26 packages, 1165 Rust files, 3438 local links, 25 normal dependency edges |
| Locked Cargo graphs | exit 0 | All features: workspace 26 members/180 resolved packages; separate fuzz graph 1/147 |

The [Cargo graph summary](cargo-graphs-summary.json) records both lockfile hashes.
Both locks are unchanged from integration base `513e92df`. The earlier default-
feature graph had 175 resolved packages; it is not substituted for the final
all-feature graph. No full workspace test run or complete Node test-roster pass
is claimed.

### Preserved failures and environment limits

Original Node builds, two explicit reduced-debug/optimization experiments, the
initial strict Clippy run and the attempted `model_evidence_v3` integration build
were killed during compilation. Their raw `SIGKILL` observations remain; no
unobserved test execution is counted. The model-evidence integration attempt
was not completed. The later original-profile funding run and published-source
replay each actually passed all six selected funding tests.

Another Clippy attempt returned `No space left on device`. Only this task's
regenerable incremental caches were cleared; source, original observations and
other workspaces were preserved. The subsequent full strict Clippy command
completed successfully. Offline fuzz metadata initially lacked `libfuzzer-sys`;
missing local cache archives were recovered only after matching the unchanged
lockfile checksums. That initial failure remains in the record.

An executor recovery interrupted four checks and temporarily made the original
compiler path unavailable. Those records retain unknown child exit status or a
failed process start. The later published-source runs are separate executions.
Rust/Cargo 1.95.0 identity and recovery details are preserved in the archive.

The successful native payment run still reports the cached SQLite I/O build
fence as **UNQUALIFIED**, and the Clippy build records an incomplete normal
loader-directory set. These payment and lint results do not qualify that I/O
boundary, hostile public service, a production deployment or all native tests.
The fence was not disabled or relabelled.

### Historical model result

The [historical replay summary](historical-replay-summary.json) records the
original frozen model/bundle and five committed partitions: train 1005,
calibration 321, evaluation A 170, evaluation B 184 and consumer 213. Both
evaluation prediction vectors exactly match their historical records. Whole
adoption scores and all three marginal adoption scores remain zero; these are
gate scores, not a claim of zero predictive accuracy.

Current settlement returns `not_adopted`, `model_reward=0` and creates no chain.
The existing 49,188-byte W1 proof independently passes the current fixed-expert,
partial-contraction binding check. Correct work and absent accepted model gain
therefore coexist in the same retained material.

Direct replay of the original report fails with `OBSERVED_EVALUATION_MISMATCH`
because its older format lacks the current `value_claim`; its bytes and failure
remain intact. Evaluation-only replay in a new directory produces a separately
named report schema. It does not import the original training-execution claim.
Every step retains before/after hashes of 295 source files and 18 original
files. No training, new mining challenge or new mining was performed.

## Retained observation package

- [observations.tar.xz](observations.tar.xz): 263 members, 20,145,763 uncompressed
  bytes; 397,284 archive bytes. Includes all checks and earlier failed attempts,
  red/green reproduction scripts, three separately identified historical
  replays, locked graphs, environment records and the original local Git history.
- [observations-manifest.json](observations-manifest.json): each member's size and
  SHA256, nested replay and graph checks, and the exact archive identity.
- Archive SHA256:
  `cec13168bcd03f0fec639fd8dbe78f47427ccc9f2d72e31efce92fde2edc288b`.

Packaging reread every member and compared its exact bytes with the source.
Packaging success is not test success or a new qualification authority. Local
history can be imported from the enclosed Git bundle when its two composition
parents are available; the published source commit is already the identical
tree and preserves both parent histories.
