# Model operations reported-acceptance contract V1

This is an offline sidecar to the existing target-decoder adapter/run evaluator,
not a new trainer, reward ledger, native activation gate or release qualification.
[Model evaluation](MODEL_EVALUATION.md),
[checkpoint tile material](CHECKPOINT_TILE_MATERIAL_V1.md) and
[confirmed round observations](EVALUATION_CONFIRMED_ROUND_OBSERVATION_V2.md)
retain their owners. Confirmation of an evaluation transaction is not confirmation
of model benefit, task independence, consent, physical use or future availability.

## One pinned preregistration and receipt

[`model_acceptance.py`](../../../../formal/pon-nakamoto-v1/model_acceptance.py)
uses fresh `pon-model-operations-preregistration-v1`,
`pon-model-operations-reported-receipt-v1` and
`pon-model-operations-assessment-v1` sidecar schemas. No signed transaction domain,
existing stored schema or old evidence is changed. The caller must pin the
preregistration digest outside the submitted receipt. A package cannot select its
own expected owner, target contract, backbone, tokenizer or run-plan hash.

The preregistration binds the existing run plan's baseline, candidate, four strong
controls, tasks, seeds, metric, full-repetition stopping policy and per-run budgets.
It adds a positive minimum gain in parts per million, adversarial-regression ceiling,
minimum unique reported consumer uses, retention byte-second ceiling, chronological
window, training/future group separation, declared role separation, governance
reference, retained material role/root mapping and seven owner-evidence roots.
Evaluation source groups must be disjoint from both training and calibration groups;
probe prompts must not alias evaluation/calibration prompts. Hash-group separation
cannot detect renamed or semantically duplicated sources.

The receipt binds the exact run record. Verification calls the existing
`evaluate_run_record` and recomputes candidate gain against the strongest evaluation
control using exact rational arithmetic. No supplied Boolean or claimed score can
substitute for this replay. Poison, backdoor and forgetting probes each include
all frozen participants. A candidate failure when any control succeeds counts as
one regression for that probe's category. These are exact-output labelled probes,
not a comprehensive safety assessment or proof against arbitrary backdoors.

Consumer observations must bind the frozen candidate, evaluation task, seed and
matching successful candidate output. Operation IDs cannot repeat. Relabelling the
same prompt/output under another operation or seed cannot increase unique reported
use. Uses must fall between reported task release and reported observation. This
receipt does not mint an inference quota, authenticate a real consumer or replace
[existing useful-output accounting](MODEL_ATTRIBUTION.md).

Retained obligations cover candidate, all controls, backbone, tokenizer and task
data roles. Actual supplied bytes are SHA256-checked; evidence bytes are also
required, rather than accepting unattached hashes. Per-root byte length, copies,
start/end, retrieval digest/time and repair bytes are mandatory. Retention must
cover the full frozen window. Byte-seconds and repair bytes are recomputed with
bounded integer arithmetic. Missing/unknown retention inputs reject; they are never
imputed to zero. Existing run cost accounting includes all reported failed/retry
stages; unknown GPU remains null and fails the complete-GPU gate. Byte-seconds are
storage obligations, not a monetary estimate or proof of paid/fulfilled retention.

Material role/root mappings are owner declarations. Small supplied chunks or
manifests do not prove availability of an entire large model or dataset. The
16 MiB package bound deliberately prevents this verifier from loading target LLMs;
full target material and storage-owner validation remain external. A receipt that
supplies only a manifest reports costs only for those supplied bytes, not the full
model. Outputs explicitly mark `material_relationship_verified` and
`full_model_retention_cost_complete` false, with
`complete_model_retention_byte_seconds` null. No model/data download or license acceptance occurs here.

## Reproducible ingestion and adversarial tests

[`verify_model_acceptance.py`](../../../../formal/pon-nakamoto-v1/experiments/verify_model_acceptance.py)
reads a local package containing canonical `contract.json`, `plan.json`,
`preregistration.json`, plus `run-record.json`, `receipt.json`,
`material-index.json` and indexed material bytes. The material index maps SHA256
to package-relative files. Escaping paths, duplicate JSON keys, nonfinite JSON,
changed hashes and oversized inputs reject. JSON inputs are bounded to 2 MiB each
and material bytes to 16 MiB total. The verifier prints its assessment; it does not
write, sign, deploy, contact owners or submit transactions. Add
`--require-reported-gates` to retain the printed assessment but exit 2 when a
reported gate fails. Exit 0 means successful record verification only, never external
acceptance, complete model retention coverage or public qualification.

```bash
python3 formal/pon-nakamoto-v1/experiments/verify_model_acceptance.py \
  --input /path/to/owner-package \
  --preregistration-hash OWNER_PINNED_PREREGISTRATION \
  --plan-hash OWNER_PINNED_RUN_PLAN --contract-hash OWNER_PINNED_CONTRACT \
  --backbone-root OWNER_PINNED_BACKBONE --tokenizer-root OWNER_PINNED_TOKENIZER \
  --owner-record OWNER_PINNED_SOURCE_OWNER
python3 formal/pon-nakamoto-v1/test_model_acceptance.py
```

All positive fixtures are explicitly fabricated tiny bytes and output records.
Tests execute negative gates for poisoning, backdoors, forgetting, no gain, missing
consumer use, GPU unknowns and retention overruns. Substitution, chronology,
source overlap, repeated operations, role aliases, material corruption, short
retention, Boolean numeric aliases and invented acceptance flags reject. These
results are executable contract evidence, not trained-model improvements.

## Explicit continuation across reported evaluation windows

[`model_window_history.py`](../../../../formal/pon-nakamoto-v1/model_window_history.py)
adds an optional offline continuation contract with fresh
`pon-model-window-history-v1`, `pon-model-window-preregistration-v1` and
`pon-model-window-assessment-v1` schemas. Existing V1 packages and parsers keep
their meaning. The new entrypoints are `empty_history`, `freeze_history`,
`freeze_window` and `verify_window`; no Node, signed transaction, native release,
reward or production activation uses this sidecar.

The caller fixes a series, owner and governance context, the complete previous
history digest and the new window preregistration digest outside the submitted
package. Window ordinal and previous-entry digest bind the complete ordered
entry chain to that context. The current operation preregistration and run-plan
identities are bound again. Owner/governance changes require an explicitly new
context; a candidate model may change within an existing context. A caller that
accepts a submitter-selected older history or new series has not preserved this
continuity obligation. Self-computing a matching hash is not external pinning.

History validation reconstructs all contacted sets from its retained entries.
Current evaluation task IDs and prompt digests cannot appear in any earlier
calibration/evaluation task; current evaluation prompts also cannot match earlier
probe prompts. Current evaluation source groups cannot appear in any earlier
declared training, calibration or evaluation groups. Renaming a task and source
group does not remove an identical prompt from this check. Training-group hashes
describe reported contact, not proof that their contents were public or used.

Later training, calibration and probes may intentionally reuse earlier material,
provided the current future-evaluation partition passes all current V1 and
cross-window exclusions. Common target strings such as `yes` or `no` are not a
global exclusion set: the same valid answer in a new task is allowed. Semantic
paraphrases, altered preprocessing, hidden source aliases and undeclared training
exposure still require actual independent task custody and review.

`verify_window` first verifies the complete current V1 operation record, including
its full supplied costs, probes, consumers and retention obligations. It then
appends the current plan/receipt identities, observed interval, reported gate
outcome and contacted-set projection to a new history value. A valid record with
zero gain, unknown GPU cost or another false reported gate still consumes the
window. A malformed record or a hard run-budget violation raises without returning
a new history. Previously released but malformed, aborted or hidden windows need
an external exposure ledger; the sidecar does not infer their missing data or
claim that its submitted history is complete.

The sidecar is finite: at most64 retained windows, 131072 total task/probe/training
entries, 16MiB canonical history and 4096 bytes for a window preregistration.
Before admitting a window, `freeze_window` reserves the complete serialized append:
all contacted fields are already known, receipt/head digests have fixed width,
the latest permitted observation is `closes_at`, and `false` is the longer Boolean
encoding. This temporary byte-size envelope is neither returned nor retained as
an observation. The actual completed append is fully validated again. Thus an
already-near-limit history cannot admit work whose mandatory result record will
not fit. Exhaustion rejects explicitly; it never prunes earlier exposures or
silently starts a fresh series.

Only supplied-history shape, hash linkage and the current complete record are
checked. The result keeps `historical_execution_verified`,
`hidden_windows_excluded`, `physical_custody_verified`, `prospective_accepted`,
`independent_accepted`, `public_reward_eligible` and `production_activation` false.
Reported chronology cannot authenticate wall time, and history summaries alone
cannot prove that earlier operations were actually executed or verified. Trusted
pin advancement, storage, concurrency/CAS and publication are caller obligations;
these pure functions do not mutate an external head or contact an operator.

```bash
python3 formal/pon-nakamoto-v1/test_model_window_history.py
```

The synthetic tests cover three linked windows, task/group relabelling, prior
probe and training exposure, valid reuse for later training/calibration, ordinary
shared target outputs, owner/context changes, external-anchor rollback, omitted
or reordered entries, negative-gate consumption and malformed-record nonmutation.
They also check canonical JSON, strict numeric/Boolean types, bounded histories,
pre-registration byte responsibility and a late false-gate result at the exact
reserved byte limit. These are record-contract tests, not new model training or
future-task efficacy observations.

## Required independent inputs remain blocked

Even when every reported gate passes, every assessment returns all seven external
gates unverified: preregistration custody; future task custody; material license and
consent; independently administered operator/reviewer; authenticated runtime and
consumer use; retention/availability; evaluator governance and appeal. Distinct
hashes and declared timestamps do not authenticate people, organizations, chronology,
legal authority, consent withdrawal, real execution or storage service.

An authorized target owner must supply actual licensed model/data/tokenizer material,
trusted prospective registration and untouched task custody, externally verified
independent operators/reviewers, real model/control execution and complete resource
measurements, authenticated consumer observations, fulfilled retention/retrieval
and repair evidence, and an accountable evaluator/dispute/withdrawal process.
Those external verifiers are not implemented by a permissive Boolean or bypass.
`prospective_accepted`, `independent_accepted`, `public_reward_eligible` and
`production_activation` are always false. Positive real future gain remains
unobserved and must not be inferred from this package's synthetic test pass.

### History byte-policy consistency

The history decoder now applies the history owner's existing16MiB bound through
both its outer input check and the shared identity/canonical decoder. Previously
the shared decoder's ordinary2MiB manifest default also applied to history, so a
valid history between2MiB and16MiB could be frozen but not consumed by the next
window. Ordinary target contracts, run plans and model-operation manifests retain
their existing2MiB default. The override is a fixed schema-owner call argument,
not a size supplied in submitted JSON or a new permission.

Every history still requires its externally pinned digest, exact canonical JSON,
complete ordered entry links, contacted-set reconstruction, byte/item/window
limits and mandatory append reservation. Larger history cannot bypass overlap,
negative-window consumption or external-acceptance boundaries. Regression fixtures
freeze and continue an actual2.5MiB synthetic history, reject altered pins and
noncanonical/link-corrupt records, and verify both the unchanged ordinary2MiB
limit and the original16MiB history ceiling. These are supplied-record tests, not
training, real future observations or an authenticated exposure ledger.
