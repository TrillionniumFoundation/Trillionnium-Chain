# Snapshot-bound loading and replay-stable trial accounting

This continuation starts at `a9b8602706b66adba82655c3c2ce90bde88620a2` in
the existing Draft/HOLD PR #688. It keeps the earlier
[model-owner observations](../model-evaluation-owner-20261104/REPRODUCE.md),
including the original failed aggregate and the earlier unstarted full pilot.
Preparation records use UTC timestamps; the continuation date is 2026-11-04
in America/New_York.

## Concrete defects and corrections

The old base loader checked public-file hashes, then reopened the directory
through automatic model/tokenizer discovery. A real tiny Llama control exchanged
two tokenizer IDs while preserving vocabulary size, chat template and all model
parameter bytes. Another changed only RoPE/RMS configuration. Both changed actual
forward logits while retaining the original declared identities. The
[original observations](base-material-before.json) and
[original-source reproducer](reproduce_base_material_before.py) retain those
counterexamples; their small constructed tensors are not pretrained efficacy
evidence.

The corrected loader captures the pinned manifest and seven members through
bounded descriptors. Hashing and parsing use those same immutable bytes. Fixed
GPT2 fast-tokenizer and Llama classes consume explicit configuration and tensor
state; no model directory participates in automatic adapter, template, index or
pickle discovery. The original complete BF16/FP32 inventory, tied embeddings and
family roots remain mandatory. The contract checks the actual loaded configuration
and tokenizer state, and derives RoPE/RMS values from configuration rather than
hardcoded labels. The helper is included in all current direct and transitive
execution-source rosters; historical profiles are not rewritten.

The old cost verifier accepted six individually bounded but mutually inconsistent
wall, CPU and RSS observations as complete local channels. The
[before record](cost-before.json), [first repair record](cost-after-initial-repair.json)
and [reproducer](reproduce_cost_containment.py) preserve their exact source hashes.
New checks enforce child/supervisor, stage/child and child/wait4 containment.
Wall/RSS and same-clock stage sums use exact bounds. Only wait4 CPU receives the
explicit finite microsecond-conversion allowance; no budget or percentage
tolerance was raised.

Historical ledger reads previously imported the current assessment and re-read
the current family file. A harmless family-file reformat or assessment upgrade
could therefore make an already completed, spent trial unreadable. The ledger
now interprets known old formats with immutable compatibility rules. New
reservations use an explicit versioned replay selector and preserve the same
policy and allowance. Live effects still require current source validation; an
old pending trial may be aborted but cannot be completed through changed code.
Unknown legacy source interpretations, families, schemas and replay selectors
remain refused.

The [actual historical upgrade](historical-upgrade.json) uses a complete SQLite
history written by the original a9b860 code. Both old-reader failures above are
reproduced, then the new reader recovers the identical policy, checkpoint, spent
count and terminal identity without live runner/assessment/family files. The DB
bytes remain unchanged. This is a genuine old-format compatibility control,
not a record freshly generated with the repaired reader.

The [training counterexample](training-match-before.json) also retains a real
SQLite fixture where zero candidate steps and 99 immutable-backbone steps were
accepted as matched against a ten-step plan. Assessment v3 now verifies the
closed training records, planned steps, compatible bounded token totals, exact
zero-training controls and finite nonnegative loss traces. Its reported-count
agreement field does not assert an actual per-step schedule. The
[final v3 containment controls](cost-after-v3.json) and
[ledger/training validation](ledger-training-validation.json) cover this change,
including exact decimal rejection of negative values that underflow to float
negative zero. Original v2 records retain their original interpretation.

## Executed component evidence

The [preparation record](preparation.json) retains the new CPython 3.12.14
environment, all 31 hash-locked distributions, seven exact public materials and
the original baseline commands. Its default aggregate is 349 tests: 226 passed,
123 skipped and zero failures. The separate actual tiny Torch loader and decoder
controls passed 12 and 10 tests respectively. This fresh observation does not
erase the earlier 224-pass/2-fail/123-skip aggregate.

The [final snapshot command](base-material-final-command.json) records 17 passes,
including seven real tiny-model controls, with unchanged tested source. A separate
snapshot/parent-step suite passed 29 controls. The
[official tokenizer comparison](official-tokenizer-parity.json) checks all 49,152
vocabulary entries, 17 AddedTokens, complete backend/behavior state and the twelve
original training prompt/target encodings. It loads no pretrained model and
discloses no evaluation score. The
[retained development observations](retained-development-observations.json) keep
both earlier failed test-development runs and their original log hashes.

The [source-closure controls](source-closure-validation.json) passed all 68
affected tests using the locked optional Torch environment, with unchanged
production inputs. The earlier [missing-dependency observation](source-closure-missing-dependency.json)
retains 65 passes and three missing-Torch errors from the default interpreter;
the subsequent run kept all 68 tests. The [native check record](native-checks.json)
retains the a9b860 M06 package's 229 passes, seven original ignored tests, locked
Cargo graph, formatting and strict Clippy. Later concurrent native changes need
their own verification rather than inheriting that result.

## Acceptance boundary

The [final source validation](final-source-validation.json) records the recovered
complete aggregate: 411 methods, 281 passed, 130 explicit optional skips, zero
failures/errors. Repository negatives passed 50, CI contract controls 98, CI
execution controls 67, source identity controls 34, evidence-source controls 38
and PQ source negatives 35. The M06 package retained 229 passes and seven original
ignored tests; its composed-source strict Clippy, locked 175-package/26-workspace
Cargo graph and all-workspace formatting passed. Concurrent storage work is
preserved without claiming a fresh full-workspace native run.

The [environment interruption](environment-interruption.json) remains a separate
UNKNOWN observation. The platform became unavailable, the old processes ended,
and several logs had no terminal result; progress markers are not a reconstructed
test result. The recovered aggregate used unchanged production/fixture hashes.
These checks precede registration and contain no actual pretrained trial.

### One published hosted opportunity

The [hosted driver](../../scripts/ci/llm_hosted_once.py),
[synthetic Git/SQLite controls](../../scripts/ci/test_llm_hosted_once.py) and
[push-only workflow](../../.github/workflows/pon-smollm-hosted-once.yml) move the
original single attempt to an isolated hosted CPU. The shared local workspace
was concurrently saturated; no pretrained trial was started here to discover
whether its resources would suffice. The original CPU/four-thread/ten-step
strict-v1 plan, phase limits and one-attempt policy stay fixed.

Freeze clean source S, then use the offline `register` command with the exact
pre-created empty ledger bytes and original manifest. Commit only its one new
intent as I, with sole parent S. Create the dedicated execution branch
`fix/chain-model-owner-hosted-once-20261105` at S without an intent, then publish I
with a normal non-created, non-forced push. This freezes source while the
original PR #688 continues to receive concurrent changes. Its fixes and actual
observations still integrate through PR #688. The campaign, policy, trial ID,
materials, metrics and budget remain unchanged; a branch is not another allowance.
Publication spends the campaign opportunity even if setup, model execution, collection or
platform delivery fails. No dispatch, rerun, replacement ledger or new campaign
identity supplies another attempt. Runtime SQLite spending remains separately
reported: publication can be spent while setup has not yet created or reserved
the model ledger. An unknown database/exit observation remains unknown.

The runner validates first-attempt event context, source tree/bytes/import
closure, exact plan and full fetched heads/tags history before downloads or
model work. It installs only the existing hash-locked dependencies, verifies all
seven public materials, invokes the original registered pilot once and retains
bounded allowlisted receipts/logs/predictions/assessment/abort/readback. Weights,
environments and profiler archives are excluded. This is a cooperating repository
campaign; it cannot prove absence of deleted unreachable history, pull-only
refs, malicious administration or duplicate platform delivery.

The [outer-timeout counterexample](hosted-timeout-counterexample.json) and
[small parent/descendant reproducer](reproduce_hosted_timeout.py) show why a
separate `subprocess.run` timeout could kill the pilot supervisor while allowing
its child to continue. The hosted pilot call now has no such outer timeout;
the existing per-phase supervisor limits and hosted whole-job deadline remain.
No pretrained model, trial authority or evaluation input is used by that control.

The [aggregate development observations](aggregate-development-observations.json)
retain both the earlier incomplete 399-method discovery and the full 411-method
run's two fixture timing failures, as well as the source/evidence negative
controls. A subsequent corrected fixture result cannot erase those observations.
The [fixture diagnosis](fixture-timing-diagnosis.json) reproduces both timing
assumptions, records the original and corrected test-file hashes, and verifies
that the production supervisors remain unchanged. Synthetic clock control now
includes construction; the actual-child positive control synchronizes on its
owned pidfd before injecting delayed reap observations, then checks the single
native wait4 result and real usage. The original 100ms exit-drain cap, unproved
50ms window, two-second fixture wall budget and RSS budget remain unchanged.
All 53 targeted controls passed. The [hosted verification](hosted-once-verification.json)
records 33 passing controls before the dedicated-branch binding, separately
from its earlier 26-test development run. The [branch-binding verification](frozen-branch-verification.json)
records the final 33 passing controls and exact source hashes; its
[scope proof](frozen-branch-scope.json) confirms that driver behavior changed
only in its fixed ref and docstring, and the workflow only in its push branch.

### Requirements that component controls do not establish

Public fixtures remain public and operator-controlled. Caller-supplied scores and
reported token counts do not establish independent task truth or an independently
verified per-step token schedule. A checkpoint kept beside an old local database
still permits the retained old-database-plus-old-checkpoint replay counterexample.

Independent custody and related-identity enrollment, unseen future evaluation,
the actual full release/router/serving composition, complete lifecycle economics,
trained-model behavioral probes and the existing Hepta CURRENT/FinalUse consumer
remain separate requirements. These component changes do not create a selector,
installer, second journal or final-use authority. Adoption, reward and production
qualification remain false.

## Full acceptance gates still requiring their original owners

| Risk | Engineering evidence retained here | Required evidence beyond these component controls |
| --- | --- | --- |
| Repeated-test overfitting | Reserve-before-effect SQLite, immutable historical replay, one published cooperating campaign | Independent monotonic custody across hosts and authorities, related-identity enrollment, genuinely unseen future tasks, whole-family multiplicity and sample-size justification |
| Author/evaluator collusion | Bound inputs/results and explicit false independence flags | Actual independent administration/data custody, provenance, blind/cross evaluation and dispute handling; another key, host or agent does not establish this |
| Cell improves while release regresses | Five separate model controls with artifact/contract/cost bindings | The same complete base/Cell/router/runtime/serving release, routing, old/rare cohorts, request latency/memory and registered cold/warm measurements |
| Many uneconomic versions | Six cost-containment refusals; training steps/reported-token-count validation; incomplete decisions stay incomplete | Original selection owner consuming all lifecycle costs, prices/horizon, net-benefit floor, rate/storage budgets and valid no-update followed by continued use of original CURRENT |
| Malicious model behavior | Snapshot/identity/tensor/finite-value checks, real tiny Torch counterexamples | Frozen true-model trigger/poison/forgetting probes, isolation, real canary observations and revocation/rollback recovery exercises |
| Weight update executes code | Fixed classes and immutable safetensor/config/tokenizer inputs; source closure controls | Current selected generation and revocation head, original resource owner, real FinalUse, installation/CURRENT and next-task/restart boundary exercised together |

The available native/formal router-composition runner uses a 257-feature,
three-class integer family, distinct from this SmolLM2 Torch family. Its results
cannot be assigned to this release. The formal acceptance probe verifier checks
supplied records and hashes rather than executing target-model behavioral probes.
The runtime-release helper establishes material/static ELF closure only. Existing
Cell/Hepta handoff paths require the original external host/daemon configuration,
installed executable and FinalUse issuer; missing inputs return NOT_CONFIGURED.
The frozen pilot contains exactly two loader, five train and five evaluate phases
and has none of those external deployment-owner inputs. Extra probe tasks or
deployment effects cannot be silently added to this one attempt.
