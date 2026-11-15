# Persistent pilot admission, local costs and retained closure validation

This increment continues PR #688 from `d0737cf5434894ce47fad8082376fc417313c2cb`,
preserving concurrent commits through `c156c2310346d1367b8f9b1111171f412b5ffce2`.
It adds executable controls and component observations. It does not establish
independent evaluation, full model efficacy, complete economic utility or release
qualification. All adoption, reward and production qualification remain false.

The compact [reproduction manifest](reproduction.json) contains exact source and
log hashes, original failures, commands, observed counts and preparation status.
Large logs, model weights, dependency environments and compiler output are not
added to Git. Reproduce from the containing commit with the original limits.

The source and log identities below bind tested model commit
`592969aa0c0e0e3246b1e156f6f0bc5951f9aa01`. A later
[source-preserving merge record](merge-validation.json) keeps concurrent W1
and Cell-storage histories. The model runtime and M06 resolved dependency
closure remain unchanged; the combined plan and corpus source inventory gain
concurrent entries, and M09 keeps its own test/qualification scope.
The original source-hash map is historical and is not silently rebound to that
merged plan. Whole-tree merge readback is reported separately in PR #688.

## Changes and deliberate boundaries

The [trial ledger](../../scripts/llm_runtime_trial_ledger.py) explicitly bootstraps
one cooperative local public-pilot authority. `run` must open an existing database
with pinned policy/checkpoint, commit a family allowance before output or child
execution, retain returned observations and validated child receipts in order,
freeze the trained five-artifact roster before evaluation, and recompute its
terminal local-cost assessment. SQLite uses `BEGIN IMMEDIATE`, DELETE journaling
and verified `synchronous=EXTRA` on every connection. Exact schema checks reject
additional executable objects, including names that would exploit SQL LIKE's
underscore wildcard. Storage and event counts are bounded before replay.

Failed execution, missing required RSS/CPU, uncertain COMMIT acknowledgement and
process death do not refund a reservation. A crash inside supervision can leave
no row for the in-flight phase. An unresolved attempt stays pending and spent;
neither inspect nor a new trial ID authorizes replaying its effects. Terminal
append failure requires reconciliation and does not become successful no-update.
These are process/acknowledgement controls, not a physical power-cut experiment.

The retained counterexample matters: an old database against a current external
checkpoint is refused, but restoring both the database and its old local
checkpoint still permits replay. Independent monotonic custody, a real multi-host
service, model-family enrollment and verified related identities are outstanding.
An inspect result must not automatically replace the owner's retained checkpoint.
The fixed family-alpha allocation is not a significance test. Public fixtures,
unregistered lower-level engineering calls and caller-supplied scores do not
establish unseen evaluation or global experiment accounting.

The [assessment verifier](../../scripts/llm_runtime_assessment.py) checks all twelve
supervisor and child returns, exact phase/cost inventories, actual wait4 and child
CPU/RSS observations, material identities, budgets and frozen role artifacts.
Wall/CPU totals retain their different scopes; RSS uses maxima, and absent optional
IO/device observations stay null. The one-thread loader has its own plan-bound
CID, while sharing the frozen source weight SHA, FP32 backbone root and parameter
count with the reference. All remaining phases match the roster CID. The ledger
reruns this verifier with persisted receipts and the submitted score table; it
does not independently derive task truth from prediction bytes. Full lifecycle
costs, tariffs/horizon and complete release metrics are absent, so even positive
reported gain yields `decision=incomplete`, `no_update=false`, `adoption=false`
and `reward=false`.

The [native classic closure owner](../../trillionnium/crates/trnm-mvcc-fee/src/public_evaluation.rs)
rechecks retained schema/context, missing counts, status, minimum score,
qualification flags and recoverable record digest during hydration and adoption.
Legal zero scores, compact digest identifiers, signed late conflicts and appeals
remain supported. An older aborted closure that later gains more conflicts lacks
historical insertion metadata; available invariants are checked without inventing
that missing subset, and it remains adoption-ineligible. This is corrupted
retained-state hardening, not a demonstrated canonical chain-root bypass.

Actual Torch controls use official safetensors and real tiny tensor modules. They
exercise loaded forward behavior, dtype/shape/extra/nonfinite refusal, pickle
refusal, single-snapshot file replacement, late-target mutation and interrupted
copy. A partially copied model must be discarded; these tests do not prove atomic
parameter rollback, malicious-model behavior or deployment authorization.

## Observations

| Executed check | Result | Interpretation |
| --- | --- | --- |
| Local ledger / additional review / assessment | 19 / 9 / 15 passed | Local admission, replay and cost controls |
| Native regressions against old production source | 0 passed, 3 failed | Original assertions exposed accepted retained corruption |
| Final native M06 package, all targets/features | 223 passed, 0 failed, 7 existing ignored | 25 completed binary summaries; ignored timing tests remain unrun |
| Strict M06 Clippy | Passed | `-D warnings` |
| Real CPU Torch artifact loader | 12 passed, 0 skipped | Tiny constructed modules; wait4 peak RSS 171659264 bytes |
| Decoder component controls | 10 passed, 0 skipped | 7 actual-tensor and 3 routing tests; peak RSS 165142528 bytes |
| Final default Python aggregate | **349 run: 224 passed, 2 failed, 123 skipped** | Preserved failed run; not reported green |
| Each failed method re-executed once | 2 passed | Unchanged source and 100 ms deadline; no further repetitions or threshold changes |
| Full pretrained twelve-phase pilot | **NOT_RUN; zero allowances spent** | Materials/dependencies prepared; execution was not started |

The aggregate's redaction test observed `exit-cleanup-deadline` before its injected
recheck exception. Its 100 ms deadline had expired before the intended branch.
The wait4 test recorded only `outcome=failed`, so its original stop reason is not
known. The single targeted passes are consistent with timing sensitivity, but do
not prove shared-resource pressure was the cause or erase either original failure.

The final Torch commands used all 31 locked distributions, including Torch
2.9.1+cpu, safetensors 0.7.0, Transformers 4.57.3 and PEFT 0.18.0. Eleven source
hashes were identical before/after. Both commands exited zero with no cgroup
OOM/OOM-kill increment. The reported RSS is wait4's peak; `/proc` polling was
incomplete and a zero sampled maximum is missing observation, not zero memory.

Seven fixed-revision pretrained material files were downloaded and verified. The
latest read-only refresh had 8589934592 / 8589934592 bytes of shared cgroup memory
in use and 2538500096 bytes of free disk. Even treating all non-shmem file pages
and reclaimable slab as available gave only an optimistic 1272458056-byte shared
ceiling, not a dedicated reservation. Full-tune parameters, gradients and Adam
states alone require 2152240128 bytes before runtime/activations, profiler retention
and temporary copies. The same-source full-pretrained peak remains unmeasured.
The full pilot was not initialized or reserved. CPU, four threads, ten steps,
strict-v1 and the original train/evaluation caps were not weakened. The README's
earlier twelve-phase result predates this increment and does not qualify this
new runner.

## Reproduction

Run the boundary check before builds or edits. The new runner and ledger are
covered without optional model dependencies:

```sh
bash scripts/project-preflight.sh
python3 scripts/test_llm_runtime_trial_ledger.py -v
python3 scripts/test_llm_runtime_trial_review.py -v
python3 scripts/test_llm_runtime_assessment.py -v
python3 -m unittest discover -s scripts -p test_llm_runtime_pilot.py -v
```

Install the exact [CPU dependency lock](../../scripts/ci/model-runtime-cpu-requirements.txt)
in an isolated environment using the pinned CPU Torch wheel. With that environment's
Python selected, run the real component suites offline:

```sh
HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 OMP_NUM_THREADS=1 MKL_NUM_THREADS=1 \
OPENBLAS_NUM_THREADS=1 TRNM_ACTUAL_DECODER_TENSOR_TESTS=1 \
python scripts/test_llm_runtime_artifact_loading_torch.py -v
HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 OMP_NUM_THREADS=1 MKL_NUM_THREADS=1 \
OPENBLAS_NUM_THREADS=1 TRNM_ACTUAL_DECODER_TENSOR_TESTS=1 \
python scripts/test_llm_runtime_decode.py -v
```

Use the repository's pinned Rust 1.95.0 toolchain and OpenSSL 3.5.9 provider, with
`CARGO_BUILD_JOBS=2`, `CARGO_INCREMENTAL=0`, `RUST_TEST_THREADS=1`, and the provider's
actual include/library paths. The manifest retains the original wrapper and
environment. Native commands:

```sh
cargo test --manifest-path trillionnium/Cargo.toml --locked --offline \
  -p trnm-mvcc-fee --all-targets --all-features
cargo clippy --manifest-path trillionnium/Cargo.toml --locked --offline \
  -p trnm-mvcc-fee --all-targets --all-features -- -D warnings
cargo metadata --manifest-path trillionnium/Cargo.toml --all-features \
  --format-version 1 --locked --offline
cargo fmt --manifest-path trillionnium/Cargo.toml --all --check
python3 scripts/ci/check_repository.py
python3 scripts/ci/test_repository.py
python3 scripts/ci/test_ci_source_integrity.py
python3 scripts/ci/check_pq_research_integration.py
python3 scripts/ci/test_pq_research_integration.py
```

The concurrent integration changed Cargo.lock only for the release-bundle owner;
the complete 138-package resolved M06 graph was compared and is identical. The
two M06 files and relevant runtime sources retain the hashes on which their
recorded tests executed. Additional source-gate results and their exact snapshot scope are listed in the
manifest: 50 repository, 34 CI-integrity, 35 PQ-integration and 29 formal-reference
tests passed. The repository mutant snapshot predates later quantum and detached-
admission/reversible research imports; runtime, M06, Cargo.lock and gate scripts
remained identical. Preserve that distinction and the final whole-tree source
check. Do not imply the package suite tested every concurrently changed package.

To reproduce the old-source counterexample, use a separate checkout of this
increment and replace only `public_evaluation.rs` with the bytes from
`d0737cf5434894ce47fad8082376fc417313c2cb`; run `--test evaluation_quorum_v2
classic_retained_closure` with the same toolchain/provider. The original red run
preceded added positive compact-record compatibility cases, but its three failing
assertions remain. Restore the candidate source before the final package checks.

A full pretrained attempt needs adequate dedicated resources and the seven pinned
materials. Use the [runtime instructions](../../scripts/llm_runtime_README.md) to
create the authority once, retain its policy/checkpoint independently, and run a
new attempt with the original caps. A pending attempt must be reconciled, not
silently resumed or replaced by a newly bootstrapped authority.

## Six outstanding real closure obligations

| Risk | Required evidence beyond this increment |
| --- | --- |
| Repeated testing / family overfitting | Externally retained monotonic history, verified family/identity enrollment, multi-host enforcement, unseen future tasks and family-wide multiplicity control |
| Author/evaluator collusion | Actually independent administration and data custody, verifiable provenance, blind/cross evaluation and exercised dispute handling |
| Composition regression | Full base + Cells + router + runtime + serving profile; measured quality, routing, old/rare cohorts, latency, memory and cold/warm loading |
| Tiny-version farming | Complete measured lifecycle costs, tariffs/horizon, minimum net benefit, genuine no-update and enforced release/storage budgets |
| Backdoor / malicious weights | Real trained-model trigger/poison probes, isolation, canary observations and exercised revocation/rollback |
| Weight-to-code execution | Actual full model loading under the complete deployment chain, current generation/CURRENT and held FinalUse checks |
