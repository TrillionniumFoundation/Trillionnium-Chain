# W1 resource-budget cost research

This evidence namespace belongs to PN1 in the sole
[development plan](../../docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md).
It records a supplemental local research campaign. It does not change W1,
production code, difficulty, reward weights or any readiness/acceptance flag.

## Frozen experiment contract

The [security game](../../docs/protocol/pon-nakamoto-v1/details/W1_COST_SECURITY_GAME.md)
defines timing, resource budgets, reuse, adaptive attacks and semantic uniqueness.
The [registered campaign](../../formal/pon-nakamoto-v1/experiments/w1_cost_campaign_v1.json)
is committed before the performance run. Sixteen jobs cover nine input families,
fourteen lawful producer arms, preparation-per-attempt, preparation reuse,
sequential batching, charged algorithm selection, long reuse, rare targets,
zero targets and original Node contexts with three parents. Unsupported arms,
failed attempts, budget overrun and zero winners remain in each denominator.

The separate [task-family selection program](../../formal/pon-nakamoto-v1/experiments/task_family_selection.py)
freezes nine family/algorithm combinations, four training attempts per combination
and 64 held-out attempts. Full-rank uses generic, field-paired and integer-paired;
zero uses generic, its specialized blocked integer-paired algorithm and general
integer-paired; maintenance uses generic, prefix and limb algorithms. These
choices are based on supported input structure before the timed campaign, not
selected from its measured outcomes. Training seed 7001 and
evaluation seed 9001 affect challenge streams, not the fixed public A/B fixture.
It pays for fresh construction in every subprocess. All nine training calls must
complete before selection; target hits cannot influence the decision. Registered
budgets are 100 ms, 1 s and 5 s of calling-process plus waited-child CPU. A child
batch is conservatively credited only on completed validation/retention, and
post-hoc strict readback is separately measured without selection feedback.

The new general arm is documented in the
[independent arithmetic review](../../docs/protocol/pon-nakamoto-v1/details/W1_INTEGER_PAIRED_GENERAL_RESEARCH.md).
The [cross-layer experiment](../../docs/protocol/pon-nakamoto-v1/details/W1_QUALIFICATION_SEPARATION_RESEARCH.md)
separates fulfillment, quality, chainwork and quantization claims.

The implementation/plan freeze is not an experimental result. Subsequent evidence
publication must identify the actual measured commit, tree, plan and executable
SHA-256 separately from the publication commit. The runner retains raw output and
failed observations outside the source checkout. Compact derived results can be
published here without rebranding them as independent hardware attestation.

The first frozen source was `bcbc922b3dbfef403effb9e9224191e2a6736017`.
Its campaign completed the first ten registered jobs, then the long-reuse hot
job reached the 64-MiB stdout collection limit. The collector preserved the
truncated stream, original failure and complete preceding observations and
marked the entire campaign incomplete. The next source revision preregisters a
256-MiB collection limit and reruns every job. Workload, algorithms, CPU budgets,
targets, seeds, sample counts and stopping rules are unchanged. The first run is
not silently combined with the repeat or counted as a complete successful trial.

## Reproduce the native campaign

Use a clean checkout of the **measured source**, direct Rust 1.95.0 binaries,
an offline populated locked Cargo cache, a permitted Linux CPU, and fresh external
output and a nonexistent build target. Existing output must not be overwritten. No implicit compiler flags,
wrappers or Cargo configuration are allowed. Paths below are explicit arguments,
not a claim that this hardware is available on every machine.

```sh
python3 -B scripts/run_w1_cost_research.py \
  --out /absolute/fresh-w1-research \
  --target-dir /absolute/w1-build \
  --cargo /absolute/rust-1.95.0/bin/cargo \
  --cargo-home /absolute/offline-cargo \
  --plan formal/pon-nakamoto-v1/experiments/w1_cost_campaign_v1.json \
  --expected-head FULL_MEASURED_COMMIT --expected-tree FULL_MEASURED_TREE \
  --cpu AVAILABLE_CPU_NUMBER
```

The strict reader also requires external source, plan, binary and manifest pins;
self-consistent hashes inside a replaceable bundle alone are insufficient.
Read the committed reader's `--help` for the exact input contract. A successful
hash/readback check does not prove that the declared hardware actually executed
the binary. Retained proof certificates allow independent Python replay of those
representatives; the remaining native verification observations are explicitly
distinguished from independent full replay.

## Cost interpretation and completion boundaries

- `cold` means actual producer reconstruction, without CPU/OS cache flushing.
- `batch` is a preallocated sequential proof queue; there is no SIMD/GPU claim.
- Adaptive selection trains algorithms on a fixed task, pays for every training
  attempt and selects before a separately domained evaluation stream. It does
  not implement arbitrary cross-task or seed-selection attacks.
- The stage ledger and inclusive production-completion clock are separate.
  Inclusive producer time subtracts original verifier/admission observers and
  includes preceding logs/dispatch. Public input generation and final context
  destruction are outside that span. Serialized bytes are reported; real network
  transfer, energy and memory bandwidth require additional instruments.
  Whole waited-child CPU includes observers, output and final teardown; Linux
  cumulative maximum child RSS includes build/setup children and cannot be
  presented as a per-producer memory peak.
- Original Node context construction produces five real auxiliary winning
  proofs. The all-work union includes those tickets and deduplicates research
  tickets against them. Production before a budget boundary is distinct from
  admission completed before that boundary. Siblings do not add serial chainwork.
- Timing ratios compare complete matching cohorts, never a different minimum
  from each sample. Repeated challenges across arms are counterfactual comparisons,
  not extra independent mining trials. A finite sample cannot prove global kappa.
- The original 400%-CPU / 16-GiB service campaign is unchanged. A separately
  measured local 8-GiB envelope cannot qualify it by changing its limits.

The four research deliverables are an exact cost game, executable attack/cost
observations, consistent multi-resource accounting and explicit protocol tradeoffs.
Completion of those local deliverables leaves global hardness, GPU/ASIC/ARM
comparisons, independent operators, real transfer/energy measurements, arbitrary
task selection and new model-training convergence visibly open where unmeasured.
