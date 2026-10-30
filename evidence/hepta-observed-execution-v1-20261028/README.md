# Explicit original-model observation execution V1

This successor activates an existing observer through a separately frozen
execution plan. It does not change the registered model plan, target contract,
training objective, 10-step schedule, four CPU threads, original budgets, or the
actual child and completion owners. It grants no qualification or installation.

## Compatibility result

`actual-parent-preflight.json` records complete preflight on historical public V2
metadata from the locally retained original ZIP. The actual parent parameter
file was read from the retained real-model run, verified at SHA-256
`1c5af7b5a7144a619dfac83b14bd83ae77f1e2227b18a6a9c5dcb214889a0cba`, and
relocated locally solely to reconstruct the original role paths. No parameter
bytes are part of this source package. The historical target and adapter JSON
were exact original bytes, and the relocated descriptor is not a new admission.

The observed request and original V2 validation projection returned equal full
preflight tuples, including all 120 factor tensors. The target contract remained
`c9b06f9a029a3257801844f89acb59b5f59f6a39087335af323f274e9152992f`; the model
plan remained `4eb748aee63bb946b93c5df6780833691dc3a90e91dd1d8e6d29d1c93b9c7420`.
Runtime source remained `65ccc6454befd96fa5ce1f5bdde2c56cb6cbb741cf495b8d24a758039f99f755`.
Torch/model execution was not invoked by this compatibility check. The real
loaded-model contract check remains in the original child and was not newly run.

## Reproduce source controls

Run `bash scripts/project-preflight.sh`, then from `scripts/`:

```sh
PYTHONDONTWRITEBYTECODE=1 python -m unittest \
  test_llm_runtime_observed_execution_v1 \
  test_llm_runtime_parent_step_v2 \
  test_llm_runtime_parent_step \
  test_llm_runtime_exit_worker_observation
```

`controls.log` is the retained 54-test result. Tests include an actual small
Python child under the original supervisor and existing observer. That probe
does not establish that a pretrained-model shutdown gap was reproduced.

For a real original public parent, construct the ordinary V2 input using its
exact model plan, materials, contract, adapter and parameter-file pins. Change
only the new request schema and initial-setup profile to the constants in
`llm_runtime_observed_execution_v1`; compute `v2.sources(observed.PROFILE)`.
Freeze `observed.plan_record(value)` as an observation plan, then bind its exact
path and file SHA-256 in `initial_setup.observation_plan`. `step.preflight(value)`
must pass before the original `parent-step` command may create child output.
The new CLI uses `--initial-setup-profile
canonical-parent-original-task-observed-execution-v1`, `--observation-plan` and
`--observation-plan-sha256` alongside all original exact parent arguments.

## Preserved boundaries

The previous strict-v1 third-round `rss-observation-unavailable` remains failed.
Earlier 1840-pass/35-fail Rust evidence, the real 12 GiB host refusal, public
candidate/control scores of 0.5/0.5, gain 0 and zero installed children remain
unchanged. This source freeze does not claim a new model run or a complete loop.
Independent SystemLongitudinal evidence and ordinary installed-child consumption
remain open. Model weights, tensors and archives containing them are excluded
from this source package and may not be exported by CI.
