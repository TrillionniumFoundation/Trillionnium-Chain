# Funded replay of public historical task A

A fresh authenticated native development Node reserved 2,000 units for an offline
evaluation of the previously frozen Hepta candidate
`6a094252772cd5bf440ecf9b8ef0009adf6b17ec8b3f7ac44fed11d3c67ab7ba`.
The historical task came from public record 52. The same task had supplied
training supervision. The second task was an authored retention item committed
by the freeze. The observed number of future tasks, prospective arrivals and
independently certified Hepta users was zero.

| Evaluated row | Frozen parent | Candidate |
| --- | --- | --- |
| Seen historical task A | Failed | Passed |
| Authored retention item | Passed | Passed |

The signed reservation and M12 Begin preceded the dedicated evaluator. Two new
offline processes loaded the parent and candidate and each made two model
calls. They consumed 145 input tokens per arm and generated 4 and 62 output
tokens respectively. The local supervisor observed 16.205516 CPU seconds and
14.655941764 elapsed seconds. No additional training steps or teacher calls
occurred during this service. The arbitration payment purchased the evaluation
and awarded zero improvement bonus or consensus credit.

The job was `e26c577d65b3bc08f3507e5ae9262baacd8026bdc40728fd2ffdbea5a62b9e11`.
The new delivery was `c726515a23d9340176d7f94a0f035f94e98470fd2a60c21615a674901a66d67a`.
The reopened native payment operation was
`a4b3af6ad86a510207b38067dd1846c7c92097adb1d9c0f0d478a27b1fd0c18d`.
Both the escrow debit and beneficiary credit were 2,000 development units.
The remaining escrow was zero.

- [Admission](ADMISSION.json) binds the freeze, model, historical request, public dataset digest and evaluated code before the contract.
- [Reservation](RESERVATION.json) retains the signed transaction, active native block, terms and M12 checkpoint after Begin.
- [Cold result](evaluation/RESULT.json) retains the two process identities, model digests and per-task outcomes. The delivery binds both original arm files, the retrospective request and this result.
- [Cost](COST.json), [delivery](DELIVERY.json) and [signed effects](SIGNED_EFFECTS.json) join the measured CPU and evaluator outputs to the signed native transactions.
- [Current payment](CURRENT.json) is the paid-v3 observation from reopened stores. It can be reproduced from the two retained SQLite files using the test below.
- [Source comparison](PUBLISHED_SOURCE.json) matches all 126 captured Python files, including the two historical drivers, to the [published Hepta source](https://github.com/TrillionniumFoundation/hepta-private-ci/tree/d0eac152e8d2e678ac412dcebdc5667904e2452c/qualification/public-historical-a-qwen2-052-20261123). The [earlier freeze](https://github.com/TrillionniumFoundation/hepta-private-ci/commit/8a7ac02e2d1bda7ebd295e8771cc137ad3e8314c) fixes the candidate and original retention item.

From the Chain repository root, verify the four raw evaluation files and their
signed payment, then reobserve the payment in fresh private copies of the Node
and M12 stores.

```sh
python3 scripts/dev_circuit_evaluation.py verify evidence/cell-historical-funded-evaluation-20261123
cargo test --locked --manifest-path trillionnium/Cargo.toml -p trnm-pon-node \
  --test native_task_operation_v2 circuit_evaluation::retained_historical_a_reopens_the_same_native_payment_from_copied_stores -- --exact
```

To commission a separate development replay, supply the historical materials
from Hepta, its publicly released parquet file and the corresponding CPU Python
and pyarrow environments. A new output directory and random job ID identify
each commission. The driver verifies the source and model pins at admission,
then starts its isolated evaluation after the native reservation.

```sh
export TRNM_DEV_HEPTA_SOURCE=/absolute/path/to/hepta
export TRNM_DEV_HEPTA_MATERIALS=/absolute/path/to/historical-a/run
export TRNM_DEV_HEPTA_PYTHON=/absolute/path/to/cpu-environment/bin/python
export TRNM_DEV_PYARROW_SITE=/absolute/path/to/pyarrow/site-packages
export PYTHONPATH="$TRNM_DEV_PYARROW_SITE"
export TRNM_DEV_PUBLIC_PARQUET=/absolute/path/to/public-feedback.parquet
export TRNM_DEV_PUBLIC_PARQUET_SHA256=f8176795f554d2e40296ad17154f1539a4eb20474dee71de3bb1b3f36d41a9a0
export TRNM_DEV_FREEZE_SHA256=447ace5cc8bc031cc772e63ccb90380f16fc81404003bc04057ec4f8b7470ef6
export TRNM_DEV_HISTORICAL_MODEL_SHA256=6a094252772cd5bf440ecf9b8ef0009adf6b17ec8b3f7ac44fed11d3c67ab7ba
export TRNM_DEV_EVAL_JOB=/absolute/path/to/new-job
cargo test --locked --manifest-path trillionnium/Cargo.toml -p trnm-pon-node \
  --test native_task_operation_v2 circuit_evaluation::funded_historical_a_replay_reopens_paid_native_operation -- --ignored --exact --nocapture
```
