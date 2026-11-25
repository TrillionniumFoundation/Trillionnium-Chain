# Offline Circuit evaluation with a native development service fee

A fresh authenticated development Node reserved 2,000 units for one paired
Circuit evaluation. The M12 journal recorded Begin before the evaluator started.
The candidate was `32ee053d020918d0a694c8b9a3a3bcaec3dfd93eed5bb7f98e0b33e46352dac4`.
The task was `019c7ce8f962e9c33ffdeb6105de3f603a9c93b696fc49604512113b7211de0a`.

The two new offline inference processes loaded the frozen parent and candidate.
The candidate alone passed the synthetic future task. Both passed the old task.
Each arm made four model calls. The local supervisor measured 21.212086 CPU
seconds and 19.229477623 elapsed seconds for the evaluator subprocess and its
waited children. The runner used a new Linux user and network namespace and
offline model loading. The payment was for evaluation, with zero training units,
zero model improvement bonus and zero consensus credit. The two tasks and local
development keys were controlled fixtures. Independent customers and external
payments remain unobserved.

| Retained record | What it binds |
| --- | --- |
| [ADMISSION.json](ADMISSION.json) | Unique request, freeze, paired input, parent, candidate, source listing, interpreter versions and budget |
| [RESERVATION.json](RESERVATION.json) | Signed reservation transaction, funded terms, active block and M12 checkpoint after Begin |
| [RESULT.json](evaluation/RESULT.json) | Newly executed paired evaluation, cold worker identities and Circuit work |
| [COST.json](COST.json) | Measured caller-side CPU, elapsed time and model calls |
| [DELIVERY.json](DELIVERY.json) | Task, candidate, result, measured cost and SHA-256 of all 12 raw evaluation files |
| [SIGNED_EFFECTS.json](SIGNED_EFFECTS.json) | Signed development delivery and arbitration transaction bytes |
| [CURRENT.json](CURRENT.json) | Reopened native owner’s paid-v3 statement, 2,000 units debited and credited, zero remaining escrow |
| [FROZEN.json](FROZEN.json) and [SOURCE.json](SOURCE.json) | Exact freeze bytes and Python source file hashes committed by admission |

All 124 captured Python files match the published Hepta [evaluation tree](https://github.com/TrillionniumFoundation/hepta-private-ci/tree/e088eb8cded407557b7b22abbe4f7fabe72ef4a4/scripts/cell_experiments).
The [source comparison](PUBLISHED_SOURCE.json) records the commit, tree, covered paths and number of mismatches.
The retained FROZEN.json was copied from the materials after the observed run and matches the file digest committed before reserve. The current driver saves that copy during admission.
The source check and hashes cover the evaluator code and retained inputs. The
runtime package versions are recorded in ADMISSION.json. The service result
does not certify independent CPU metering or the patch's training history.

Run the following from the Chain repository root. The Python readback checks the
retained byte commitments, transaction IDs, resource declaration and fee. The
Rust test copies both closed databases to a new temporary directory, opens a
fresh authenticated Node and M12 journal, and recomputes the paid-v3 export
from those owners.

```sh
python3 scripts/dev_circuit_evaluation.py verify evidence/cell-circuit-funded-evaluation-20261123
cargo test --locked --manifest-path trillionnium/Cargo.toml -p trnm-pon-node \
  --test native_task_operation_v2 circuit_evaluation::retained_evaluation_reopens_the_same_native_payment_from_copied_stores -- --exact
```

To commission a separate isolated local evaluation, point the environment at a
Hepta checkout, the prepared materials directory, and a Python environment with
its CPU model dependencies installed. Set independently retained freeze, request
and Circuit digests, and choose a fresh absolute output directory. The original
materials directory must contain `FROZEN.json`, `paired.json` and all referenced
model files. The driver requires Linux `unshare -Urn`. It stops on a failed
evaluation before signing delivery or arbitration.

```sh
export TRNM_DEV_HEPTA_SOURCE=/absolute/path/to/hepta
export TRNM_DEV_HEPTA_PYTHON=/absolute/path/to/environment/bin/python
export TRNM_DEV_HEPTA_MATERIALS=/absolute/path/to/frozen-materials
export TRNM_DEV_EVAL_JOB=/absolute/path/to/new-job
export TRNM_DEV_FREEZE_SHA256=269d9ef760fec2feb1c75cd0b08ebfd3dc77e302a148929568c500861de0cdad
export TRNM_DEV_PAIRED_REQUEST_SHA256=7d60577d12d49a10a6896cdef6c9762f7dd40e8d831cdeaf0597c3d626d50276
export TRNM_DEV_CIRCUIT_SHA256=32ee053d020918d0a694c8b9a3a3bcaec3dfd93eed5bb7f98e0b33e46352dac4
cargo test --locked --manifest-path trillionnium/Cargo.toml -p trnm-pon-node \
  --test native_task_operation_v2 circuit_evaluation::funded_offline_circuit_evaluation_reopens_paid_native_operation -- --exact --ignored --nocapture
```
