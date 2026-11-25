# Paid cold evaluation of one released plain-model request

A private SQLite intake released one **researcher-authored arithmetic exercise** for the Hepta model frozen in [#7022](https://github.com/TrillionniumFoundation/hepta-private-ci/pull/7022). Its paired request used the registered admission checks in [#7025](https://github.com/TrillionniumFoundation/hepta-private-ci/pull/7025). The release carries `scope=engineering_fixture`. Observed real participants, commercial purchases, certified prospective arrivals and learning bonuses are all zero.

A new isolated native Node reserved 2,000 development units before the evaluator started. Each fresh arm loaded its own ordinary model and evaluated the artificial incoming question followed by the original frozen retention item. The evaluation consumed 11.318814 CPU seconds and 9.571286355 wall seconds across the isolated supervisor and its children. Each arm took 120 input tokens, generated 4 output tokens including EOS and made two calls.

| Task | Expected | Frozen parent | Frozen candidate |
| --- | --- | --- | --- |
| Artificial incoming task, thirteen minus twelve | 1 | 0, failed | 0, failed |
| Original retention item | 0 | 0, passed | 0, passed |

The native payment bought the evaluation. The reopened Node/M12 stores reproduced a 2,000-unit escrow debit, a 2,000-unit beneficiary credit and zero remaining escrow. The measured gain on the exercise was zero. The signed transaction carries commitments. The evaluator's private directory holds the records; the public evidence here contains only the deliberately authored exercise and previously published materials.

| Original | SHA-256 or native ID |
| --- | --- |
| SQLite admission | `510ab2c3fd431548104f3e668fa9cb31a44196a9aa3dd9cb6dbda7e16cfe5f03` |
| Independently retained release | `ffafe1803eae4de802b46ca3e97e424ab4478228b789bb837b18c87046301b19` |
| Ordinary paired request | `f06b71caec78ab5d1e1c247b183a83f9086d75ebb489fdc72084de1ec9f2b039` |
| Canonical freeze | `447ace5cc8bc031cc772e63ccb90380f16fc81404003bc04057ec4f8b7470ef6` |
| Candidate | `6a094252772cd5bf440ecf9b8ef0009adf6b17ec8b3f7ac44fed11d3c67ab7ba` |
| Funded native task | `abf694c4cd0d799cd0ee3b13414e23d8f51954c2ee487285ebb8a6c0f2ec78a6` |
| Result file | `05d1e985352cfc863381fd3e12fddfd9ece7358d9f63f5c48ad9af11144d0840` |
| Delivered output | `bdda1991528b32cc4c3c426f739901cd9adc040c6dd60df7e8477aaf3ad854f7` |
| Payment operation | `26ecbc8936fafdc44ea65e33bf573c348b339c514c165b4b302ae4712397d028` |

[Admission](ADMISSION.json) binds the release, freeze, model, study, request, source and catalog before reservation. [Source comparison](PUBLISHED_SOURCE.json) matches all 126 Python files and the catalog against the Hepta commit. [Signed reservation](RESERVATION.json), [raw predictions](evaluation), [delivery](DELIVERY.json), [metering](COST.json), [signed effects](SIGNED_EFFECTS.json) and [current payment](CURRENT.json) bind the same work. With only the independently supplied release digest changed, admission exited before creating any job file, reservation or prediction. [Refusal](REFUSED.json)

## Reproduce the evidence

From the Chain repository root, pass the independently retained release digest to the ledger reader. The Rust test copies both closed SQLite stores into a clean directory, reopens them and compares the entire paid-v3 result. A mismatched model commitment is also exercised.

```sh
evidence=evidence/cell-released-pair-funded-evaluation-20261123
python3 scripts/dev_circuit_evaluation.py verify "$evidence" ffafe1803eae4de802b46ca3e97e424ab4478228b789bb837b18c87046301b19
cargo test --locked --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --test native_task_operation_v2 \
  circuit_evaluation::retained_plain_paired_intake_reopens_the_same_payment_from_copied_stores -- --exact
```

## Commission an isolated evaluation

Use the two files and canonical release commitment delivered through the private intake. Supply the original frozen model directories, the pinned Hepta source with its qualification catalog, a CPU Python environment with the Hepta inference dependencies, Linux user/network namespaces and a new private job path. The dispatcher checks the release's exact scope and digest, the join to the ordinary request, actual model files, frozen tokenizer input checks and the exposure catalog before creating a funded reservation. It repeats the checks for each arm at execution. The documented study digest is bound to the protocol used by this experiment. The retained source listing identifies the program actually executed.

```sh
export TRNM_DEV_HEPTA_SOURCE=/private/hepta-checkout
export TRNM_DEV_HEPTA_MATERIALS=/private/frozen-run
export TRNM_DEV_HEPTA_PYTHON=/private/cpu-environment/bin/python
export TRNM_DEV_INTAKE_RELEASE=/private/released/release.json
export TRNM_DEV_PAIRED_REQUEST_FILE=/private/released/paired.json
export TRNM_DEV_INTAKE_RELEASE_SHA256="$retained_release_sha256"
export TRNM_DEV_PAIRED_REQUEST_SHA256="$retained_request_sha256"
export TRNM_DEV_FREEZE_SHA256="$retained_freeze_sha256"
export TRNM_DEV_PAIRED_MODEL_SHA256="$retained_candidate_sha256"
export TRNM_DEV_EVAL_JOB=/private/new-development-job
cargo test --locked --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --test native_task_operation_v2 \
  circuit_evaluation::funded_plain_paired_intake_reopens_paid_native_operation -- --ignored --exact --nocapture
```

The chain-side entry accepts exactly one incoming task and the frozen retention panel. The release contains only digests and the original scope. The authenticated channel for receiving that commitment, participant independence, purpose, timing and an external customer's actual use and payment remain the responsibilities of their respective owners. This development harness creates an isolated ledger for each new directory. Reopening the retained ledger verifies the original purchase. Separately created development ledgers do not provide a shared spending history.
