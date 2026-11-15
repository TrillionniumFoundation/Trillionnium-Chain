# Actual SmolLM Cell replica and next-task research

Status: **research completed, no-update; original Hepta installation remains
unqualified**. The native optimized transport has a retained failed run described
below. No source pins, observations or model scores grant chainwork, selection,
installation, payment, account migration or FinalUse authority.

## What actually executed

The original `llm_inherited_runtime.py` trained three consecutive CPU LoRA
artifacts against the repository-pinned **SmolLM2-135M-Instruct** revision
`12fd25f77366fa6b3b4b768ec3050bf629380bac`. All seven public upstream files matched
their original byte lengths and SHA-256 pins, including the 269,060,552-byte
`model.safetensors`. The runtime loaded the real 134,515,008-parameter backbone,
verified its complete FP32 index and tokenizer contract, and preserved that
backbone while updating the original rank-4 query/value adapters.

Each generation used the original 10-step AdamW recipe, two CPU threads, the
same explicitly labelled public smoke input and the previous generation's
actual adapter. These are 40 supervised tokens per generation, not a real user
cohort or evidence of useful general learning. All three actual receipts report
parameter changes; generation 2 reloaded generation 1, and generation 3 reloaded
generation 2. The original process supervisor accepted each execution. Training
process peak RSS was about 3.07 GB; the operation wall times were roughly 43–46
seconds on this shared host.

The new [research runner](../../scripts/run_smollm_cell_replica_research.py)
uses the original native TCL4 cache and TCR1 release CLI. It packs eleven exact
dependencies: seven base files, their retained manifest, and the three original
adapter/target-contract files. That complete release is **272,190,131 payload
bytes in 269 chunks**.

1. An actual publisher process serves a fresh replica cache over TCP.
2. The publisher is terminated and reaped. A new acquisition against its old
   endpoint fails with `ECONNREFUSED` and produces no release completion file.
3. Another fresh consumer cache receives all 269 chunks from the replica alone:
   zero initial cache hits, 280 connections and 272,204,931 response bytes.
4. The replica also stops. The consumer materializes all eleven files without
   another network connection and rechecks the original model and adapter pins.
5. The original `llm_neural_read_worker.py` loads the actual transferred candidate
   and performs the subsequent comparison. Both original model workers terminate
   successfully and remove their sockets.

This is one machine and one administrator. The native configured-peer transfer
is not the PQ PCS1 transport, a WAN swarm, independent custody, a DHT, a storage
proof, a retention promise or a proof of operator diversity. The full model was
not replaced by a small signature fixture. The source and destination stores
were distinct and the fresh consumer used the original TCP client.

## The model result is no-update

A single seed and 32 balanced public integer-comparison prompts were frozen
after both adapters existed and before any comparison forward. Expected answers
were retained by the evaluator and were not passed to the inference worker.
Both models used the existing `hepta-smollm-single-token-action-score-v1`
profile: real first-token logits over frozen `no`/`yes` actions. These observations
are not relabelled as fixed-token decoder receipts.

| Observation | Generation 2 | Generation 3, loaded from replica bytes |
| --- | ---: | ---: |
| Actual forward passes | 32 | 32 |
| Correct public comparisons | 16 / 32 | 16 / 32 |
| Accuracy | 50% | 50% |

The measured accuracy difference is **zero**. Full logit digests differ for all
32 paired inputs, while the selected action changes on none of them. Thus the
candidate's weights participated in actual inference, but this run found no
improvement on its bounded fixture. Training loss and changed parameters are
not an adoption criterion. The recorded decision is `no-update`.

No independent, authorized user cohort was supplied. The complete model-family
set of required quality controls was not executed. Even a positive difference
on this public fixture would not qualify a release. No existing Hepta selector,
installation store, inference-control owner or independent Unix FinalUse issuer
was exercised by this Chain-only experiment; the runner does not manufacture a
replacement receipt or authority service.

## Performance observation and the retained optimized failure

The completed end-to-end run used the **debug** native binary at source
`4b6b8a91b6dfe41fbd7f40f40b359d535c2c4251`. Full-model packing took 29.82 seconds;
release preparation 77.36 seconds; publisher-to-replica acquisition 86.97 seconds;
and the fresh consumer's replica acquisition 64.30 seconds. These include local
verification and persistence. They are not release throughput, disk isolation
or chain TPS measurements. Per-transfer budgets were explicitly 180 seconds;
the old handoff command's 35-second contract was not changed.

A separate optimized native build packed the same model in 4.32 seconds and
prepared the same release in 2.14 seconds. Its first acquisition **failed after
2.05 seconds with a response-header connection reset**. That failure is retained
under `failures/optimized-original`, including both process and command records.
It does not count as a completed transfer. The bounded server's worker cleanup
and the client's single-attempt behavior need a focused admission/backpressure
repair before this optimized path can be called reliable. No worker, connection,
byte or time limit was raised to hide the failure.

The subsequent [bounded transport retry refinement](CELL_TRANSIENT_CAPACITY_RETRY_V1.md)
retains this original failure and records a focused repair, its negative controls
and a successful native optimized replay. The no-update model result and all
original Hepta authority boundaries remain unchanged.

## Reproduction and source boundaries

The [evidence directory](../../evidence/smollm-cell-replica-research-v1/README.md)
contains original training plans/receipts, exact command arguments, frozen
comparison inputs, all 64 forward observations, listener/process exit records,
native transfer logs, source hashes and the measured failure. Model weights and
SQLite caches are deliberately not committed as source code.

Use Python 3.12 with the retained package versions. Install the CPU wheel from
the official PyTorch CPU index, then the pinned remaining packages. Obtain the
seven files at the model family's immutable revision and create the retained
`material-manifest.json` with that exact model, revision and `files` map. The
original runtime rechecks every pin before use. Reproduce the three training
commands from the retained command records with fresh absolute output paths;
then run:

```sh
python scripts/run_smollm_cell_replica_research.py \
  --materials /absolute/pinned-model-materials \
  --baseline-parent /absolute/gen2/worker/parent-material.json \
  --candidate-parent /absolute/gen3/worker/parent-material.json \
  --python /absolute/cpu-venv/bin/python \
  --cell-bin /absolute/native-build/trnm-cell \
  --output /absolute/fresh-research-output --threads 2
```

No script in this change changes the sole development plan or installed
consensus. Production installation still requires the original Hepta product
bootstrap/current-selector and FinalUse owners; those remain blocked until
their real qualification prerequisites are supplied and exercised.
