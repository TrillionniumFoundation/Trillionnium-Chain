# Shared real materials: complete operator and hostile verification observation

This record belongs to the sole Chain work plan and existing PR #688. It records a finite offline experiment, including its negative results. It grants no work, public-service, model, release or payment qualification.

## Frozen identity

- Executed source: `59321c326313b78640b2df11122e00b3c7cfd71f`, tree `8164d7eda29de5ca93a08b1fb6a8691a7f9c242c`; all six primary runs observed a clean checkout.
- Input-corpus source: `ef1fa4d48ab9894f3d7a4b1c797ca9e7e490b155`.
- Native binary SHA256: `ad4ddcb32a0128ce5b26b5c66628d851c593e916d88bfab3163a8169f7059ee1` (817,128 bytes).
- Model domain hash: `16443887511f5ffbcdf611ce3ca6b6811bc699aad649961fce5a83c168534671`.
- Evaluation-bundle domain hash: `0308341b06b152167da48dc706ee82b7e691aa9ebb2c4d2d7d5cd6a55d12acd5`.
- Shared host: AMD EPYC 9V74, 8 CPU cgroup quota, 8 GiB memory limit; concurrent workloads and near-limit memory are recorded. These are not isolated-hardware qualification samples.

The [contract and reproduction commands](../../docs/development/specs/pon/SHARED_CELL_WORK_V1.md) describe unchanged W1 and its separately versioned grouped research design. [summary.json](summary.json) retains exact nanosecond values, phase definitions, source/file hashes, task identities, original pass/fail boundaries and checks. Full raw inputs, attempts, outputs and development failure records are retained in the separately delivered reproducibility archive; this directory contains a small index, not duplicated large logs.

## Complete operator: correct arithmetic, negative cost result

The existing trained integer model has base, router and three expert-delta matrices, each 3 by 257. Five 64 by 64 W1 tasks cover all 257 coordinates, including the bias, for the same 64 frozen corpus examples. Only fully verified `VerifiedWork.product()` bytes are consumed. All 960 linear outputs, 64 routes, 192 logits and 64 predictions match ordinary integer inference.

Both arithmetic arms use identical nonce/challenge/trace/ticket streams and produce byte-identical proofs/products at the same target. Total attempts are 14 for target 0 and 58 for target 1. All four final output hashes equal `f7f2ef71c1505eb9b75a6f7d370a8f3b146448a4c3807d8f44ca3c05cdf80234`.

| Case | Producer CPU ms | Native child CPU ms | Native child wall ms | Ordinary cold ms | Ordinary warm median ms | Child/warm ratio |
|---|---:|---:|---:|---:|---:|---:|
| target 0, full-limb | 8.564 | 38.766 | 64.900 | 1.273 | 0.1162 | 558.4x |
| target 0, transposed | 8.101 | 37.936 | 46.147 | 1.336 | 0.0829 | 557.0x |
| target 1, full-limb | 20.139 | 41.915 | 46.170 | 0.971 | 0.1237 | 373.2x |
| target 1, transposed | 34.050 | 60.270 | 66.316 | 1.330 | 0.1085 | 611.1x |

The ordinary control caches base-plus-delta and evaluates only the router and selected expert. Its 98,688 multiply-adds occupy 7.5293% of the 1,310,720 padded W1 positions. All five unconditionally computed matrices use 246,720 positions (18.8232%); unselected experts and padding receive no useful-work credit. Repeated challenge cycles also receive no extra application credit.

Each run transmits 163,840 canonical input bytes, produces 245,940 proof bytes and copies 81,920 product bytes. Actual local pipe traffic is 1,667,784--1,683,001 bytes, including diagnostic hex and repeated records. These counts overlap and must not be summed again. WAN and energy are unmeasured.

The full experiment takes 1.617--1.909 seconds including source replay, 100 baseline samples and independent output checks. That total is not a production single-inference latency. The child timing contains process startup, diagnostic serialization and a second reference verifier; it is the measured implementation cost, not an irreducible relation lower bound. Even the native full-verifier phase alone used 2.425--3.020 ms per batch. There is no observed net work-saving result here.

Numerical agreement is not model usefulness: predictions match only 25 of the 64 known labels. This batch is retrospective and is not a new independent evaluation window or an LLM forward pass.

## Same-material hostile verification

Each target uses the same five A/B pairs, four cycles per tile, one actual legal preparation per tile, 20 attack prefix preparations and 40 full false-transcript searches. Every completed search retains all misses and its hit. Each false transcript uses public inputs without first obtaining a valid proof.

| Target | False-trace attempts | Attack candidates | Attack setup + search CPU ms | Raw native refusal CPU ms | Raw refusal / attacker CPU |
|---|---:|---:|---:|---:|---:|
| 0, `7f...ff` | 78 | 40 | 1.160063 | 17.574517 | 15.1496x |
| 1, `07...ff` | 1,192 | 40 | 2.139263 | 19.403591 | 9.0702x |

All 80 candidates are rejected in all 360 verification calls (80 native, 80 scalar-reference and 200 cache calls). Repeated verification is not 360 independent attack samples. All ten processes completed; no exhausted search, missing clock or control failure was reported. The semantic refusal observation coexists with an adverse CPU cost ratio; no absolute public-service budget is certified by either result.

For each target, the five cache paths are observed 20 times each. Warm calls reuse the exact trace and cost about 30--31 microseconds each. A different challenge, eviction and owner recreation cause full replay again, about 485--553 microseconds per after-churn/recreation call. Cache setup and reset are separately charged. Owner recreation is volatile in-process state loss, not durable restart or service recovery.

The ratio includes attack prefix construction and both complete searches, but excludes serialization, the scalar verifier, cache probes, supervisor and network costs. It describes this instrumented attack, not a minimum-cost attacker. Only two legal arithmetic implementations were compared; global cheapest legal work remains unresolved.

## Model evaluation and correct refusal

The original trainer performs real parameter optimization. The frozen strong control is `best_single`, selected by the existing calibration path.

| Partition | Candidate correct | Strong control correct | Statistical adoption gate |
|---|---:|---:|---|
| evaluation A | 165/347 | 164/347 | false |
| evaluation B | 147/281 | 151/281 | false |
| consumer | 155/251 | 154/251 | false |

A separate local `settle_model.py` run recomputes the evaluations and returns `not_adopted`, `model_reward=0`. There is no funded ledger transition on this refusal path. Independent evaluators, a future window, ordinary Hepta adoption and production payment are all false.

## v2 proof: narrower repair, explicit remaining block

The receipt-report parser previously accepted missing, zero or boolean image identifiers. It now requires all eight exact u32 image words. The independent Rust verifier already fixed that image: this is observation-binding hardening, not a demonstrated cryptographic forgery fix or a new proof.

The frozen-source observer suite passes 26 tests, including the new image cases. Normal locked Cargo metadata subsequently succeeds; earlier offline dependency failures are retained and are not the current blocker. [v2-preflight.json](v2-preflight.json) retains the earlier setup snapshot: required guest/tool binaries absent, a free-disk sample below the unchanged 1 GiB floor, and `proof_started=false`.

A later free-space window allowed the exact official archives to be downloaded, SHA256 checked and installed. Actual guest Rust 1.88.0-dev and pinned `r0vm` 3.0.3 version checks succeeded. The [setup follow-up](v2-setup-followup.json) then records a build admission refusal: 773,115,904 bytes free, below the unchanged 1,073,741,824-byte floor. The runner/fresh-verifier build and prover did not start. Successfully verified recoverable download archives were removed after installation; the installed tools and all observation records remain. No new full v2 receipt, 58 saved-receipt controls, or proof-cost benefit was obtained. The original 7,200-second proof total, 300-second segment bound and 256 MiB checkpoint cap remain unchanged.

## Validation and acceptance boundaries

On frozen source 59321c3: 135 retained crypto tests, six native example tests, nine complete-operator tests, 26 receipt-observer tests and 35 source-integrity negative tests pass. The attack parser additionally passes 12 directed negative controls. Locked dependency metadata, strict example Clippy, workspace rustfmt, generated source inventory, full repository/Markdown links and whitespace checks pass. This is not a claim that every workspace package or independent runtime suite ran.

The original 0.25 CPU / 2 GiB / 4-second / 16-hostile-work / depth-6 service gate is unchanged and unqualified by this campaign. Rectangular/grouped challenges, real request deadlines, complete v2 proof benefit, independent future model evaluation and funded external effects remain distinct open gates. All production activation flags stay false.


## Raw archive integrity

[archive.json](archive.json) binds the separately delivered `pon-shared-material-v1-20261105.zip`: 356 entries, 3,306,416 compressed bytes, SHA256 `07e2e47c431cc2e183207b9191009de247914c6548f8f52856e2291dfcb2a1cd`. Its payload retains 38,567,811 bytes of raw evidence; each payload file has its own SHA256.
