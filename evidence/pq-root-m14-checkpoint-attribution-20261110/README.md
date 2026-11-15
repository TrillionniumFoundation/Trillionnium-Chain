# PQ Root / M14 original native campaign — history/checkpoint attribution (HOLD)

**HOLD_NO_GO / DENY_ALL; evidence-only stacked continuation of #847.** No production activation, acceptance parameter change, test edit, source acceleration, or claim of independent execution.

## Exact original host source and artifact

- Candidate: [Chain #847](https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/847), Git commit `ac8501a85a770ba34f34e1bed507ca747e5c3f8d`, tree `3f321d412ab7eb1f5c03f18ba21201e96a3db144`.
- Actual original hosted [GitHub Actions run 42693805359](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42693805359), artifact ID **13708896865**; original artifact ZIP SHA-256 `7996763ffc628f025f2d8e47bf3a6f184805a4b5b24dd13b273ee508903b1f78`, **1,766** archive entries.
- Three separate original campaign runs, each with baseline/from-zero/late-product 30-second phases, attacker counts **0/24/24**, **1,024 actual signed transfers in four seed blocks**, **21 business blocks**, original receiver/verifier **0.25 CPU / 2 GiB**, separate controller **4 CPU**. Source head, original JSON fields, each original complete `run-N-raw/report.json` SHA-256 against `results.json`, and each embedded phase against its separate source JSON are checked by the accompanying strict read-only [verifier](./verify_imports.py).
- This is readback of the **unchanged failed** original artifact, not a new execution. Original release build succeeded; each complete run exited **101**, with no phase startup error. Campaign **0/3**; phase **0/9**.

## New, bounded measurements from the nine original phases

The import sample below includes *only successful local history imports*; it does not silently substitute incomplete imports with zero time. Checkpoint cost is nested inside import cost, **not additive** to the enclosing CPU interval.

| Mode (3 runs each) | Successful / failed history imports | Checkpoint Host calls in successful imports | Checkpoint calling-thread CPU | Import calling-thread CPU | Successful import wall time | In-window signed confirmations |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| baseline | 32 / 3 | 347,414 | 14.880399306 s | 17.173991607 s | 74.375650021 s | 3 |
| from-zero | 18 / 3 | 159,111 | 7.421135683 s | 8.601365492 s | 64.311084723 s | 0 |
| late-product | 18 / 3 | 159,115 | 7.532049737 s | 8.728126796 s | 67.080505441 s | 0 |
| **Total** | **68 / 9** | **665,640** | **29.833584726 s** | **34.503483895 s** | **205.767240185 s** | **3** |

The successful import totals are across **nine separate 30-second phases**, not a single elapsed interval. The CPU fields are actual **calling-thread** observations, not whole-process or whole-host CPU. Original phase records continue to report **no paid-CPU-credit depletion, no receiver/client state equality and no successful phase**. No amount of rejected hostile work can be counted as a confirmed business round. The baseline completes one of two signed-confirmation rounds per run; neither hostile mode confirms its one attempted round.

**Bottleneck hypothesis, not proof:** independent client history import repeatedly traverses a large checkpoint-validation path (8,755–29,954 observed checkpoint calls per successful import; 665,640 in aggregate). That path is a concrete target for semantics-preserving, cost-matched profiling and redesign. The observed total count does **not** prove the checks are duplicates, unnecessary, safe to skip, or the unique cause of deadline expiry. The original authenticated-state, data integrity, resource/accounting and confirmation semantics must remain enforced when optimizing.

## Reproduce / negative controls

Download the actual unmodified ZIP via the GitHub Actions artifact API, then run:

```bash
python3 evidence/pq-root-m14-checkpoint-attribution-20261110/verify_imports.py original-13708896865.zip > attribution.json
```

Expected: JSON with **nine** `phase_results`, the three exact `by_mode` rows above, original `HOLD_NO_GO`. The locally executed reader produced all nine rows and exactly the above aggregates. Two explicit refusal tests were also executed: `--sha256` set to 64 zeroes and `--head` set to 40 zeroes both returned exit **1** with zero stdout, respectively `ValueError: ZIP_SHA_CHANGED` and `ValueError: WRONG_EXECUTED_HEAD`. These check the input binding, not cryptographic assumptions or external host authentication.

Only the source-locked original ZIP, native reports, source head and the code here define this measurement. Missing or changed inputs must fail rather than produce a partial success projection. The reader's evidence scope does **not** authenticate independent operators or remote execution.

## Remaining qualification gates

Real independent root/writer/anchor/provider operators, distinct devices, keys, backup and tested recovery; a fresh authenticated external root surviving **joint owner + all-anchor rollback**; native M15/FinalUse with real provider API/payments/resources and reorg liability settlement; explicit safe algorithm/version migration; concrete eight-domain bounds plus all key/epoch/offline and shared-hash query coverage, implementation reductions and whole-chain event composition; successful original full Host and three-run campaign without changing the thresholds. None of these is closed by this artifact. **Actual lifetime failure bound remains null, not `2^-128`.**

Review the parent #847 and the distinct original-source artifact audit #853; this branch adds no overlapping production patch.
