# Original F0 execution: independent terminal audit

The original runner completed on source `657bf2a462ff13a6101ebcb4fbe0fb91c515c972`, tree `7ce7ac50f788dd421e7cc0c9ddb957ade3e8df73`. Source identities match before and after; the outer log, copied binary, every retained manifest file, individual process receipts, and named-test transcripts were checked independently. No program was rerun and no original record was changed.

## Process and acceptance denominators

All **five planned invocations ran and returned exit 0 without timeout**. Each transcript identifies its exact requested test and reports one passed test. There are five named-test passes, zero named-test failures, zero process timeouts, and zero unexecuted planned invocations. This is a harness denominator, not a count of completed business requests. The raw report explicitly limits libtest success to native protocol/accounting invariants; the finite business target is retained as a separate outcome.

All **three report-acceptance stages were reached**. Service and sustained validators passed; confirmation validation failed with `CONFIRMATION_TARGET`. The outer command returned **1**. All three raw reports are present and their hashes match both the before-validation and retained identities. The null validated `confirmation_report` summary means failed acceptance, not a missing raw report. Finalization completed; `native_execution_completed=true` and legacy `execution_finished=false` express different scopes.

## Retained business outcomes

Each scenario uses the same packet sequence, one required signed business transaction, seven supporting Submit calls, and the original four-second window. Baseline and pressure each retain **7/7 successful Submit ACKs** and **16/16 successful History responses**. Separate native-execution and chain-inclusion counts are **not_separately_observed**; their values remain null. ACKs cannot supply either count.

Each scenario retains **16 independent page-replay failures**, all explicitly `PUBLIC_HOST_KERNEL_PARENT`, with zero accepted replays. The raw reports explicitly record **0/1 independently confirmed transactions** in each scenario. These are observed report fields, not zero values manufactured from missing evidence. The final independent-confirmation stage and successful confirmation latency are absent; latency and p99 remain null. Confirmation TPS and network capacity TPS remain unqualified and are not computed by dividing by four seconds. The conservative unconfirmed-latency lower bounds do not reach the complete configured window.

Baseline retains all **95/95 receiver connection records**, with dispatch outcomes **95 accepted / 0 rejected / 0 unknown**. Pressure retains all **549/549**, with **99 accepted / 435 rejected / 15 unknown**. All retained owners are closed and none are unfinished; this establishes observation closure, not business success. No receiver records were omitted and no measurement failures were reported. Unobserved client attempts remain unknown.

All-worker CPU, physical network bytes, disk growth, and request peak RSS are not measured by this report. Whole-child CPU and nested thread samples must not be added into whole-request CPU or a post-disconnect CPU tail. The earlier Host-readiness refusal remains a separate result. These actual replay errors do not justify inferring timing contention, changing budgets, or repeating the workload.

Authoritative inputs: `validation/original-from-zero-native.json`, `validation/from-zero-native-final/manifest.json`, each child `process.json`/stdout/stderr, and the three retained raw report files. Detailed hashes, invocation names, scopes, and denominators are in `from_zero_native_audit.json`.
