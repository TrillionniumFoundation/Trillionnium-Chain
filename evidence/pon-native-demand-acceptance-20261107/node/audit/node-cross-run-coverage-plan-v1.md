# Node coverage across the original failed run and the remainder run

This is a diagnostic coverage plan. Its qualification is always false. It must not be described as one successful Cargo run.

## Frozen source and actual partition

- Commit: 690f710c1b6808787996e86aa4c36bd53e1f3939.
- Tree: b9ff2e5c4ca6e465b86cb4b2bd466ad831147899.
- Actual Cargo inventory: 91 targets (1 lib, 1 bin, 69 integration tests, 20 examples), bound to locked offline all-features metadata.
- Original job: 1a1b6390138-12894-305; native terminal state timed_out, exit 124.
- Original sealed failure audit: original-node-failed-inventory-v1.json, 189970 bytes, SHA-256 d906a690639ee78b6b38e1a97e27904e1a1b7a540f9206cadbde03aa40adbc70.
- Original complete coverage: 30 targets, including 4 targets with failures; 1254 passed, 8 failed, 40 ignored, 0 measured, 0 filtered.
- Original incomplete target: tests/model_composition_v4.rs; 60 other targets have no observed start header.
- Remainder job: 1a1b6b4fa87-12894-60d, stable key 525798-remaining-node-690f710c-v1, independent 10800-second supervisor timeout.
- Remainder selection: all 41 unfinished integration targets and all 20 examples, explicit Cargo target arguments. It does not select the original complete 30.
- Actual selection file: build-receipts/remaining-node-690f710c-v1/selection.json, 52584 bytes, SHA-256 9bd89ad1849745b3be329094de6a37571fb680307b868dea2375d3526812cb46.

The original after-source snapshot is absent because the original recorder did not finish. The remainder snapshot must never be substituted for it.

## Original evidence stays intact

The two runs retain separate source snapshots, commands, environment projections, metadata graphs, raw logs, native receipts, and host terminal status. Original failed tests, raw failure lines, the partial target, and the timeout remain visible. No original recorder or receipt is rewritten.

The remainder recorder preserves the recorded provider artifacts, toolchain, kernel, Cargo profile, build jobs and single test thread. The launcher adds no memory, CPU or nice override. It keeps inherited policy variables and does not change the public-host guard, OS setup, source budgets or test deadlines. Only the independent outer supervisor timeout is longer.

## Eligibility to read and audit the remainder

Save the actual native H terminal status of the remainder job as JSON. The auditor requires the exact job ID, a terminal state, durable/complete output, and confirmed terminal publication before reading either test log. A running status cannot serve as an ending receipt.

If the recorder reached result.json, verify its actual raw log bytes/hash, command, source, environment, graph, recorder identity and retained SQLite witness. If it did not reach that file, report the absence and use only a fresh stable post-termination raw-log observation. Do not manufacture missing source-after or result files.

## Counting rule

Use the canonical inventory identity (target kind, target name, frozen source path). Binary basename alone is insufficient.

The assignment is fixed before the remainder results are known:

1. The original complete 30 supply their original complete target summaries, including every failure.
2. The other 61 can supply only the new run's unambiguous complete target summaries.
3. The original partial model_composition_v4 observation remains attached to the original run and is excluded from sums. The complete new invocation of that target may be counted once.
4. Unexpected or repeated Cargo target headers are refused. Missing, interrupted or ambiguous target summaries are not assigned zero or counted as passed.

For every counted target, retain the job/run identity, exact command, frozen source identity, raw-log size and SHA-256, Cargo header, segment byte interval and summary byte interval. Byte intervals are zero-based with an exclusive end.

Only the first top-level running N and the unambiguous final target summary can supply counts. Require N = passed + failed + ignored + measured and top-level filtered-out zero. Child harness summaries and their filtered counts are excluded. Any same-sized nested harness start remains an attribution ambiguity even if a greedy matcher could consume it. Ignored tests remain a separate count; libtest has no skipped summary field.

## Output and interpretation

The new auditor is recovery-evidence-tools/audit_node_union_coverage_recovery_v1.py. It loads the hash-pinned failure-attribution helper rather than changing either version of the success parser.

From the host root, after the real remainder terminal status is retained:

    /usr/bin/python3 recovery-evidence-tools/audit_node_union_coverage_recovery_v1.py \
      --remainder-terminal-status recovery-evidence-tools/remaining-node-terminal-status.json \
      --output recovery-evidence-tools/node-cross-run-coverage-v1.json

Output is create-only. Preserve any failed audit output before fixing the tool and using a new output filename.

The report gives per-run and combined complete-target counts, uncovered canonical targets, all observed failures, nested and partial exclusions, and source-provenance gaps. Even 91 complete summaries would establish only complete counting coverage across two invocations. The original failures, timeout and absent source-after snapshot prevent interpreting the union as a successful full gate. This evidence does not verify independent business demand, production adoption, physical training cost, or model efficacy.
