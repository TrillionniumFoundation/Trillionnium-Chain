# PR 784 W1 fresh challenge service: retained failures

Both x64 lanes failed newly executed acceptance observations in run 42431209904. These failures are distinct from the missing historical artifact in the priority workflow.

The original named Rust test ran and exited 0, but its report retained `finite_target_met=false`; the acceptance reader refused `CONFIRMATION_TARGET`. The fresh named test also ran, then panicked at `fresh_challenge.rs:244` with native exit 101. Its raw log states that fresh challenges failed the original four-second/six-depth business target and forbids post-window success credit. The wrapper consequently refused `FRESH_NATIVE_PROCESS_REQUIRED`; this does not mean the test was absent or never executed. Both manifest failure lists remain failures.

The source/host preparation succeeded, host error lists were empty, and the controller accurately propagated child exit 1. The compared workflow, runner, host controller and main native test bytes equal the base. Source equality is not a measured no-regression result or a complete explanation of the performance outcome. No acceptance threshold, source, CI run, or guard was changed during this read-only review. No rerun, cancellation, or comment was issued.

## Evidence

- Head job: https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42431209904/job/128580281914
- Prospective merge job: https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42431209904/job/128580282001
- Workflow: https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/b5c655ebe9611b3d62cf739e61e6867decc053e3/.github/workflows/pon-w1-work-security.yml
- Fresh test failure predicate: https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/b5c655ebe9611b3d62cf739e61e6867decc053e3/trillionnium/crates/trnm-pon-node/tests/public_v3_from_zero/fresh_challenge.rs#L244

`diagnosis.json` records exact source identities, native process outcomes, finite-target fields, and artifact hashes. `native-process-excerpts.txt` preserves the complete short native logs; `source-failure-excerpts.txt` shows the corresponding predicates. Raw job/check/annotation responses and logs, workflow/source snapshots, both downloaded ZIPs and all extracted files are retained. The two ZIPs match the GitHub artifact digests, pass CRC, and every extracted regular file matches its archive entry. There are no unverified partial ZIPs in the archive set.

A future bounded implementation task may clarify the wrapper error with native exit/panic details and investigate missed honest confirmation under the existing budget. This observation does not authorize weakening the target or certify production, work hardness, independent WAN, or resource fairness.
