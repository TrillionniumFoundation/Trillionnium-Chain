# Integration controls after preserving the concurrent candidate

The existing candidate advanced to
`9ecdbebc897d35f07b998d084b015db8474be84b` while the six experiments were running.
Its runtime cancellation and W1 FullLimb observation changes are preserved. The
runtime pilot and two CI command files merged cleanly against their common base;
both append-only development-plan sections are retained. This record checks the
combined components, not an installed model or native full-source candidate.

| Selection | Actual result | Count boundary |
| --- | --- | --- |
| `scripts/test_llm_runtime_trial_ledger.py` | 24 passed | Reruns the ledger subset already counted in the proof/recovery record. |
| `scripts/test_llm_runtime_trial_replay.py` | 20 passed | Reruns the history subset already counted in the proof/recovery record. |
| `scripts/test_llm_runtime_stop.py` | 12 passed | Real child cancellation controls from the concurrent candidate. |
| `scripts/ci/test_ci_contract.py` | 100 passed | Source/command contract controls; this does not execute the complete CI lanes. |

The exact merged pilot SHA-256 is
`59e1c14d3cd8ffd977e33502f174adebe42c9db7d0887de3c3e20abff50e0b52`.
Its ledger-only recovery command and the concurrent sticky cancellation owner are
both retained. The full 100-case CI selection is rerun after adding negative
coverage for the new journal, fixed-Host reader and ledger commands.

That negative coverage initially exposed two failures: duplicating the new F0
reader or ledger command into another lane was not rejected. The original
[failing log](ci-contract-cross-lane-duplicate-red.log.json) remains as losslessly
encoded UTF-8, with its original bytes and hash retained. The checker now
counts the actual commands across all lanes and requires exactly one in the
original protocol lane, alongside existing full command/order checks. The final
[100-case log](ci-contract-tests.log) passes. The earlier 100-case run before
those additional negative mutations is retained separately and is not added to
the final count.

Source byte hashes, command selections and log hashes are in
[validation.json](validation.json). Rust compilation, fmt/Clippy, hosted head and
prospective-merge execution, and original fixed-Host F0 are not claimed here.
