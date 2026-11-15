# Fixed F source checks and retained integration observations

The exact source checked here is **2d72fa3293989b01596ec8ce0ba3ff370dc4c584**, tree **ebc11e05eb0015ae5be58ca85ed764e06f4386be**. The full physical fence covered **28,758 tracked entries / 2,595,711,115 bytes** before and after each original command. The protected `trillionnium`, `formal`, and `scripts/ci` bytes match native-tested source **bac6b7659bd7e2d633e25c2da0add60f6a10c7fb**.

## Actual result and parser refusal

All **10 actual commands** and their repository recorders exited **0**: preflight; current authority, Root, and corpus registers; the **65** authority/Root/V5-runner controls; **43** source rejection controls; repository links; formatting; and locked default/all-feature dependency graphs.

The external v2 wrapper itself exited **1**, and its original summary still says `all_gates_passed=false` and `python_controls_observed=65`. Its end-of-stream parser required `OK` to be the final output. The 43-method source test actually emitted a single plain `OK`, followed by six buffered fixture receipt JSON lines: **FAIL, FAIL, FAIL, FAIL, PASS, FAIL**. Those are the expected outputs of five source-fence fixture methods, including one PASS/FAIL loop.

`derived-F-qualification.json` is a separately versioned, **raw-only reread**. It binds the unchanged original summary, all **45** original F artifacts, all ten command receipts and raw logs, complete source identities, and the actual original PTY exit 1. It matches all **65 + 43 = 108** unique successful unittest method identities against the exact fixed F source AST, requires one plain `OK` with no skips/errors/failures for each suite, and permits only the identified six fixture JSON lines. No repository test or native test was rerun to correct the wrapper's parser classification. The original failed wrapper is not relabelled as an exit-0 run.

## Integration and auxiliary provenance

The archive includes both completed integration operations: the initial true whitespace-check refusal (command exit 2, before any commit), and the successful continuation that preserved original log bytes and checked all authored paths before committing clean F. It contains the **actual v2 integration driver**, original input-v1 and authoring-drafts-v2, the actual continuation driver, and all attempts, owners, receipts, stdout/stderr and result files. PTY CRLF and Rust trailing blank lines remain unchanged. The independent 71-diagnostic / 23-raw-path review is retained as a separate read-only observation.

The isolated corpus-delta helper's initial AST selector failure and corrected **1 positive + 13 negative** observations are also retained. These are auxiliary driver checks, never added to the repository's 108 controls or native counts. The earlier unused child-gate v3 is preserved. The prepared child-gate v4 has the reviewed corpus semantic guard, direct parent source identity, and original receipt-to-log bindings; only its syntax is checked at this stage. Its later E execution belongs to E's own receipt.

## Qualification boundary

Native qualification remains attached to **bac6b7659bd7e2d633e25c2da0add60f6a10c7fb**: Root **66 unique methods** (80 executions, 14 overlaps), the incentive campaign, SQLite campaign and strict Clippy each keep their original scopes elsewhere. This source artifact performs **no native tests, no Clippy, no daemon activation and no external effect**. Status remains **HOLD**. A later evidence child must retain F's original failure and separate qualification and run its own limited source gate; it does not inherit a claim that 108 controls executed at the child's HEAD.

## Archive validation

`full-F-original-observations.tar.gz` stores 233 exact payload members plus its manifest. `archive-members.json` records every member's original path, size and SHA256. `archive-verification.json` records a successful bounded streaming reread; no extraction is required, and every member and publication file stays below the existing **4 MiB** cap.

Run `python3 verify_archive.py` from this directory to recheck archive hashes and original receipt/log/source bindings. This is an archive integrity check, not new test execution.
