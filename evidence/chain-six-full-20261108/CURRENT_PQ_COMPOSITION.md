# Current PQ composition validation

`run_pq_composition_current.py` is a new, explicitly scoped composition runner.
The historical `evidence/pq-seven-layer-composition-20261108/run_validation.py`
remains unchanged. All 29 commands, arguments, ordering, source-before and
source-after gates, native checks, failure propagation and the original
1200-second limit for each command are retained.

The historical runner requires 49 claim tests. The merged current test file has
55: every original test remains, with six additional reserved-claim refusal
controls. The new runner requires the complete literal roster of 55 qualified
test identities, one exact `ok` outcome per identity, no duplicates, no missing
or unknown records, exactly one 55-test success summary, empty stdout, exit zero,
and the fixed test-file hash before and after execution. A summary substring,
skip, expected failure, duplicate record, or changed source cannot satisfy it.
The old fixed-49 gate is never relaxed or reinterpreted.

## Source and log provenance

| Input | Fixed identity |
| --- | --- |
| Historical runner bytes | SHA256 `080dc1c54fb7f9a9990fcdcbdb83baf74e7065ab78c32534f65e8717990ce638` |
| Historical 49-test source | Commit `1d29818ad927f549f43d74a06f51e91771feac70`; test-file SHA256 `f3b02029ee8a8f353fdfce4ea72630833cf39bbc8938f317fa6a22461f2d6cd5` |
| Six additional test methods | Commit `580d191981537988dde8bd1cc75eeb8a84540563`, retained through PR #806 and merge `5edb84fad23c1a4eaeec2af0e00dad1d69439759` |
| Current reviewed test file | `scripts/ci/test_pq_chain_claim_guard.py`; 28476 bytes; SHA256 `5a3c2e0d15dbfed68cb7afcc0c7f88a6b5c8620823ea7257e0dc5ef2be570a6f` |
| Actual F2 execution source | Commit `0101b0ce76239832e0b2d19d0fd3f07e40fabeb4` |
| Actual F2 stderr fixture | `claim-tests-f2.stderr.txt`; 7054 bytes; SHA256 `30d70900e35d735a2ece7be26771d3e8be928b3ed26cf751e111905d0302d2eb` |
| Historical 49-test stderr | Existing `committed-source-1d29818/claim-tests.stderr.txt.gz`; decompressed SHA256 `ea166eb3bd7c75fe30e13076ed29cd1de620730d5ba80a28818197fddbbffd31` |

The six added methods cover true reserved aliases, numeric reserved claims,
nested mappings/lists, exact false booleans, exact null bounds, and permitted
false/null HOLD declarations. The reviewed AST and both actual verbose logs
show a 49-name subset and an exact six-name difference; no test was invented
to meet a count.

The F2 command itself exited zero and reported 55 successful tests, while its
historical fixed-49 acceptance gate failed. That failure remains a failure.
The subsequent F2 storage exhaustion and missing supervisor terminal outcome
also remain recorded; this file does not claim that F2 completed. The copied
F2 stderr is only a parser fixture. Every new campaign executes the original
test command afresh and records its own source identity and raw output.

## Focused verification and qualification

Run `python3 -B evidence/chain-six-full-20261108/test_pq_composition_current.py -v`
for the small parser/AST controls. They mutate the actual F2 log to reject the
old 49-only outcome, missing/unknown/mismatched identities, duplicates, skips,
failures, false success summaries and real source-byte drift. They also compare
the new runner's 29 command ASTs, timeout, and early source-gate failure handling
against the unchanged historical file. These controls do not rerun the full
composition or the complete CI contract suite.

The new result schema is `trnm-pq-current-composition-validation-v1`, with
`qualification: HOLD_NO_GO`. Whole-chain PQ qualification, production
activation, complete Node-suite execution and hosted-CI acceptance remain false.
Passing these local controls establishes only the recorded current composition
under its fixed inputs and conditions.
