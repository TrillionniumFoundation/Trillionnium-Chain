## Scope

This draft composes the reviewed PoN sources on the existing #847 integration branch and fixes ordinary Submit's current-clock ancestry check.

- Target: `fix/chain-hepta-closure-candidate-20261109-481716` at `2419777413e44314a4e9e693e81e03bb7590800f`.
- Candidate T: `297bb40798ca1b4e4a987ef00582067282cda4e9`, tree `129267332b2ef87d3d66d014fddeb894faa9379f`.
- Sources retained through ordinary merge commits: #895 `11e242db`, #847 `24197774`, #897 `376d82bd`, and #860 `6ab14e5f`.
- Owners: M01 W1 verification, M06 application execution, M09 node-local adoption, and M15 Node admission/activation.

A candidate can pass its own MTP check while a nonmonotonic ancestor is still too far ahead of the current clock. Previously ordinary Submit could complete W1, execute M06, and persist that candidate before refusing activation. The new private admission context checks the activation parent's ancestry after full W1 and before M06, and again under the reacquired clock before detached commit. Historical import explicitly retains its independent admission contract. Existing exact-packet retry behavior, cancellation, paid CPU accounting, and post-admission activation checks remain.

W1 V1/V2 exact-content accounting and explicit node-local adoption are composed without transferring their authority to other propositions. Source pins are rebound to reviewed implementation S `f2375a08f4458f842b96d30215adcd5380270f1d`; historical reports remain byte-identical.

## Executed verification

**Validation is in progress; this PR remains Draft.** Final original receipts will be linked from a separate evidence commit so this tested candidate head stays immutable.

- The original defect has been reproduced on test-only subject `e63427560885b65c57db6bdc478df023111b4733`: the expected native assertion fails after W1=1, M06=1, candidate durable=true. This is an expected failure of the old implementation, not a passing candidate test.
- T's W1 native suite: 135/135 passed; the remaining 61 library tests are explicitly filtered. Exact source and executable observations are retained.
- Original CI contract, source-integrity, authority and PQ128 controls have completed successfully; remaining original Python controls, full DA targets/features, 14 Node selectors, formatting, locked dependency graphs and strict workspace Clippy are being collected.
- No prior-head native result is attributed to T, and no running or missing check is recorded as passed.

## Recovery and authority

The five propositions stay separate: relation correctness, all-legal-strategy mining cost, independent full-cost model benefit, legitimate adoption, and actual subsequent-task FinalUse. Source consistency and passing mechanism tests do not establish the latter four.

No original work-cost bound, qualification flag, production permission, mining target, consensus rule, acceptance deadline, or historical fixture is promoted. W1 remains a complete-recomputation relation verifier, not integrated succinct SNARK/STARK acceptance. Historical admission remains available without current activation authority. Ordinary Hepta stage-owner assembly and cross-repository HEPLCP04 acceptance remain open.

No merge, production activation, live-key operation, or historical runtime restoration is performed.
