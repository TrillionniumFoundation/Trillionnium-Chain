# Dynamic-participation input-bound repair observations

Executed source: `8d4c915939f2ae7659e254ec3475d2dadb919f2a`; tree `9ed7a23f58cb427fe45b23bf01bf07bf4fca4fbf`.
Base research candidate: `0ff81958a611d2c0be54d2ca839b955ae7cb2772` (#843).
The later evidence commit adds this packet and does not relabel these executions
as observations on that new commit. No native consensus source or rule changes.

The original recorder verified every tracked raw byte before and after each
listed command. The complete receipts, command arguments, environment metadata
and raw logs are retained in `checks/`. Matching source identities are not a
proof of mathematical assumptions, WAN liveness or production qualification.

## Actual observations

| Original recorded command | Exit | Recorder state |
| --- | ---: | --- |
| dynamic-tests | 0 | command_succeeded |
| fifo-real-control | 0 | command_succeeded |
| source-integrity-tests | 0 | command_succeeded |
| repository-check | 0 | command_succeeded |
| ci-contract-check | 0 | command_succeeded |
| cargo-graph | 0 | command_succeeded |
| cargo-format | 0 | command_succeeded |
| strict-clippy | 124 | command_failed |

The dynamic suite passed **34/34** tests, retaining all 28 original methods and
six new CLI controls. The separate source-integrity suite passed **43/43**.
Their fixture/negative controls do not constitute native consensus execution.

The standalone real FIFO control extracts the exact baseline Python file from
Git. With no FIFO writer, that original process exceeds its one-second observation
budget; the repaired process exits 2 with a structured `REFUSED`,
`HOLD_NO_GO` and null six-successor risk bound. The full receipt retains the
two distinct process outcomes and elapsed observations.

The offline locked Cargo graph, formatting, repository and CI-contract checks
passed. Strict all-target/all-feature Clippy was stopped by the explicitly recorded
**120-second timeout** (exit 124). That is **not a passing Clippy result** and is
not classified as a demonstrated Rust source defect. The original command and
its incomplete log are retained. No broad native campaign, public service,
cryptographic security or production acceptance is claimed.

## Retained history

`prior-isolated-observations/` contains the earlier cloud partial-snapshot
observations, including the original missing-Git preflight failure, baseline
28-test run, repaired 34-test runs, real CLI comparisons and exact input hashes.
These historical scopes remain separate from the complete-worktree executions
above. The original bounded-input patch is preserved byte-for-byte.

`manifest.json` hashes every other member in this finite packet. The manifest
does not authenticate independent operators, source semantics or execution by
itself. All whole-chain/production qualification fields remain false.


## Publication completeness repair

The initial publication at `9b4c6866b846c74fd9d827225e6ce66eb0bcdec3` declared 47 packet files, but its Git tree
contained only 15. The existing log ignore rule excluded
32 original `.log` files from the ordinary add. A subsequent GitHub
read of `checks/dynamic-tests.log` returned 404. The initial commit and its
incomplete manifest remain in history; `publication-history.json` records the
exact missing paths and original ignore-rule output.

The follow-up explicitly stages only those manifest-bound log files after
checking their original lengths and SHA256 values. It also checks every packet
member from the committed Git tree. No test is rerun or attributed to this
evidence-only follow-up: the executions remain bound to source `8d4c915939f2ae7659e254ec3475d2dadb919f2a`.
Strict Clippy remains an incomplete exit-124 observation, not a pass.
