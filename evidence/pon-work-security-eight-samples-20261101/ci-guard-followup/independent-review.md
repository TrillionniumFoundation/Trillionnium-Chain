# Independent review: branch-encoding CI follow-up

**PASS; no blocking finding.** Initially inspected the staged three-file diff, then independently checked final commit `9cd91ed69a0c69df42f8d7812d32d271df6e1998`, tree `60a521c7299febfe26a8c7d38d3420d490d07cd8`, parent `3bbc0288d6b7b6ed7f2bf0ee70d99b3b14236129`. The final working tree is clean. No repository code was edited and no native, Python test, service or cost campaign was rerun by this reviewer.

## Exact changes and retained gates

- `pon_wire.rs` source guard now requires actual blob `46bb09a69d68318580e2856116267376489aaf78`, replacing stale `6b0e3687c7c1348dec11fd5fff91b7eda884d561`. The wire suite count changes only from 17 to 18 passed; `0 failed; 1 ignored` is retained.
- The new Header binding test is additionally invoked using its full name, `--exact`, `--release`, `--locked` and one test thread. The unchanged `check_required_native_test.py` requires that exact one named test, one passed and zero ignored/failed. `set -euo pipefail` still requires successful Cargo execution.
- Existing complete wire suite, state-root semantic controls, explicit ignored cost observation, all-feature Clippy, native account/archive controls, required-work arithmetic, CPU-reserve controls, service campaign, before/after source checks and artifact retention remain unchanged. The architecture/source matrix, timeout and pinned compiler are unchanged.
- Corpus change is exactly one workflow pin, `50936c3203f97a550d65ae422e3b660634616eb4`, independently computed from actual workflow bytes. All other corpus content and acceptance predicates are unchanged.
- The sole plan records the stale-guard issue and explicitly preserves existing installation, native and service failures. It does not convert source equivalence into a successful new execution receipt.

## Independent byte checks

- Exactly three paths differ from 3bbc: workflow, corpus pin and development plan. The complete index has the same path set as 3bbc and differs only at those paths; no untracked or unstaged files are present.
- Independently recomputed every literal source-blob assertion across `.github/workflows`: **20 / 20 match** actual file bytes and index blobs.
- Directly hashed **1078 Rust files, 53 Cargo/toolchain inputs, 234 scripts, 39 other config files and 12 other workflows**, totaling **20,805,924 bytes**, against the 3bbc and current index blobs. All are identical. Runtime, tests, legal-cost runners/readers and resource/deadline code therefore remain byte-identical.
- Removing only the three added exact-Header-test lines reproduces the old workflow after exactly one blob substitution and the 17-to-18 count substitution. No other gate changes are present.
- Seven previously retained author validation receipts report exit zero, and their log hashes match. Those are prior author executions, not new executions by this reviewer.

## The original CI failure occurred before wire execution

Reviewed the retained head/x64 job log `job-124919350878.log`, SHA-256 `88f84c56621ef1244544025fb4c1077ce347737ace45bdb3ec3cf597ac48926b`. It shows the state-wire step's shell block, beginning with `set -euo pipefail` and the stale blob assertion, then exits 1. The displayed Cargo commands are the runner's printed shell script, not evidence that those commands executed; no wire libtest invocation appears before failure.

The source mismatch is independently verifiable without running tests: actual 3bbc `pon_wire.rs` has blob `46bb...`, while that step required `6b0e...`. Its first assertion therefore fails before the following Cargo command. The 17-pass count was a **subsequent latent blocker**, not the observed cause of this run's first failure. Both are correctly repaired. The other three lane failures are described by the parent investigation; this reviewer directly inspected the representative head/x64 log and common workflow logic.

No old wire-test pass is inferred. The new 18-pass/one-ignored assertion and exact named-test execution must be satisfied by the follow-up's own CI; this static review is not that execution.

## Service result remains failed

Run 41330488677 at 3bbc still has four failed pressure-confirmation observations, despite seven receiver ACKs in each. Independent active state remains at genesis in all four. This CI-only follow-up does not alter that result, increase the original budget, or grant work/service qualification.
