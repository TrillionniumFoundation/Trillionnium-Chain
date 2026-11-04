# Native liveness continuation — 2026-11-04

Status: candidate implementation and local controls. Issue #639 remains OPEN;
the original business gate and full liveness program are not accepted. No
production, consensus, service or whole-chain PQ flag is promoted.

## Scope

The existing PR #688 receives deadline enforcement at the real V3 completion transition,
exact local Queue Busy recovery at the authenticated service, GrowthV2 batch nonce
queries using a single snapshot and multiproof, and namespace-range access inside M06
mandatory block maintenance, including model evolution, integer-factor candidate
and model-evidence cleanup. Original signed bytes, proof checks, state roots,
nonce/debt rules, resource totals and four-second/sixteen-hostile-W1 acceptance stay intact.

The cleanup controls compare final state, first error and mutations that precede
an error against the retained original full-map algorithms. They include four
model profiles and 8,192 unrelated accounts. The changed passes select exact
ordered namespaces, preserving new archive visibility, monetary inputs,
expiry priority/caps, debit/credit and receipts.

The batch nonce change is a public `Node` API fix: existing Growth CLI/business
callers do not yet use it. The selected checkpoint still verifies the complete,
bounded working partition and schema metadata. Returned values reserve no nonce
and grant no execution authority. Full-State clones, roots and historical replay
remain separate costs.

## Component result summary

| Check | Observed result |
| --- | --- |
| Full M06 library | 119 passed; 0 failed; 7 original ignored tests |
| Selected Node runtime controls | Not executed: 14 selectors / 19 planned tests; planned counts are not results |
| Whole-workspace strict Clippy and formatting | Passed on the candidate source recorded in reproduction.json |
| Repository negative controls | 50 passed |
| PQ source / CI source-integrity negative controls | 35 / 34 passed |
| Original from-zero / Host reader controls | 109 / 78 passed; these are reader tests, not live Host campaigns |
| Original 4-second / 16-producer Host business gate | Not run locally; not accepted |

Earlier Node build attempts encountered five SIGKILL terminations. One attempt
compiled successfully, but its ELF was unavailable when execution began. No
selected Node runtime test executed, including on the final combined source.
The initial missing-input failure, interrupted build, first M06 fixture failure,
all later outcomes and ignored/unexecuted categories remain in the receipt.
The receipt binds its recorded source base and overlay; later integration checks
must be recorded separately rather than transferring these results to new code.

## Integration result and source boundaries

The immutable implementation component is `1e6efc39e192323f34c2a499e29736b507c8f500`.
Its original receipt above is unchanged. The integration combines it with
`33a170e863a413279d6611457d907913a54e9e5a`, preserving incoming Cell storage,
evaluation, Growth observer and report-reader work.

The separate [composition record](composition.json) binds each intermediate
combination and retains its raw check logs. The F11 combination passed strict
workspace Clippy. A later d481 combination failed while compiling SQLite with
`No space left on device`; that failure is not a source-validation pass.
On the final 33a combination, formatting, repository and Markdown links,
PQ source contracts, all 35 PQ source-negative tests, and this component's
whitespace check passed. Full workspace Clippy and native runtime tests remain
incomplete on that combination.

M06 `public_evaluation.rs` and its integration tests changed after the component
run. Therefore **119 passed / 0 failed / 7 ignored applies only to its recorded
source**, not to the later integrated M06. Selected Node controls remain
**0 executed / 19 planned**. Original Host qualification remains unexecuted.
The source checker returning `HOLD_NO_GO` with exit zero confirms the retained
source contract; it does not accept cryptography, liveness or performance.

## Reproduction

Use Rust 1.95.0 with the committed Cargo.lock and the repository's pinned native provider.
Run `bash scripts/project-preflight.sh` before building. The exact local command and result
record is [reproduction.json](reproduction.json); retain its failures and
unexecuted categories. Build interruptions and missing executables are not
counted as executed tests.

```sh
cargo test --offline --locked --manifest-path trillionnium/Cargo.toml -p trnm-mvcc-fee --all-features --lib
cargo test --offline --locked --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --all-features --lib completion_deadline_tests -- --nocapture
cargo test --offline --locked --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --all-features --lib signed_socket_local_queue_busy_keeps_exact_nonce_for_retry_and_invalid_work_terminal -- --nocapture
cargo test --offline --locked --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --all-features --lib native_growth_v2_nonce_batch -- --nocapture
cargo clippy --offline --locked --manifest-path trillionnium/Cargo.toml --workspace --all-targets --all-features -- -D warnings
cargo fmt --manifest-path trillionnium/Cargo.toml --all -- --check
PYTHONDONTWRITEBYTECODE=1 python3 scripts/ci/check_repository.py
PYTHONDONTWRITEBYTECODE=1 python3 scripts/ci/test_repository.py
PYTHONDONTWRITEBYTECODE=1 python3 scripts/ci/check_pq_research_integration.py
PYTHONDONTWRITEBYTECODE=1 python3 scripts/ci/test_pq_research_integration.py
PYTHONDONTWRITEBYTECODE=1 python3 scripts/ci/test_ci_source_integrity.py
PYTHONDONTWRITEBYTECODE=1 python3 scripts/ci/test_run_from_zero_native.py
PYTHONDONTWRITEBYTECODE=1 python3 scripts/ci/test_from_zero_host_ci.py
```

The final local Node functional build sets its optimization to 0, codegen units
to 16 and test-profile debug information to 0. M06 retains optimization 1 and
cryptographic/protocol dependencies retain their configured optimization levels.
Earlier build settings and failures are recorded separately. These command-line
overrides do not edit repository profiles and are not performance evidence.
The local container uses a shared 8-CPU / 8-GiB cgroup.

The retained business gate must run on its existing, independently checked Host:

```sh
python3 scripts/ci/run_from_zero_host.py -- python3 scripts/ci/run_from_zero_native.py --out "$TRNM_CI_RECEIPT_DIR/from-zero-native"
```

A passing Rust safety/accounting selector does not imply a passing confirmation report.
The original gate still requires 4,000 ms, 16 hostile producers, 1,024 calls per producer,
a real signed transaction, complete W1, separate client replay, six-deep confirmation,
and the same aggregate 0.25 CPU / 2 GiB / 256-task Host parent.
The denominator includes every failed, cancelled, timed-out and unresolved
attempt. The 30-second / 24-producer campaign remains supplementary. Historical
data used by reader-negative tests is not a current candidate run.

## Limits

The local container is not that Host and cannot provision its fixed root-owned slice.
Local functional results cannot establish #639, WAN liveness, Sybil-resilient service at
unbounded arrival rates, complete touched-key scaling, physical fault recovery, or the
six-domain whole-chain PQ claims. CI source hashes are refreshed to changed
files; no deadline, threshold or required gate is relaxed.

| Required scenario | Existing control and remaining boundary |
| --- | --- |
| Complete business with no attack | Original same-packet attack-free baseline exists; a fresh original-Host result is still required. |
| Hostile traffic from zero | Original 4-second / 16-producer gate exists; local correctness controls do not replace it. |
| Attack introduced after normal operation | Reopen/sustained controls provide partial coverage. A continuously running normal-to-hostile transition still needs its own acceptance. `late-product` means a late W1 product failure, not delayed attack injection. |
| Cold start, History, reorg and recovery | Native controls include an explicit 4,105-block long-sync gate. Small local tests do not qualify all long-history or hostile combinations. |
| Cell download with normal authorization | Separate controls exist; a simultaneous run on one bounded Host with a complete outcome denominator remains required. |
| Legal and illegal signatures under new crypto configuration | Native signature/tamper and account controls exist; their mixed load with the original W1 pressure remains unqualified. |

The shared service domain limits resource amplification through identity
rotation; it does not establish general fairness among distinct valid W1
requests. Read, History and Cell work still lack the requested unified cost
scheduling and four reserved service classes. Exact retry identity does not
create a durable CPU budget across retries. Deep state clone/root, some SQLite
operations and in-flight cryptographic work retain non-preemptive intervals.
These are explicit remaining items, not successful or omitted observations.
