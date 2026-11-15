# Four independent PoN propositions: implementation validation

**HOLD / NO-GO.** These records validate a reporting implementation and its
source/CI controls. They do not prove a real customer, data rights, complete-cost
model benefit or a universal Sybil resource lower bound. They grant no payment,
adoption, consensus-credit or production authority.

## Exact implementation source

- Tested commit: [`10562694eab721f273d217c33d6eba12cf32a639`](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/10562694eab721f273d217c33d6eba12cf32a639).
- Tested tree: `d1578a15c15beade4991c16369531e00b7e38188`.
- Ordered parents: #835 `e2a02f9271b49f146e70806c8a66e161b5973971`, then #832 `e8f81ca15634d0393e7bc6257193b4dbe88d9b2e`.
- Native `trillionnium` tree: `d44a52ab659ea75577669df322f923e2c0012fac`, identical to #835.
- Each of the 11 local validation commands used the original `record_pq_native_command.py` and its unchanged full tracked-byte verifier before and after execution: **26,168 tracked entries, 2,501,233,489 bytes**, with identical source observations.

The [merge review](merge-review.json) records the nine exact imported accounting
files and four changed current-source corpus pins. Both development-plan
continuations remain. The historical #832 selective-import manifest remains
unchanged; it does not retroactively acquire ancestry.

## Actual local executions

**310 unittest methods** passed across the suites below, plus four separate
source/static commands. The CI contract suite includes explicit synthetic native
log readers; these are not native Rust executions. The 13 accounting methods
are named in their original command receipt and are a selected reference scope.

| Command | Executed methods / scope | Result | Retained evidence |
| --- | ---: | --- | --- |
| `accounting-selected-tests` | 13 | exit 0 | [receipt](source-10562694/accounting-selected-tests.json) · [original log](source-10562694/accounting-selected-tests.log) |
| `ci-contract-tests` | 166 | exit 0 | [receipt](source-10562694/ci-contract-tests.json) · [original log](source-10562694/ci-contract-tests.log) |
| `ci-contract` | source/static check | exit 0 | [receipt](source-10562694/ci-contract.json) · [original log](source-10562694/ci-contract.log) |
| `demand-evidence-tests` | 29 | exit 0 | [receipt](source-10562694/demand-evidence-tests.json) · [original log](source-10562694/demand-evidence-tests.log) |
| `distributed-source-inventory` | source/static check | exit 0 | [receipt](source-10562694/distributed-source-inventory.json) · [original log](source-10562694/distributed-source-inventory.log) |
| `four-propositions` | 21 | exit 0 | [receipt](source-10562694/four-propositions.json) · [original log](source-10562694/four-propositions.log) |
| `pq-source-integration` | source/static check | exit 0 | [receipt](source-10562694/pq-source-integration.json) · [original log](source-10562694/pq-source-integration.log) |
| `repository-links` | source/static check | exit 0 | [receipt](source-10562694/repository-links.json) · [original log](source-10562694/repository-links.log) |
| `source-integrity-tests` | 43 | exit 0 | [receipt](source-10562694/source-integrity-tests.json) · [original log](source-10562694/source-integrity-tests.log) |
| `upgrade-policy-tests` | 23 | exit 0 | [receipt](source-10562694/upgrade-policy-tests.json) · [original log](source-10562694/upgrade-policy-tests.log) |
| `work-utility-tests` | 15 | exit 0 | [receipt](source-10562694/work-utility-tests.json) · [original log](source-10562694/work-utility-tests.log) |

The repository checker checked **6,038 local links**, 26 workspace packages and
the committed-clean source. The cross-branch reader checked **915 source blob
pins** while still returning `HOLD_NO_GO` and false cryptographic/production
acceptance. Static gate success is not scientific qualification.

## Environment and unavailable observations

[Environment](environment.json) records Python, cryptography and tool availability.
No local Cargo/rustc was available. The original ai395 HeptaRuntime process-status
query returned MCP `-32603: Internal error`; this read-only failure is retained
in [remote observations](remote-observation.json). Earlier remote merge work is
not execution of this implementation commit. The local merge's two expected
text conflicts are retained in [the original merge log](local-merge.log).

The initial remote observation retained queued workflow runs. A later
[hosted snapshot](hosted-results.json) records mixed results, including a passed
four-axis evidence-controls workflow and a failed W1 QROM implementation workflow.
The QROM head and prospective-merge jobs both report
`input exceeds bound: formal/pon-nakamoto-v1/w1_v2_verifier/src/main.rs`.
That verifier's blob remains `1b2999ec2efb51b1291e4fac19f55ee0afeb5d75`
(11,172 bytes), identical to the first parent. Preserve the
[head failure log](hosted-qrom-job-129200220224.log) and
[prospective-merge failure log](hosted-qrom-job-129200219654.log);
The head job tested `10562694eab721f273d217c33d6eba12cf32a639`; the
prospective-merge job tested its distinct GitHub merge source
`37dd2b669dd4e3e00bf47776bd968975b0b72cf0`. This continuation does not relax
the original bound or historical mapping.
The separate W1 QROM closure workflow also failed. Its retained
[head log](hosted-closure-job-129200219404.log) reports
`source identity mismatch: trillionnium/crates/trnm-pon-node/src/store.rs`.
The local 310-method result is not an all-hosted-CI pass.

Live CI may later change; consult the [required baseline run](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42629037024)
and [PR #841](https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/841)
for later observations. Local native execution remains NOT_RUN. Queued,
unavailable, failed and skipped observations are not PASS.

## Four proposition boundary

The [acceptance specification](../../docs/research/PON_FOUR_PROPOSITIONS_ACCEPTANCE_20261109.md)
and [view specification](../../docs/development/specs/pon/FOUR_PROPOSITIONS_EVIDENCE_VIEW_V1.md)
keep specified-relation correctness, genuine commissioned demand, complete-cost
utility and all-legal-strategy Sybil resistance separate. The view replays
supplied observations through pinned original readers, preserves unknown costs
and NoUpdate reasons, and leaves every `proven` field false. Matching review
labels do not authenticate semantic binding or execution provenance.

Reference operation counts, legal caching/low-rank/batched implementations,
finite model checks and signed external attestations retain their own meanings.
None is relabelled as the missing universal resource theorem or independent
prospective net-benefit observation.

## Publication identity

This evidence directory is appended after testing the implementation commit.
Its publication necessarily creates a new commit identity. The retained records
above do not claim execution of that later commit. Any fresh head checks are
reported separately in the PR. [manifest.json](manifest.json) binds the actual
commands, log hashes, source identity and qualification boundaries.
