# Frozen release-cost environment follow-up

This follow-up restores startup consistency for five existing cost invocations.
It does not report a successful native cost campaign or promote any release,
work-hardness, PQ, service, or independent WAN qualification.

## Observed conflict and narrow change

The exact candidate `acd8f79f2dcc22ecdee1d1a5fd88d619d06f37c9`
inherited a workflow-wide `CARGO_INCREMENTAL: "0"`. The original cost owner
rejects any nonempty `CARGO_INCREMENTAL` value, including the string `"0"`, as
a release compiler/configuration override. Both the workflow setting and the
two owner files were byte-identical between this candidate and the earlier
`cea95fb44d8152a0eb1138727619fcced056f496` base.

The retained old-head job excerpts show the actual inherited value and the
corresponding pre-execution refusal:

- [Cross-architecture cost, x64](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41287811776/job/124792592211)
- [W1 actual reuse V3, head x64](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41287811776/job/124792592393)

Only these existing commands in `trnm-required-baseline.yml` now prefix Python
with `env -u CARGO_INCREMENTAL`:

| Existing job | Existing execution |
| --- | --- |
| `cross-arch-cost` | Default release setup and repeated search |
| `cross-arch-cost` | Zero locality, version 2 |
| `cross-arch-cost` | One-zero locality |
| `cross-arch-cost` | Fixed maintenance paired costs |
| `cross-arch-w1-reuse-v3` | Complete native V3 grid |

The original guard, Cargo configuration checks, compiler, profile, resource
budgets, global environment, and all other job commands are unchanged. The
existing exact CI contract and mutation strings follow the five new commands.
Existing mutation cases additionally reject removing the one-variable unset
or broadening it to remove `RUSTFLAGS`. Three corpus blob pins track the changed
workflow, checker, and test file; the corpus remains `HOLD_NO_GO`.

## Local control results

Every command and its original stdout/stderr are retained under `controls/`.
Gzip files preserve the raw bytes; `receipt.json` records their raw and packed
hashes, source blobs, exact commands, exit codes, and timings.

| Existing control | Observed result |
| --- | --- |
| `check_ci_contract.py` | Exit 0; two cost architectures and four V3 source/architecture cells retained |
| `test_ci_contract.py` | 95 tests passed |
| `test_ci_execution.py` | 67 tests passed |
| `test_ci_source_integrity.py` | 34 tests passed |
| `test_cross_arch_cost.py` | 47 tests passed |
| `test_run_w1_reused_cost_v3.py` | 24 tests passed |
| `check_pq_research_integration.py` | 346 exact source blobs; `HOLD_NO_GO`; activation false |
| `bash -n scripts/ci/ci_job.sh` and the five new shell commands | Exit 0 |

The execution suite imports source-integrity cases, so the suite counts are
not disjoint. The original guard was also called through the actual `env -u`
process boundary: the inherited zero was removed, while supplied `RUSTFLAGS`
and `CARGO_BUILD_INCREMENTAL` remained visible and rejected. This observation
did not launch a compiler or a native cost campaign.

## Retained from-zero failure on the preceding candidate

The already-completed [head protocol-contract job](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41287811776/job/124792592288)
is bound to `acd8f79f2dcc22ecdee1d1a5fd88d619d06f37c9` and tree
`4e83d2d4ba6b15ddd962ef08652dbeb24858c533`. Its downloaded artifact ZIP had
SHA-256 `ac77f3e4c540cd58d278b52fe659e5e5aedb86495f8695ac485a113c78b58cb0`,
matching the GitHub artifact metadata. Only relevant original report/log
entries are retained here; `remote-observation.json` identifies the artifact,
run, job, raw entry names, and hashes.

The original release build succeeded. Each of five named native libtests
actually executed one test and exited zero. The original driver nevertheless
returned `passed=false`, with `failures=["CONFIRMATION_TARGET"]`; the host
record has `host_errors=[]` and `native_child_exit=1`.

The original confirmation report has `finite_target_met=false`,
`invariant_target_met=true`, and `same_packet_sequence_in_both_runs=true`.
Reading those unchanged report bytes with the unchanged original reader
reproduces the failure at the top-level positive flags check. The Rust test
explicitly limits its own success to protocol/accounting invariants and records
the finite business result separately. The overall from-zero result remains
**FAIL**. No assertion, target, pressure window, or budget was changed to make
that result pass.

The old-head observations do not confer execution qualification on a later
commit. This follow-up's local tests establish source/CI contract consistency
for the recorded working-source hashes only. Ongoing remote jobs were not
waited on, rerun, or counted as successful.
