# Native liveness repair evidence — 2026-11-04

**HOLD. The original four-second / 16-hostile-producer selector executed and passed its safety/accounting assertions, but both phases confirmed 0 of 1 required business transactions. The independent verifier's History replay was refused by the original Host check. The unchanged acceptance reader rejected the report. The 23 new native regressions have not executed. This record does not close issue #639 or establish a performance improvement.**

The companion [results.json](results.json) retains exact command receipts, source identities, complete outcome denominators, failures, and unknown outcomes. All raw command logs and receipts named below are included in this directory, with byte counts and digests in the results file. The [compressed original report](original-confirmation-report.json.gz) preserves every byte of the emitted report, including all failed requests and observations.

## Published composition: native gates still HOLD

Final implementation checkpoint: **3e601d0c6769b973b8436245293ad00ecb86c3f9**,
tree **87f974c3ad327d5da2c61286ec86fcb1580b3fcf**. It preserves incoming
1c885019fdf1cc2f33af8da0780da603fff1c353, including namespace range maintenance,
Growth batch nonces, precise local Busy retry and concurrent formal work.
The [composition review](publication-composition-review.json) records all 34 incoming
paths, eight overlaps and unchanged Cargo inputs. The [state-path review](publication-growth-review.json)
and [completion review](publication-completion-review.json) are source reviews only.

On this clean checkpoint, full tracked-byte verification passed: **9,002 entries,
946,597,739 bytes**. Workspace formatting, 452 exact source pins and repository
checks (2,605 links, 26 packages) passed. Corpus qualification remains HOLD_NO_GO.
**Strict Clippy, reader/source-suite and native runtime were not rerun on this
checkpoint after the retained 0ba SIGBUS/ENOSPC failures.** Earlier green checks
and the original 2b native report retain their own revisions.

The six-argument completion gate retains all five local and four incoming tests.
A late/cancelled completion whose encoding actually failed also keeps secondary
output-failure event counts; the primary terminal remains Deadline/Cancelled,
with accepted/CPU unchanged. These overlap on one request and do not add requests
to the denominator. The existing schema has no second full error-text slot;
neither a second complete diagnostic nor a new reactor phase is claimed.
Historical completion_cutoff metadata and patch still describe the earlier 0647.

The incoming worker regression holds real body bytes, body/lane reservations and
the original task observer together. Connection/output release does not mark
the task complete while the worker still owns those resources. This composition
contains **27 scoped native regressions: this work's 23 plus four incoming
completion tests, all NOT_RUN on this composition**. That count does not cover
every regression in the shared PR. Unknown outcomes are those same 27 tests.

The [publication source bundle](publication-source.bundle) retains exact 3e601
and its local history. It requires public 1c885 and local 0ba, retained by
final-source-history.bundle; verify/fetch that earlier bundle first. Actual
verification is in publication-source-bundle-verify.log.
The [earlier evidence review](prepublication-evidence-review.json) binds the old
97-file snapshot; it does not claim to review this later composition.

Final evidence materialization also encountered ENOSPC. The complete new evidence
and documentation were retained in RAM and assembled into verified Git objects
for connector publication. The full worktree guard above remains bound to the
3e601 implementation checkpoint; it is not relabelled as a later documentation
commit check. No payload bytes or failed outcomes were omitted.

Original 4s/16 business outcomes, all failures, late returns and unknowns remain.
Issue #639, native acceptance and production activation stay open.

Before publication, concurrent 0ceffc048e733e2116841385a1d3b3abb35bc9c5 added
five research documentation/evidence files. They are preserved, with non-overlapping
plan changes composed. The trillionnium, config, scripts and .github subtrees
remain byte-identical to 3e601. This does not supply a new native or Clippy result.

## Retained previous composition status (0ba09db0)

Concurrent update `33a170e863a413279d6611457d907913a54e9e5a` was preserved in
local merge `0ba09db0cf1c684013a896dd83f29c327f58521e`, tree
`924397c8ca6ea1d0d8e9c003f4ca7f3c6a9022be`. **That composition has no
successful full Clippy or reader/source-suite result.** Fresh Clippy exited 101
when the getrandom build-script linker terminated with SIGBUS. The Python suite
exited 120 with ENOSPC during Git-fixture creation and no final successful suite
summary. Simultaneous disk errors do not uniquely establish the compiler signal's
cause. Earlier successes remain bound to their own source revisions.

That composition passed the full tracked-source guard (8,969 entries,
945,272,745 bytes), formatting, and consistency of 452 exact source pins while
qualification remained HOLD_NO_GO. All 57 Cargo manifests/lockfiles match 0647.
The [late merge review](latest-composition-preservation-audit.json) verifies both
parents' changes. New bounded Growth observation APIs have no complete request
ExecutionControl/deadline parameter; they do not close lifecycle-budget work.

The [final source history bundle](final-source-history.bundle) preserves that
composed source and its predecessors. It requires public ancestors d0737cf5,
245146c7, d4816ca5 and 33a170e8; exact refs and verification are retained in
`latest-composition-source-bundle.log`. The earlier `native-tested-source.bundle`
still independently preserves the measured 2b source and the 0647 cutoff repair.
Original native results, all 23 NOT_RUN regressions and prior failures remain
unchanged. No failed or unknown outcome was promoted to a pass.

## Source and implemented scope

The starting revision was `d0737cf5434894ce47fad8082376fc417313c2cb`. The composed, frozen source was `92a0750e3278f71f86000dfcb14388f3e86baa2a`, tree `72d12bd434055f67c5f6becf2ee480a9ec09b99e`. The original native experiment revision is `2b4d7b46f0de6507ca960b259bc3d52f09f9dc36`, tree `0296ed99dde48e287038fc27e47ef9e310d40117`. The latter changes only a test assertion from `.max(11).min(20)` to the equivalent `.clamp(11, 20)` and its source pin. Results measured on the frozen revision retain that identity; they are not relabelled as new runs on the later revision.

This round implements operation-local header-window reuse in GrowthV2 and ordinary admission, original-request header checkpoints, epoch refusal after changed local observations, response cancellation before starting further encoding/signing, and resource ownership through task, connection, output, and worker cleanup. It also preserves an offered business transaction in the failure reader when its start is already outside the original window. Full W1 validation, original owner permissions, transactional readback, and original service limits remain required.

These are source changes with regression coverage added. Runtime success for the new regressions remains unobserved.

## Completed checks

| Check | Exact revision | Observed result | Scope |
| --- | --- | --- | --- |
| Full tracked-source verification | `92a0750e3` | PASS: 8,782 entries; 941,197,770 bytes | Source identity; executes no native tests |
| Repository checks | `92a0750e3` | PASS: 2,468 local links; 26 packages | Source graph, boundaries, and links |
| PQ source corpus | `92a0750e3` | 412 exact blobs; `HOLD_NO_GO` | Source consistency; no cryptographic or release acceptance |
| Confirmation and Growth observation readers | `92a0750e3` | 160 Python tests PASS | `test_run_from_zero_native`, `test_growth_scale_observation` |
| Source-control negative/positive tests | `92a0750e3` | 135 Python tests PASS | Source integrity, repository, project boundary, PQ source checker |
| First strict Clippy run | `92a0750e3` | FAIL, exit 101: one `manual_clamp` diagnostic | Failure retained in `strict-clippy.log` |
| Strict Clippy after equivalent assertion fix | `2b4d7b46f` | PASS, exit 0 | Entire workspace, all features, all targets, `-D warnings`; no test execution |

The negative source-control suite deliberately emits refusal records. Its unittest summary reports all 135 tests passing; those expected negative controls are not erased or presented as native execution.

## Failed native build attempts and retained denominator

| Attempt | Revision and build scope | Observed result |
| --- | --- | --- |
| Baseline library-test build | `d0737cf54`; Node library tests, all features, no-run; original test profile | Rust compiler killed by signal 9 (`SIGKILL`); `base-build.stderr` and `base-build.jsonl` retained |
| Composed library-test build | `92a0750e3`; package debug information disabled for Node and M06 | Cargo exit 101; Node library-test compiler `SIGKILL`; `final-lib-build.json` / `.log` retained |
| Component-oriented library-test build | `92a0750e3`; global test debug information disabled, Node test optimization level 0 | Cargo exit 101; Node library-test compiler `SIGKILL`; `component-lib-build.json` / `.log` retained |

**New native regressions: 23 planned, 0 executed, 23 NOT_RUN.** The initial 18-test inventory comprises five ordinary-header tests, five Growth header-window tests, one real-ingress resource-refusal test, five resource-lifetime/shutdown tests, and two PQ response-cancellation tests. Later completion-cutoff tests are separately identified and retain NOT_RUN outcomes. Their exact names appear in `results.json`. No old executable supplied a result for this source. No successful runtime latency, throughput, or native pass rate can be calculated from these attempts. The compiler signal alone does not identify the reason for termination.

## Original acceptance: executed, business gate not met

The completed command used revision `2b4d7b46f` and the original release selector:

```text
cargo test --offline --locked --release --manifest-path trillionnium/Cargo.toml
  -p trnm-pon-node --test public_v3_from_zero
  from_zero_signed_business_reports_confirmation_in_original_pressure_window_against_same_packet_baseline
  -- --exact --nocapture --test-threads=1
```

The full launcher and environment assignment are in `original-four-second-native.json`; output is retained in `original-four-second-native.log`. The release build completed in the reported 6 minutes 40 seconds; the one selected integration test executed in 8.40 seconds, with five other selectors filtered out. Cargo returned 0 because this selector asserts protocol/accounting invariants while retaining finite business outcomes separately. The report has `invariant_target_met=true` and **`finite_target_met=false`**. The unchanged reader in `original-confirmation-readback.json` / `.log` returned **exit 1, `CONFIRMATION_TARGET`**.

| Outcome | Attack-free baseline | From-zero pressure |
| --- | --- | --- |
| Original window / hostile producers | 4 seconds / 0 | 4 seconds / 16 |
| Required business transaction confirmed | **0 / 1** | **0 / 1** |
| Business unconfirmed / unknown | 1 / 0 | 1 / 0 |
| Successful honest Submit acknowledgements | 7 / 7 | 7 / 7 |
| Successful honest History responses | 16 / 16 | 16 / 16 |
| Independent History replay accepted | **0 / 16** | **0 / 16** |
| Independent History replay refusal | 16 `PUBLIC_HOST_KERNEL_PARENT` | 16 `PUBLIC_HOST_KERNEL_PARENT` |
| Successful honest Heads responses | 79 / 79 | 76 / 77; one `FRAME_DEADLINE` |
| Full W1 calls finished / started | 7 / 7 | 442 / 442 |
| Full W1 calls returning an error | 0 | 435 |
| Required pressure/confirmation overlap | Not applicable | `false`; zero overlapping calls |

**The Host refusal occurred in the independent verifier, not in all receiver service.** The receiver accepted every honest Submit and served every honest History request. All 32 independent page replays were refused at Host resolution, before independent confirmation. Confirmation timestamps and successful business latency are therefore `null`; there are two unconfirmed phase offers, not a success-only latency sample. `receiver_matches_valid_honest_prefix=true` in both phases does not replace independent replay. `full_native_state_equal=false` records the verifier's unadvanced state and does not establish receiver corruption or attribute the failure to full-State processing.

The pressure phase retains **all 450 hostile client calls**: 434 refusals with `WORK:Transcript`, 15 I/O errors (`Resource temporarily unavailable`, error 11), and one `FRAME_DEADLINE`. Sixteen attack calls and the one failed honest Heads call returned after the original window; none is dropped. The service's 435 failed W1 calls and the client's 434 received refusal responses are different observations and are not forced into the same count. All 102 baseline and 550 pressure connection records are retained and marked complete, with no observation loss; 16 pressure connections never created a task. The reported post-shutdown body/output reservations, CPU reservations in flight, and lane grants are zero.

Actual full W1 verification did run: this selector uses `PublicServer::new` with no arithmetic-fact or W1 rejection cache, reaching `WorkCheckedPacket::verify_with_progress`. Pressure-phase calling-thread full-work CPU was 365,600,906 ns; dispatch excluding work was 490,510,845 ns; their sum equals charged mutation CPU, 856,111,751 ns, with zero clock failures. These local measurements do not establish the requested end-to-end performance. `overlapping_false_calls=0` and `overlap_demonstrated=false` follow from the absent confirmation endpoint. The raw field `completed_false_calls_at_confirmation=127` is a counter sampled after the replay loop, even though `confirmation_ended_ns=null`; it is not the complete attack-call denominator.

This local Host-gated observation does not relabel the historical [issue #639 failure](https://github.com/TrillionniumFoundation/Trillionnium-Chain/issues/639): that original qualified-Host run reported no Host errors and missed the business deadline under hostile W1. Its failure remains open.

The four-second window, 16 hostile producers, six-depth independent confirmation, same-packet baseline, and original Host checks remain unchanged. No 30-second / 24-attacker campaign replaces this result. This is a Host-gated, unconfirmed business outcome with observed receiver W1 work; it is not a completed measurement of business confirmation under demonstrated W1 pressure.

The original report is 14,612,673 bytes, SHA-256 `a8dfce1f27c3f164131aae98ba001e7bf466693f78075e84738419a0c75d5f5c`. Its complete, deterministic gzip (`mtime=0`) is 548,592 bytes, SHA-256 `80cbaa8f2b4ef9093aee5f8d8ab6493bb0d662a55a1fb128df5931f70ce6ad94`; decompression was verified byte-for-byte. The executable path is recorded in the actual Cargo log, but the executable was no longer present when evidence was collected. `retained_binary=false` and `binary_sha256=null`; no digest or replacement execution is invented.

## Environment and SQLite qualification

This container has an eight-CPU cgroup ceiling and an 8 GiB memory ceiling. Its cgroup mount is read-only; the required `/sys/fs/cgroup/trnmponpublic.slice` is absent. It is **not the original fixed Host**. The unchanged Host observer reports missing parent identity, kernel observations, finite limits, reviewed unit bytes, and service membership. Loopback diagnostics cannot substitute for the original Host-qualified acceptance.

The first direct-Cargo build reported SQLite I/O boundary `UNQUALIFIED: normal Cargo loader directory set incomplete`; that warning remains in the baseline and draft-check logs. The launcher was corrected to invoke the real Rust 1.95.0 toolchain through rustup, followed by normal package cleanup and rebuilding. Later actual Cargo build-script receipts contain `cfg(trnm_sqlite_layout_witness)` and `sqlite-3.51.3-normal-native-linux-layout-v3`. No build fence, source assertion, or qualification token was weakened or fabricated. This build-boundary qualification neither changes the Host result nor turns a killed Node test build into a native pass.

## Work still open

- Full-State clone, root calculation, traversal, and audit costs on hot paths remain. Fewer header callbacks do not establish lower total CPU or bounded business-state cost.
- GrowthV2 still lacks an integrated unknown-parent History recovery path.
- Fixed reservations across consensus candidates, ordinary queries, historical synchronization, and Cell transfer, including cost feedback, remain incomplete.
- Cancellation is cooperative. Already-running cryptographic/provider, hashing, and SQLite operations are not hard-preempted.
- This record does not complete the requested late-attack, cold-start, historical-sync, reorganization/recovery, concurrent Cell/authorization, or new-profile valid/invalid-signature campaign matrix.

The original business gate remains unmet, all 23 new native regression outcomes remain NOT_RUN, and performance benefit remains unaccepted. Production activation remains false. Raw build/lint failures and all request outcomes remain in the package.


## Composed source and reproduction

The concurrent Cell/model/W1 changes at `d4816ca5d1375347d8ed341a434158e350c29bbc`
were preserved in local merge `fc9ebe7accf99d6017a5a9046b1380ec8a40d03e`, tree
`15f8b38fd9f320de4e987a6c635af2b39cb01333`. The
[composition audit](composition-preservation-audit.json) records the exact
overlap and source inventory union. The detached payload counter still traverses
the full State; it removes a temporary allocation without changing that cost class.

On that clean merge, strict workspace/all-feature/all-target Clippy, formatting,
the full tracked-byte guard (8,887 entries, 942,771,853 bytes), 229 reader/source
controls, repository checks (2,593 local links), 444 source pins and the locked
26-workspace/180-resolved-package graph passed. These are fresh source/check
results on the merge; they do not relabel the earlier native experiment. The
metadata receipts retain exact commands, commits and raw-log hashes.

The [source history bundle](native-tested-source.bundle) preserves the local
implementation commits and the exact `92a0750e3` / `2b4d7b46f` source history.
It requires the existing public ancestors `d0737cf5434894ce47fad8082376fc417313c2cb`,
`245146c7d2e6f7dfcda463f6a7dd342d4d7ca818`, and
`d4816ca5d1375347d8ed341a434158e350c29bbc`. In a clone containing those ancestors,
verify and fetch the bundle before checking out the measured source:

```sh
git bundle verify evidence/pon-native-liveness-20261104/native-tested-source.bundle
git fetch evidence/pon-native-liveness-20261104/native-tested-source.bundle HEAD
git worktree add --detach ../native-liveness-measured 2b4d7b46f0de6507ca960b259bc3d52f09f9dc36
```

The retained `run-native.sh` is the actual session launcher, including its
absolute toolchain/provider paths. It documents the observed environment; those
paths must be mapped to a separately provisioned, identically pinned native
environment for reproduction. The original fixed Host requirements still apply.
The original binary itself was not retained.

Decompress `original-confirmation-report.json.gz` to recover the unchanged raw
report, then use the original `scripts/ci/run_from_zero_native.py
--summarize-confirmation` reader. Its retained result is a failed business gate,
not a successful confirmation benchmark. No historical log is edited to describe
a later source revision.

A subsequent 66-test repository/project-boundary invocation exited 1 while copying the RepositoryMutants fixture with ENOSPC. Its raw error and command receipt are retained; no successful suite count is inferred. This does not erase the 135 source controls on the earlier frozen revision or convert them into a pass on this merge.

## Original completion queue deadline correction (0647)

Five additional completion-cutoff native regressions were added after the three retained Node library-test build failures. Their status is NOT_RUN_ADDED_AFTER_BLOCKED_BUILD: five planned, zero executed, five unknown runtime outcomes. The earlier SIGKILL attempts are not compilation or execution results for these added selectors. Together with the prior 18 unexecuted regressions, the planned native regression denominator is 23, all unexecuted.

The production change checks the original work, total and service deadlines, including equality at the cutoff, plus service stop and request cancellation, before promoting a queued completion from Await to Output. Worker response checks alone do not cover later CPU settlement, channel send or reactor delay. A refused completion releases Finished bytes, its output reservation and TaskObservation before closing the connection; it leaves prior native dispatch and CPU observations unchanged. A timely output stage remains capped by the original total/service deadlines and existing OUTPUT_MS. A late result, including a late encoding error, is recorded as deadline/cancellation rather than serialization or consensus invalidity. An on-time encoding error retains the original serialization path.

The regressions exercise the production completion helper with real TCP sockets, Instant deadlines, listener permits and observers. One holds the real connection slot while peer EOF proves connection destruction has begun, so it can verify that output resources were already released and the connection observation is still open. Their preexisting accepted/CPU values are observation fixtures; these tests do not perform durable native admission or W1 verification. The missing-connection branch retains its existing counters and terminal outcome; abandoned_tasks is a subset counter, not the complete failed-operation denominator. Complete request/connection observations retain the orphan completion.

No wire field, signed resource profile, worker count, numerical budget, W1 rule or original 4s/16 acceptance threshold changes. This enforces the existing r14 absolute work/overall/service bounds; it introduces no new namespace. The 2b4d7b46f runtime report is not relabelled as execution of this later source, and the original business gate remains unmet. Cancellation remains cooperative, not hard preemption of already-running provider/hash/SQLite calls.

After that correction, exact source `0647ba9e0a928e772946a2f055a2edfbe3fd2870` (tree `923c1aa59bc090baeff79979d950aebeec4def78`) passed strict workspace/all-feature/all-target Clippy, 229 reader/source controls, formatting, 444 exact source pins and a full tracked-byte guard (8,887 entries, 942,786,370 bytes). These checks do not execute the 23 new native regressions. Only public_v3.rs and its corpus pin differ from fc9; the Cargo graph and lockfile are unchanged. The source bundle now also includes this implementation commit.

Publication packaging also encountered ENOSPC while writing local Git objects and an initial verifier receipt. No remote ref had moved and that verifier did not start. The completed Clippy target cache was removed to restore local write capacity; all measured source history, raw reports, command logs and prior failures were retained. This later cache cleanup supplies no native execution result. See `publication-enospc-observation.json`.

A publication-time source-guard invocation made while the raw logs were staged returned `source is not clean`; that failed receipt/log are retained. Source formatting checks treat the captured raw logs as immutable evidence: the original Git bundle output has trailing spaces and the Cargo log has its original final blank line. Their bytes were preserved.
