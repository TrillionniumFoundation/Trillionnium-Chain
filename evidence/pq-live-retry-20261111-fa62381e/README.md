# C5: lossless evidence storage within the retained source-reader limit

> **Whole-chain qualification: HOLD. Production activation: false.**
>
> The S3 positive batch completed 64 named native controls. Its isolated
> old-behavior child reproduced five real native failures and two passes.
> The original strict Clippy and seven-observation supply-chain checks passed
> on S3. These are scoped observations, with their actual source identities
> and failed controls retained; they do not establish whole-chain PQ security.

**C4 completed with overall FAIL: corpus-source exit 1 and native-batch exit 1.**
Its 5,906,836-byte campaign archive exceeds the unchanged 4,194,304-byte
per-file source-reader cap. Its actual native batch passed 63 of 64 named
controls; strict Clippy returned 0. C5 changes the archive storage representation
to two ordered raw byte parts and an explicit manifest. That storage change
does not repair or relabel the separate native failure. No original result,
reader limit or qualification predicate changes. The successor still requires
its own committed-source checks.

This evidence update binds two scoped runtime fixes, dependency/source
maintenance and retained observations to their actual sources. It does not
establish whole-chain post-quantum security, production activation, quantum
mining security or an end-to-end lifetime error bound. The qualification state
remains `whole_chain_post_quantum_qualified=false` and
`production_activation=false`; the native evidence also retains its existing
`whole_chain_quantum_security_qualified=false` field.

This **new evidence namespace** preserves historical reports, input bytes,
command logs, source labels and failures. Artifact paths below are relative
to this directory. The evidence commit and its Root-register maintenance are
distinct from the S3 source actually built and tested by the native, Clippy
and supply-chain observations; their source labels are not rewritten.

## 1. Source identities and final execution ledger

| Identity | Commit / tree | Scope |
| --- | --- | --- |
| S1 runtime checkpoint | `7f83ea843d6d1578a475a7a0c4dc026da564a795` | The runtime fixes and dependency update; the selected-source lifetime and W1 implementation mappings retain this source checkpoint. |
| S2 maintenance and earlier hosted observations | `3c98e08e92094bb79ac811b682192d7252a7c325`; tree `34f4288927ec5e08430f7b2516db909859fab075` | Source maintenance, the earlier supply-chain observation, and the original hosted campaign failure described below. Its observations remain labeled S2. |
| S3 final maintenance source | `454ae116159867ff6cddd91b964523df7f7e16f0`; tree `3117250c4db0f2ae681d51ed6ee5e6a2fa7555a9` | Public source identity for the fresh positive run, strict checks and supply-chain run. It has S2 as its parent. Runtime `src`, Cargo manifests, both lockfiles and the original supply policy/helper/recorder are unchanged from S2; the reviewed Rust maintenance delta is the generated distributed source inventory. |
| N, isolated negative-control child | `f7c51532cc6657360b97226d9f396158253cea78`; tree `628f0d54ad9127471cc3902b50b915c4df2dcad7` | Committed child of S3, changing only the two identified behavior files back to the guard/witness behavior from `6c35f94d9387fac41c1547f05742d70150320b2e` while retaining the new tests. Preserve its exact lineage record; do not label its binary or failures as S3. |
| C4 evidence and Root-maintenance parent | `35b7c47f65ad0442cf1c459f5b16c9e9bcca0ed8`; tree `15fd9e7a2f4121dce861e9e96b78d8196d3892fb` | The actual committed source passed its full physical-source check: 28,315 tracked entries and 2,578,250,705 bytes. Its final 23-command run remained FAILED: corpus-source and focused-native-batch each returned 1; the other 21 commands returned 0, including strict Clippy. The native batch passed 63/64. The failed preparation and post-commit observer outcomes remain retained. |
| C5 storage successor | Identified by its actual final committed-source records and the PR execution ledger | Replaces the current-tree monolithic archive with two complete byte parts and their ordered manifest. Final successor outcomes are not assigned from S3, N or C4. |

The S3 commit name alone is insufficient to assign a result. The final records
must establish the actual physical source before and after the command, the
real compiled artifact and the actual terminal outcome.

| Retained observation | Required source and scope | Actual terminal result | Evidence location |
| --- | --- | --- | --- |
| Fresh positive **64** named native controls | S3; original 52 + supplemental 7 + five unique focused extras | **PASS: 64/64 named native tests; 52 retained + 7 supplemental + 5 unique extras; no skips or timeouts** | `positive64-summary.json`, `positive64-batch-summary.json`; complete command/source receipts, actual ELF identity and per-test logs inside `native-controls-s3-and-negative.tar.xz` |
| Isolated negative **7** named native controls | N, exact child of S3; original behavior restored only in the two reviewed files | **Observed: 5 actual native failures, each exit 101, and 2 passes; all 7 expected outcomes matched. Native batch remains exit 1 / command_failed; component validation remains false.** | `negative7-summary.json`, `negative7-batch-summary.json`, `negative-source-lineage.json`; complete real failures, source bundle and logs inside `native-controls-s3-and-negative.tar.xz` |
| Strict Clippy | S3; original required command, features and warning policy | **PASS: original recorder and launcher exited 0** | `s3-strict-clippy.json` and `strict-clippy-s3.tar.gz`; original 1800-second command, source-before/after identity, complete log and launch record |
| Original supply-chain policy and both locked graphs | S3; pinned cargo-deny 0.20.2, original helper/policy, archived actual advisory database | **PASS: all seven original observations exited 0; no timeouts; exact physical source verified before and after** | `source-records-desktop-s3.tar.gz`: S3 supply-chain manifest, complete observations and advisory snapshot; manifest SHA256 `ddc83487afd3d9841634ce6bda62c249a47a3cf3cc83351c3ff415afc76b099d` |
| C4 corpus-source gate | C4; original per-file source-reader bound | **FAIL: 5,906,836-byte file exceeds the original 4,194,304-byte cap.** This is the correct refusal. | [Complete C4 observation archive](c4-final-output-evidence.tar.xz): original `corpus-source.log` and source-bound command receipt. |
| Complete C4 execution | Actual committed C4; original 23-command record | **FAIL: outer exit 1, no outer timeout, complete terminal output.** Of 23 commands, 21 returned 0; `corpus-source` and `focused-native-batch` each returned 1. Source/provider/helper/final evidence guards all remained true. | [Complete C4 observation archive](c4-final-output-evidence.tar.xz); actual terminal summary is 41,868 bytes, SHA256 `1d894e92944e32cf5f2a883b8d3a1d747bb68669734efba7b0a0c52dd7e028d1`. |
| C4 native batch | C4; same retained 52 + supplemental 7 + five unique extras | **FAIL: 63/64 named controls passed: 51/52 retained, 7/7 supplemental and 5/5 extras; batch exit 1.** Retained control `pnq2-42` exited 101 with ConnectionReset on its exact replay; fixture cleanup completed. The inventory is not an additional control. | [Complete C4 observation archive](c4-final-output-evidence.tar.xz); native batch summary is 8,427 bytes, SHA256 `8346f4629b38f08b46240ec40ecf15b2a25f9d6e0afa4a5ba5fb7fecb25de7cb`. |
| C4 strict Clippy | C4; original workspace/all-targets/all-features command and warning policy | **PASS: source-recorded command and launcher returned 0.** This result does not make the native batch or overall C4 suite pass. | [Complete C4 observation archive](c4-final-output-evidence.tar.xz); original command receipt SHA256 `49b712d9468eee3608b68fe9aa5ce32c3cd7ac91a1992d22ddbc0269b5a4f37e`. |
| Final C5 candidate checks | Exact successor commit, original contracts and all current source files | **Requires the successor's own committed-source checks.** Their actual final results belong in the PR execution ledger; this evidence document does not assign a C5 PASS. | [Draft PR #908](https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/908) and its exact-source execution ledger. |
| Hosted observations, including exact-source CodeQL export | S3 head or each actually observed prospective merge | At 2026-11-11 16:18:15 UTC: 18 workflows succeeded, 5 failed, 1 remained in progress. S3 API export failed closed on HTTP 503; successful local SARIF is a separate observation. | `s3-ci-status-snapshot.tar.gz`; all original responses, annotations and complete retained logs |

### C4 failure and the storage successor

C4's complete physical-source identity is distinct from the bounded corpus
reader's acceptance. The full checkout check succeeded for the source listed
above; the separate corpus-source gate refused the 5,906,836-byte archive
because its original single-file cap is 4 MiB. Preserve that real failure and
its command output. A successful byte reassembly or local reader exercise does
not turn the C4 final suite into PASS.

The actual C4 terminal summary finished at 2026-11-11 17:50:45 UTC and records
all 23 commands. Twenty-one returned 0. The two failures are `corpus-source`
(exit 1) and `focused-native-batch` (exit 1); the native batch passed 63 of 64
named controls. Strict Clippy returned 0. The original corpus controls, all
43 Root controls on committed C4, the original report reader/reproduction and
byte comparison, claim controls and formatting also returned 0. Keep the
committed Root result distinct from the earlier applied/uncommitted
43-control observation.

The C4 Node lib build returned 0. It used the existing completed S3 target
directory, with actual Cargo `fresh=false` and `fresh_target_claimed=false`;
this is not labeled a fresh-target run. The recorded build interval was
641.971872953 seconds. Its actual compiled ELF SHA256 is
`486632abadaeb612945ecc51ac2364b682f85c892356a5527b7955311da0f1f2`.
The original source-before/final records agree, all 23 source receipts were
revalidated, and the provider, helper and historical evidence checks remained
true. These identity checks do not convert a failed native control into PASS.

The failed retained control is `pnq2-42`:

```text
store::pq_rollback_witness::combined_tests::guarded_npq6_submit_recovers_after_invalid_signature_and_independent_process_restart
```

Its actual native process returned **101**, with no owner timeout; the test
harness reported **6.55 seconds**, zero passed and one failed. The original
panic is at `combined_tests.rs:637:6`: `Result::unwrap()` received a transport
error, `Connection reset by peer (os error 104)` / `ConnectionReset`. The held
ELF was observed as `PINNED_AND_OBSERVED`. The first legitimate Submit and its
block assertions had already succeeded; this panic occurred on the second
`sender.send`, the exact replay. The subsequent independent-process restart
steps had not executed. The other retained controls passed, as did all seven
supplemental account/witness controls and all five extras.

The original parent phase diagnostic records `PQ_WITNESS_DEADLINE` for the
client CAS under the existing 250 ms request deadline. The enclosing mutation
commit did not attempt or finish its local commit. These observations identify
the failed phase; they do not establish the complete underlying cross-process
cause. Process-local operation identifiers are not treated as cross-process
correlation identifiers.

The original cleanup record reports `primary_error_preserved=true`,
`cleanup_complete=true`, `worker_join_observed=true`,
`child_exit_observed=true` and `child_exit_success=true`. Both worker and child
cleanup errors are null. Cleanup completion remains a successful observation
alongside the failed test. The earlier #901 cleanup-phase failure retains its
own diagnostics and unresolved root cause. No deadline, resource budget, selector or acceptance criterion
is changed to make it pass.

The complete 31,504-byte `c4-final-validation/batch/pnq2-42.log` has SHA256
`df7ff178df67e358a59e7c71458a08696646c9b74c03d09563341e864b3b845d`.
Its 2,370-byte native receipt has SHA256
`663cf0cf73323aae0d4a4ac8e036c56371329b21b44a41f6720b36b9db3ba916`.
Both are preserved inside the [complete C4 archive](c4-final-output-evidence.tar.xz).
The [C4 native batch summary](c4-native-batch-summary.json) records the actual
51/52 + 7/7 + 5/5 counts. The earlier S3 64/64 result remains a separate
source-bound observation.

The successor retains every original archive byte, the original member
manifest, verification, file list and transfer observations. Both parts and the
ordered manifest are explicit current-tree source files with their own corpus
requirements/pins and artifact-manifest identities. Only the oversized
monolithic current-tree entry is replaced; its full original identity remains
in the parts manifest and immutable C4 history. No current evidence file is
excluded from source coverage, and neither the source reader nor its limits is
changed. The successor still requires its own final source-bound checks.

Do not substitute a successful local CodeQL extraction/grid, diagnostic reader
or unrelated source analysis for a missing eligible exact head/merge analysis.
Do not convert an earlier S1 typecheck or S2 dependency-policy result into an S3
result. Where a final command does not complete, retain its real failure or
timeout rather than filling the table from another observation.

## 2. The two runtime fixes and their threat boundaries

### 2.1 Recheck the current account scope before classical network effects

`require_classical_network_settings` in
`trillionnium/crates/trnm-pon-node/src/ingress.rs` now invokes the existing
account-profile validator after the existing explicit-PQ classical-route
refusal. The check applies to the current local `Settings`, rather than relying
only on matching network/parameters/genesis identifiers or an earlier
successful settings construction.

The protected boundary is a local configuration inconsistency: invalid,
missing, mistyped or contradictory development-scope fields, or unavailable
native-PQ selectors, must be refused before the classical route constructs a
session, signs or authenticates a request, opens a socket, advances a replay
nonce, or starts the public-client work stages exercised by the controls.

The tests deliberately mutate internal settings while preserving the ordinary
network identity. They do **not** establish that a remote unauthenticated peer
can rewrite a node's private settings. A previously valid signed request must
be rejected if the node's current local scope is invalid. Valid development
scope retains its existing Ed25519 signature and socket behavior. An explicit
PQ selection retains the existing `AUTH_CLASSICAL_FOR_PQ_PROFILE` refusal
precedence.

This change does not upgrade ordinary development transactions to ML-DSA, add a
production authorization profile, or establish that every public, WAN,
bootstrap, recovery or operator path uses PQ TLS. The already implemented PQ
algorithms and explicit transport profiles retain their separate scopes.

### 2.2 Bind witness retry acceptance to independently retained provenance

The durable-witness owner now retains `retry_from=Some(previous)` in live
memory only after it successfully commits that compare-and-swap (CAS) edge.
When a duplicate CAS observes `current == next`, acceptance requires both that
live predecessor and the existing durable predecessor to match. SQLite
`previous_generation` / `previous_root` fields alone no longer establish that
the current live owner committed the edge. A changed durable predecessor at
the same current head is refused rather than accepted as an exact retry.

Cold reopen starts with `retry_from=None`. It therefore refuses replay of an
old CAS even when the independently retained current checkpoint is genuine and
the database's previous fields have not been modified. Signed `Current`
readback and valid new successors remain permitted; after a successful new
commit, exact live retry is permitted again. The retained controls also cover
independently pinned reopen and fencing after a failed local commit.

The boundary is retry provenance in the local durable-witness owner. The design
still relies on a genuinely independently retained current head/checkpoint and
the existing head pin. This memory field or dual-algorithm signatures cannot
detect coordinated rollback of the entire state together with all external
anchors. It does not establish independent operator custody, all recovery
paths, hardware-backed monotonicity or whole-chain PQ qualification.

The isolated negative run reproduced both witness assertions against the
original behavior as actual native failures, while the two compatibility
controls still passed. Synthetic parser and barrier checks are recorded
separately and are not counted as native execution.

## 3. Retained 52 + supplemental 7 + focused 5

The original `config/pon/pq-system-required-tests-v1.json` remains a **52-control**
roster, with SHA256
`31960141da6e571eaa373ac6374a956e1458b4eaf5beb622aa11bb145b89f3bc`.
Its child-process harness is not counted as an independent meaningful control.
The hosted original roster/count is not replaced by a different total.

The new `config/pon/pq-system-supplemental-tests-v1.json` is a separate required
**seven-control** roster with scope
`account-scope-and-witness-retry-provenance-only`. It preserves
`retained_meaningful_controls=52`, `expected_meaningful_controls=7`,
`original_business_budgets_changed=false` and whole-chain qualification false.
The existing named-test checker must confirm each actually executed full
selector; zero-match or harness-only success is refused.

| Supplemental control | Behavior verified on S3 | Actual outcome on original guard/witness logic in N |
| --- | --- | --- |
| `ingress::account_scope_tests::invalid_account_scope_refuses_classical_session_and_signed_request` | Reject invalid current scope | **Actual FAIL, exit 101**, at the reviewed scope-refusal assertion. |
| `ingress::account_scope_tests::current_local_scope_refuses_previously_valid_classical_request` | Reject under invalid current local scope | **Actual FAIL, exit 101**, at the reviewed scope-refusal assertion. |
| `ingress::account_scope_tests::invalid_account_scope_never_connects_or_advances_classical_clients` | No connection, nonce advance or public-client work for invalid scope | **Actual FAIL, exit 101**, at the reviewed connection-count assertion. |
| `ingress::account_scope_tests::valid_development_scope_retains_classical_signature_and_socket_path` | Preserve valid development behavior | **Actual PASS, exit 0.** |
| `ingress::account_scope_tests::explicit_pq_selector_retains_classical_route_refusal_precedence` | Preserve explicit-PQ refusal precedence | **Actual PASS, exit 0.** |
| `pq_rollback_witness::tests::live_retry_refuses_changed_durable_predecessor_at_the_same_head` | Refuse changed predecessor | **Actual FAIL, exit 101**, at the reviewed witness assertion. |
| `pq_rollback_witness::tests::cold_reopen_refuses_database_retry_history_and_accepts_new_successors` | Refuse database-derived retry history; accept valid new successors | **Actual FAIL, exit 101**, at the reviewed witness assertion. |

The focused positive runner forms a union of those **52 + 7** controls with its
existing witness, M12 recovery and cleanup selection. After deduplication it
requires **five** additional unique selectors and **64** actual named tests.
The final `selection_provenance` must retain all three exact sets and their
source manifest hashes. Do not count the overlapping focused controls twice.

The five extra selectors are:

```text
pq_rollback_witness::tests::known_checkpoint_preserves_exact_retry_and_unobserved_other_writer_progress
store::async_w1_generation_v2::tests::recovery_v3::lost_or_corrupt_cas_ack_recovers_same_operation_pending_without_redispatch
store::async_w1_generation_v2::tests::recovery_v3::independent_service_reopen_pin_rejects_restored_witness_database
store::async_w1_generation_v2::tests::recovery_v3::local_commit_without_external_commit_remains_quarantined_on_cold_reopen
store::pq_rollback_witness::combined_tests::guarded_npq6_valid_submit_cleanup_preserves_primary_error_and_child_diagnostics
```

The focused witness controls
`cold_reopen_requires_exact_independently_retained_checkpoint` and
`failed_local_commit_fences_owner_until_explicit_reopen` are already in the
retained 52. They are executed once, without increasing the unique total.

The completed positive execution records one fresh default-workspace-profile
Node all-features libtest build with two Cargo jobs, followed by the complete
64-control batch. Each control has its own original outer cap, actual exit,
complete stdout/stderr/log hashes and named-test result. The original in-test
business budgets remain unchanged. Source verification covers the actual
build and the batch, with a final source readback. The actual ELF and artifact
record are pinned before release and checked at use. Build coordination grants
no PASS and does not extend any test or business deadline.

The negative run uses a separate fresh build and separate release, exact
lineage to S3, and only the seven supplemental selectors. The observed old-code
counterexample is **five real failing native tests (exit 101) and two real
passing compatibility controls**. The separate expectation assessment matched
all seven outcomes. The nonzero native batch receipt is retained; this is not
seven passing native tests and `component_validation_passed` remains false.
The positive S3 batch completed all 64 named tests, while the negative child
records its own actual source, ELF and assertions.

## 4. Original S2 native campaign: three retained failures

The original hosted experiment is bound to S2, GitHub run **43026071397**, job
**130540971588**, and artifact **13858366171**. The original ZIP has **75,865,526
bytes** and SHA256
`7250117547e038c408cb9400d76759777f578c67979f0d0e3353dd7ee5051945`.
The native release ELF was recorded with SHA256
`b45215393abf3b311edc0146754f83c2a2a360a210c714eb225605642e234a26`
before and after its original runs.

The original build succeeded. All three planned complete campaigns failed with
actual native exit **101** after approximately **112.951, 112.783 and 112.470
seconds**. Their original 600-second outer cap did not fire. No phase startup
error or report-readback failure was recorded. Producer economics was complete
in all three runs.

| Original phase | Confirmation progress in each campaign | History import progress in each campaign | Retained business outcome |
| --- | --- | --- | --- |
| baseline | **1/3** signed-confirmation rounds | 14 calls, 13 successful; last call reaches the deadline at submit-result/activation | **FAIL** |
| from-zero | **0/3** | 7 calls, 6 successful; last call does not complete | **FAIL** |
| late-product | **0/3** | 7 calls, 6 successful; last call does not complete | **FAIL** |

These denominators are business rounds, not extra libtests. Each native test
invocation ran one whole campaign. The first panic in each retained stderr is
the original finite-experiment-criteria assertion at
`tests/public_v3_multiprocess.rs:1765`; the later catch-and-rethrow location is
not a separate root cause.

All nine phases report `PUBLIC_REQUEST_DEADLINE` within the same original
30-second phase window. The ordinary History importer consumes approximately
24.51–25.28 seconds of cumulative wall time per phase. Most final imports stop
at activation; campaign 2's two attacked phases stop earlier at
admission/commit. The final receiver/client mismatch accompanies incomplete
import/activation; this evidence alone does not establish that an invalid
ledger state was accepted or that a persistent fork occurred.

The measured path leads through `receive_public_page_from_before_observed`,
History `Control.check`, authenticated state/account-graph verification,
admission/commit/activation, and fresh `KernelBudget.check` observations. The
three baselines record **164,864 / 165,143 / 164,194 Host checkpoints**, with
about 4.1 seconds of separately recorded Host CPU each. Campaign 1's client
account-graph stage records 122 calls and about 17.114 seconds wall time.
These measurements include nested stages and different thread scopes; their
CPU or wall values must not be added or converted into an unsupported common
percentage.

The original fixed resource placement remains material: controller CPU 400%
and memory 16 GiB; receiver and verifier under the original public Host parent
with CPU 25% and memory 2 GiB. Actual cgroup throttling was observed. It does
not authorize changing those limits or bypassing the fresh resource checks.

All six attacked phases also fail the independent original genuine paid-credit
depletion condition. Their observed minimum paid credit remains approximately
**1.9748–1.9834 seconds**, with original burst 2 seconds and reserve 0.1 seconds.
Physical CPU throttling, queueing and booked reservations are not paid-credit
depletion. Campaign 2 late-product additionally records one measurement
failure and incomplete observer coverage; that additional failure is retained.

The three failures establish unmet finite business qualification under those
recorded inputs and resources. They do not establish a regression caused by
the two runtime fixes, a provider failure, or a proven safe one-line repair.
The cost attribution is a direction for further implementation work, not
permission to remove checkpoints, cache a Host verdict, enlarge readback
authority, increase resources, shorten the attack or extend the deadline.
Any future candidate must preserve those boundaries and satisfy all original
confirmation, depletion, overlap and coverage predicates in the original
three-run campaign.

### Complete counterexample retention

[The complete original campaign archive in C4 history](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/35b7c47f65ad0442cf1c459f5b16c9e9bcca0ed8/evidence/pq-live-retry-20261111-fa62381e/native-campaign-failure-evidence.tar.xz)
contains **100 verified members**, including **86 original artifact members**:
all three full raw reports, economics/preparation records, stderr/stdout,
phase readback, original source/resource/build/Host records and the original
runner. It excludes the original ZIP container, ELF, databases and build
products. Archive metadata are normalized; every complete member was reopened
and hashed after compression.

| File | Bytes | SHA256 |
| --- | ---: | --- |
| `native-campaign-failure-evidence.tar.xz` (reconstructed / C4 historical archive) | 5,906,836 | `6c8a6fa91659283a7d7ad85795a82dfc7ea8f3f64cfb39d5a0c2a20465a7757b` |
| `native-campaign-failure-evidence.manifest.json` | 48,584 | `357bc091c19faa009c385503acc3e8927c2c91ac32c9c3c158c869dc2e8a4522` |
| `native-campaign-failure-evidence.verification.json` | 18,181 | `1ed7f162248fb00ea222449127b57039c211883c828e8251a19f65ca1ce8950a` |
| `native-campaign-failure-evidence.filelist.tsv` | 15,142 | `f9cc0676c69ddb01642fa9dca4812c6b0d571d4cda6a7a24b87eba7e9963cb9f` |
| `FINDINGS.md` (presentation copy) | 10,959 | `fd960b4cad68a046b207496ed4089e89a1c3ee6a2a821fd6b6191e9b2bc8b0b0` |

The top-level `FINDINGS.md` is a presentation copy with exactly one terminal LF
removed. Its original 10,960 bytes, including the extra final blank line, remain
unchanged as the `FINDINGS.md` member of the frozen
`native-campaign-failure-evidence.tar.xz`, with SHA256
`3e2bb3f073b5762045941b3623ede1fea283127bdae1e03b3ab3a1e85c50bd6f`.
The original archive and its manifest, verification and file-list records keep
their recorded bytes and identities; the top-level artifact manifest and corpus
pin identify the normalized presentation copy separately.

The initial C4 commit preparation stopped before `git commit`: the original
`git diff --cached --check` returned exit 2 for `FINDINGS.md:87` (a new blank
line at EOF), and the outer command returned exit 1. That failed observation
is retained. This one-byte presentation correction preserves the whitespace
check and changes no analysis, original report, native outcome or business
criterion.

The next commit attempt did create C4 successfully: its normal `git commit`
returned 0, its original full physical-source check returned 0, and post-commit
clean/source checks completed. The outer observation then failed with exit 1
when its final summary attempted to create `commit.json`, a name already used
by the successful commit command receipt. The original receipt was preserved;
this observer filename collision does not mean that no commit occurred.
The independent reconciliation and complete C4 observation package retain both
states without another commit or an overwritten receipt.
The original [source reconciliation](c4-source-reconciliation.json) is
3,113 bytes, SHA256
`4297e7bcef207b9c5f2f67a5460d7c063571aa5bb72a4c1c0f29d1be2c2f89dc`.
It records the actual successful commit and physical-source command while
preserving the original outer exit 1; it did not replay the commit or overwrite
any original receipt. The complete observation archive below includes the
original command receipts, logs and the independent reconciliation.


### Complete C4 outcomes retained without changing their verdicts

The [C4 observation archive](c4-final-output-evidence.tar.xz) is **243,888
bytes**, below the unchanged 4 MiB source-reader limit. It contains **317
members: 316 payload members plus its manifest**. The collector completed with
exit 0 and full compressed-stream/member readback. That successful collection
retains the original C4 run's overall **FAIL / exit 1**, its two failed command
labels, and the native **63/64** result.

The archive preserves the complete C4 command and owner logs, all 23 source-bound
command receipts, native transcripts and executable identity metadata, frozen
observer/helper source, and the original commit-observer failure and successful
source reconciliation. It does not contain the compiled ELF, private keys or
private transport requests. [The archive member manifest](c4-final-output-evidence.manifest.json)
and [independent readback verification](c4-final-output-evidence.verification.json)
identify the exact retained bytes; [the failed-command summary](c4-failed-command-summary.json)
keeps both actual nonzero commands explicit. These eight current-tree files
are individually included in the artifact manifest and corpus source pins.

| Retained C4 file | Bytes | SHA256 |
| --- | ---: | --- |
| [c4-final-output-evidence.tar.xz](c4-final-output-evidence.tar.xz) | 243,888 | `9cd12948d25bc1a08f9c86eb79c3b03555a223671cea3a67aef90c95c9798176` |
| [c4-final-output-evidence.manifest.json](c4-final-output-evidence.manifest.json) | 106,949 | `bec0f8183313300be9bf3725f9c6b453aa9923ff66ce083058b887d67756feab` |
| [c4-final-output-evidence.verification.json](c4-final-output-evidence.verification.json) | 36,887 | `dff3c28f4a80af0e1c194c08fef702c5d852ded05baaafce3329af8b846fc9c5` |
| [c4-final-output-evidence.archive.json](c4-final-output-evidence.archive.json) | 1,091 | `10f0594746a548c2c325148c9bbc518f304403d0fb54b1ca5d250f146737943c` |
| [c4-final-summary.json](c4-final-summary.json) | 41,868 | `1d894e92944e32cf5f2a883b8d3a1d747bb68669734efba7b0a0c52dd7e028d1` |
| [c4-native-batch-summary.json](c4-native-batch-summary.json) | 8,427 | `8346f4629b38f08b46240ec40ecf15b2a25f9d6e0afa4a5ba5fb7fecb25de7cb` |
| [c4-source-reconciliation.json](c4-source-reconciliation.json) | 3,113 | `4297e7bcef207b9c5f2f67a5460d7c063571aa5bb72a4c1c0f29d1be2c2f89dc` |
| [c4-failed-command-summary.json](c4-failed-command-summary.json) | 1,053 | `ce978cd9b4aab97303d02e3e91d3009da9e6cf258ee438cfb2a1e327fcb10895` |

### Original campaign archive storage

The complete original S2 campaign archive remains in [C4 history](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/35b7c47f65ad0442cf1c459f5b16c9e9bcca0ed8/evidence/pq-live-retry-20261111-fa62381e/native-campaign-failure-evidence.tar.xz); the [immutable full-download URL](https://raw.githubusercontent.com/TrillionniumFoundation/Trillionnium-Chain/35b7c47f65ad0442cf1c459f5b16c9e9bcca0ed8/evidence/pq-live-retry-20261111-fa62381e/native-campaign-failure-evidence.tar.xz) identifies that same C4 object. The current tree stores its exact bytes as two ordered parts so that each pinned file fits the original 4,194,304-byte source-reader limit. The checker and reader are unchanged. [The ordered parts manifest](native-campaign-failure-evidence.parts.json) binds both part sizes and hashes, their order and offsets, and the complete original archive identity.

| Ordered part | Bytes | SHA256 |
| --- | ---: | --- |
| [Part 000](native-campaign-failure-evidence.tar.xz.part-000) | 4,194,304 | `f52587354338163d3e52046049bb4646cbecf4365c69735b866f7089644d54ab` |
| [Part 001](native-campaign-failure-evidence.tar.xz.part-001) | 1,712,532 | `8154c24e6ac7b57887c4f93bfa6016abb60d63cebbdeaa38f6cc0bd18542f638` |

From this evidence directory, concatenate the two parts into a new temporary directory outside the checkout. Require the complete original byte count and SHA256 before using the result:

```sh
(
  set -eu
  reassembly_dir=$(mktemp -d "${TMPDIR:-/tmp}/trnm-campaign-reassembly.XXXXXX")
  cat native-campaign-failure-evidence.tar.xz.part-000 \
      native-campaign-failure-evidence.tar.xz.part-001 \
      > "$reassembly_dir/native-campaign-failure-evidence.tar.xz"
  test "$(wc -c < "$reassembly_dir/native-campaign-failure-evidence.tar.xz")" -eq 5906836
  printf '%s  %s\n' \
      '6c8a6fa91659283a7d7ad85795a82dfc7ea8f3f64cfb39d5a0c2a20465a7757b' \
      "$reassembly_dir/native-campaign-failure-evidence.tar.xz" \
      | sha256sum --check -
)
```

The expected size is **5,906,836 bytes**. The original archive member manifest, file list, verification report and transfer observations retain their existing bytes and historical identities. Reassembly does not rerun the original campaign, change its failures, or grant any security or production qualification.

The ordered manifest itself has **2,162 bytes**, SHA256
`9fb7fe38c0f01019bf29d7fc844005697652bff93d4db9e28fa75a2360fe49e8`.
The raw byte parts have offsets 0 and 4,194,304; their listed sizes sum to the
original 5,906,836 bytes. The first part equals the existing limit and the
second is smaller. The complete original archive has Git blob identity
`9b29a146004222acfc73404f69b7a66704e543cc`.


The original [archive member manifest](native-campaign-failure-evidence.manifest.json)
maps each archived member to its original ZIP member or derived analysis, with
size and SHA256. The raw report hashes remain:

| Original member | Bytes | SHA256 |
| --- | ---: | --- |
| `run-1-raw/report.json` | 43,777,179 | `c7583275f6eada884e0f9f5962af6c863a66cfcdfa93b94a0e76f79af6b5c6bb` |
| `run-2-raw/report.json` | 43,487,265 | `b70c00eac55a97e9435d1ab9880427738e9fee1c480ec2caeb617d3f998cab50` |
| `run-3-raw/report.json` | 43,788,976 | `6cde8bea5bbcdb81b3c9072cd450597bd7e8bb0d100d3771747182ae2c632120` |

The first bounded evidence retrieval succeeded at HTTP Range: all 18 responses
were 206, obtaining eight small members and 422,007 bytes. Its temporary 1 MiB
compressed / 8 MiB uncompressed per-member limits refused the first 43.8 MB raw
report. This was a collection-limit failure, not lack of Range support and not
a native failure. The later full ZIP fallback matched the published complete
size and SHA256. The retained collection observations do not change any native
result. **Collection integrity PASS and original native FAIL are separate
statements.**

## 5. Provider and observation infrastructure

The retained official provider preparation uses the original pinned helper and
OpenSSL 3.5.9 source identity. Its successful preparation includes the original
build, ML-DSA signing/verification and wrong-message rejection smoke, while
earlier failed preparation attempts remain preserved. The provider archive
`provider-evidence.tar.xz` is a preparation record, not a Node test receipt or
whole-chain qualification.

The fresh native runs must use their actually observed provider environment
and artifact hashes. Explicit `OPENSSL_LIB_DIR` or `OPENSSL_INCLUDE_DIR`
overrides must not silently select another provider. Pin the actual compiled
ELF and record all command results; do not infer runtime linkage from a version
string alone.

The observer/parser/barrier synthetic controls exercise only the temporary
observation machinery. Their real result, when retained, must explicitly keep
`actual_native_tests_executed=false` and `native_builds_executed=false`. They
cannot fill a missing entry in either native roster. Similarly, a successful
source pin refresh, reader refusal test, artifact restoration or report
reproduction is evidence for that operation alone.

### Current Root dependency-register maintenance

The S3 repository-truth head job executed its original 43 controls and failed
with four failures and one error, beginning with the stale workspace lockfile
pin. The original complete log is retained in `root-register-c4-review.tar.gz`.
All 41 declared source files were independently reviewed against S3. Exactly
three pins changed: `trillionnium/Cargo.lock`, the crypto-primitives Cargo
manifest and the pon-node Cargo manifest, all for the existing Rustix 1.1.4 to
1.1.6 remediation. The other 38 pins, 41-path roster, six roles, algorithms,
feature selections, refusal conditions and qualification flags remain intact.

The current map/checkpoint and reader's frozen digest were updated after that
review. Its source-map digest is
`0a6cb7dc497a9365e0538b0ab7de510c28068ef0f0b211d0f0971b460a7302d4`.
The original 43 controls then all passed on the applied, uncommitted C4
maintenance snapshot. `root-register-maintenance-observations.tar.gz` preserves
that actual scope, complete output, selected hashes before/after and the
separate zero exit. This preliminary observation is not relabelled as a clean
committed-source or native execution result.

The [new current report](root-dependency-register-current-report.json) has
SHA256 `ba105760040e55b26e7c24c3074da6f274920a844d91c6c9606bb5415a6d0678`.
It remains `HOLD`, with eight null domain failure bounds and a null actual
lifetime failure bound. Its `source_revision_bound=false` is intentional: it
checks the declared source files and frozen map, rather than authenticating a
Git commit or the deployed protocol. No historical report was rewritten.

### Physical checkout recovery before the S3 freeze

The initial repository gate found 114 missing tracked compressed files,
representing 798,951,930 bytes. Their Git index entries carried skip-worktree
flags, while the corresponding Git objects were available locally. The
observation does not identify when or by whom that state was introduced.

The first restore launch remained unknown. Before a distinct restore attempt,
a create-only entry fence prevented that old attempt from entering its source
write phase if it ever launched late; it was not reported as a proved
terminated process. The subsequent actual restore verified the exact Git blob
and SHA256 for all 114 files and cleared the stale flags. It preserved the ten
planned S3 maintenance changes. The original repository check then completed
successfully; the original failed gate and recovery records remain in
`tracked-source-restoration.tar.gz`.

Fresh S3 builds and hosted checks later independently verified all 28,284
tracked entries and 2,567,446,061 bytes before and after their own commands.
This recovery did not alter those tracked artifact blobs or become a native
security test.

## 6. Hash, PoN and lifetime qualification

**Whole-chain post-quantum qualification remains unestablished.** The retained reports keep `whole_chain_post_quantum_qualified=false` and `production_activation=false`. This evidence update records source identity, reader and control behavior, dependency-policy results and actual native outcomes. It does not supply a quantum mining lower bound, a theorem for the deployed chain, or permission to publish a whole-chain post-quantum claim.

### Source and observation boundaries

| Source | What is bound to it | Qualification boundary |
| --- | --- | --- |
| **S1 runtime:** `7f83ea843d6d1578a475a7a0c4dc026da564a795` | The current selected-source lifetime survey uses this checkpoint and 20 exact source pins. Its refresh changes the crypto-primitives manifest and workspace lock pins; the other 18 selected pins remain unchanged. The current W1 implementation mapping also uses the recorded S1 checkpoint, with 16 selected project files and 138 closure pins. | These are selected-source surveys. They do not certify every authority path, an exhaustive hash inventory, the whole repository's behavior or a lifetime security bound. |
| **S2 maintenance / old hosted CI:** `3c98e08e92094bb79ac811b682192d7252a7c325`, tree `34f4288927ec5e08430f7b2516db909859fab075` | The original seven-observation supply-chain run completed against this exact clean source, with actual before/after source records, cargo-deny 0.20.2 and the archived advisory database. Existing hosted CI observations retain their actual head or prospective-merge source labels and outcomes. | S2 results remain S2 results. In particular, the ARM64 head service-model job first failed the original release from-zero step with exit 1; its streamed log does not establish the failing inner assertion or a resource-exhaustion cause. |
| **S3 final maintenance / fresh native observations:** `454ae116159867ff6cddd91b964523df7f7e16f0`, tree `3117250c4db0f2ae681d51ed6ee5e6a2fa7555a9` (public branch identity confirmed) | S3 has S2 as its parent and the reviewed ten-file maintenance delta. The reviewed hosted head jobs independently verified this exact physical source before and after execution (28,284 tracked entries; 2,567,446,061 bytes). The fresh desktop supply-chain run also passed its own original full physical-source guard and all seven original observations with per-command before/after source verification. Its actual terminal state is succeeded / exit 0. The separately recorded fresh positive native batch passed all 64 named controls; the isolated negative child retained five actual failures and two passes. Strict Clippy also completed with exit 0 on S3. Relative to S2, the reviewed Rust change is the generated `examples/support/distributed_source_inventory.rs`; production `src`, Cargo manifests, both lockfiles and the original supply policy/helper/recorder are unchanged. | The S3 supply result applies to this exact dependency-policy execution; it does not assign native or whole-chain qualification. Record fresh native terminal outcomes separately. The S2 source labels remain on old receipts. |

The preserved pre-freeze QROM maintenance observation explicitly says `source_scope=uncommitted-maintenance-selected-input-snapshot`, `whole_repository_source_verified=false` and `github_workflow_execution_claimed=false`. Its selected input hashes were checked before and after execution. Matching those files to the recorded S3 bytes preserves the observation's scope; it does not turn that run into a fresh S3 native or hosted-CI run.

The later hosted S3 observations are retained separately from the pre-freeze maintenance run: [closure head job 130596764262](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/43042229658/job/130596764262), [implementation head job 130596764987](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/43042229838/job/130596764987), and [four-axis evidence job 130596763511](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/43042229620/job/130596763511). All reported steps completed successfully, and all three original before/after source identities match S3. The saved complete logs establish the actual named controls and reproduction stages below; this is more specific than a workflow-level success label. Four-axis also executed the original inventory check and source/resource controls; its retained-record reproduction is not a fresh native campaign.

### What the control counts establish

| Recorded controls | Established scope | Remaining qualification |
| --- | --- | --- |
| **105 fixed-roster QROM closure controls**, including **19 lifetime controls**, and all **seven report reproductions, each with its byte comparison** | The original roster is retained byte-for-byte: SHA-256 `ee2b11492a362bd4be2f2df4e7ad691f4dd8a78cd9df884979cb3409e117745f`. Both the pre-freeze observation and the later hosted S3 head log retain the completed 105-control roster. The hosted run actually executed suite counts 19/16/10/22/9/8/21, printed all seven OK summaries, and validated named completion twice; every required stage succeeded. The 19 lifetime controls are part of the 105, not an additional disjoint suite. The seven reproduced reports matched their committed or successor reference bytes. | This is reader, accounting, source-refusal, artifact and completion-control evidence. It supplies no mining lower bound, physical adversary limit, deployed-chain security proof or new cryptographic assumption. |
| **14 current-implementation controls** | The current mapping reader and its source/identity refusal controls passed on their recorded maintenance inputs and again in hosted S3 head job 130596764987. Its 14 distinct CurrentImplementationTests each completed with ok; the supplemental-current completion and final exact-source stage validator both succeeded. The 138 closure pins were refreshed only where the actual manifest/lock source changed. | **15 obligations remain unresolved** in the current implementation mapping. Passing the mapping controls does not discharge those obligations. |
| **26 proof-profile controls** | The root-owned descriptor and mapping-pin maintenance check passed all 26 controls on its recorded inputs. | The profile retains **15 unresolved obligations and eight unknown native terms**, with whole-chain qualification false. Those eight terms belong to that profile's accounting; they are not a count of every unresolved chain domain. |

These control counts have different scopes and may overlap. They must not be added together as independent security evidence.

### What remains unknown

The [lifetime successor report](lifetime-report.json) preserves the all-unknown numerical input and the previous qualification decisions. Its input bytes remain equal to the historical all-unknown input; the source checkpoint and the two changed source pins explain the report refresh. Historical input/report files remain unchanged.

The ledger's three acceptance lines remain independent and unqualified:

| Acceptance line | Remaining evidence |
| --- | --- |
| **PQ authorization** | Complete coverage of authority-producing entry points and actual effects; current trust roots and custody; migration, revocation, replay and rollback composition; implementation and side-channel assessment; a lifetime, multi-user authorization bound. |
| **Complete computation relation** | The whole permitted relation and control programs; recursive and state-restoration behavior; vector-commitment extraction assumptions; the concrete shared-hash/transcript model; an instantiated composition theorem and its lifetime error bound. Native full replay and the isolated succinct-proof candidate retain their separate scopes. |
| **Quantum work and chain weight** | The cheapest legal attacker strategy, preprocessing and task reuse, marked-set sizes and all query costs; hardware, data-access and error-correction calibration; actual adaptive target/timestamp/restart/withholding/propagation behavior; a named common-prefix or confirmation result under equal additive resource budgets. A fixed-context reversible oracle construction is evidence about a construction, not a lower bound against all legal strategies. |

The selected hash survey includes shared Poseidon2, SHA-256, SHA-384 and SHA-512 uses, ML-DSA XOF use and an explicit `other_unmapped` group. Distinct purpose tags do not establish independent random oracles; coherent queries may address several tags, and their real shared-oracle cost still needs accounting. This update provides no new exhaustive migration argument for old roots, historical commitments, protocol-version transitions or every remaining hash purpose. SHA-512 commitment candidates do not by themselves close those obligations.

The lifetime accounting requires one common budget covering offline work, all identities and processors, failed or abandoned attempts, recursive/delegated/cross-protocol work, reorganization and protocol upgrades. The extractor, relation-decider and oracle-simulator overheads and the Fiat–Shamir/vector-commitment online masses remain explicit. Request meters and native permutation counts do not establish an external adversary's abstract quantum-query budget. Uniform conditional bounds must hold under the same prior history, offline information, quantum auxiliary state and lifetime-query envelope; marginal or accepted-only bounds are insufficient for this ledger.

Consequently the retained outputs still have `coverage_exhaustiveness_proved=false`, `quantum_query_unit_instantiated=false`, `uniform_conditional_premises_verified=false` and `composition_theorem_instantiated=false`. The project total error upper bound and target verdict remain `null`, and each independent line keeps `qualified=false`, `security_error_upper=null` and `security_bits=null`. Reader success, source freshness and supply-chain remediation do not convert any of those unknowns into a proved security value.

## 7. Public CI observations and release disposition

The dated S3 snapshot retains all 24 workflows. At 2026-11-11 16:18:15 UTC,
18 had succeeded, five had failed and the required baseline was still running.
The PQ network/witness workflow completed all 16 jobs successfully. CPQ full,
Chain Hepta closure and the original workspace workflow also succeeded within
their own source labels and contracts. These workflow statuses are not counted
as extra independent cryptographic proofs.

The following different failures remain separate:

| Observation | Actual retained finding |
| --- | --- |
| S3 repository-truth head | The unchanged 43-control Root register suite produced four failures and one error from stale source pins. The successor maintenance and its actual preliminary 43-pass result are recorded above. |
| S2 and S3 original native campaigns | Original acceptance criteria failed; actual nonzero native runs are retained. The complete selected S2 raw reports remain available, including its public deadlines and incomplete observation. Later local controls do not erase these campaign failures. |
| S3 ARM service-model from-zero owner | The original artifact shows five named release tests passing, but the separate original confirmation target fails. Under the four-second window the baseline confirms one transaction; the 16-worker pressure run confirms zero of one. Its report retains PUBLIC_REQUEST_DEADLINE and only six of seven independent page replays completing in the original window. The original validator raises CONFIRMATION_TARGET. This is an acceptance failure, not a failed named test or evidence of OOM. |
| Other service-model matrix failures | Three other matrix jobs retain their own head/merge source labels and original service-step exit 1. The ARM head artifact's CONFIRMATION_TARGET is not assigned to those jobs without their own original reports. |
| S3 W1 fresh-service owner | The visible original wrapper reports failure after a successful native preparation. A later diagnostic test-only panic is not substituted for its original inner cause. |
| Priority history | The x64 head and merge 4105-block paid full-sync steps failed; the corresponding ARM history jobs succeeded. The available observations do not establish the x64 inner cause. |
| Baseline cross-architecture cost | Both x64 and ARM jobs failed their original from-zero cost stages. Their actual exit/step records remain; no unobserved inner cause is substituted. |
| Priority retained pressure | The requested historical artifact list contains zero entries for the fixed artifact, so download fails. The observation alone does not establish deletion or expiry. |
| CodeQL API export | The original S3 exporter reports HTTP 503 while reading PR #908 and fails closed. The separate successful local SARIF lane does not fill this missing export. |
| Two macOS cleanup cancellations | Official annotations report unsuccessful runner allocation, with an ARM64 capacity notice. These jobs were not executed and are not counted as passes. |
| Two baseline protocol cancellations | Official annotations report the original 45-minute maximum execution time. These are distinct from runner-allocation failures. |

The original ARM service artifact is retained by exact source, original
manifest hashes and official ZIP digest in `s3-arm-from-zero-evidence.tar.xz`.
Its native execution completed while acceptance failed. A legacy
`execution_finished=false` field does not override the actual completed-child
and failed-acceptance records. No confirmation target, Host check, replay
boundary, admission limit or original deadline is relaxed to change this
outcome.

The prior S2 native campaign's full evidence ZIP is independently identified by
its original digest. Its selected complete reports are archived separately.
An interrupted chunked transfer was not treated as publication: four chunks
were confirmed, the fifth remained unconfirmed, and commit was never sent.
The independently recorded fixed-ZIP reconstruction delivered the exact
original selected archive: 5,906,836 bytes with SHA256
`6c8a6fa91659283a7d7ad85795a82dfc7ea8f3f64cfb39d5a0c2a20465a7757b`.
All six delivery outputs were independently read back and verified. `transfer-observations.json` preserves the
real transfer errors and readback result without private transport requests.
These are collection observations, not native execution outcomes.

## 8. Evidence index and qualification boundary

[The delivery manifest](evidence-artifact-manifest.json) records each retained
file's actual size and SHA256. It excludes itself from its own hash list. The
corpus binds the explicitly reviewed current files and source records. The
successor replaces exactly the oversized archive's current-tree requirement/pin
with requirements/pins for both raw parts and their ordered manifest. All
unrelated prior required paths, pins, unknowns and refusal contracts remain;
the complete monolithic bytes and their historical pin remain in C4 history.
Every current evidence file remains covered.

| Evidence | Contents and scope |
| --- | --- |
| [Complete C4 outcomes](c4-final-output-evidence.tar.xz), [C4 summary](c4-final-summary.json), [failed commands](c4-failed-command-summary.json) | Original C4 overall FAIL, 23 source receipts, actual 63/64 native result, strict Clippy exit 0, complete failure/cleanup logs and preserved commit-observer reconciliation. |
| [Native observations](native-controls-s3-and-negative.tar.xz) | Complete S3 positive64 and N negative7 logs, exact source/ELF receipts, actual observer scripts, release decisions, isolated source bundle, original preparation failure and separately labeled synthetic controls. |
| [Positive summary](positive64-summary.json), [negative summary](negative7-summary.json), [negative lineage](negative-source-lineage.json) | Original readable bytes copied from the actual observations; not rewritten for the evidence commit. |
| [Strict Clippy](strict-clippy-s3.tar.gz) | S3 original command, source-bound receipt, complete log, provider launch and completed-native prerequisite guard. |
| [Desktop source records](source-records-desktop-s3.tar.gz) | S2/S3 supply-chain raw checks and advisory snapshots, prior source refusals, historical-object restoration, QROM/current-source maintenance and original report comparisons. |
| [Controller source records](source-records-controller.tar.gz) | The original #901 failing quality artifact and advisory/source review. |
| [Original S2 campaign storage](native-campaign-failure-evidence.parts.json) | Two ordered raw byte parts reconstruct the complete original archive; the immutable C4 copy, full raw reports, original criteria, ZIP identity and collection observations remain preserved. |
| [Root register review](root-register-c4-review.tar.gz), [maintenance observation](root-register-maintenance-observations.tar.gz) | The complete 41-file review, prior map and original 43-control failure; then the distinct applied-candidate 43-pass observation and HOLD report. |
| [S3 hosted control logs](s3-hosted-controls.tar.gz) | Original complete logs establishing the actual 105-control closure, current14 and four-axis source stages. |
| [S2 public CI records](public-ci-observations.tar.gz), [S3 CI snapshot](s3-ci-status-snapshot.tar.gz) | Dated official responses, failures, cancellations and annotations with actual source labels. |
| [S3 ARM confirmation failure](s3-arm-from-zero-evidence.tar.xz) | Original artifact metadata, complete required reports and named receipts, actual confirmation gate and independently verified source identity. |
| [Provider preparation](provider-evidence.tar.xz) | Original fresh OpenSSL source/provider observations and retained preparation failures, excluding keys and compiled provider binaries. |
| [Tracked-source recovery](tracked-source-restoration.tar.gz) | Original missing-file observation, effect fence and exact restoration records; no source payload duplication or security qualification. |

The final committed candidate must retain its own original source-bound
checks and any subsequent failures. The S3/N evidence here supplies no result
for a different commit by inheritance. The storage successor changes no Rust source, Cargo
manifest, lockfile, source-reader limit, cryptographic domain or business budget. Its source-file
inventory is generated by the original tool and checked separately.

**Whole-chain post-quantum qualification and production activation remain
false.** Ordinary classical account execution, complete transport/recovery
coverage, independent custody and freshness, historical commitments, quantum
work/chain security and uniform lifetime composition premises remain separate
unclosed obligations. This update establishes the scoped engineering changes
and actual observations above; it supplies no whole-chain PQ product claim.
