# Receiver verification evidence

This directory retains original execution records with their exact tested
source and observed failures. Implementation qualification and the publication
source's external closing receipts are separate. Adding these records to a
commit does not transfer a prior revision's test result to that new commit. The sole development plan remains
`docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md`.

## Sources and changes

| Revision | Commit | Tree | Meaning |
| --- | --- | --- | --- |
| Baseline #940 | `8970e2c81abbf48e2a4d3f0802d79624ab20fadd` | `fbd1a451b911d218bbb48548892fc8cd53eaf66b` | Existing integration baseline. |
| V1 | `e974fd617e0e2c0d1fc88584b1301a7ffb714a73` | `4b72a88414c8ce17f7ef33fc3aa9a346028452cb` | Refusal-output ownership and exact deferred authenticated-request recovery. |
| V2 | `a878584d10f13ea5cd6f35130033457658985b51` | `263d7d3df6b47da2dbdcd0634d57bd6cccd9ebbd` | Registers the omitted new regression file in distributed inventory and updates its corpus pin. |
| V3 | `a9909fe579dd938005b9d17074f7937c8fa8eb98` | `534518db8a76707a36bda82d8b5c530f16eee872` | Corrects two test assertions to the actual framed-client `FrameEof` code and updates the corpus pin; production code is unchanged from V2. |
| V4 | `97aa8539aad3ee7f497136c6d2f64e420605c1fa` | `ff4a423084e02e438b0bb9f8d238cd7e32ff2e3d` | Boxes both test-client variants and uses `expect_err` in the new fixture, with its corpus pin updated; production code is unchanged. |
| Final V4 counterfactual | `570801af9995a65f3f6c12a339bbca935e32282b` | `1c55152a221697e8dd37385b5cb6c85c1f4d33d8` | Same final fixture bytes with the targeted implementation functions restored; five selected native assertions fail at the reviewed regression sites. |
| Prepared V3 counterfactual | `a464210ab88088fb27237a711bab819403ac0ab3` | `be774f69dcced620d46caad2d96d6b48b324f861` | Source preparation only; native execution did not occur. The final V4 comparison is recorded separately as 570801af. |

Public V3 previously serialized and signed an output-capacity refusal without
an output permit. r15 reserves its bounded refusal in the same 32 MiB pool:
2/8 KiB classical/PQ frames with fourfold conservative byte allowance; at most
64 KiB of the original 512 KiB control reserve is available to refusals,
leaving 448 KiB for control output. No refusal permit means no response
encoding/signature and no native dispatch from this initial capacity branch.
The final receiver owner also refuses materialized bytes without a permit.
PQ signing keeps the original authentication account. This is conservative
software accounting, not a whole-process RSS or complete CPU qualification.

The authenticated owner retains the original payload/nonce for exact typed
`UnknownParent`, `TimeDeferred` and `AdmissionHeaderEpochChanged` retries,
alongside prior cancellation and exact queue-busy cases. It does not grant
retry authority to all errors or change deterministic block validity.
This corrects request recoverability, not an established consensus split.
r10–r14 raw policy vectors and r13–r14 arithmetic vectors remain historical;
r15 and its derived arithmetic profile use fresh resource identifiers.

## Observed outcomes

| Source/lane | Observation | Scope |
| --- | --- | --- |
| e974 static | 18/19 commands succeeded; overall FAIL at the actual distributed-inventory check. All 16 unittest-file runs reported OK, totaling 742 test executions. | Executions are not claimed to be unique tests across imported suites. The inventory failure remains failed after its later source fix. |
| e974 compile | All-feature test build recorder exit 0. | `cargo test --no-run`; no native tests were executed by that command. |
| a878 static | Final runner summary PASS, 19/19 commands, source-after success and exact clean source. | Raw stages and summaries are retained under `a878/static`. |
| a878 native | Original output-reservation selector: 2 failed, 0 passed, 0 ignored, 1,424 filtered; exit 101. | The client reported `FrameEof`, while the new assertions expected `PublicEof`. The original failure is retained; unexecuted later lanes are not counted as passing. |
| e974/a878/a990 Markdown | Each original repository gate passed: 6,877 local links, 1,485 Rust files, 26 packages; preflight and source-before/after checks passed. | External URLs and pure anchors are not checked by this gate. No activation/runtime qualification was granted. |
| a990 static | PASS, 19/19 commands; 742 unittest executions across 16 file runs. | Final result-index, 22 raw logs and eight JSON originals are collected; source-before/after match the exact clean V3 tree. |
| a990 native / Clippy | All 89 named native tests PASS; strict workspace Clippy recorder exit 101. Overall cohort FAILED_OR_INCOMPLETE. | Stable original receipts and logs are retained. Clippy reported the large test-client enum and two `err().expect()` calls; the original failure remains failed after its V4 fixture-only correction. |
| a464 counterfactual native | NOT_RUN. | Its preparation alone does not demonstrate a regression control; final V4 fixture bytes require a separately identified comparison. |
| V4 native / Clippy | PASS: all 89 named native tests and all 19 original recorder commands, including strict workspace Clippy, graph checks, formatting and the all-feature build. | Exact implementation source is 97aa; original source-before/after checks and log hashes are retained. No Python/Markdown result is relabeled as V4. |
| Final V4 counterfactual native | Build exit 0; five exact native selections each exit 101 with one actual failed test, zero passed/ignored, and no timeout. All five assertion sites were reviewed against the targeted behavior. | The original driver remains `NATIVE_OBSERVATIONS_COMPLETE_ASSERTION_REVIEW_REQUIRED`; the separate derived review records the later 5/5 assertion-site assessment and its limits. |
| V4 Python / Markdown | NOT_RUN at this intermediate revision. | The most recent full observations for these gates belong to a990. Full original gates will run on publication commit E. |
| Publication source | Requires its own exact-source closing receipts, retained outside the source tree or in CI. | This directory gives no fabricated publication HEAD and no inherited PASS. The external receipt identifies the actual tested publication commit/tree. |

The six native groups passed separately on a990 and V4 and are listed below. Their counts total 89;
this is separate from the 742 Python test executions. Every group was listed
first with the original ELF and `--include-ignored`, then run with
`--test-threads=1 --nocapture --format pretty --include-ignored`; the original
roster checker requires exact names and zero failed/ignored/measured counts.
The output-reservation tests each execute classical and PQ loops; these remain
two named tests, not four separately counted libtest tests.

| Native label | Exact selector prefix | Named tests |
| --- | --- | ---: |
| output-reservation | `ingress::public_v3::output_reservation_tests::` | 2 |
| auth-recovery | `ingress::tests::authenticated_activation_recovery::` | 6 |
| completion-deadline | `ingress::public_v3::completion_deadline_tests::` | 10 |
| growth | `ingress::public_v3::growth::tests::` | 7 |
| work-arithmetic | `ingress::public_v3::work_arithmetic::tests::` | 5 |
| public-v3-retained | `ingress::public_v3::tests::` | 59 |

The ignored-by-default
`ingress::tests::authenticated_activation_recovery::withheld_original_frame_must_not_stall_a_different_honest_signed_mutation`
was explicitly executed under its original ten-second deadline. This finite
signed-socket control is not the original sustained-pressure campaign.

The e974 test ELF is 581,908,832 bytes, SHA-256
`107247ac5e7075cb5b5941935ac2f8586fe23b81389a6e3e562c11740e646a22`.
It exceeds the opt-in `pinned_native_process.py` limit of 512 MiB
(536,870,912 bytes). The original recorder's source-before/after checks and
separately retained artifact digest are used without claiming live-executable
`PINNED_AND_OBSERVED` qualification. The observer cap, build profiles and
original service/verification budgets were not weakened to accommodate it.
No ELF, target directory or test-only tmp directory is copied into this stage.

The original e974 inventory error, a878 native failures, a990 strict Clippy
failure, initial wrong-ref import failure, and earlier counterfactual
preparation's author-identity failure are kept separately. A corrected attempt never overwrites its failed
predecessor. The e974 source was imported from recovered committed bytes and physically
verified before later remote fixes. V2–V4 retain their separate commit
identities. The original `/workspace/scratch/33ceda412cc1` directory and its
local collection subtree no longer exist at collection time. The earlier
sparse-checkout 62-test/five-error original is not collected in this package. Its previously observed local path, 6,282-byte size and
SHA-256 are retained as explicitly uncollected metadata; no substitute raw log
is generated. This external gap is separate from completed remote collections.

## Reconstructing the unpublished counterfactual

The final comparison source is
`570801af9995a65f3f6c12a339bbca935e32282b`, with tree
`1c55152a221697e8dd37385b5cb6c85c1f4d33d8`.
Its parent is the implementation revision
`97aa8539aad3ee7f497136c6d2f64e420605c1fa`, which will be available
as an ancestor of the publication branch. No separately published or fetchable
counterfactual ref is claimed.

The reconstruction capture retains the [original commit-object bytes](570/source-reconstruction/counterfactual.commit.raw)
and a [standalone binary patch](570/source-reconstruction/counterfactual-from-97aa.patch)
written directly from the recorded `git diff --binary` stdout.
It verifies the raw commit object ID and the source tree before/after capture.
To reconstruct in a separate checkout of the parent, apply that patch with
`git apply --index --binary`, verify `git write-tree` gives the tree above,
then import the raw commit with `git hash-object -t commit -w --stdin` and
check its returned object ID before checking it out. The original patch,
commit bytes, commands, output and hashes remain independently reviewable;
source capture itself does not execute native tests.

## Reviewed counterfactual assertions

The [original driver summary](570/native/driver-summary.json) retains its
review-required status. The [derived assertion review](counterfactual-assertion-review.json)
binds the later assessment to each original log hash and source 570801af.
All five names also occur in the passing V4 native rosters.

| Exact-selection label | First observed regression assertion | Limit of this observation |
| --- | --- | --- |
| auth-kind | The old context-retry predicate returns false for a locally recoverable typed context error. | Exact identity/kind predicate case; not universal error retry. |
| auth-socket | After the parent arrives, the exact retry still returns `UNKNOWN_PARENT`; the old terminal cache has ended its original nonce retry. | One signed socket missing-parent recovery scenario. |
| output-full | The old branch sends a signed `PublicReply` instead of closing with frame EOF when no refusal-output reservation exists. | The observed early failing variant; later loop variants are not inferred to have run. |
| output-refusal | `output_refusal_reservations` is zero where the first accounting assertion expects one. | The old implementation does not reach the later headroom-exhaustion/wire assertions in this test. |
| completion-defense | The connection remains present after an unreserved completion where the owner defense expects it removed. | This first failed owner-state assertion, not later assertions skipped by the panic. |

The raw driver does not automatically classify a failure as a valid negative
control. The derived review records the observed assertion sites; it does not
change the original exit codes, qualify sustained service, or claim that
unreached counterfactual steps executed.

## Artifact ownership and integrity

The package contains 808 copied originals totaling
11,947,653 bytes. `collection-index.json` lists each by its actual source path,
staged relative name, size and SHA-256. Files are opened without following
symlinks, copied only after stable-file checks, and read back from the stage.
Existing staged originals may be reused only when bytes/hash agree.
`SHA256SUMS` covers copied originals; README/index files are derived review
metadata and are not presented as original command output. The package
manifest additionally covers the retained metadata/history files; its own
digest is reported in the detached sealing receipt to avoid self-reference.

Only stable, top-level text receipts/logs from completed cohorts are collected.
Each exclusion is recorded. The requested remote collection is complete; the
explicitly uncollected local sparse-checkout original remains a separate gap.
`collection-history/` preserves derived intermediate notes/manifests and
collection checksum output. Its earlier README snapshots describe staging
states and are not original test observations. A transfer failure or unknown job status is
separate from an observed command result; missing bytes/hashes are not
synthesized. Full native artifacts, loaded libraries, descendant execution and
whole-lifetime images are not certified by this collection.

## Exact-source publication boundary

The final evidence directory is intended for
`evidence/chain-verification-20261112-33ceda`.
Adding it creates a new publication commit. That commit's identity cannot be
substituted for the recorded implementation or counterfactual source.
After the publication source is frozen, run the original Cargo graph/lock,
retained tests, Clippy/fmt, negative source-integrity and Markdown gates on
that exact source. Retain its closing receipts outside its source tree or in
CI artifacts and bind them through PR checks/reporting. Appending those
closing receipts back into the source would create another untested commit. GitHub publication is owned by the
root operator through the existing ProfHepta channel.

## Qualification remains HOLD

Deterministic correctness, aggregate receiver resource bounds and honest
confirmed service are separate acceptance questions. Local exhaustion,
timeouts and deferred context do not determine a block-invalidity fact.
Full-path CPU still includes unresolved classical refusal encoding/signing,
parse/decompression where enabled, authentication, proof/FFI, I/O/logging,
response construction and cancellation/cleanup; reservations are not actual
CPU measurements.

Hard interruption of same-process nonpreemptible native segments remains
unqualified. A killable confined W1 worker needs bounded versioned IPC,
immutable complete statement identity, no state/signing/commit authority,
original-domain child/descendant accounting and termination/reaping, followed
by the current owner rechecking state, authority and budget before commit.
This patch does not implement that process boundary.

The original pressure campaign and capacity/churn supplement remain unchanged.
Offered, accepted and independently confirmed honest work, full failure
denominators, deadlines, p95/p99 and worst rejection/cleanup costs remain
required. Component success is not sustained honest goodput, work hardness,
production activation or whole-chain post-quantum qualification.

## Primary-source context

- [Wasmtime Config](https://docs.wasmtime.dev/api/wasmtime/struct.Config.html):
  fuel/epoch interruption does not interrupt blocking host calls; an outer
  timeout alone is not an executing-CPU bound.
- [zkGPT, USENIX Security 2025](https://www.usenix.org/system/files/usenixsecurity25-qu-zkgpt.pdf):
  specified GPT inference with GKR/Lasso and Hyrax/BN254 does not establish
  complete-training or post-quantum verification for this chain.
- [Neo/SuperNeo full paper](https://www.microsoft.com/en-us/research/wp-content/uploads/2026/10/Neo-and-SuperNeo.pdf)
  and [Sonobe](https://github.com/ethereum/sonobe): folding with Ajtai/Module-SIS
  is a research candidate; Sonobe marks SuperNeo/Ajtai work as WIP. No complete
  final-compression, noninteractive proof-chain or Fiat–Shamir/QROM
  qualification is inferred. An outer PQ signature does not repair a
  quantum-vulnerable inner proof.
