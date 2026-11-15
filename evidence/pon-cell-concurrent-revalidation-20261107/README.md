# Cell concurrent revalidation — recovered public evidence

This record follows the sole [development plan](../../docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md)
and the earlier [Cell integration record](../pon-cell-integration-v1-20261107/README.md).
It preserves the actual concurrent CI and native observations and the actual
publication of their source, without changing the computation.

The tested source is commit
`acc2ec24fac7e6fbebb49384fc7efc7c9f8b2030`, tree
`e59270db7fe6ea77e01362b591dd98e4e93d62fe`. Its existing integration candidate
is `fix/chain-six-axis-performance-20261103` in
`TrillionniumFoundation/Trillionnium-Chain`.

## Recovery provenance

The original local evidence addition was committed as
`7f54bfe3be663bfffabfbab3d3ac6dff468e8470`, tree
`b35e12a110836201c719426b29894abbc44a8d7b`, but its bundle had not been
uploaded or pushed when the execution environment stopped exposing the earlier
local paths. This record does **not** claim that 7f54 was published, that its
tree was reproduced, or that those inaccessible files were deleted.

Both original concurrent archives remain on the HeptaRuntime desktop and are
copied with their original compressed bytes and SHA256 values. Their manifests,
commands, stdout/stderr, proof materials and failed observations remain intact.
The original desktop publication directory also remains available and is copied
without reconstructing its streams.

Some packaging-only local sidecars and the earlier root-local source/link/CI
raw files could not be recovered as original bytes. [RECOVERY.json](RECOVERY.json)
lists these explicitly. Their missing outputs are not recreated from remembered
success summaries. Instead, an independent complete desktop checkout of exact
acc2 ran **new** source-before, repository/link, CI-checker and source-after
checks. Those new raw observations are retained in `fresh-checks/`.
This is a new evidence recovery addition; it leaves all computational source
bytes equal to acc2 and does not repeat calculation suites.


The first full-network attempt ended with a recorded connection reset and
incomplete Git pack; it is not a successful check. Separate cache-assisted
checkouts reused only public Chain object stores. Their detached HEAD caused
the development preflight to refuse the branch; the final complete checkout
then selected an allowed development branch and passed its new checks. The
independent cache audit verifies 266 reused blobs by actual SHA1 and SHA256;
only 70 distinct blobs across 75 paths remained to fetch. Every one of the
final 11,070 materialized entries is checked against its acc2 Git blob ID and
has its raw SHA256 recorded in
[the complete raw-source manifest](fresh-checks/materialized-raw-source.json).
[RECOVERY.json](RECOVERY.json) and `recovery-runtime/` retain the actual attempt
states, any owned-process cancellation request and terminal reply, preparation
refusals, and observed partial-pack metadata. None is counted as a native or CI
test failure, and no failed or cancelled attempt is labeled PASS.

## Actual concurrent controls

| Control | Observed result | Counting boundary |
| --- | --- | --- |
| Native Cell Rust suite | **12 passed**, zero failed or ignored; 3.34 seconds of test execution | Seven cross-language oracle cases are inside one test. Cargo took 257.931 seconds including compilation. |
| Strict native Clippy | Exit 0 | Library, actual Node binary and Cell test, all features, warnings denied |
| Native workspace formatting | Exit 0 | `cargo fmt --all -- --check` |
| Native Cargo metadata | Exit 0 | Locked and offline |
| Existing CI contract controls | **103 passed**, 15.820 seconds | Repeated executions are not additional distinct tests |
| Added upstream push-source controls | **13 passed**, 3.748 seconds | Covers the changed integration source resolver and workflow contract |
| CI contract checker | Exit 0 | A wiring check, not a computation test |

Exact commands, exits and unedited streams are inside the two archives. Native
used Rust 1.95.0 and retained OpenSSL 3.5.9 provider artifacts. The
[native index](native/retained-validation.json) pins the binary, Cargo.lock,
source arrays and build durations. These elapsed times do not qualify work cost.

The 43 source-integrity controls and V3 computation were not repeated because
their checker/test and computational source were unchanged. The earlier
[integration record](../pon-cell-integration-v1-20261107/README.md) retains those
43 controls and the 143 original V1/V2 controls. The separate
[V3 record](../pon-useful-cell-multimodal-v3-20261107/README.md) retains its
59 tests, owner inputs, final **96 unique complete W1 transcripts** and
fresh-process results. Reverification adds no new proof.

## Distinct source scopes

| Observation | Actual source material | Limit |
| --- | --- | --- |
| Concurrent native Cargo execution | **1,369 materialized tracked files**, 21,925,836 bytes | Declared build inputs include source, configuration and vectors; this is not a count of Rust files individually compiled |
| Concurrent CI execution | **2,322 materialized tracked files**, **8,748 explicitly sparse-absent files** | Raw bytes, Git blobs and executable bits were checked before/after; sparse clean is not full materialization |
| New complete desktop acc2 check | **11,070 tracked entries**, 1,035,950,468 bytes | New full-tree raw-byte check; it does not execute computation |

The native input scope is `trillionnium`, `config/pon`, `tests/fuzz` and
`formal/pon-nakamoto-v1/vectors`; no tracked file within that scope was missing.
Native before/after-gates/final arrays agree. Both original remote runners
explicitly decline a whole-repository materialization claim. Their overlapping
counts must not be added.

The new [source-before](fresh-checks/fresh-acc2-source-before.stdout) and
[source-after](fresh-checks/fresh-acc2-source-after.stdout) observations bind the
complete acc2 tree. The new [repository/link result](fresh-checks/fresh-acc2-repository-links.stdout)
and [CI checker result](fresh-checks/fresh-acc2-ci-contract.stdout) retain their
actual outputs and separate stderr files. [Their command ledger](fresh-checks/steps.json)
records the source, paths, timing and exits. They are explicitly new recovery
observations, not the inaccessible old root-local stdout/stderr.

The recovery review also compares all 2,322 CI and 1,369 native snapshot entries
against immutable acc2 Git blobs and the complete recovered file bytes.
[INTEGRITY.json](INTEGRITY.json) records those comparisons. This material
integrity review does not claim to be another arithmetic or cryptographic
proof-verifier execution.

## Native full corpus and cold subset

The full native corpus contains **12 case directories, 11 distinct complete
claim byte strings and 55 distinct full W1 proof byte strings**. Each complete
claim retains five W1 proofs, its owner admission, declared settings, actual
intermediate tensors, output, after-state and after-model. Each decoded proof
is 49,188 bytes. The retired-model counterfactual remains an explicit synthetic
control, not an external task or production use.

The cold subset comprises **six fresh historical-verifier invocations across
three fresh stores**, over **two distinct claims containing ten distinct full
W1 proofs**. Legacy and authenticated history share one claim and verify before
and after the active tip advances. Masked sampling/training repeats its claim
at the same verified parent. Ordinary status/submission processes used for
store setup are outside the six-verifier count.

Cold replay generates **zero new proofs** and uses no Cell historical
`--logical-now` override. It does not replay the entire 11/55 corpus.
[A4/A5 byte continuity](native/a4-a5-byte-continuity.json) covers **40 case
files**, including owner admissions, claims, settings and parent/successor
packets. The recovery reviewer independently compares their exact bytes and
decodes all indexed proof strings to check lengths and hashes. Repeated suites,
claims and cold calls do not increase unique test, claim, proof or external-use
counts.

## Concurrent preservation and actual acc2 publication

The earlier candidate `644a6c04450804f0ea3575beef7c964bf7a1da6b` was refused
by the write-before-push ancestor guard after the remote candidate advanced to
`d26e047dedfcdb17a1ac2c47cc26e6f1185f6b89`. That guard returned exit 1;
its retained step log has **no push step**. It is not a CI test failure.

The subsequent integration compared 18 prior edits with committed 644 source,
retained stash `132112817f122c09388651b28bd396537dadfe1b`, and selected acc2.
The original 44 context files remain inside the CI archive at
`integration-context/publication-public-final-644a6c/` and
`integration-context/concurrent-integration-acc2/`.

The actual [acc2 publication receipt](publication/receipt.json) and
[step ledger](publication/steps.json), with all original desktop streams,
record the successful non-force push through HeptaRuntime's local GitHub
channel as **ProfHepta**, from d26e047 to acc2ec24, with tree e59270d.
That receipt concerns acc2. It is not a receipt for the later recovery evidence
commit, and neither publication activates consensus or deployment.

## Retained files

| Record | Contents |
| --- | --- |
| [CI archive](ci/concurrent-ci-acc2ec24-v1.tar.gz) | 97 safe ordinary members: 96 indexed payloads plus self-excluded `FILES.json` |
| [Original CI summary](ci/summary.json), [restored CI index](ci/concurrent-ci-acc2ec24-v1.json) and [desktop archive metadata](ci/archive-origin.json) | Unedited remote result and compressed archive identity |
| [Native A5 archive](native/concurrent-native-acc2-evidence.tar.gz) | Root `concurrent-native-acc2/`; 176 ordinary members: 175 indexed payloads plus self-excluded `FILES.json` |
| [Native index](native/retained-validation.json), [A4/A5 continuity](native/a4-a5-byte-continuity.json), [desktop archive metadata](native/archive-origin.json) and [restored download sidecar](native/download-verification.json) | Exact source/build/material counts and their original metadata |
| [Recovery disclosure](RECOVERY.json) | Restored original bytes, unavailable former local inputs, old unpublished identities, and the origin of new checks |
| [Review index](REVIEW.json), [integrity checks](INTEGRITY.json), [archive identities](ARCHIVES.json) | Exact counts, evidence scope and qualifications |
| [Manifest](MANIFEST.json), [package hashes](PACKAGE.sha256) | Per-file sizes and SHA256; the checksum file does not hash itself |


The restored native download sidecar retains its original
`verified_payload_files: 176` field. Independent archive inspection counts
175 indexed payloads plus the manifest itself. Its complete original result
object and original serializer were retained; the recovery readback SHA is
recorded, while an independently retained old file SHA was not available.

Both compressed archives are copied without repacking. Earlier native setup,
formatting, Clippy and transfer refusals remain in the
[original native record](../pon-native-cell-v1-20261107/README.md).
No private Hepta code or raw owner evidence is included. Public archive members
and publication streams are reviewed for safe paths and bounded credential/private
source-path patterns before copying; this review is not a universal secret detector.

## Qualification boundary

These remain bounded synthetic correctness and integration observations.
The public native proof is **not consumed by the private Hepta owner path**
here. No ordinary runtime proof-to-owner composition, real owner operation
consumption, FinalUse, checkpoint commit, external delivery, production model
adoption, independent quality, cheapest-legal-work eligibility or new consensus
admission/reward rule is established. A pure verifier may accept the same valid
claim repeatedly.

Native historical time remains the verified parent Header's UNIX **seconds**;
V3 uses its distinct UNIX-millisecond lane. Neither silently becomes Hepta's
monotonic-microsecond owner clock. Historical validity stays bound to protocol
parent state/time. Current authorization, revocation, FinalUse and atomic
operation consumption remain the real current-use owner's responsibility.

Arbitrary multimodal encoders and model graphs remain open. Source checks,
evidence recovery and GitHub publication change none of these qualifications.
