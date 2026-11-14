# PQ quorum preflight and root-family observations

Status: **component evidence / HOLD**. This work continues the existing PQ
candidate at `12e510b211110d93d9ead07e02c07a1eecc28ae9` (tree
`a8c9634b9e0d59ccc9fd6a03875eee7fc76c099f`). The final source validation
receipt identifies the committed successor; precommit observations below keep
their explicit file identities and are not relabelled as committed-source runs.

See the [authority review](../../docs/security/PQ_AUTHORITY_PREFLIGHT_20261108.md)
and the [single development plan](../../docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md).

## Release regression

The original production kernel with the nine new regression tests returned
**3 passed / 6 failed**. The fixed kernel returned **9 passed / 0 failed**.
The red cases expose the original interleaving of structural checks and
signature mathematics. They are preserved as expected failure observations,
not counted as passing verification gates. The green checks also retain
extra-signature refusal, complete state equality on refusal, root retirement,
historical recovery, current generation checks and expiry.

The cache test reaches its missing-entry red assertion first. Its remaining
key-ID and SPKI mismatch cases run in the green loop; this is not three
independent red observations. Formatting is the only test-source difference
between the recorded red and green overlays. No primitive-call counter was
added; the ordering claim uses the source control flow and observed errors.

- [Baseline compilation receipt](baseline-build/receipt.json): compilation only.
- [Red receipt](quorum-red/receipt.json) and [original output](quorum-red/stdout.log.gz).
- [Green receipt](quorum-green/receipt.json) and [actual output](quorum-green/stdout.log.gz).
- [Provider verification](baseline-build/provider-verified.json).

An initial green launch had an unknown local outcome. The remote job directory
and systemd unit were absent, and the original kernel was still unchanged.
The exact same idempotency key did not launch a duplicate. A guarded recovery
used a create-only output directory before any mutation. That infrastructure
observation is retained separately from the successful test result.

## Independent fuzz graph repair

The first complete CI contract check refused the new normal dependency because
the independent fuzz lock still omitted the edge from `trnm-release-bundle`
to `trnm-protocol`. The [original refusal](source-integration-initial-failure/ci-contract.stderr.log)
is retained. An offline metadata resolution added exactly that one local edge;
the complete parsed package lists, versions and all other lock fields were
unchanged. The primary workspace lock is unchanged. See the
[repair receipt](fuzz-dependency-repair/receipt.json) and
[one-line lock diff](fuzz-dependency-repair/lock.diff.gz).
The [non-test library precheck](non-test-library-precheck/receipt.json) also
passed; final committed-source validation remains separately identified.

## Root-family experiment

The [frozen harness](../../formal/pon-nakamoto-v1/pq_root_quorum_research.py)
and its [18 codec/policy tests](../../formal/pon-nakamoto-v1/test_pq_root_quorum_research.py)
use a trusted fixed AND policy. The ML-only component has a separate frame and
always returns `hybrid_policy_satisfied=false`; it cannot grant the combined
policy even after relabelling its frame. All keys are explicitly public,
deterministic test fixtures. Temporary private key files were not archived.

The real OpenSSL 3.5.9 run completed **64 distinct proposals**, **128 paired
observations**, **9 legal subset combinations**, and **12 refusal controls**.
There were **877 native commands**: 429 signing and 435 verification calls,
plus version/key-generation/public-export commands. The three signature
rejections are expected controls, not tool failures. Total run time was
324.237 seconds.

| Path, 64 observations each | Stage | Median ms | Empirical p95 ms | Maximum ms |
| --- | --- | ---: | ---: | ---: |
| ML-DSA-87 component | Sign and encode | 20.468 | 25.184 | 400.484 |
| ML-DSA-87 component | Verify complete component frame | 16.539 | 20.398 | 52.994 |
| ML-DSA-87 component | Combined | 37.429 | 47.128 | 414.864 |
| ML-DSA-87 AND SLH-DSA-SHA2-256s | Sign and encode | 4,120.412 | 4,643.601 | 5,161.910 |
| ML-DSA-87 AND SLH-DSA-SHA2-256s | Verify complete AND frame | 36.787 | 72.509 | 301.864 |
| ML-DSA-87 AND SLH-DSA-SHA2-256s | Combined | 4,160.439 | 4,682.190 | 5,204.239 |

The common proposal is **846 bytes**. The component frame is **15,484 bytes**,
and the complete AND frame is **75,378 bytes**. The trusted full 3+3 roster and
configuration is **8,717 bytes**, encoded separately. The frame includes
selected signer SPKIs and signatures, but excludes prior distribution of the
complete configuration. The approximately four-second combined cost is
dominated by signing/encoding, not verification.

- [Complete result and scope](root-quorum-research/result.json).
- [Independent consistency/statistical readback](root-quorum-research/analysis-receipt.json).
- [Raw observations, gzip](root-quorum-research/observations.jsonl.gz).
- [Every native command record, gzip](root-quorum-research/commands.jsonl.gz).
- [Artifact hashes](artifact-index.json).

Compression preserves the exact JSONL bytes. The raw observation SHA-256 is
`2868b1bdd190988ed13c5312bd9e68d5ab77e1c66aadc30e6653e88a71011dac`;
the raw command SHA-256 is
`b86e8409e6bea29d12a7f359c31eba7e42fe19ef985be6c2199fa5f1c853b878`.
No samples or outliers were removed. Statistics use ordinary median and
nearest-rank p95. Stage medians need not sum to the median of total duration.

These are command-cold observations on a shared, non-isolated Linux host,
including process startup, key import, temporary file IO and command-record
flushing. Cargo validation may overlap. Runtime limits were requested
(100% CPU quota, 2 GiB, nice 5, 1800 seconds), but the post-exit systemd query
cannot prove their historical enforcement. They are not reserved resources,
host attestation, warm-EVP measurements, production throughput or production
tail guarantees.

## Qualification boundary

The fixed research verifier is not connected to a production root owner.
Current views are independent fixture snapshots, not durable root transitions
or anti-rollback enforcement. This experiment does not measure configuration
distribution, independent custody, WAL, network, deployment or a complete
key-management lifecycle. No deployed keys, protected main, services or
activation state were changed. All production, whole-chain PQ, physical
rollback and cross-repository Hepta final-use claims retain their original HOLD.

## Exact-source validation before concurrent-base integration

The [first full run](committed-source-01/summary.json) passed all **28 command gates**
on `62ed4e4facae4e0eb9f3fdeb82001acb3b21be47` (tree
`38a1d4da1a6dc8c93d49ca181c8e35ecb79ef776`). It executed 52 release tests,
442 tests across the other five selected packages, four doctests and 40 Node
release-owner tests. Two existing cost observations and one isolated fixed-root
Node control remained ignored; 1,244 unrelated Node tests were filtered out.
This is not an all-workspace test run or full Node/Host acceptance.

Formatting, locked offline graphs, strict all-target/all-feature workspace
Clippy, Python guards, source integrity and repository links passed.
Before/after source and provider identities matched, and actual retained
SQLite build outputs were qualified. This run predates integration of
`8d8f05566b2a1612a3bf4a6c6c71635df454d397`; it is not relabelled as a
run on the merged source. All raw logs, including empty streams, are retained.

## Lossless capture formatting

Raw native output includes deliberate final blank lines. Captures that trigger
Git whitespace checks are stored as lossless gzip, with their original byte
lengths and SHA-256 values in the compression mapping of `artifact-index.json`.
No captured output is trimmed or rewritten, and original receipt paths and
hashes remain unchanged. The initial archive-format check refusal is retained
separately from the passing source and native validation.

## Exact-source validation after concurrent-base integration

The [corrected-source run](integrated-source-02/summary.json) passed all **31 command gates**
on `a14b7e2b51af9772210e5114945dfa7e309bf97b` (tree `16da421e676ab516b44c35cd7a9319af7be32b4f`).
The counts below are read from the retained command receipts and checked
against their exact stdout/stderr bytes by the
[collection readback](integrated-validation-readback.json).

| Native test scope | Passed | Ignored | Filtered |
| --- | ---: | ---: | ---: |
| Release bundle | 52 | 0 | 0 |
| Other five selected packages | 442 | 2 | 0 |
| Six-package doctests | 4 | 0 | 0 |
| Node `release_owner::` only | 40 | 1 | 1,244 |

Every supplied release test name matches the complete 37 + 6 + 9 roster.
The ignored cost observations and isolated fixed-root control remain
explicitly ignored. This is not a full Node test run, an all-workspace
test run, or full Node/Host acceptance. Strict workspace Clippy, formatting,
the locked offline dependency graphs, source guards and repository checks
are separate passing gates in the retained run.

| Python command gate | Tests reported |
| --- | ---: |
| `ci-contract-negatives` | 116 |
| `upstream-migration-signatures` | 7 |
| `upstream-migration-journal` | 13 |
| `upstream-public-seed-relation` | 21 |
| `pq-root-quorum-research` | 18 |
| `pq-integration-negatives` | 55 |
| `pq-claim-negatives` | 37 |
| `pq-authority-negatives` | 15 |
| `source-integrity-negatives` | 43 |

The 18 root research unit tests exercise encoding and policy with
test doubles. They are separate from the earlier native provider experiment.
Before/after source and provider identities match. The retained SQLite
build-script outputs contain the required native qualification markers.

The [original 28-gate run](committed-source-01/summary.json) remains attributed to `62ed4e4facae4e0eb9f3fdeb82001acb3b21be47`
(tree `38a1d4da1a6dc8c93d49ca181c8e35ecb79ef776`), before the concurrent-base merge.
Its [count readback](first-validation-counts.json) is retained separately.
Those old results are not relabelled as results on the integrated commit.

The [first integrated run](integrated-source-01/summary.json) remains **FAIL** on `af6b06fa1cb944e639148b58e9765fe2bb0065ab`.
Its Node scope reported 39 passed, 1 failed,
1 ignored and 1,244 filtered tests. The failing gate was
`node-release-owner`; its original failure, output streams and receipts
are retained without alteration. The successful corrected-source run
above does not replace or relabel this failed attempt.

The exact source changes from the failed merge to the successfully tested
successor are recorded in the [binary Git patch](source-correction.patch.gz)
and [commit/tree/path record](source-correction.json). The final evidence
commit changes no files outside this task evidence directory relative
to that successfully tested successor.

The [fixture-correction supplement](node-expiry-fixture-fix-01/receipt.json)
retains 11 driver commands and a separate
[exact native test](node-expiry-fixture-fix-01/node-expiry-exact-native.receipt.json).
That targeted run reports 1 passed,
0 ignored and 1,284 filtered tests
on the same corrected source commit, with unchanged source/provider
identities and qualified retained SQLite outputs. Its
`full_validation_executed:false` remains unchanged: this one-test
supplement does not increase the 31 command gates or the Node total
reported for the complete selected run above.

The complete [initial integration attempt](concurrent-base-integration-01/commands.json)
is retained with its final whitespace-check refusal (exit 2) and without
a success receipt. The [recovery receipt](concurrent-base-integration-recovery-01/receipt.json)
records the completed merge; it predates the integrated validation above.

All captured streams, including empty files, are retained. Raw `.patch`
and `.raw` artifacts, and captures rejected by Git whitespace checks, are
stored as lossless gzip. `artifact-index.json` maps stored gzip bytes to
the original byte length, SHA-256 and relative path. Receipt paths and
hashes are left unchanged; captured bytes are never trimmed or rewritten.

**Scope remains HOLD:** production activation and whole-chain PQ
qualification remain false. This evidence does not establish full
entrypoint migration, independent custody or recovery, original fixed-Host
availability, WAN acceptance, or a complete quantum security composition.


## Inventory correction retained with local and hosted HOLD

**Current local validation is FAIL, not a 32-gate pass.** The complete run on
`ca3c4f88afc70399000b18fc7d68cfa62e57fb2f` retained [its original summary](inventory-source-01/summary.json):
31 command gates passed, while `node-release-owner` exited 101. This collector's
PASS means that the evidence was verified and retained, not that the failed
native validation became successful. The tested commit is recorded under
`retained_failed_validations`; `validated_commits` keeps its earlier identities.

The initially published source `527e2e58db6d7c1fd84ba88c3131289edea86b1d` omitted the new quorum test file
from the embedded distributed source inventory. This was our integration
omission. The base inventory was fresh. The unchanged generator adds only
`trillionnium/crates/trnm-release-bundle/src/pq_release/quorum_preflight_tests.rs`, from 1,368 to 1,369 entries. [The separate inventory correction
record](inventory-source-correction.json) binds the exact six-file correction.
The earlier `source-correction.json`, documenting the positive Node fixture
correction, has not been rewritten. [The inventory-fix receipt](distributed-inventory-fix-01/receipt.json)
retains one expected failed pre-fix check (exit 1, `passed: false`) and nine
successful commands; the fix driver did not run native tests.

The frozen final runner preserves the original 31 commands and adds the actual
inventory freshness command immediately after the first source guard. That
freshness check passed on the corrected source. [The original raw-output
readback](inventory-validation-readback.json) records the complete outcome:

| Scope | Actual outcome on this source |
| --- | --- |
| Release library suite | 52 passed, exact 37 + 6 + 9 names, none ignored |
| Five other related packages | 442 passed, 2 existing ignored |
| Six-package documentation tests | 4 passed |
| Node `release_owner::` module | **38 passed, 2 failed**, 1 existing ignored, 1,244 filtered |
| CI contract / pure root research | 116 / 18 passed |
| Three upstream migration groups | 7 / 13 / 21 passed |
| Other command gates | Strict workspace Clippy, formatting, three locked graphs, source guards, provider identity and SQLite qualification passed |

The two actual Node failures are:

- `release_owner::service_tests::clock_reply_then_real_elapsed_expiry_refuses_without_cas`:
  the initialized fixture's open path panicked at `service_test_fixture.rs:215:51`
  with `Kind(TimedOut)`, before the intended injected elapsed-expiry point.
- `release_owner::service_tests::durable_preparation_then_real_elapsed_expiry_refuses_without_cas`:
  the assertion at `service_tests.rs:87:9` observed `TimedOut` where the test
  required `PermissionDenied`. This is a failed test, not a successful expected
  refusal. The earlier corrected positive `admitted_completion_after_expiry...`
  control did pass in the same output.

No native or CI rerun was used to replace these outcomes, and no clock,
signature, service deadline, business threshold, or refusal assertion was
changed after this observation. The previous 31-command PASS remains bound to
its previous source; it does not establish that this newer source passed.

### Retained hosted CI failures on the earlier published source

[The scoped readback](hosted-ci-final-readback-01/receipt.json) observed
105 checks on `527e2e58db6d7c1fd84ba88c3131289edea86b1d` at `2026-11-08T09:23:59.049925+00:00`:
73 success, 22 failure,
9 in progress and 1 skipped.
This is a dated snapshot, not a claim that still-running checks subsequently
passed. All retrieved original logs, annotations, reports, process evidence and
artifact ZIPs are archived in the hosted observation and late-triage directories.
Bounded late priority/factorial triage retains full job logs, metadata and
annotations; it does not claim that every hosted artifact was downloaded or
that every still-running check was fully diagnosed. The small original CodeQL
export artifact is retained in full.

- The pinned historical artifact `11531476198` from run `37730166589` was
  unavailable: artifact API 404, original-run artifact count zero, and no
  download candidates. Its workflow is unchanged from the base. Recovery
  still requires the exact original failure data and provenance; no different
  artifact or newly generated failure is substituted.
- Original native campaign run `42463825169` built and executed three actual
  campaigns. All three failed finite confirmation/client-state criteria with
  retained `PUBLIC_REQUEST_DEADLINE` records. These are not startup failures.
  The original 71,722,426-byte artifact ZIP `13610289272` is included with SHA-256
  `b6415ddf54d336c1c0647eca920cfe7ed0dfe24b75a7d65cf9a8c5b118d6c354`.
- Four protocol/cross-architecture observations report `CONFIRMATION_TARGET`:
  each five named native controls passed, but the confirmation reader rejected
  the retained report and the native child exited 1; host-error lists were
  empty. These are separate failures from the inventory omission.
- The three late factorial jobs failed their pinned OpenSSL 3.5.9 provider
  preparation/download step with exit 22. Each later `--legal-strategy-v3`
  Python command still ran and reported PASS; the containing jobs remain
  failed. The deeper provider `build-and-smoke.log` was not retrieved, so no
  particular HTTP status or deeper root cause is claimed.
- Later service-model and other W1 observations are retained in their dedicated
  raw triage directories. The CodeQL export job reports that analyses/checks
  did not complete and stabilize before its deadline. That export failure does
  not itself establish either a vulnerability finding or successful remediation.

Unchanged workflow/test files alone do not prove an inherited runtime failure
or exclude every shared-code effect; no comparison campaign was rerun on the
base. The unavailable historical-artifact gate and confirmation thresholds
remain intact. The failed GraphQL PR-note attempt is retained even though it
has no terminal receipt; later PR text updates use the existing draft.

[Archive accounting](followup-archive-inventory.json) records every ordinary
original file, including all zero-byte logs. Raw patches and text captures with
Git whitespace diagnostics use lossless gzip with original path, size and
SHA-256 in the index; raw receipts are never rewritten. [External artifact
accounting](external-artifacts.json) explicitly records any original at least
100,000,000 bytes retained outside Git (0 such
files). No oversized file is silently omitted. The unused PASS-only collector
draft is identified in [its supersession record](unexecuted-collector-draft.json)
and was not executed. Previous 31-command PASS, earlier genuine Node FAIL,
research captures and all previous evidence retain their original bytes.

The draft remains **HOLD** for current native validation, hosted acceptance,
service performance, production activation, whole-chain PQ security, physical
rollback safety, WAN qualification, HeptaFinalUse and PoN quantum claims.
