# Cell storage four-gate continuation — retained observations

**Local native and research observations PASS on runtime C3
`030de92be05bfd4f73e199098c12dfeaedf29b17`. Production qualification remains HOLD.**

The complete continuation passed 68/68 candidate commands and 7/7 separate
observer/build commands. A fresh actual paged-model operation completed
within its original 300-second operation. Hosted CI is a separate gate:
six C3 workflows were observed failed. This record retains the failures and
does not turn successful local execution into production qualification.

The [sole development plan](../../docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md)
and [four-gate contract](../../docs/development/specs/pon/CELL_STORAGE_FOUR_GATE_CONTINUATION_V1.md)
define the implementation and acceptance boundaries. This directory records
observations; it is not a second development plan.

## Source identities and attribution

| Source | Exact commit | Meaning |
| --- | --- | --- |
| #879 base | 30ce6e99c5d0d86e6563a49786e8b1e41b44c6c6 | Original contracts and resource limits |
| Test-only before | 6985aca3803debe2945eebbc55e6c495598ae609 | Three unchanged TCP controls on the unmodified #879 scheduling runtime |
| C1 | 987e248f12760449ca111c12ff03f50be953a324 | Runtime implementation; initial source guard refused sparse entries |
| C2 | 3592b85b04a2800791c342df6ab3d0cd903072f2 | Complete continuation runner; actual unsupported FIFO-test API failure |
| C3 | 030de92be05bfd4f73e199098c12dfeaedf29b17 | Pinned mkfifoat(CWD, ...) test API and matching source binding; all recorded current native gates passed |

C3 tree is `21e970bfdb11ab64403d2af5f3c56536a2961f80`.
The publication descendant adds documentation/evidence, two narrowly scoped
CI workflow repairs, the matching strict CI contract and exact source pins.
Its Rust, Cargo and native/model execution runner bytes remain those of C3.
Native observations are not retrospectively relabeled with the publication head.

## Implementation and open work

| Direction | Implemented and exercised | Remaining implementation or qualification |
| --- | --- | --- |
| Discovery | Bounded time shares reach later pinned bootstrap sources while preserving the original absolute deadline and every connection/byte/signature reservation | Independent bootstrap operation, current authority, permissionless Sybil/eclipse resistance and WAN qualification |
| Version consistency | One manager-bound revisioned complete-release CAS; both actual closures admitted before assignment; stale/ABA/foreign refusal; paired eviction protection and actual sealed research use | Durable original Hepta CURRENT, crash/revocation ownership and ordinary FinalUse integration |
| Retention | Existing bounded schema/arena/repair-ledger checks before admission/reconciliation and again before physical copy; original durable debits survive refusal; nonblocking regular-file CPS1 admission | Approved replacement-domain successor owner, independent remote read challenges, actual funded renewal/settlement and sustained custody |
| Performance | Cold/prefetched/warm/hot byte-path instrumentation, chunk reuse, 1,000 raw hot samples and cumulative real-model milestones | Controlled WAN and independent-load distributions, full inference/first-token latency and target service qualification |

The inherited authenticated V3 protocol supports at most four explicitly
pinned bootstraps and two rounds, signed provider/query statements, nonce
binding, expiry/withdrawal and quotas. This change schedules those sources;
it does not provide an identity-independence oracle. Six local storage slots
remain one operational failure domain. Same-provider repair is not a complete
lost-provider replacement lifecycle. Hashes and funding admission do not
establish permanent retention, escrow or a completed paid renewal.

## Native validation on C3

| Execution | Recorded result |
| --- | --- |
| Complete DA crate | 785 unit + 34 integration + 16 documentation = **835 passed** |
| Node storage, default | **44 passed** |
| Node storage, pq-native-openssl | **44 passed** |
| Sealed V2 / paged sealed examples | **11 passed each** |
| Actual sealed-worker Python process | **24 passed**, original exact-roster reader passed |
| Original required DA controls | **5 exact executions + 5 strict readbacks passed** |
| Original required Node controls | **13 exact executions + 13 strict readbacks passed** |
| Discovery / storage CI controls | **5 / 19 passed** |
| Source-integrity negative controls | **43 passed** |
| PQ integration controls | **59 passed** |
| Next-architecture Python controls | **33 passed** |
| Other original gates | Locked/offline default and all-feature graphs, fmt, inventory, PQ source bindings, repository links, six vectors/fixtures, strict default DA/Node and release workspace/all-target/all-feature Clippy passed |

Counts are separate suite observations, not unique behavior counts. All
12 added DA controls are present in actual passing output: three discovery,
eight complete-selection and one FIFO/reopen control. Both candidate and
observer/build lanes preserve original per-command stdout/stderr and source
receipts. The full source receipts agree on all 27,100 tracked entries and
2,521,527,652 tracked bytes.

### Actual before/after discovery differential

The test-only predecessor has #879 as its direct parent. Its three-test blob,
`6244859ea896ff0c729121129660e9d065d429a6`, is identical to C3; its discovery
runtime is unchanged from #879. Each selected before test really compiled
and ran, reporting one exact named FAILED case and 775 filtered cases.

The principal case reports 4.0642586 seconds, withholding-source query counts
[1, 1, 0], honest-source count 0, two connection attempts, zero response bytes
and the original discovery absolute-deadline error. Its enclosing libtest
time is separately 4.09 seconds. The all-withholding case reports
2.018328126 seconds, counts [1, 0] and one attempt.

The exhausted one-connection case also fails at the original deadline
assertion before its later counter assertions. It does not establish a
connection refund or overrun. All three tests pass on C3 under their original
four-/two-second windows. Successful suite output suppresses their positive
diagnostic timings; no exact after elapsed value is invented.

### Retained failures and incomplete attempts

- Initial C1 and before-lane launches stopped at the unmodified complete-source
  guard: hidden tracked worktree entries. They did not run native controls.
  Later complete worktrees were materialized; the guard was not weakened.
- Local sparse-source diagnostics include missing historical evidence and
  an incomplete 180-second PQ-control attempt. Local sealed Python execution
  had 22 successes and two AF_UNIX EPERM errors; its strict reader refused.
- C2 records 55/68 commands passing and 13 nonzero outcomes. The FIFO test
  used unavailable rustix::fs::mkfifo, causing E0425; strict required-test
  readers correctly refused unexecuted cases. C3 changes only that test API
  to the pinned dependency's mkfifoat(CWD, ...) and its source binding.
- Synthetic early-abort runner controls check report-state handling only.
  The retention source-review concern is not an executed metadata-corruption
  exploit or an atomicity guarantee against noncooperating database writers.

No later success erases these observations.

## Synthetic first usable-byte and residency observation

Each synthetic version has a 65,536-byte base, 1,024-byte tokenizer and
4,096-byte adapter, totaling 70,656 bytes. The versions share base/tokenizer
and differ in the adapter. The fixture does not perform model tensor
admission or inference.

| Observation | Milliseconds |
| --- | ---: |
| Empty consumer CAS to complete resident closure | 21.510309 |
| Empty consumer CAS to first fully rehashed selected use | 21.587216 |
| Successor prefetch to complete residency | 5.503003 |
| Prefetched selection to first fully rehashed use | 0.101516 |
| Fresh manager, warm disk, prepare and first verified use | 0.847720 |
| Exact resident-hit prefetch | 0.051088 |
| 1,000 hot full-payload checks: min / median / p95 / max | 0.074537 / 0.092747 / 0.098196 / 1.138339 |
| Enclosing interval for those 1,000 checks | 92.687067 |

Cold acquisition downloads six chunks / 70,656 bytes. Successor prefetch
reuses five chunks and downloads one new 4,096-byte chunk, preserving the
previous selection until an explicit switch. Both closures use seven unique
chunks / 74,752 bytes and four shared base buffers. The provider is stopped
and joined before warm-disk/hot access. The hot checks rehash 70,656,000 bytes
without provider access.

All 1,000 samples are retained, and the statistics were independently
recomputed. Sequential reads in one process are not independent request-tail
observations. Host page-cache temperature is unspecified. These measurements
cannot substitute for model, WAN or service latency.

## Actual paged-model operation

Fresh operation identity:
`47c6fe65ee2a3e339c07a1c9eee166ecd05b4596bc9fea5050ddcdd447b2c1b3`.

The run preserves the original 30 files / 280,269,602 bytes / 95 chunks,
CTS1/TCV1/TCV2 and BEP52 pins, shard subset [0, 2, 4, 5], 300-second operation,
360-second outer cleanup watchdog, 512-MiB payload ceiling, 8-GiB runtime RSS
limit and four runtime threads. All 17 mandatory metadata files were checked.

It records 570 target publications, 570 logical restore callbacks, 380
verified shard reads and 190 unavailable callbacks. Original slots 1 and 3
were isolated, the catalog payload arena was made unavailable and original
source/delivery/staging caches were removed for this fresh operation.
All 95 consumer chunks and complete selected-version readback passed.
These are local data-removal controls, not independent-provider persistence.

| Milestone | Cumulative seconds from custody-observation entry |
| --- | ---: |
| Pinned snapshot ready | 5.454308496 |
| Transport complete | 15.970244233 |
| Cold recovery complete | 62.318658435 |
| Complete selected typed release ready | 66.401049437 |
| Both sealed model/environment closures ready | 67.697317774 |
| Verified two-forward receipt | 103.736029521 |

The origin follows source-spec reading/parsing and output-directory creation,
before verification/packing/transport. Values are cumulative and must not be
summed. Typed release readiness is complete byte/type admission, not first
token. Transport and custody are local/loopback.

The enclosing native wait4 observation is 103.804071986 seconds, exit 0,
78.940139 user CPU seconds, 14.856832 system CPU seconds and maximum RSS
1,430,912 KiB. The watchdog did not fire and the operation was not interrupted.
This wait4 RSS value is not simultaneous whole-process-tree memory.
The worker record retains one exit-time RSS gap, its 33.748335-ms
kernel-exit-cleanup reconciliation and terminal wait4 reaping; observation
was not continuously gap-free.

The historical #879 evidence records 36.047064473 seconds on runtime
`8dee97636e2b6932fb7a22b1b54f2cab09ae8406`. The runs are unpaired for host load
and conditions; neither speedup nor causal regression follows from the
difference. Both action outputs favor yes. The second numeric probe,
8517 > 8518, is incorrect. Completed forwards prove this research execution
path, not model efficacy or remote computation correctness.

## Provenance and availability incidents

All complete execution lanes have original source-before/source-after checks.
The model runner additionally pins its built binary, frozen candidate and
observer outputs, input spec and mandatory metadata.

After execution and source-after checks, packaging raised FileNotFoundError
for the executed runner and a read-only probe found the whole original source
root absent. The cause is unknown. The runner was recovered from immutable
C3 blob `6d6c55d908f313e059a456363b54a9e6f3bf8060`; all 17,381 bytes match original SHA256
`2ec4016fd414fb95ea9731f9157a9856fc2ee5b0c49e7457ebd908290c611c5e`.
Raw packaging failure, absence probe and recovery provenance are retained.

Bounded review of task-owned wrappers found no recursive source-root deletion;
it does not establish the cause or rule out external activity. Before/after
receipts are point-in-time observations, not continued-existence guarantees.
A separate publication checkout later passed the original C3 full physical
source verifier with all 27,100 entries, no skip-worktree/assume-unchanged flags
and sparse checkout disabled. That byte audit is not a new native execution.

The local review workspace subsequently exhausted shared scratch capacity.
A planned verified migration was interrupted when the platform marked that
environment unavailable. No completed-migration or unrun CI-control success
is claimed. Final publication continues on the already verified desktop
checkout. Recovered evidence keeps original bytes and hashes; material
regenerated from original Actions artifacts has its own new archive identity.
The original desktop records include one invalid setup/summary.json with a
literal backslash-n suffix. Its raw archive is unchanged; an expanded Git copy
uses a .json.raw suffix with a recorded filename mapping.

## Hosted CI failures and publication repairs

A retained C3 API page observed six failed workflows, twelve successful
workflows, two in progress and one queued. The snapshot is not an assertion
about the eventual state of every workflow. Final-head hosted results are
separate from C3 and must be reported at their actual observed state.

| C3 workflow | Observed cause and scope |
| --- | --- |
| W1 QROM implementation | Frozen contract allows a 9,233-byte verifier; unchanged #879/C3 verifier is 11,172 bytes. Original bounded reader refuses before digest comparison. No bound was widened. |
| W1 QROM closure | Frozen comparison differs at the w1_zkvm/Cargo.lock provenance hash. The related #879/C3 source blobs are identical. No frozen result was rewritten. |
| CodeQL API exporter | Exact analyses/check selections remain empty through 39 polls and the original 1,200-second deadline. Exact #879 exporter also fails this way. |
| Original native campaign | Build succeeds; three actual runs exit 101 on finite_experiment_criteria_met, not the 600-second watchdog. All nine phases fail original service criteria. An earlier equivalent runtime also failed; no paired timing or no-regression claim follows. |
| Next architecture | All four matrix jobs execute native/source/summary stages successfully, then upload-artifact rejects colon-containing Rust-selector filenames. The workflow remains failed. |
| W1 work security | Two fresh-challenge service jobs fail original four-second/six-depth business criteria. Original native variants exit 0 but finite_target_met is false; fresh variants exit 101. These are real acceptance failures, not outer-timeout substitutes. |

The CodeQL local-SARIF workflow omitted this stacked PR's exact base branch.
Publication adds only that branch to its PR trigger. Its three-language,
head/prospective-merge matrix, permissions, same-repository/source guards,
upload: never and retention predicates stay unchanged. The existing 12
retention controls are validated separately. This local-SARIF lane does not
supply the Advanced Security app/API records consumed by the unchanged
exporter; enabling it does not qualify that exporter.

The next-architecture repair replaces colon characters only in the
component/owner log filename stems and matching strict-reader paths.
The original Rust selectors, exact executions, full suites, source guards,
matrix, resource bounds and failure predicates are preserved. The existing
19 storage-contract and five discovery-workflow controls must pass on the
actual publication files. This is a repair to retention of CI artifacts,
not relaxation of native acceptance.

## Remaining acceptance

Independent administration/failure domains and the original 72-hour PN5 WAN
duty remain open. Approved replacement-domain ownership, actual remote read
challenges, paid renewal/settlement and ordinary Hepta CURRENT/FinalUse need
their own implementation and evidence. Deployment and production remain HOLD.

The BT-like path is used for cold recovery, explicit prefetch and repair.
No per-token WAN weight path or Petals-style activation privacy, malicious-worker,
execution-correctness or timeout-charging guarantee is introduced.

## Evidence index and publication checks

| Retained material | Entry point |
| --- | --- |
| Original current C3 records, 206 members; 205 member hashes and 165 streams verified | [Raw archive](raw/remote-current-records.tar.gz), [original manifest](current/manifest.json) |
| Original earlier attempts, 177 members; 176 member hashes and 170 streams verified | [Raw archive](raw/remote-prior-records.tar.gz), [original manifest](prior/SNAPSHOT_MANIFEST.json) |
| Test-only predecessor with #879 parent and the same test blob as C3 | [Original bundle](raw/cell-four-before-source.bundle), [object verification](publication-recovery/before-source-verification.json) |
| Original desktop C3 setup, Draft PR publication and full physical-source audit | [Records and exact rename mapping](desktop-publication/README.md) |
| Recovered original native-campaign and CodeQL Actions material, new archive identity | [Archive, member manifest and receipt](hosted-ci/native-codeql/README.md) |
| Next/work job logs, retained extraction output and QROM originals, new archive identity | [Archive, member manifest and receipt](hosted-ci/next-work-qrom/README.md) |
| Five exact source-binding changes and unchanged 994/902 rosters | [Binding review](publication-recovery/source-binding-review.json) |
| Actual workflow/contract patch and C3 byte-preservation scope | [Unified diff](publication-recovery/ci-changes.diff), [scope](publication-recovery/source-scope.json) |
| Actual publication 19/5/12 controls, inventory, PQ bindings and whitespace gate | [Raw commands and count guards](publication-recovery/controls/summary.json) |
| Preserved failed first assembly attempt and successful parser correction | [Original failed summary](publication-recovery/assembly-attempt-v1/summary.json), [original error](publication-recovery/assembly-attempt-v1/assembly-error.txt) |
| Preserved index-reader failure on identical frozen summary copies | [Original failed index summary](publication-recovery/index-attempt-v1/summary.json), [original error](publication-recovery/index-attempt-v1/index-error.txt) |
| Original-package transfer and interrupted review-environment facts | [Transfer receipt](publication-recovery/original-package-recovery.json), [outage record](publication-recovery/interrupted-local-review.json) |
| Original candidate summary, SHA256 98e514c9f632d9919bf8f2615018ebc73a688fea393b848116a65d0adcabc75c | [Raw summary](current/candidate/summary.json) |
| Original observers summary, SHA256 5f3f100dda83ba4689006367831f35916356eff6024cc002f234ae07388b7e40 | [Raw summary](current/observers/summary.json) |
| Original model summary, SHA256 f94d2090cd084d69863113c77f1011796574ffc0c8936ca783e324c20385bd3b | [Raw summary](current/model/summary.json) |

The prior C3 precommit-maintenance records remain present. The separately named local-precommit/local-runner-controls packet and the six local archive-download failure receipt files were not recovered from the unavailable scratch environment. Their descriptions are retained observations; they do not claim that all lost raw bytes are included. See the [precise recovery scope](publication-recovery/local-records-recovery-scope.json).

The two Actions recovery archives have their own observed identities. The native/CodeQL package does not claim restoration of the old local 32-review attachment set or the old aggregate archive. The next/work/QROM package retains 65 payloads checked against their prior SHA256, ten complete job logs, four complete extraction stdout/result files and four verified QROM ZIPs with 84 members. The eighteen original fresh-challenge selected members were not all recovered; no complete-restoration claim is made.

The current/prior/desktop raw archives remain byte-identical to their recorded originals. Expanded copies preserve original bytes. Only the known invalid desktop setup JSON is renamed with a recorded mapping. Original Markdown entry points copied from the compressed Actions packages use .md.raw names so their unchanged archived-relative links are not presented as unpacked files.

Publication checks above are Python/source/evidence checks. They are not additional native or model executions. The commit-bound full physical source guard is retained outside the worktree and read back before normal publication; native execution remains attributed to C3.

### Publication physical-file restoration and repository gate

The first publication repository scan failed on a historical Markdown link to a missing tracked archive. The earlier complete C3 physical audit and this later absence are separate point-in-time observations; the cause of the missing file is unknown. No existing documentation, CI edits or checker rules were overwritten. Missing tracked regular files were restored create-only from their exact C3/index Git blobs; the historical native-7150 archive also matched its independent recorded size and SHA256.

The first physical-restoration attempt restored some paths before its create-only blob-cache writer encountered a second path with the same content-addressed Git blob. Its [original partial summary](publication-recovery/physical-restoration-attempt-v1/summary.json) and [error](publication-recovery/physical-restoration-attempt-v1/error.txt) remain unchanged. The next attempt enumerated only remaining missing paths and reused cached blobs only after size and both Git-blob/SHA256 verification.

The [original failed repository attempt](publication-recovery/repository-attempt-v1/summary.json) and [raw stderr](publication-recovery/repository-attempt-v1/repository-precommit.stderr) remain unchanged. The [missing-file list and exact restoration hashes](publication-recovery/physical-restoration/summary.json) record the physical correction. The unchanged repository checker then passed: [actual result and command](publication-recovery/controls/repository-after-physical-restore.json), [raw stdout](publication-recovery/controls/repository-after-physical-restore.stdout), [raw stderr](publication-recovery/controls/repository-after-physical-restore.stderr). This restoration is not a native rerun or newly generated historical observation.
