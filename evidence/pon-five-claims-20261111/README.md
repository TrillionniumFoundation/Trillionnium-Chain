# PoN source composition and Submit ancestry evidence

This archive records source **T `297bb40798ca1b4e4a987ef00582067282cda4e9`**, tree `129267332b2ef87d3d66d014fddeb894faa9379f`, for [draft PR #907](https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/907). The implementation change is **S `f2375a08f4458f842b96d30215adcd5380270f1d`**. This evidence branch is a separate descendant; its own file tree is not described as the native-tested T tree.

**State of this snapshot: the Submit repair and scoped W1/accounting controls have successful observations; complete DA acceptance and overall production qualification remain HOLD.** Original unsuccessful observations remain in this archive. An isolated pass does not replace a failed complete suite.

## Source composition and change

T retains the exact #895 budget source, #847 integration source, #897 node-local adoption source, and #860 W1 content-accounting source through ordinary merge commits. [Source identities and merge parents](source/identity.json) identify each input. The implementation patch is retained in [implementation-S.patch.gz](source/implementation-S.patch.gz); the five affected Node source files are separately available in [five-source-files-S.patch.gz](source/five-source-files-S.patch.gz).

A historically admitted, nonmonotonic ancestor can be too far ahead of the current observation clock even when a new candidate's own timestamp meets MTP. Ordinary shared Submit previously completed W1 and entered M06 before the later activation check rejected that history. The fix carries the activation parent from the same owned packet, checks its ancestry after full W1 and before M06, and checks again under the reacquired clock before detached commit.

The second check can reject after detached application execution has occurred; that case establishes no durable candidate, not zero application work. Historical import explicitly supplies no activation parent. Existing exact-packet retries retain their admission fact and activation checks. Cancellation and paid CPU control use the original progress path. Ancestry reads are proportional to history depth; this patch supplies no throughput improvement claim.

## Actual observations on T

| Scope | Observed result |
| --- | --- |
| W1 crypto library selection | 135 passed, 0 failed/ignored; the other 61 library methods were explicitly filtered |
| Submit regression selection | 14 distinct exact selectors, each actually running one test and passing; seven new and seven retained controls |
| DA integration targets | 45 passed, including 11 adoption CLI tests; three binary harnesses contained zero tests |
| First complete DA library | 740 passed / 1 failed out of 741 |
| First isolated DA control | 0 passed / 1 failed / 740 filtered |
| Quiet isolated DA control | 1 passed / 0 failed / 740 filtered |
| Quiet complete DA library | 740 passed / 1 failed out of 741 |
| Existing Python controls | 620 successful named methods across the original attempt and its narrowly scoped setup recovery; no skipped or expected-failure results |
| Formatting | Workspace format check passed |
| Dependency graphs | Workspace and fuzz locked/offline metadata checks passed |
| Strict Clippy | Default profile, full workspace, all targets/features, `-D warnings`: passed |

No counts from repeated executions are added together as independent cases. Neither the 14 Node selectors nor the 135 W1 methods constitute a full workspace test campaign.

The seven new Node controls cover the initial future-ancestor refusal, bad-product refusal precedence, currently eligible nonmonotonic ancestry, exact-existing-packet retry, clock change before detached commit, original cancellation and slot release, and historical admission without activation authority. The M06 counter observes the existing `BeforeStateClone` execution entry; the persistence control observes `BeforePersistence`. No separate new deadline case is claimed.

The 620 Python methods comprise CI contract 179, source integrity 43, authority 18, PQ128 58, corpus 59, current QROM mapping 14, proof-profile binding 26, V1 accounting 21, V2 W1 accounting 17, demand 29, work utility 15, upgrade policy 23, learning scope 13, and the original seven-suite QROM closure roster 105.

## Negative subject and preserved failures

The test-only negative subject is `e63427560885b65c57db6bdc478df023111b4733`, tree `10a70f10bf5c64fe4b1d8df42c6463ff17aeba88`, based on the unchanged #895 production source. Its qualified release build succeeded and the exact native assertion failed with exit 101: full W1 ran once, M06 was entered once, and the candidate was durable before activation refusal. Execution stopped at the first Legacy/private-order case; the other combinations are not reported as observed before failures. Its prerequisite Git bundle, original commit metadata and patch are in [before-subject](node/before-subject/).

The archive also retains:

- The earlier non-qualified SQLite build and its diagnostic native failure, and the cancelled loader-environment attempt. Their results are not substituted for the qualified negative subject.
- T's first failed Node build. Reusing a target across worktrees caused Cargo to reuse the earlier private M06 method's metadata as fresh. The published T source already had the required public method. The before ELF was retained; all 26 local/path package outputs in the dedicated target were normally cleaned. The successful rebuild checked the source paths and first fresh=false observations of its 14 local compilation units.
- The Python runner's two initial output-directory refusals. The original 38-command result remains false for all-exit-zero. Creating the directory required by the original workflow allowed the original 105-method roster and its independent completion checker to run successfully without source or assertion changes.
- Both complete DA failures, the isolated failure, and the subsequent isolated pass. All original deadlines and assertions remain.

The DA failure is `retained_shard_plan_initial_128_profile_accepts_complete_65_and_128_chunk_catalogs`. Both complete suites returned `CacheWriterBusy` at the original plan-creation assertion. The first isolated run returned `Invalid("RS46 provider deadline")`, which is an explicit absolute-deadline comparison in the provider. The quiet isolated run passed both 65- and 128-chunk cases. Each creation has its own original 10-second deadline; a complete two-case test lasting more than 10 seconds is not itself a violation.

The quiet complete suite still failed. The isolated pass therefore does not establish the cause of the complete-suite failures or close the acceptance gap. No deadline, capacity bound, refusal assertion or SQL durability setting was relaxed.

## Five independent propositions

| Proposition | This snapshot supports | What remains unestablished |
| --- | --- | --- |
| Correct computation relation | Complete native W1 replay, independent scalar accounting replay, and the recorded relation/refusal controls | Succinct SNARK/STARK admission and end-to-end production qualification |
| Prescribed mining work cost | Exact content accounting keeps reported costs and distinguishes repeated content from nonce variation | Cheapest legal strategy, preprocessing, hardware, amortization and joint consensus/resource bounds |
| Independent model net benefit | Evidence readers keep benefit and authority separate from relation success | Independent evaluation, strong baselines, future ordinary tasks and full-cost net gain |
| Legitimate adoption | Explicit node-local selection, version and execution-identity boundaries; the recorded adoption controls | Actual authorized production deployment, independent recovery custody and downstream effect authority |
| Actual subsequent use | Explicit refusal to infer FinalUse from a claim or a local selection | An ordinary same-operation training/evaluation/selection/install/FinalUse/next-task trace |

The selected W1 profile remains full recomputation. The accounting bridge is not native proof admission. The local adoption API does not grant release, Root, fee, payment, consensus-credit or FinalUse authority. Model benefit, universal work security and production activation remain unqualified.

## Hosted CI and retained refusals

[Hosted observations](hosted/) retain the original API snapshots and four complete job logs. Each snapshot is a time-bounded observation; queued or running checks are not passed checks.

On T, the hosted native full-relation/path lane succeeded, while the original native campaign and other required lanes were not all successful. The older QROM implementation workflow still uses a historical 9,233-byte verifier input bound against the current 11,172-byte file. The current mapping reader deliberately retains this historical rejection; its 14 successful controls and the 105 closure controls do not make the older workflow pass.

The public-readiness reader also rejects #847/T's new account-profile check in `open_selected_mode`: its closed whole-body allowlist still names the previous body. The new body is inherited unchanged from #847. The guard was not deleted or weakened to turn this refusal into success. The hosted quality lane's dependency-policy refusal is distinct from the successful local strict Clippy command.

## Evidence map and verification scope

| Directory or file | Purpose |
| --- | --- |
| [source](source/) | Exact subjects, merge lineage and implementation patches |
| [python-controls](python-controls/) | Original controls, fixed readers, source receipts, setup refusals and recovery |
| [node](node/) | Before subjects, failed build attempts, cache cleanup, successful rebuild, 14 exact native results and original drivers |
| [components](components/) | Crypto, complete DA attempts, isolated controls, formatting, metadata, Clippy, provider/toolchain receipts and original drivers |
| [publication](publication/) | Initial draft publication and remote identity readback |
| [copy-map.json](copy-map.json) | Original absolute artifact paths mapped to archive paths, with exact sizes and SHA256 |
| [summary.json](summary.json) | Bounded machine-readable observation summary |
| [artifact-manifest.json](artifact-manifest.json) | SHA256 and byte size of every archived file except the manifest itself |

Original receipts retain their original paths and bytes. Raw log/text/patch streams are gzip-compressed losslessly; the copy map records both their archived and decoded sizes and hashes. Use the copy map to resolve original paths inside this archive. Run `python3 verify_archive.py` from this directory to verify every archived file and every decoded stream. The negative bundle records its prerequisite rather than silently borrowing a different base.

The native T source guards checked all 28,807 tracked entries and 2,615,077,043 bytes against Git before and after their recorded executions. The qualified negative subject checked 28,059 entries and 2,592,592,885 bytes. Identity checks themselves do not execute project tests.

The Node driver records Cargo's exact executable path, argv, exits, raw streams and ELF hashes before and after execution; it does not claim a live /proc process-image observation. Component native receipts separately record their observed process images. Neither kind of record verifies every loaded library, runtime memory state, model identity or the whole production deployment.

Retained ELF files remain at their recorded validation-host paths and are explicitly excluded from this Git archive. This is a complete archive of the selected text/JSON/drivers/source-bundle evidence, not a complete native-binary distribution.

No merge into main or production activation is granted by this archive.
