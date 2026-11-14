# Branch consolidation audit — 2026-11-14

This report records the repository inventory, implementation choices, source review,
verification evidence, and remaining conditions for the requested single-branch
consolidation. It is an audit result. The sole development plan remains
[TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md](TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md).

## Status and source of truth

The frozen remote snapshot contains **908 branch names and 892 distinct tips**.
The snapshot was observed at 2026-11-14T04:07:38.570192Z. Its manifest has SHA256
`e52bb1c8c0963b2ddd303761ffe7ba949c080b3a0f72983f508978f8971e7734`.
The protected main tip was `dd6e1c3cbeacbdc532b0679297835b3a0aac78f0`;
the existing consolidation PR is [#847](https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/847).

The selected runtime integration and current reader bindings are combined at
`96643a2dd8a90cded0059216cae15e2cd620c77b` (tree
`b3adb2552cf47b7dbd6956b3b23cdac3f588c4cb`). The final binding component is
`b84568a714e24070d9554008660f1382e2c1b1b5`. The branch-disposition ledger is
bound to the earlier selected composition `5c04c60e463462d9df8884786e0d5bb32af08a64`,
which remains an ancestor of the combined candidate. The documentation commit
containing this report adds the evidence bundle and the sole-plan cross-reference.
It does not claim a protected main merge or remote branch deletion.

The executable selection follows the current portability inventory and named
protocol owners. Historical alternatives are retained as evidence with explicit
dispositions. A branch being an ancestor of another branch does not establish
that every behavior on it is present in the selected implementation. Likewise,
a source hash establishes identity, not successful execution or protocol
qualification.

**At the time this report is committed, protected integration and branch deletion
must be judged from exact-head remote checks and a fresh reference inventory.**
No component result below grants the original four-second confirmation target,
native campaign qualification, production activation, or consensus authority.
A later execution receipt must identify the actual merge, immutable history
archive, and final remote branch set.

## Audit coverage and limits

The inventory covers every branch name in the frozen snapshot, including aliases
sharing the same tip. The detailed reviews are retained in the first 80, later 80,
CI 81, and multi-base ledgers. Twenty-seven multi-base cases were examined
separately; an absent unique merge base was never treated as an empty delta.
Their commit accounting includes 287 unique commits, of which 265 are ordinary
commits and 22 are merge commits. All-parent merge seams and current ownership
were considered when deciding whether a historical change was represented,
ported, superseded, or deliberately not selected.

The final ledger has **296 terminal dispositions**, with exactly one owner across eight groups (80, 80, 81, 10, 6, 11, 20 and 8). All 908 names have a concrete disposition and no unclassified rows. Root independently checked all name/SHA pairs against snapshots 0170 and 0208, the presence of all 892 commit tips, all 473 nonancestor-to-terminal witnesses, and the ancestry of all 60 explicitly selected port commits. The remaining 435 references are ancestors of the observed current candidate. These are reference-level and disposition-level statements, with the source-review limits below.

Selected runtime deltas were reviewed together with their complete applicable
controls and current callers. Unchanged original controls were compared by Git
blob identity or parsed test-body identity. Necessary adapters are identified
explicitly. The records preserve different claims separately:

- Reference and object coverage: which names, commits, trees, blobs, and paths
  were enumerated.
- Semantic disposition: why each reviewed branch family contributes code,
  controls, evidence, or a historical alternative.
- Source identity: exactly which bytes were reviewed and executed.
- Behavioral verification: the actual test command, source revision, outcome,
  ignored controls, and original logs.
- Qualification: the independent current protocol and hosted acceptance gates.

This is not a claim of line-by-line semantic review or formal verification of
every historical source body in the 7.94 GB of recorded blob content. Some historical ledgers expressly retain
`source_body_audit_complete=false`. The bounded source and contract reviews
record their scope rather than converting metadata completeness into semantic
equivalence.

## Findings that affect acceptance

### The original confirmation target remains a separate blocking gate

Earlier exact-head and prospective-merge runs failed `CONFIRMATION_TARGET`.
The retained host limits were `cpu.max=25000/100000`, CPU burst zero, 2 GiB
memory, no swap, and 256 PIDs. The five Rust safety controls passed, while the
original four-second, 16-worker confirmation test failed.

The causal review records two concrete paths. One run finished baseline work at
about 2.100 seconds, gathered seven acknowledgements in about 0.943 seconds, and
reached a later History replay at 3.978 seconds, leaving about 21.8 milliseconds
before the deadline. Work then failed at about 4.063 seconds. The prospective
run reached baseline at about 3.099 seconds and a later replay at 3.997 seconds;
the following context step required about 94 milliseconds of wall time.
These observations are retained in the original failure evidence.

The selected reactor, fresh-descriptor, clock, and contention changes have
their own correctness evidence. They are not proof that the four-second target
now passes. The r20 maximum-two-per-caller grant must be evaluated by the real
gate; the classic small-payload path in the original failure did not enter the
post-quantum optimization. No budget, worker count, assertion, qualification
flag, or hosted-only execution restriction was relaxed.

See
[the causal review](../../evidence/branch-consolidation-20261114/failures/confirmation-causal-review-v1.md)
and the native receipts indexed below.

### macOS physical retention capacity remains unqualified

At source `b98ef2436bdef513daa44b8eb96f0f164b1f2067`, the complete macOS
restore module passed seven tests and failed nine. Every failure arose during
fixture creation with `Invalid("retention physical capacity")`, before the
restore operation. A probe using unchanged production create APIs and a
canonical temporary path succeeded in 23 of 24 attempts. The failed arena had
a logical length of 8,388,608 bytes but only 7,602,176 allocated bytes. Later
readback of eight retained failed arenas still showed their original short
allocation.

No causal fix was established, and the physical-capacity check was not weakened.
macOS retention qualification remains open; the separate Linux 16/16 result
does not establish this macOS guarantee. No filesystem-specific cause is inferred.
The [original module failure](../../evidence/branch-consolidation-20261114/native/macos-retention/controlled-restore-macos-full-module-failure.log),
[canonical-path probe](../../evidence/branch-consolidation-20261114/native/macos-retention/retention-public-api-canonical-probe.json)
and [later readback](../../evidence/branch-consolidation-20261114/native/macos-retention/retention-failed-arena-later-readback.json)
remain available.

### Ownership and lifecycle boundaries needed explicit integration

The merged selection preserves current ownership at durable writes, cached
queries, successor outputs, worker observations, caller authentication, and
release cleanup. The key changes are listed in the next section. Alternative
implementations that weaken current ownership or replace the full verification
path were not activated merely because they appeared on a branch.

### Historical dependency findings cannot be reported as an all-clear

The dependency audit used `cargo-audit 0.22.2` and RustSec database commit
`4ef2df8e806a65e2f1ecc14f56f51249062b23d6`, dated 2026-11-13.
It enumerated 36 lockfile paths and 28 distinct dependency graphs without
suppressing advisories or applying a target filter. The advisory results for
the selected workspace, fuzz, and native-cost inputs contained no reported
advisory vulnerabilities or warnings in that frozen database.

Historical prototype graphs contain recorded advisories involving
`tracing-subscriber 0.2.25`, `rsa 0.9.10`, and `ruint 1.15`.
Historical evidence also references the older affected SQLite binding;
the current selected binding is the fixed version. Unmaintained dependencies
including derivative, paste, and bincode are recorded where present.
The current rustix selection is 1.1.6.

Twenty-seven graph audits encountered registry or yank-query timeouts. Therefore
the result does not establish a complete clean registry/yank audit for every
graph. Historical lockfiles and published evidence were not rewritten to
conceal these findings. The exact graph results and advisory identifiers are in
[the dependency results](../../evidence/branch-consolidation-20261114/security/dependency-short-results.json).

### Protected deletion is currently disallowed for one legacy branch

The read-only query authenticated as ProfHepta with repository ADMIN access.
For `fix/chain-bulk-state-tree-20261017` at
`57c1ed545d067937cbd7aaa7570d5f22123265e6`, both its protection rule and the
viewer-specific `refUpdateRule` reported `allowsDeletions=false`.
`viewerCanPush=true` and REST `enforce_admins=false` do not establish
permission to delete that branch.

The rule was not changed or bypassed. Its actual deletion policy must be
resolved through repository governance before a one-branch result can be
reported. The raw observation and official references are preserved in
[the CI and deletion review](../../evidence/branch-consolidation-20261114/remote/required-trigger-and-legacy-delete-review-v1.md).

## Selected implementation and control integration

The full ledgers contain original tips, paths, blob identities, reviewer
decisions, adapters, negative controls, and integration commits. This table
summarizes the choices that materially affect current behavior.

| Area | Selected behavior and reason | Verification boundary |
| --- | --- | --- |
| M12 generation custody | Validate the generation under the owner lock before a durable claim; retain a claim when the durable write fails. | 18 M12 controls plus the node control on all three backends. |
| Host observations | Read fresh held descriptors with NOFOLLOW/NONBLOCK, regular-file checks, EOF bounds and typed scalar limits. Pathname and stale-descriptor caches were not selected. | 44 parent controls and 20 actual bounded children; the separately ignored child entry remains identified. |
| Successor outputs | Bind completed M12 journal custody to store, operation, fund, subject, receipt, window and anchor; retired readback is not live custody. | Two node controls across three backends each. |
| SQLite cache invalidation | Invalidate on COMMIT/ROLLBACK/BEGIN/savepoint ABA and implicit rollback, including error paths; preserve typed cancellation and foreign ownership. | 10 query controls. |
| Parallel PQ preparation | Preserve canonical dependencies and error priority while joining cancelled, panicked and partial workers. | Three original M06 controls plus node equality and cold replay; original worker counts 1/2/4/8 retained. |
| THP2 freshness | Re-read time after the single ML-DSA verification, keep SPKI pins and inclusive/exclusive boundary semantics. | 10 native controls; no new production FinalUse caller claim. |
| Relay callback boundary | Perform preflight before hashing/callback and obtain fresh time before map commit. | 31 native controls; no retired wire format or production caller restored. |
| PublicV3 reactor | Retain direct-buffer behavior and progress semantics while parking/unparking around the existing one-millisecond receive timeout. | Full current PublicV3 suite; this does not prove four-second confirmation performance. |
| PQ claim-file JSON guard | Reject nonzero numbers that underflow to zero while preserving signed zero and valid subnormal values. | 57 boundary controls. |
| Authenticated caller observation | Keep complete default V4 output; expose caller binding only through explicit V5 opt-in after real signature verification. A second binding retains the first and records failure. | Three additional native controls and 96 phase-reader controls; the V4 reader still refuses V5. |
| W1 clock receipts | Bind four finite positive clock values to the same deadline and exact remaining budget; retain the old default V2 namespace. | 31 report controls, 10 current-stage controls, complete 19-kernel and 41-History rosters. |
| Cell peer ordering | Keep a bounded per-session actual-address failure score and stable ordering. Ordinary misses retain fallback peers. Existing connection, byte, deadline and cancellation budgets stay intact. | 19 release, 13 availability, 8 budget and 4 cancellation controls; first Mac failure remains preserved. |
| Original mining-time controls | Restore both complete historical wall-clock/MTP controls with only the reviewed current-settings and registered-material adapters. | 4,096 attempts, two-second success and 150-millisecond wait remain unchanged; two native tests. |
| Worker terminal observations | Use three fresh typed pending namespaces. Missing tasks do not imply zero RSS or completion; postbinding retirement requires original bindings, held pidfd readiness and exactly one proved loss. | 36 original pending controls plus 23 existing worker controls; original 100-millisecond bound retained. |
| Campaign phase reader | Preserve the original positive-phase precheck and error priority without weakening the postcondition. | 28 reader controls, 95 phase controls in the root integration, and 30 ZIP controls; the later T01 composition ran 96 phase controls. |
| Collected-unit observer | Observe the current unit and cgroup with bounded, fixed local commands; an unknown or malformed observation cannot become EMPTY. Preserve the original native failure. | 23 controls, including the exact inactive four-workflow fixture and current-trap shell cases. No historical active workflow was restored. |
| CodeQL evidence readers | Retain exact readonly original collection and the pure semantic-log reader, including unlocated failures and bounded diagnostics. | 26 original collector controls plus four semantic controls; no retired scanner, runner or toolchain activated. |
| Pure Rust lexer | Retain the original subset lexer and five original tests as a helper for its declared subset. | Not represented as a full Rust parser or a replacement for PQ/History verification. |
| Current readers | Retain SQLite metrics, rank-v5 validation, native acquisition, optional CPU/wall fields and typed host outcomes. | 10 SQLite, 14 rank and 6 acquisition controls plus independent source/command negatives. |
| Historical lifetime ledger | Read the exact original fixture and report from Git, with no replacement objects, lazy fetch or network access. | All 20 historical controls; the current successor report remains unchanged. |

The current r20 caller-resource contract and R19 CPU conservation algorithm remain
selected. Historical held-mutex sleep, CPU-refill, cached profile witness,
winner-only proof, private unchecked PQ backend, and unbounded prepared-cache
alternatives are explicitly unselected. Their history and rationale remain in
the audit records. Historical throughput/cost variants are not promoted into a
new protocol profile by this consolidation.

## Current source bindings and historical observations

The four current source contracts cover 44 authority inputs, 20 lifetime inputs,
145 QROM local inputs, and 46 root-dependency inputs: **232 distinct files** after
deduplication. Their reviewed physical bytes, SHA256 values and Git blobs match
the selected source at `5c04c60e…`; the same selected bytes were independently
checked against the preceding Rust composition. The QROM closure follows six
actual local Cargo roots and eight literal includes. Relative to its former
140-input roster, 131 inputs remain identical, nine changed and five were added.
The five additions include the reviewed C36 example, low-rank prefix helper,
statement-boundary controls, and task-product fact module and controls. The
separate SP27 research example is outside this closure.

The current proof-profile descriptor is
`8e95754db175bf8f2c4b3ffc0afe46f7b1eff476479d15fb2c005bf6d79dd0f1`;
the canonical route source set is
`0ecde8d4e43ba120318c9777e78e317f3f2fdfc12bc65d7e2e893abaec8bcdd7`.
These bindings establish the declared source correspondence. HOLD, unknown
security values, false qualification flags and the existing unbound-revision
claims remain unchanged. In particular, the earlier 45-pin root-dependency
snapshot is retained as a declared snapshot; it is not falsely represented as
a complete checkout at the older `225ab38e…` revision, where the later V6 receipt
inputs did not exist.

The current named roster has 77 controls. The supplemental roster contains the
same eight historical controls plus 16 current controls. Two new current controls
cover the reviewed expanded source closure. The historical job remains byte-bound
to `f88c5e041b943ea39be2de6665e9621b0b6a0c056c44dcae2a6215615eb6b130`.
Historical saved reports and source namespaces were not rewritten as current.

The current drift reader independently requires the exact four reviewed paths
and their order. Negative controls also jointly mutate the report and its map:
omission, addition, same-count substitution and same-count reordering all refuse.
The explicit `TRNM-W1-SEMANTICS-CURRENT-CORRESPONDENCE3` reader permits exactly
two provenance SHA fields, for the independently pinned V2 verifier and zkVM
locks, to differ from the frozen historical report. It reads both physical locks
and canonically compares every other report property, including the unchanged
guest lock. Both earlier saved reports retain their original bytes. This is not
a dependency-graph equivalence claim or new native execution.

The workflow fixture initially selected duplicate step names across two source
jobs. A first narrowed fixture then exposed 26 failing subtests because current
supplemental and status controls were still being sent to the historical job.
Both failures are retained. The final fixture sends the original historical name
runner, current supplemental scope checks, and actual current verification CLI
to their real consumers. All 14 original methods remain: 11 method bodies and
all 25 report mutators are AST-identical; three status methods adapt only the
current namespace, nested receipts and boolean field paths. The independent
14-stage roster and exact production CLI invocation are checked. All 14 methods
then passed.

The original Mac C compiler rejected the OpenMP option before executing its
controls. The unchanged eight C controls subsequently passed with the installed
GCC 15 compiler and the original warning/OpenMP flags. This compiler correction,
the source-binding checks and their original failures are retained in the binding
receipt bundle.

Root integration also found that the generated native source inventory lacked
the already integrated `mining_timestamp_liveness.rs` control. The original
generator added exactly its seven-line, 270-byte `include_bytes!` entry; removing
that one entry reproduces the prior inventory byte for byte. The source inventory
check and formatting then passed. This derived inventory is outside the 232-input
binding union and changes no production runtime algorithm.

The 77-control named receipt precedes the final same-count subcases; its affected
13-method module was rerun successfully afterward, and the remaining 64 methods
and inputs did not change. The 112-control corpus run precedes the final workflow
fixture correction; the actual corpus checker passed again after that correction.
The original eight C controls and 14 lifetime controls are included in the 110
closure controls, and the current supplemental 16 are included in the named77.
These receipts must not be summed into a count of unique tests. See the full
[binding evidence table](../../evidence/branch-consolidation-20261114/bindings/FINAL_BINDING_EVIDENCE.md)
for command and source applicability.

## Verification receipts

Each row describes a particular source state. Rows overlap; their counts must
not be added together as a count of unique tests.

| Source state | Recorded result | Scope and limits |
| --- | --- | --- |
| `b940…` and `692f…` | PublicV3 268 passed with two pre-existing ignored entries; 68 sealed/bridge/entry/trial controls passed; recorded strict Node checks passed. | Earlier integration evidence retained unchanged. |
| `1897d0fb…` | 429 top-level controls passed: 41 Python and 388 Rust. Three pre-existing ignored entries were identified. Twenty bounded Host children actually ran. | Exact source manifest: 2,214 files; SHA256 `4cb07ef37de2bea5313e8d61cbaad0b9bb4eebd2055912d21930c3a63370b44f`. |
| `1897d0fb…`, complete W1 roster | 19 kernel and 41 History controls passed; the separate ignored child entry is recorded. | Additional roster evidence, not 60 newly invented controls. |
| `e8241969…` | Original statement boundaries 3/3; original M06 parallel controls 3/3; node parallel/cold replay 1/1. Strict all-target/all-feature Clippy for crypto, M06 and node, plus formatting, passed. | Exact source manifest: 2,228 files; SHA256 `a6159214a8cda62c1dcc757bfdaa7ca3fb6c8908d172c6ed73f0cee0777ce276`. |
| Final Rust composition | 275 PublicV3 controls passed with two pre-existing ignored entries; 44 Cell controls and two original mining-time controls passed. Strict all-target/all-feature Node and DA Clippy and formatting passed. | Head dba81d56be6598cec9df2774446ca3ab7fccca98; 2,241 verified source files, manifest SHA256 38b9cb01715ac961dbf07cd2237f68bf4037d73aa6d2277f04117cd9d02bf651. |
| T03 Linux observation controls | 59 passed; zero failures, errors or skips. | 67 actual absolute project inputs and loaded-module source identities checked. A separate readback proved all 67 inputs identical to Git at merged head 5c04c60e, without re-execution. 7,331 unresolved relative-open events were counted separately. |
| Local source and consumer checks | The complete CI contract suite passed 225/225 at `51c215b4…`. The binding evidence records the complete named77 run, the affected13-method rerun after its final subcases, supplemental24, workflow14, closure110 and corpus112 at their stated source stages. Final-head source gates will be recorded after this report commit. | A subsequent publication receipt must bind the immutable final head/tree to seven exact commands, before/after full tracked-worktree identities and every original stdout/stderr. The complete Linux repository-truth lane and required hosted exact-head/prospective-merge lanes remain independent acceptance conditions. No full-lane or hosted pass is inferred here. |

Linux Rust checks used the pinned OpenSSL 3.5.9 provider whose CLI SHA256 is
`f956c01f912fc3211836ed5086d16755dc605a5458b29ee2ae8bf9c7a353142d`.
The provider and source manifests were checked before and after execution.
The available system 3.5.5 provider was not substituted.

The first T03 instrumentation attempt produced 240 subtest errors because the
driver incorrectly interpreted unresolved relative opens as current-directory
project reads. The corrected driver verifies absolute project inputs and loaded
module sources and records unresolved relative events separately. No production
code, original assertion, or 100-millisecond bound changed in that correction.
A late durable start and a PTY fallback were reconciled by the same create-only
evidence-directory guard; the losing fallback exited before source edits or
tests. These records remain failures of the instrumentation/recovery attempt,
not successful protocol observations.

The first Mac Cell availability suite returned 12/13; a server-count assertion
observed one rather than two. The unchanged baseline isolated control and the
patched isolated control each passed, and the complete Linux roster passed.
The root cause of the initial Mac failure was not established. It is retained
and is not relabeled as a proven environmental fault.

Other original failures, including source-roster composition, historical report
namespace, strict Clippy, and transfer/setup mistakes, are retained with their
actual corrections and source states. Successful later runs do not overwrite
the earlier logs.

## Object integrity and credential-pattern scan

The initial frozen object enumeration included **16,372 commits, 95,805 trees,
and 74,256 blobs**, covering **7,939,757,665 uncompressed blob bytes**.
The all-object Git integrity check completed successfully.

The scan found zero matches for its GitHub classic token, GitHub fine-grained
token, AWS access-key-ID, and Slack token patterns. Three private-key-header
matches were individually inspected: each was a 27-byte detector or negative
test string, with no PEM body or end marker. Raw secret values were not emitted.

These results apply to the documented patterns and frozen object set.
Compressed archive payloads were not recursively unpacked, and the scan does
not establish the absence of every possible secret format.

The later frozen enumeration contained 1,105 additional objects: 411 blobs,
631 trees and 63 commits. The 411 blobs contain **130,927,248 raw bytes**. Every
byte was scanned and every blob's Git content address was recomputed. Five
explicitly documented new patterns—GitHub classic/fine-grained tokens, AWS
access-key IDs, Slack tokens and private-key headers—returned zero matches.
The original scanner's exact regex implementation is unavailable, so the
preserved original result and this new result are not described as identical
implementations.

A separate appendix covers only the two new blobs introduced by the exact
`96643a2d…` integration after that enumeration: the merged corpus and the generated
source inventory, totaling **1,006,072 bytes**. Both content addresses match and
all five patterns again return zero matches. Later report/evidence/documentation
and archive objects fall outside these declared scan sets; subsequent checks must
identify their own exact source and object scope.

The first full Git check overlapped the integration commit and returned exit 2.
All ten objects it reported missing were absent from its earlier frozen enumeration,
were subsequently readable with the correct types, and belong to the exact new
integration tree. After pausing writes, the complete check ran from 05:24:29 to
05:24:50 UTC and returned **0**, with identical reference snapshots before and
after. Its log contains only dangling objects, with no missing or corrupt objects.
No repair, fetch or prune was performed. Both original logs and the object-by-object
reconciliation are retained in
[the final delta evidence](../../evidence/branch-consolidation-20261114/security/final-delta/summary.json).

## Evidence index and remote execution conditions

The open-PR inventory, observed between 04:50:42 and 04:52:21 UTC, contained 579 open PRs: 569 drafts and 10 non-drafts; 80 targeted main and 499 targeted other branches. All heads belonged to this repository. An independent REST inventory matched the GraphQL records on number, head SHA/ref, base name, draft state and repository. Pagination was not an atomic snapshot.

The complete evidence directory is
[`evidence/branch-consolidation-20261114`](../../evidence/branch-consolidation-20261114/).
Its [artifact index](../../evidence/branch-consolidation-20261114/ARTIFACT_INDEX.json)
records each published artifact's byte length, SHA256, original source path,
and any deterministic compression. Original ledgers and logs remain immutable;
current overlays record subsequent decisions and results.

The published index contains **527 artifacts**, totaling **49,605,430 bytes**, excluding the index itself and this report. Every indexed payload was checked against its recorded SHA256 before copying. The bundled original ledgers and native receipts were independently verified before publication. Post-commit source gates and remote publication/merge outcomes are recorded separately so that this document does not claim an outcome that had not occurred at its own commit.

At 04:24–04:26 UTC the exact `e40d7071…` required workflow
[43551533528](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/43551533528)
was pending with zero jobs. The prior PR847 run
[43540659883](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/43540659883)
still occupied the same concurrency group. Its three remaining Rust jobs had
started at 02:21:31 UTC with the unchanged 180-minute job timeout. The nominal
05:21:31 boundary was not a guarantee of whole-run completion. At 04:46:29 UTC the later readback showed two remaining runtime shards; the old run still occupied the group. Earlier protocol
and repository-truth failures in that run were retained.

A later read-only observation at **05:23:52 UTC** superseded that scheduling
estimate. Run `43540659883` had completed with failure (last updated 05:03:25),
and the `e40d7071…` run `43551533528` had already started at 05:03:28. The latter
had six remaining jobs: four Rust shards and the exact-head/prospective protocol
lanes. Four completed jobs had failed: the two repository-truth lanes and two
cross-architecture service-control jobs. At this observation, their API
annotations supplied exit codes rather than a causal diagnosis. The original
180/240-minute timeouts remain; a nominal time limit is not a completion promise.
The new candidate must enter the existing queue. See the
[updated queue observation](../../evidence/branch-consolidation-20261114/remote/queue-refresh-0521-v3/summary.json)
and its separately timestamped annotations.

A later review of the original job logs retrieved at 05:30–05:32 UTC identified
the two repository-truth failures precisely: `CurrentCiTests.setUpClass` reached
the old `len(expected) == 2` drift check and refused before running any tests.
That is the guard corrected by the independently reviewed four-path-and-order
binding in this candidate. The old failures and final local controls are separate
observations; they do not establish that the new candidate has passed its remote
lanes. The two cross-architecture job logs report an inner service exit without
the failing assertion, so their cause is not inferred from that outer exit code.
All four original logs and their hashes are retained in the
[download record](../../evidence/branch-consolidation-20261114/failures/e40d-required-jobs/download-summary.json).

A normal fast-forward update of the existing PR head triggers the required
pull_request synchronize path. Exact-head and prospective-merge evidence must
both be checked. No running predecessor was manually cancelled, no concurrency
policy was loosened, and workflow_dispatch was not used as a substitute.

The main branch requires linear history. Code integration therefore needs the
repository's protected linear merge route. A separately recorded archive tag and content-addressed commit
must preserve every frozen branch tip and its reachable history, together with
the exact name-to-SHA manifest. Preservation in that archive is distinct from a
claim that every historical tip is an ancestor of the linear main branch.
Record both the annotated tag object and archive commit SHA: a tag name remains
a Git reference subject to repository permissions, while the recorded objects
have fixed content addresses.

Before any branch cleanup, verify the archive remotely, verify the protected
main integration, refresh the full remote reference set, and compare every
deletion to its expected old SHA. Concurrently changed or newly created branches
require reconciliation. The repository currently deletes a merged PR head
automatically, so the full-history archive must be published before merging.
No earlier local archive name is relied upon without verifying its object and
remote reference.

The single-branch result can be asserted only from a fresh remote inventory after
all authorized deletions. Any unresolved required CI result or explicit deletion
protection remains visible in the final execution receipt.
