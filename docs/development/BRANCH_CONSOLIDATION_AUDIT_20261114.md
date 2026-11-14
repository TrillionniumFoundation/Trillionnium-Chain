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

The initial runtime integration and reader-binding checkpoint was
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

### Published-candidate repository-truth stopped at a stale current mapping

The first full Linux repository-truth attempt on published source
`dc42ce4df5cff79cc61c5addbaf01074b56b06ca` (tree `9fda17fed2542b2baccaa34585bb00afd699e12b`) returned exit 1
after **6.677 seconds**, before the remainder of that lane could execute.
The original 58 lifetime-budget controls reported **57 passes and one error**:
`test_default_research_register_contains_no_known_security_bound` reached
`pq_lifetime_budget.inspect` and rejected the stale `pon_work.rs` source hash.
The original [summary](../../evidence/pq128-lifetime-source-binding-20261114/original-full-lane/summary.json)
has SHA-256 `9a4bc9c021e80adff3d2c7d5500e1aed3f9eda519efb3942cbd42a2e34c5eab2`;
all 37 original streams/receipts are preserved. Source checks before and after
the failed lane matched the same clean checkpoint. This is a failed full-lane
attempt, not evidence that later commands passed.

The documented default is a current reviewed source mapping. Its 0f9 bytes
remain historical evidence; preserving those bytes alone does not establish
that the current physical source satisfies that default inspector. All 21
old/current regular Git blobs were compared explicitly: eight changed and
thirteen did not. The corrective mapping binds the selected current source
without changing the original budget reader, 58 controls, mathematical
parameters, event roster or qualification flags.

The current composition bridge also required exact-child synchronization:
its already reviewed root register contains 46 paths, so the strict joined
inventory is 21/46/1/66. The root register remains unchanged. Only two existing
composition controls adapt their exact count expectations; the original
probability, source-integrity and nonqualification assertions remain.
The repaired working source passed the original **58 lifetime, 60 composition,
51 root-dependency, 57 chain-claim and 39 proof-profile controls** (265 method
executions), with no failures or skips. The five actual inspectors, current
corpus and CI contract also passed. All 79 selected validation inputs matched
before and after; the selected proof-profile descriptor remained unchanged.
Sixteen separate negative observations refused each stale source digest, mixed
old/current revision pair and superseded composition identity. These targeted
Mac observations use Python 3.14.3 and a canonical private temporary directory;
they do not replace the required full Linux lane on the final successor commit.

The [corrective evidence](../../evidence/pq128-lifetime-source-binding-20261114/README.md) separates the
original failures from subsequent targeted results. A complete successor lane
and exact-head hosted checks remain required; neither has a passing result
from this corrective source review.

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

## Follow-up source bindings and preserved complete-lane failures

The published dc42ce4d source failed its original complete Linux
repository-truth run in the 58-method lifetime suite, with 57 passes and one
source-lock error. The reviewed lifetime successor
7d8d4c59fcd01480a12e1c64835b202079091800 passed all seven local source gates, but
its complete original Linux lane then failed in the hash-use source binding:
31 of the original 33 methods passed, one failed and one errored. That lane
exited 1 after 30.922 seconds; its original limit remained 2700 seconds.
Both failed complete runs and their original source readbacks are preserved.

To identify the remaining causes, a separate diagnostic executed the 122
remaining original command units from the unchanged lane, preserving each
unit's body and arguments. All units ran; 116 exited zero and six exited nonzero
(units 1, 6, 10, 22, 23 and 107). The original 58 repository mutation controls
were among the successful units. The diagnostic continued between failed
units and therefore cannot qualify as a complete original lane pass.
The [complete diagnostic package and integration record](../../evidence/branch-consolidation-followup-20261114/source-binding-integration-v1/README.md)
retain the original summary, all 266 original files in the indexed ZIP,
and the exact source identity before and after.

The four independently reviewed corrections are:

| Component | Exact scope | Focused result |
| --- | --- | --- |
| Hash-use source map, e811c204 | Six changed and 25 unchanged inputs in the fixed 31-path map; original 19 uses and semantic digest retained | Original 33 methods and the existing CI registration control pass; actual reader remains HOLD_NO_GO |
| Fixed-probability source map, 2d9baf31 | One changed and three unchanged inputs; original probability 1/16, research credit 16u, reader and all original methods retained | Original 16 methods pass; old map is refused; actual reader remains HOLD_NO_GO |
| Joint-consensus source map, 6418023d | Four changed and 19 unchanged inputs, bound to the actual F1 source commit; no parameter or runtime change | Original 35 methods pass; one current-revision assertion is adapted and old-revision rejection is added; qualification request still exits 3 |
| Historical collector binding, 341a8b5f | One fixed historical source/tree/producer tuple checked as bounded raw data; current collector and original native evidence remain unchanged | All original 25 methods plus six new boundary methods pass; one new corpus omission/tamper method passes |

The [hash-use review](../../evidence/hash-use-current-source-review-20261114/README.md),
[fixed and joint source review](../../evidence/pon-fixed-joint-source-binding-20261114/README.md)
and [historical collector provenance](../../evidence/branch-consolidation-followup-20261114/native-collector-history-v1/README.md)
state their exact coverage. The historical producer is never imported, compiled
or executed. Its content-address proof does not authenticate a native build.
The fixed source contexts identify reviewed inputs; they are not presented as
the later commits which store the new mapping metadata.

The original failed Mac temporary-path control and the two failed staged
whitespace checks remain recorded. Canonical temporary-path selection and
byte-preserving ZIP carriers corrected those execution/carrier issues without
weakening readers, tests or the repository checker. The old joint Markdown
document is retained byte-for-byte as .md.original because its thirteen original
relative links do not describe its new archival location.

No Rust runtime source, original service deadline, worker count, probability,
cost parameter or qualification flag is changed by these four follow-ups.
The next complete gate receipts must identify their actual committed successor.
The current published C0 external-evidence failure is a separate unresolved
observation at this checkpoint and is not claimed as fixed by these changes.

## Later remote and dependency observations

The original e40d workflow 43551533528 subsequently completed with 15 successful
and six failed jobs. Its two protocol runs and two architecture-specific service
runs retained real CONFIRMATION_TARGET failures under the original four-second,
16-worker contract. The exact-head and prospective protocol receipts both
recorded zero accepted confirmations out of one pressure request; all five
native processes in each run exited normally. These business acceptance
failures are preserved and are not inferred from an outer process exit.
The later C0 workflow 43567821538 remains a separate source and observation;
its ongoing or failed checks cannot be replaced by the predecessor's results.

The seven then-open Dependabot alerts all concern the main branch's
cryptography 41.0.7 requirement. The selected candidate uses cryptography 50.0.2,
outside each of the seven reported vulnerable ranges. Four alerts were high,
two medium and one low. Their original API responses and advisory records are
retained in the later execution evidence; no alert was manually dismissed or
closed. This narrow comparison is not a claim that every dependency, wheel or
OpenSSL deployment is qualified. The 27 historical registry/yank-query timeouts
and the unresolved macOS physical-retention result remain open observations.

The original 908-name archive was confirmed remotely before any merge or branch
cleanup. Its annotated tag is archive/branches-before-consolidation-20261114-dc42ce4df5cf-v2,
tag object 9dafd9192e4040fab530958ef71598aaec9265b9, commit
5f57c4e1e2b7ae95a7b0651d7674979d3f44b90b. That commit retains all 892 original
tips plus the published C0 candidate as its 893 direct parents. A later execution
archive may retain this archive and the reviewed successor as separate parents;
an older tag is never represented as capturing source added afterward.
At this source checkpoint, main integration and the single-branch remote result
are still uncompleted actions.

## Public-readiness reader correction after the C0 external failures

The two C0 external-evidence jobs reached the original 76-method readiness
suite and reported 46 failures and 23 errors. Their actual first mismatch was
the complete observation_only opener-body digest. The
[readiness source review](../../evidence/public-readiness-selected-body-binding-20261114/README.md)
preserves both complete hosted logs and the exact historical/current body
comparison.

Component a3495dab updates one independently reviewed digest. The only body
difference is the already selected requirement for a TLS endpoint witness,
checked before namespace effects; the M06 account-profile refusal remains
before that check. The reader retains the historical growth-body digest and
all DDL, domain, typed-mode and schema checks, and accepts no old-body fallback.
All original 76 methods are byte- and AST-identical. One added method refuses
old-body rollback, an ignored witness error and moving the guard after a
namespace effect.

The first local Mac run attempted 77 methods: 69 passed, eight encountered
missing-dependency errors and none failed an assertion. The new three refusal
cases passed. No dependency installation or test skip was used to turn that
run into a pass. Complete Linux and hosted outcomes must be recorded separately
on their actual tested source. This reader correction changes no Rust runtime
or production qualification.

The e1bf seven-source-gate run also remains an original failed observation:
six commands passed, while the corpus checker refused the newly appended
development-plan bytes. The 308878 follow-up changed only the stale plan pin.
All subsequent plan appends must be pinned after their final bytes are written.


## Original full Linux failure and bounded exec-gate repair

The 1a7afc candidate passed its seven local source gates. Its complete original
Linux repository-truth command subsequently exited 1 after 496.806 seconds,
with identical source identities before and after execution. The last suite
passed 13 of 14 original collector controls. In the post-fork identity-refusal
case, the recorded root exit was -15 rather than the required 125. The
[collector review and complete failed-run package](../audit/20261114-m4-closed-exec-gate/README.md)
retain the raw result and its source identity.

The source review found a concrete ordering race: the parent closes the exec
gate, but cleanup can signal TERM before the child is scheduled to read EOF.
Component b71b84bb adds a successful-close flag and defers only that root's
TERM when exec was never released. The original KILL threshold and total
cleanup grace remain unchanged; descendants, already released roots and
unconfirmed gate closures retain their original signal behavior. No return
code is rewritten. All original 14 test methods are preserved, and two
deterministic signal-order controls are added.

Linux execution of the changed 16-method suite and the complete original lane
is still pending at this source checkpoint. This Python collector correction
does not change the active Rust workload or resolve its four-second pressure
confirmation failure. Local source checks, hosted qualification and the final
remote one-branch result remain distinct observations.


## Complete M5 observations and exact-count integration

The full Linux repository-truth lane on 08c9beca exited 1 after 481.260 seconds.
All 16 collector tests passed, including the original post-fork refusal case,
but the later CI parser still required exactly 14. The failed execution and
both unchanged source identities remain preserved; passing the collector
suite does not turn the complete lane into a pass.

Component f0f6a419 updates only the exact collector count in the shell,
its independent CI contract, and their existing mutation controls. It
requires all 16, retains failures for 0/13, and adds refusal of old 14 and
incomplete 15. The original zero-skip, exact-OK, missing-log and failed-process
guards remain. All four original focused CI methods and ten synthetic parser
cases passed; no collector or Rust runtime code changed in this follow-up.

The independent complete external-evidence-contract command on 08c9beca
passed in 225.948 seconds. The previously incomplete readiness suite now
passed all 77 tests in the prepared Linux dependency environment. All 14
declared historical source trees were present, the original materializer
reported fetched=[], and before/after source identities were equal. This
validates the declared historical-evidence contract on that exact source;
it does not grant current system, hosted or production qualification.

The new integration requires its own original full repository-truth result.
The unchanged original C0 head and prospective native confirmation failures,
the original four-second window and 16 pressure workers, and all prior
HOLD_NO_GO / DENY_ALL conditions remain in force. No main merge or branch
deletion has occurred at this checkpoint.


## Complete M6 validation and concurrent-source reconciliation

The exact M6 source `2a62061177852dc3ebd200fa8d7c66c661a119a1`, tree
`f8d170ff75990e879e93888a95e5408f36b36f6c`, subsequently passed all seven
Mac source gates and both original complete Linux commands. The original
repository-truth command passed in 582.575 seconds, including all 16 collector
controls. The original external-evidence-contract command passed in 221.499
seconds, including all 77 readiness methods. Its historical materializer reported
`fetched=[]`. Each complete lane retained equal before/after identities for
41,671 tracked entries and 3,994,766,803 tracked bytes.

| Original M6 receipt | SHA256 |
| --- | --- |
| Seven Mac source gates | `fc8901b9c33e0887f28994a29ca1fefa3df1301169cfd611a4f30f392fb1f155` |
| Complete Linux repository-truth, 18-stage driver | `7516f4d8602dd58949eeb608439005882c3703a189dac32b0cea716eafd157ce` |
| Complete Linux external-evidence contract, 12-stage driver | `c7ed3b0109e09b1fe18ede0986250c96cb9cf1e41bedf9b1966875ecc03874f4` |

These successes qualify those exact source checks on M6. They do not qualify a
later source, hosted native performance, deployment or production activation.
Earlier failed runs retain their original outcomes.

The attempt to publish M6 stopped before any push because PR #847 had advanced
from C0 to `5a4b7fe8de1adce803184f262fd9f704ead1930c` (N). The actual
pre-push receipt has SHA256
`c7878c180b7019ff635203f08fe05a9c09e00d8e8e9ee44232f4df7272d05183`,
`push_started=false`, `push_exit=null`, and `archive=null`.
No M6 publication or new execution tag was inferred from this refusal. The
09:57:36–09:57:42 UTC full reference observation still contained 908 names and
892 tips: only the candidate had advanced, while the other 907 names and main
were unchanged. N adds 14 commits and changes 49 paths relative to C0.

The reconciliation preserves both M6 and N as parents and explicitly selects
53 paths. This report and a final sole-plan append record the root decision;
all other M6 source and historical evidence remain unchanged. The reviewed
pre-append selected-file manifest has SHA256
`7cd35f9aa4f4cc11ba0b3dc10eb19148c1d5a087d464101573188afa9edb7d95`.
The reviewed source choices are:

- Retain the complete C0/M6 Node store blob
  `d596dc6bab16698cd18bcc15bcbbe1fafedf603e`. Moving the initial readiness
  check before the admission epoch capture introduces an uncovered reorganization
  interleaving. Moving time deferral before local chainwork validation changes
  fatal local-integrity refusal into a nonfatal time refusal. Both findings
  concern source ordering; no executed exploit or false confirmation is claimed.
- Adopt N's worker artifact reader blob
  `f021a33e2969305241099998f703172d29b15251`. It preserves the originally
  validated metadata across the lock boundary and adds independent permission
  and hard-link mutation controls. The complete Linux module now contains
  eight retained controls and two new controls; its actual execution remains
  a separate exact-source result.
- Restore the three genuine C0 frozen PQ JSON identities and use a separate
  current correspondence map. The map binds the same 21 declared source paths,
  including the retained store. Its SHA256 is
  `b1a3e6d9124aa3e15b3f1e46ba361cc3876514f587eeaf4ff7d4530d4b8e2c7a`;
  the independent canonical map digest is
  `69b8f761e92ecd0d43378f44eae7458a0acced35bd9323a171fe59fd843cf5f9`.
  Frozen arithmetic is explicitly unbound. The current 21-path and existing
  46-path inventories still share one release path and cover 66 distinct paths,
  without proving a Git revision, security theorem or complete dependency closure.
- Preserve H1's 31 current hash-purpose bindings, the authority and current
  lifetime inventories, F1/F2, the B1 historical collector carrier, C5's bounded
  cleanup repair, and C6's exact 16-control requirement with the 0/13/14/15
  refusals. Retain the original 58 budget command and add the 25 current-map
  controls. Both endpoint-witness methods remain, giving a static roster of
  78 readiness methods.
- Accept explicit SQLite connection closure, strict JSON type matching, exact
  SP27 native-process readback, current History phase validation and the separate
  10-control W1 workflow roster. Retain the original QROM observations; the new
  fixed expected report changes only the reviewed dependency-lock identity and
  does not become a native execution receipt.

The merged source requires new complete source, repository and external-evidence
gates, the worker module tests and strict lint, and the required hosted checks.
M6 passes cannot substitute for any of these. The original four-second window,
16 pressure workers, fresh Host checks, 30-second campaign and all
HOLD_NO_GO / DENY_ALL conditions remain unchanged. This reconciliation is not
a demonstrated fix for the original confirmation failures or macOS physical
retention failure. Main integration, the explicitly protected legacy deletion,
and the final one-branch inventory remain separate uncompleted actions at this
source checkpoint.


## Reconciled-source inventory check

The first seven-gate run on `c3ae6e71d7b0da4b43b0c7aa6df34aeabf838f47`
passed six commands and failed the distributed-source inventory check. The
complete failed receipt has SHA256
`df8fafcf273cdd00bf2a3a468cbc7e4d318235f0b14a5033f93bfe16c37db512`.
Both source observations were equal and verified 41,677 entries and
3,994,945,659 bytes. The two new current PQ JSON paths were absent from the
generated native inventory. The original generator adds exactly those two
`include_bytes!` records, without removing or changing an existing entry.
The sole plan and its corpus pin are updated after the correction. The new
commit must pass its own gates; the original failed run remains failed.

### 2026-11-14: PublicPolicy ID prefix-equivalence successor of M8

This local component starts from M8 ed0d35487f2a67239e4d646fd41c2c7acb5cc740
(tree 1aa9c21812489080980bdc3c1c2bb43611e88354). The reviewed Rust patch is
16,945 bytes, SHA-256
519f7b6950743386f53e655edf5e31d3f198de581c7125461a08b28d81211a37.
The original public_v3.rs is 433,736 bytes, SHA-256
1a90c3eebf8a8642264f8a65ef906f5bdb9c1e656fab8650dc028328f104fb70;
the candidate is 438,782 bytes, SHA-256
0fd32665f5a666af27d8650214cdfd956d1efb5f72927a003ff0b7c84d10f49a.
Reversing the four declared transformations recovers the original file byte
for byte, including all 84 preexisting test bodies and all Host, authorization,
nonce and deadline code.

The private cache retains the unfinalized state of the existing pon_wire::hash
framing after its immutable 5,105-byte prefix: 79 complete SHA-256 blocks plus
49 buffered bytes. The six original framed dynamic fields add 61 bytes; warm
calls finalize two blocks from a cloned state. These are encoding counts, not
measurements or a latency bound. Cold initialization still performs the prefix
work. The four-thread control checks independent clone results, but does not
guarantee that the harness scheduled simultaneous cold initialization.

Actual observations remain distinct:

- Mac libtest compilation: HOLD, 11 existing Darwin fixture errors and zero
  executed Rust tests; summary SHA-256
  2447c1d7d7300e3a1b8d0d2591ad362c294b261510ef493511496d0a8bfcdcdf.
- Independent Linux M8 plus the exact single-file Rust proposal: serial
  RUST_TEST_THREADS=1 passed the three new controls and original full-qualified
  golden. Strict all-target/all-feature Clippy with -D warnings passed.
  Summary SHA-256
  bf16496bd43d61e935e84748177d8add0ef5cc661be35f77ddb2ec11f94448f4.
- Default-harness follow-up: all RUST_TEST_* environment variables were removed;
  unchanged 3-prefix and 1 --exact commands passed with no ignored tests.
  Summary SHA-256
  0be788fea02aa1a59869c7610f42002c39954f52a63b4f4a76bfdf78f038780a.
  Clippy was not repeated. Both Linux records verify that the root M8 worktree
  stayed clean and the independent uncommitted proposal did not change.
- Original Python policy-vector 7/7 and Hash-use 33/33 controls, the actual
  Hash-use inspector and workspace formatting passed; summary SHA-256
  6464a84fa41517c4d41b0ff4a03032009347c079a904e363a291ed7c4ad8a27a.
- The first budget suite encountered the Mac system temporary directory's
  symlink ancestor: Ran 58 tests; failures=1, errors=4, including two
  subtest errors in one method. That failure is preserved. With only a
  canonical temporary directory selected, unchanged
  budget58, current-correspondence25, composition60 and chain-claim57 all
  passed. The three actual inspectors retained HOLD/HOLD_NO_GO and
  activation=false. Summary SHA-256
  ec1a745291e4ec3f4cda2eb9769d7196490edabc49e92587a17f2dca43b0f9be.

The Linux compilation warning "SQLite I/O boundary UNQUALIFIED: RUSTC must be
absolute" is retained. The hash controls grant no SQLite/native acceptance;
Clippy applies to the exact isolated Rust-proposal source. These are not
hosted 4-second results.

For one reviewed successful paid RPC, the server computes the base policy ID
once for cookie construction, once for Solution validation, once for body
validation and once for response construction; the client computes it once
and reuses it. WaitGrant polling does not repeat it. This is a per-RPC static
count, with no proven global invocation bound. Two historical numbers are
different: the W1 trace's 1,099 fresh Host observations are
3 + 256 + 128 + 512 + 200; the separate x64 policy-stage lower bound is
370 issued + 369 spent + 360 delivered = 1,099 (ARM:
524 + 519 + 510 = 1,553). The latter uses distinct server counters, not direct
id() instrumentation, an exact 4-second interval or a Host count.

This successor's current 21-path map changes only the public_v3.rs digest.
Its new raw-map SHA-256 is
4f234fbff89fdf5693b4d7b82676a46574f92e297fdd535101110a76b9abb3e0,
and canonical source-map digest is
e8b0d9ceb227e95a045cee1b9224719c8b9ac9c416f8f503218bfee0160d57dc.
The current reader and composition independently bind this pair. These
successor metadata bytes are not claimed to exist at the M8 commit. Frozen
V1 budget, source lock and V2 composition remain respectively SHA-256
0315e07ca2988b3b209a6fd2980ca6d9aa22a5bb3aa98b5444a041852b2f0afd,
094dcae805f3872ee621d6554ab26a7a3a34c498e21be669740949ada424ccb2 and
5b527fbd56885bf7a7cba7516a45f0f911479b0d2867d03ff5361ee3e7a8b052.
Path sets, mathematics, caps, flags and source-revision limitations are
unchanged. H1's 19-use/31-source inventory is not expanded: the helper retains
the existing PublicPolicy SHA-256 purpose, reviewed by framing/oracle evidence,
without claiming full-callgraph coverage. No nonce optimization, Host-check
reduction, limit increase or qualification waiver is included.
