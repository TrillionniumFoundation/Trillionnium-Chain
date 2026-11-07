# PQ recovery and migration owner boundaries

This continues the [sole development plan](../../docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md)
and existing Chain #688 / runtime #4812 candidates. It does not activate a network,
install production keys, authorize a release, or close whole-chain PQ qualification.

## Sources and intended scope

The inspected baseline is Chain `ef1fa4d48ab9894f3d7a4b1c797ca9e7e490b155`
(tree `c3e1144f7131e1aa79fe5230674720a29c8ed5f7`) and **hepta-private-ci**
runtime `3558ced0fd983603a3082a42359e8da63dfc8418`
(tree `74366da4b0fe86e55f3c0c48cfb1484035181ba0`). The language repository
`TrillionniumFoundation/Hepta` is not the runtime repository for these owners.
The source pair, lockfiles and selected configuration digests are recorded in
`baseline-pair.json`. A source pin is not a binary or deployment receipt.

The Chain baseline was materialized from existing Git objects plus 60 missing
blobs obtained through GitHub. Every imported blob, every reconstructed tree and
the original commit hash was checked; the original commit's timezone and message
termination were preserved. The complete remote tree contains 9,669 blob entries.
No execution result from a different tree is relabelled as this complete baseline.

## Published source-review pair

The single source-review candidate is Chain
[`70df2c644ed8dd64afa1e7533743664cddacb9da`](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/70df2c644ed8dd64afa1e7533743664cddacb9da)
(tree `ef6eee36f4ac1cc823b29a2e499e2f2ef6b54855`) and runtime
[`70115620a7f540c8618a9b0d32ead20f8bc508f0`](https://github.com/TrillionniumFoundation/hepta-private-ci/commit/70115620a7f540c8618a9b0d32ead20f8bc508f0)
(tree `ebd1437475d71252786788f67d2911f5a6e6108d`). Both were published to the
existing #688/#4812 branches with expected-head checks and without force.
`source-publication.json` retains the first S/R1 publication; the subsequent
`runtime-R2-source-publication.json` records R2's exact tree/blob readback and
identity. R2 preserves the intervening peer qualification evidence and fixes one
existing product-fixture error conversion. Earlier R1 test outcomes retain R1's
source identity.

[`source-pair.json`](source-pair.json) and its
[scope statement](source-pair-scope.md) pin selected lockfiles, configuration and
real owner source bytes from those Git objects. They expressly retain
`HOLD_NO_GO`, no activation, and an unmet P0-1 strict exit. Actual installed
configuration and a qualified Node/Agentd binary pair are not supplied by this
source manifest. Ordinary startup, recovery tools and acceptance are not claimed
to share an independently exercised deployment combination.

The actual ordinary Agentd native-test executable was built and started; its
1,232,076,656 bytes and SHA-256
`1fda3237fa995431be7a909e69f938aa0e92ef1f10b80cd425dd2544b5b23d2f`
were independently read back at manifest finalization. It is retained as an
unqualified test build, not an installed Node/Agentd release pair.

Runtime evidence was published separately as
[`7530e4bc7aa61a0c23a5933fef4a65d86a586cf8`](https://github.com/TrillionniumFoundation/hepta-private-ci/commit/7530e4bc7aa61a0c23a5933fef4a65d86a586cf8):
98 evidence files, with an index of the other 97 files. Its
[complete record](https://github.com/TrillionniumFoundation/hepta-private-ci/blob/7530e4bc7aa61a0c23a5933fef4a65d86a586cf8/evidence/pq-recovery-owner-20261105/README.md)
and [machine-readable results](https://github.com/TrillionniumFoundation/hepta-private-ci/blob/7530e4bc7aa61a0c23a5933fef4a65d86a586cf8/evidence/pq-recovery-owner-20261105/R2-validation-summary.json)
retain actual R2 execution identities. `runtime-evidence-publication.json`
records the expected-head update and remote summary/index/README byte readback;
no production source, CI or lockfile changed in that evidence commit.

After S, peer commits `583077fdc543ae4dee012a2a8ac2aa419c79a788` and
`2ef9e2fa1985881721a1bff4d546a1b2bdc5ae47` added or updated five current-root
evidence files. Their exact blobs, trees and raw commits were imported and
verified before this evidence publication. They do not change code, configuration,
the sole plan or the source corpus. `publication-peer-preservation.json` and
`publication-peer-history.json` retain that readback. The frozen S/R2 source pair
and all execution attribution remain unchanged.

### The publication branch has advanced beyond the frozen candidate

Before the final evidence update, the shared branch advanced to
`2e3e1cc2df14f809dcbfb560b94bca2b37a48a35`
(tree `a8785b53959dc3ae94fefb1eda91d4b3c2531018`). Since the earlier 2ef
evidence parent it added seven commits and changed 86 paths, including six
outside evidence: the branch-encoding workflow, source corpus, W1 staged runner
and its tests, and two account-archive/native-store Rust files.

This update preserves all of those concurrent changes. Its own overlay changes
only this evidence directory. **The shared PR head is therefore a newer
publication carrier, not the frozen Chain S verification candidate.**
[`publication-carrier-scope.json`](publication-carrier-scope.json) records the
complete path mapping and this distinction. Use the explicit S/R2 commits for
the recorded review combination; the carrier must not inherit S's source checks,
older native outcomes or a deployment qualification. No native or complete
repository rerun on that newer carrier is claimed. P0-1 remains unmet.

Those peer files include their own
[late verification record](../pq-current-root-integration-20261104/LATE_INTEGRATION.md)
and [publication scope](../pq-current-root-integration-20261104/PUBLICATION_SCOPE.json).
Their native, canonical Node, Clippy and Python observations belong to
`dba49c2f66d8a72d6845c70958c4a24d6c4e7e89`, before S's migration repair.
They are preserved as separately sourced evidence; they are not reruns on S or
additional independent-operator acceptance by this continuation.

The published Chain source passed the exact-source corpus (487 pins across six
upstream heads), distributed inventory and complete repository/link checks
(26 packages, 1,146 Rust files, 2,970 links and 25 dependency edges). These ran
while every tracked file was materialized, before the documented cache-space
reclamation. The source-negative fixture suite's 35 passes belong to local
`e218ec649509e328eee4c7ef6021d96c647514ef`; the published source differs only in
four peer evidence documents, and the fixture run is not relabelled as execution
on the published commit. No new Chain native, Clippy or formatting result is
claimed for that later combined source.

The [source-integration archive](source-integration/README.md) retains original
receipts, raw commits, merge mapping, complete-check timing and subsequent
working-copy state. Its original references to an outside-repository handoff or
parent agent describe preparation time; the package is now retained byte-for-byte
here, with its original SHA-256 index. The historical 14f native and research
records above retain their earlier source and input ranges.

## Changes and validation

### Historical migration must not discard unhandled rights

`TrustedPqPrecommitments::pin_checkpoint` checked the supplied source root and
monetary projection, but the importer could silently omit unhandled source rows.
The inventory already classified unknown namespaces and even zero-valued quota or
release records as requiring preservation. A correct hash authenticates the
omitted input; it does not make that omission safe.

The importer must reject any source row whose semantics it cannot preserve.
Valid account/task/reward projection and the existing nonzero-liability refusal
remain. The narrowly supported inert model metadata must match its canonical
initial form. Adversarial controls recompute the correct source commitment for
each altered state, so rejection cannot be attributed to a deliberately invalid
hash. These are reachable source-owner states: quota settlement retains a spent
zero-remaining record until its deadline, while RELEASE can install a nonempty
CURRENT and retain its zero-remaining current release. The new test fixtures are
root-checked synthetic checkpoints, not a complete live W1 migration. Complete
arbitrary-state migration, source-network retirement and external anti-rollback
remain separate obligations.

### Recovery authority belongs before shared-store use

The inspected Agentd recovery checkpoint used Ed25519 and could be omitted.
Protecting only `EvidenceHost::open` would leave other callers of the same
`HeptaEvidenceStore` outside that boundary. In particular, Agentd enables the
governance extension for its ordinary app-server path; thread initialization can
open the same database even when the evidence append service is not enabled.

The runtime change therefore guards both ordinary CLI entrypoints and the public
Agentd `run` owner. Each CLI performs a read-only recovery preflight before
cognitive/plasticity or neural model preparation; `run` repeats authentication and
snapshot admission. It uses
explicit ML-DSA-65 recovery authority, a new V3 signature namespace, a pinned
canonical SPKI/key ID, store identity, signer epoch, revocation and a minimum
frontier generation. The signed snapshot retains qualification, replay and
provider-effect counts/roots. Missing recovery authority must not be treated as
proof of first initialization. Detailed runtime changes and their native outcomes
are retained in the runtime PR; they do not imply coverage of a directly launched
non-Agentd app server.

### Actual runtime results on the frozen R2 source

The original-profile frontier command on exact runtime
`70115620a7f540c8618a9b0d32ead20f8bc508f0` completed with **nine passed**,
zero failed and 239 other library tests outside this selection. It exited 0 in
31.491847 seconds; source and working tree were clean and unchanged. The log
SHA-256 is `ee6e6876bbe4cccc5a6f6f661cec89e904350c687ac8cc2e156029f59780f44b`.

The four real `kernel_evidence_product` tests then compiled and ran on the same
R2 source: **two passed, two failed, zero skipped**, exit 100 in 62.546287 seconds.
Both rollback rejection tests passed. Both positive startup tests failed when the
real Agentd child attempted to bind its Unix control socket and received
`Operation not permitted` (OS error 1). The original nextest local retry behavior
is retained in the log. This is an executed but failed product gate, not four
successful tests, not zero product execution, and not evidence of completed IPC
composition. Its log SHA-256 is
`778c0d4b447451fd6f648b39ea10e6971a1d633a18780614b7ee9311cddaa379`.

The earlier R1 source `fc0c6f7430cc1cce9274d407536e7249f2290ccd` independently
passed nine frontier tests, but its first product build failed with Rust E0277
before executing a product test. R2 fixes only that fixture error conversion;
the inputs, operation identity and assertions remain unchanged. Earlier missing
tracked-input, ENOSPC and linker-SIGBUS attempts retain their original zero-test
scope and classification in the runtime evidence.

The new exact-R2 CI audit separately matched **154 source/synthetic-log fixture
outcomes** and checked 37 mandatory names against 12 unchanged source inputs.
That audit executed zero native tests. The workflow preserves its original 24
controls and adds nine frontier plus four product controls; every selected test
must pass exactly once. Local native receipts above are not the hosted CI lane,
whose own build environment and test budgets remain separately recorded.

The original inference-host library command stopped at linking after 107.717685
seconds, exit 101, with **zero tests executed**. The linker reported signal 7
(Bus error); its cause was not established. Required three-package `just fix`
attempts both exited 101 with explicit ENOSPC diagnostics, after 368.188540 and
337.497042 seconds respectively. They do not establish lint success. All original
profiles, features and flags were retained, and neither attempt changed source.
No further native commands remain running.

The earlier Bazel lock update succeeded without a generated lockfile difference,
but its command-boundary source state was not fully captured. Its separate scope
receipt records the contemporaneous f040 HEAD observation and does not attribute
that tooling result to R1, R2 or a complete binary pair. Terminal cache cleanup
records retain both the observed resource failures and artifact retention state.

### Executed migration controls

On the unchanged inspected production importer plus the new test patch, the real
migration selection produced **9 passed and 3 failed**. The failures exposed an
unhandled debt row, zero quota/release lifecycle state, and nonempty CURRENT
metadata. Both the exact red test patch and the raw logs are retained in
`native-migration-initial/`; missing-fixture compilation attempts remain distinct
from that assertion red run.

At local source commit `36f5d18a93834792025326cfb178415d78103e42`
(tree `2721dbf2f3b58327b51d1d452d0504fa5427df75`), the complete M06 package
ran **25 targets: 239 passed, zero failed and seven existing ignored component
timing tests**. All-target/all-feature strict Clippy and workspace formatting
also passed. Source state was clean and unchanged during each run. The original
profiles, compiler/provider identity, command environment, logs, reconstructible
source patch/raw commit and hashes of all 25 test executables are retained. These
are component test executables, not deployed Chain/Agentd binaries.

Concurrent upstream Chain commit `04be5f02c84cf5cb626a53f34bc03a5bd6ff5137`
was preserved, including its Growth activation fence and monetary/capacity range
scans. The combined source candidate is
`14fcbede085b414a9621aef3f288d2b1ca1839ae`
(tree `64b1a7e4072eddac05604d4bb4b1ef713e10d874`). The 239-test result above
is not relabelled as execution on this later hotpath. A new original-profile
all-target/all-feature M06 run on that exact candidate completed **246 passed,
zero failed and eight existing ignored timing observations across 25 targets**,
with zero filtered tests. Strict all-target/all-feature Clippy also passed.
The additional ignored capacity-range timing observation came from the concurrent
upstream change; no security regression was newly ignored by this repair.
`native-migration-merged/` retains the new commands, clean before/after source
identity, logs, package profile overrides and all 25 executable hashes.
The pinned-source corpus, distributed inventory and full repository source/link
checks also passed; the actual head and dirty documentation state are recorded
in `source-checks.json`. Later upstream `2e7fbaeabc396d501d9d802adc63df963f1d288c`
adds documentation and historical evidence only. It is preserved in publication
without rewriting the native candidate or transferring its tests to another SHA.
The next integration base was the later concurrent source head
`dba49c2f66d8a72d6845c70958c4a24d6c4e7e89`
(tree `25ae0d2035b763b916575292d04571e93a512dd1`; parents
`fc86ed8e927a8eb4e048b160437126a6c0b96c0d` and
`8f8462803f190e6c60e3e8d87f6673c3480504b7`). The earlier `fc86ed8e` changes
Cell, Growth, continuity and ingress; the additional 21 changed paths retain
current-root checkpoint, release, network and Cell controls, quantum DAA changes
and their peer evidence. All peer source bytes are retained outside the two
migration files; the shared corpus preserves its latest formatting and every
peer field except the two corresponding migration pins. The shared plan receives
only the original 1,234-byte additive owner-boundary note.

This continuation did not run native tests, strict Clippy or Rust formatting on
the published S source. Its own 246-test/Clippy receipt remains exclusively attributed to
`14fcbede`; the historical 230 research tests are not execution of the newer
quantum DAA source. Their original receipts and input-equivalence scope remain
unchanged. The separately preserved peer late-verification records name dba as
their actual executed source and likewise do not transfer those outcomes to S.
`source-checks.json` records only the earlier `14fcbede`
source and its then-dirty documentation. Any source-only checks on the final
committed combination carry their own exact source identity and execution scope.

## Threat model and limits

The controls cover replaying a classical checkpoint; changing its domain,
profile, signer, scope, epoch or generation; omitting recovery configuration;
changing an effect count/root; and importing correctly committed but unhandled
historical state. The intended owner has a separately provisioned current root
and a fresh retained checkpoint. Neither a candidate artifact nor the restored
database may supply that root or derive its own expected recovery state.

The new file boundary excludes home, workspace, run and fleet roots for both
checkpoint and root-policy files. A pathname outside those directories is not
evidence of a separate machine, operator
or failure domain. If root policy, checkpoint and database are rolled back
together, these files cannot prove prior execution. A valid startup snapshot is
also not an atomic provider-effect protocol: stable operation IDs, exclusive
consumption, external monotonic state and authenticated outcome reconciliation
remain required at dispatch. There is also a smaller checkpoint-publication
window: start from database S0 and retained checkpoint Q0; let a real effect move
the database to S1; crash before the independent recovery owner retains Q1. A
restore of S0 still matches the unchanged, valid Q0. Startup authentication alone
cannot prevent another release of the consumed permission unless the real
provider/independent monotonic owner blocks it. The rollback controls retain Q1
before restoring S0; they do not establish atomic effect consumption plus external
checkpoint publication. This is a source-level counterexample, not a claim that
a real provider was exercised in this session.

Signed source-commit/tree fields describe provenance;
the recovery verifier does not yet compare them to the running binary's identity.
Writer-lock and configuration infrastructure can precede preflight; this is not a
claim that the entire process performs zero filesystem operations before admission.
The repaired ordinary startup checks the existing exact-schema image read-only
before writable open, then checks the snapshot again. Missing, incomplete or old
images require the explicit installer/recovery owner. Independent concurrent
openers and the snapshot-check/store-binding transaction boundary remain outside
an atomic whole-effect protocol; the two-stage check is not a witness CAS.

The existing snapshot's `provider_effect_*` projection must not be confused with
the default governance extension's separate `provider_invocation_intents` and
`provider_invocation_terminals`. Those invocation tables are not part of the
inspected V2 recovery projection. The default shadow governance mode can also
allow an invocation after an observation failure. Authentication at Agentd startup
does not establish atomic consumption or rollback resistance for that path.

## Research and capacity observations

The existing 13 research/component-budget suites completed **230 tests, with zero
failures, errors or skips**, in 156.849799436 seconds of unittest execution. Their
actual checkout remains `dbc24913e9c23f2359dd22ff9b01243877a6dd4d`; all 52 captured
repository inputs have the same Git blob and SHA-256 bytes at the inspected Chain
baseline. This input equivalence does not certify a complete new binary pair.

The 12 archived component-budget rows were recomputed with exact rational
arithmetic and matched. None certifies the declared `2^-128` research error
budget. In particular, `1 / 2013265921^4` alone is about `2^-123.627562`;
raising the query count cannot remove this term. These expressions are bounds
used by the component model, not measured attack costs or a complete QROM theorem.

The fixed-template PNH1/PGH2 W1 oracle construction exists. Its gate/qubit census
is a constructive upper bound, and native-size evaluation uses macro semantics.
Attacker-minimal costs, real marked-domain probabilities/correlation, calibrated
physical layout and mixed classical/quantum DAA/fork/network security remain open.
The Fast DAA numerical component is not the complete CRYPTO 2026 parallel-chain
protocol. Relevant primary sources are [PQ succinct reductions](https://eprint.iacr.org/2025/2166),
[Fast DAA](https://eprint.iacr.org/2026/1116),
[quantum difficulty-increase attacks](https://arxiv.org/html/2403.08023v2) and
[multiple-resource Nakamoto consensus](https://doi.org/10.4230/LIPIcs.AFT.2025.16).
The two ePrint PDF requests were unavailable in this session; their abstracts and
revision metadata do not supply the missing detailed theorem mapping.

At the inspected source, `with_native_growth` still excludes PQ
identity and the two profiles expose different wire operations. Removing that
refusal would not establish a safe joint profile. The original four-second / 16
producer gate, 4,105-block History gate, same-source PQ/Growth business run and
independent WAN/fault-domain deployment remain unaccepted. W1 v2's retained proof
record contains one observed segment out of 43; complete proof and 58 actual
receipt controls are not established, and an interrupted segment remains unknown.
No new proof run or trial-budget reset is performed by this continuation.

## Strict exit status

| Work | What is established by this continuation | What still prevents exit |
| --- | --- | --- |
| P0-1 fixed combination | Exact source baselines, lockfile/config digests and explicitly scoped reproduction | One independently exercised complete binary/configuration/deployment combination |
| P0-2 current PQ authorization | Verified restricted-import repair; recovery-owner change and strict native CI selection | Every real owner, direct app-server paths, AuthBus/evidence issuers, HTTP/PoN and joint-profile authorization |
| P0-3 release/recovery roots | Existing release-role kernel and actual installer callsites inspected | Fleet installer/updater integration, real custody, old/new root rotation, retirement and device-fault deployment |
| P0-4 historical rights | Reject unsupported authenticated source projections | Full rights/task/revocation migration, CLAIM/reorg/recovery and independently enforced source retirement |
| P0-5 real effects | Recovery snapshot includes provider-effect state | Atomic live consumption plus independent monotonic state and provider outcome reconciliation under faults |
| Research A/B | Reproduced research controls and bounded mathematical conclusions | Full proof/QROM composition and attacker/network/quantum security arguments |
| P0-6 capacity/deployment | Current incompatible profile boundary and incomplete evidence made explicit | Original hostile conditions on the same PQ binary pair, independent WAN/fault recovery and activation responsibility |

All overall exit gates remain **OPEN / HOLD**. Component native outcomes are
recorded above and separately from source-only/CI-fixture and research outcomes.
They do not substitute for a complete binary pair or original business gates.

## Research reproduction

The original executed runner is retained as `research-original-runner.py`; its
absolute paths describe the actual historical run. `research-reproduce.py` is a
later portable equivalent CLI. Its provenance record explicitly distinguishes
creation and CLI checks from the original executed script bytes. The unchanged
original provenance record calls them `original-runner.py` and `reproduce.py`;
the delivery names are `research-original-runner.py` and `research-reproduce.py`,
respectively, with the same recorded bytes. `migration-handoff-original.json`
likewise retains the original receipt paths; their basenames are delivered in
`native-migration-initial/` or `native-migration-merged/`, and
`migration-source-scope.patch` is delivered as `migration-green.patch`.

```bash
python3 evidence/pq-owner-boundaries-20261105/research-reproduce.py \
  --root "$PWD" \
  --output /tmp/trnm-pq-owner-research-new-run \
  --compare-commit ef1fa4d48ab9894f3d7a4b1c797ca9e7e490b155
```

The output directory must not already exist. The command replays the existing
research tests; it does not launch a new proof, native business benchmark or
independent deployment. Record the actual checked-out commit and its new results.
