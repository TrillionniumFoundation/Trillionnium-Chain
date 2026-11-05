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
Publication is fixed to the later concurrent source head
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

Native tests, strict Clippy and Rust formatting on this latest combined source
are **NOT_RUN**. The 246-test/Clippy receipt remains exclusively attributed to
`14fcbede`; the historical 230 research tests are not execution of the newer
quantum DAA source. Their original receipts and input-equivalence scope remain
unchanged. `source-checks.json` likewise records only the earlier `14fcbede`
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
