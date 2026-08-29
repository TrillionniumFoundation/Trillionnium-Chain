# G1-R4C Safety, signer journal, whole-node checkpoint and anti-rollback v1

Status: **BLOCKED_UPSTREAM / candidate-only / no gate or release claim**

Package: `G1_R4_SAFETY_CHECKPOINT_V1` (A05, Gate G1)

This package records the A05 boundary and the smallest safe next interfaces.
It does not promote a validator, create a production signer, alter a JMT or
Application object, change a machine/release flag, or turn a fixture into
authority. The package stops at `BLOCKED_UPSTREAM` because the required A03 and
A04 capabilities are not present on the exact candidate source.

## 1. Authority and exact source identity

```text
repository = TrillionniumFoundation/Trillionnium-Chain
candidate_ref = refs/heads/feature/chain-g1-r4c-full-gap-closure-20260829
candidate_commit = 6e0189e351015ef3230f217ca7ff86149baedcf0
candidate_tree = efea864cb2fbc4835a59a089b3dbab8934e71231
package_branch = feature/chain-g1-r4-safety-checkpoint-20260829
package_base_ref = refs/heads/feature/chain-g1-r4c-full-gap-closure-20260829
package_base_commit = 6e0189e351015ef3230f217ca7ff86149baedcf0
package_base_tree = efea864cb2fbc4835a59a089b3dbab8934e71231
package_head_before_changes = 202d4b9ab719fe596b00b189acb1e2372bcb99fa
package_tree_before_changes = 8209d4a8089b9260e754ec3519af4c2deb23b48f
assessed_plan_ref = refs/heads/docs/chain-poco-bft-mainline-20260825
assessed_plan_commit = 8198fea0307eb368df34ff77ffc272a6b0e655ec
assessed_plan_tree = a1be71bba1b54c428493d186fafb656d081b31a9
observed_plan_tip = 92449b8e101642f39d644d863db7bb60dea488f7
observed_plan_tree = cf8f1ab4f5065cb0551a30ec0e036cd44cb31766
assessed_control_docs_ref = refs/heads/docs/agent-fleet-plan-v1-20260829
assessed_control_docs_commit = a3bdc659d42b92574e591ab687d92a6672ec7cc0
assessed_control_docs_tree = c36032581897d86f2f6b8d295af2b685622f8f90
observed_control_docs_ref = refs/heads/docs/agent-fleet-plan-v1-20260829
observed_control_docs_commit = 8bfd73f0cf1b785a29ae212f13212e51fe34231e
observed_control_docs_tip = 8bfd73f0cf1b785a29ae212f13212e51fe34231e
observed_control_docs_tree = cfedd363147934f50d1352dae31b7d87d79aa8d9
observed_main_tip = b2d485e5641614ea0ca34ebf80a5f7843ff1e6d9
observed_main_tree = ffbad926850a12159336126390271abffc1d99a6
release_truth_path = RELEASE_READINESS.md
release_truth_sha256 = 1659693f0662f8a19b526c602379fe9fa54626afefe33d35917983f699f2dfa4
live_scan_at_utc = 2026-08-29T13:10:49Z
live_scan_result = authenticated connector scan found PR7/8/9/20/21/22 open Draft/mergeable/unmerged; PR22 head 4936caeba16656dd196e95a60dc7455d9cca43d3/tree 056e32bf9a62fbd8e55e0439a36fa5a224138014; no pre-existing remote A05-owned G1-R4C branch or path overlap (local package branch unpushed); re-scan is required after publication
# Complete exact candidate/control/main and PR7/8/9/20/21/22 commit/tree tuples
# for this scan are recorded in the manifest; this package does not promote
# abbreviated PR references to source truth.
```

The assessed plan commit is immutable truth even though the remote plan branch
currently advertises a later tip (`92449b8e101642f39d644d863db7bb60dea488f7`).
The later tip is recorded, not substituted. The assessed Plan file hash is
`3e0fade83c72c9a8ee16efd94f4f2605057610dac8abb1f8b6a71b844038be03`, while
the canonical Plan blob observed on the candidate is
`aba99ae6be2ff8a4aac4d6355e1f778e49a7075a80b09453f16984f85bb0b6cd`; these
are recorded separately. The current default `main` tip
(`b2d485e5641614ea0ca34ebf80a5f7843ff1e6d9`) is an observed divergent legacy
line (including unrelated README/history differences) and is recorded for
context only; it is not this package's base and is not substituted. The
control-tip snapshot's embedded `default_branch_head_observed` value
(`e73d1a930991f0e308bf72854b334b6191c7fcc3`) is historical; the live main
observation above is the current revalidation.

The governing control and registry documents were validated from the assessed
snapshot of `origin/docs/agent-fleet-plan-v1-20260829` at
`a3bdc659d42b92574e591ab687d92a6672ec7cc0` (tree
`c36032581897d86f2f6b8d295af2b685622f8f90`). The live control ref has since
advanced to `8bfd73f0cf1b785a29ae212f13212e51fe34231e` (tree
`cfedd363147934f50d1352dae31b7d87d79aa8d9`). The contract SHA remains
`54cd6d8233ff7812427cf2b8e208ba7628f0593cbfc1b5db545f29b4d3c86d2e`; the
registry SHA is now `cafffe3c45c32a838485a4e6502ccb25b5a5a15245a6d6893f981905ff8d24a3`
(assessed snapshot `c43a8470def968f78676787b1220b1f9a1d5faa53ec93137f73a9a71fbeb43a8`).
The registry change resolves A00/A01 ownership of `CURRENT_SNAPSHOT_V1.*` and
its checker; the A05 entry and its owned/forbidden surfaces are unchanged.
The active PR ledger blob is observed at this tip with SHA256
`374fe528e57152fcb9aebab21810adfa907d2d6314c3018d2da23bec357ddb01`; its
embedded source-head tuple (`d2c14fa686a7836e607661aaf1da34f971d12bc4`, tree
`86d17fbb369481a66684078ea1acef9550d36dad`) is historical metadata. A live
authenticated PR scan supersedes that inventory snapshot. Prior control-tip,
registry, and PR-inventory observations are therefore invalidated and this
run records the revalidated A05 scope; no control-plane file is modified here.

The parent R4 closure contract was read at the same docs branch, commit
`0e059c1c3d96d75f3fa301a8219de6b987a551d3`, file SHA256
`e370a9ad10e67f2bc11e35768fa11949ea1291eac017355558c20006c721d0d3`.
Its commit tree is `59c78557fb6dab482288fc72751fdaa697891960`.
It is an unmerged input, not a local pass claim.

Frozen input hashes:

```text
plan_sha256 = aba99ae6be2ff8a4aac4d6355e1f778e49a7075a80b09453f16984f85bb0b6cd
assessed_plan_content_sha256 = 3e0fade83c72c9a8ee16efd94f4f2605057610dac8abb1f8b6a71b844038be03
observed_plan_content_sha256 = aba99ae6be2ff8a4aac4d6355e1f778e49a7075a80b09453f16984f85bb0b6cd
evidence_contract_sha256 = f524f06e3395ce5a097a6ce98ff06c4863c68cbfbd18a4a91dfff451dfe1f401
assessed_control_contract_sha256 = 54cd6d8233ff7812427cf2b8e208ba7628f0593cbfc1b5db545f29b4d3c86d2e
observed_control_contract_sha256 = 54cd6d8233ff7812427cf2b8e208ba7628f0593cbfc1b5db545f29b4d3c86d2e
assessed_registry_sha256 = c43a8470def968f78676787b1220b1f9a1d5faa53ec93137f73a9a71fbeb43a8
observed_registry_sha256 = cafffe3c45c32a838485a4e6502ccb25b5a5a15245a6d6893f981905ff8d24a3
observed_active_pr_ledger_sha256 = 374fe528e57152fcb9aebab21810adfa907d2d6314c3018d2da23bec357ddb01
machine_truth_sha256 = 19baef8a393d235b4f87a1351e2b8cdf2e7bb1f2eea8770ecc67d3e18966c6be
protocol_manifest_sha256 = ca41347d4559934e706aea13d242625e905b99d956b6187f7df449c1c27299aa
trillionnium/Cargo.lock_sha256 = ee1e9a8382092a397f1b041107cf6b86e468d521af3aa7963e5f6e714e6c3382
```

Machine/release truth observed without modification:

```text
stage = G1-native-host-incomplete
production_candidate = false (config/consensus-mainline.json)
production_consensus_activation = false (config/consensus-mainline.json)
normative_freeze = false (assessed plan/machine-truth state; no flag changed)
release_ready = false (RELEASE_READINESS.md)
```

## 2. Objective, ownership and non-claims

The objective is the exact durable sequence:

```text
Core finalization queue front
 -> finalization intent durable
 -> exact Application/JMT commit and fresh readback
 -> Core application-finalization receipt
 -> tag-3 Safety intent/persist/readback
 -> exact Application/Safety/Signer cut
 -> successor-only whole-node CAS
 -> external monotonic-anchor readback
 -> Ready/reopen
 -> only then a one-shot signer admission
```

Owned surfaces are the six consensus/checkpoint crates, remote signer
protocol/service, and `docs/development/packages/**/*R4C*` listed in the A05
registry. Application object mutation/JMT final apply (A04), ordinary proposal
execution (A03), and network campaign harness (A07) are forbidden here.

This package does **not** claim a production SafetyRules owner, a Core-issued
finalization permit, an authenticated Application JMT readback, an atomic
Application/Safety/Signer transaction, independent anti-rollback, physical
power-loss or disk-full evidence, HSM/KMS custody, a 100,000-block real-node
corpus, restart takeover, network evidence, Gate G1 exit, release readiness, or
activation.

## 3. Frozen interface requests

The exact current interface digests and complete request records are in
[`TRNM_G1_R4C_INTERFACE_CHANGE_REQUESTS_V1.md`](TRNM_G1_R4C_INTERFACE_CHANGE_REQUESTS_V1.md).

| Request | Missing capability | Owner/status |
| --- | --- | --- |
| `G1-R4C-ICR-A03-SAFETY-ADMISSION-CHECKPOINT-V1` | non-`Clone`, one-shot Safety admission binding durable revision, Core affinity, Application statement, checkpoint predecessor and intent | A03, proposed |
| `G1-R4C-ICR-A04-APPLICATION-FINALIZATION-CAS-V1` | Core permit → one transaction → canonical JMT/receipt/queue readback and exact retry | A04, proposed |
| `G1-R4C-ICR-WHOLE-NODE-EXTERNAL-ANCHOR-V1` | independent monotonic anchor and coherent namespace rollback detection | A00/designated authority, proposed |
| `G1-R4C-ICR-REMOTE-SIGNER-CUSTODY-ADMISSION-V1` | admission-bound remote wire, HSM/KMS custody, intent/event ordering and crash replay | A00/remote-signer owner, proposed |
| `G1-R4C-ICR-A05-SIGNER-JOURNAL-LIFECYCLE-ATTESTATION-V1` | explicit signer-journal odd-prepared/even-signed lifecycle attestation; unknown and per-reservation modes fail closed | A05, proposed |
| `G1-R4C-ICR-A06-LAB-WATERMARK-LIFECYCLE-MODE-V1` | wrapped semantic authority must preserve pair-vs-reservation lifecycle mode | A06, proposed |

No requester may implement an owner interface until its owner publishes an
accepted version and digest. These requests are the terminal blocker, not a
reason to edit A03/A04 or widen an inert crate's flags.

## 4. State machine and invariants

```text
Unobserved
  -> FinalizationIntentDurable
  -> ApplicationPermitConsumed
  -> ApplicationReadback (exact root/queue and committed target)
  -> CoreApplicationReceipt
  -> SafetyTag3Durable (exact predecessor + fresh readback)
  -> SignerIntentDurable (intent before producer; external watermark exact)
  -> WholeNodeCAS (successor-only expected predecessor)
  -> CheckpointTargetReadback
  -> SignAdmissionConsumed
  -> SignatureEventVerified
```

Any unavailable, stale, foreign, mixed, forked, copied, renamed, torn, or
third-state observation must fail closed. A CAS response loss resolves only to
exact target (applied), exact source (retryable/no sign), or durable halt. A
duplicate intent/nonce may return only the same durable event/signature. The
default node never handles a raw private key. Bounds remain fixed 32-byte
digests, checked `u64` revision/generation/nonce values, one successor per
operation, existing checkpoint/intent/message limits, bounded ancestry/receipt
counts, and no unbounded retry queue.

## 5. Local evidence and retained mutants

Existing owned tests provide local candidate evidence for tag-3 record shape
(`trnm-consensus-safety-store/tests/sqlite_store.rs`), exact SafetyStore
readback/retry, signer intent-before-signature and watermark negatives
(`trnm-consensus-signer-journal/tests/sqlite_journal.rs` and
`tests/external_watermark_contract_v0.rs`), external lower-watermark/CAS
(`trnm-consensus-external-watermark/tests/authority_blackbox.rs`), local
checkpoint CAS (`trnm-consensus-external-node-checkpoint/tests/cross_process.rs`),
and whole-node predecessor/phase validation
(`trnm-whole-node-checkpoint-types/src/tests.rs`). These are source-present but
not executed in this environment. They do not join real Application, Safety,
Signer, and external stores in one process boundary. The `100k` replay helper
is an ignored synthetic kernel test, not real-node evidence.

### Candidate slice implemented in this run

`trnm-consensus-signer-journal/src/sqlite.rs` now consumes the complete
semantic `(watermark, facts)` response from one adapter load call. The adapter
must provide those facts as one authenticated snapshot; lifecycle mode bits are
not part of this tuple and still require an immutable binding/token. The
journal does not claim transport-level atomicity. For every non-genesis head,
it derives the expected epoch/view/Safety revision, lifecycle nonce,
fingerprint, and signing root from the authenticated local event and intent,
and requires the loaded event sequence, lifecycle parity, event checksum, and
chain checksum to equal the durable journal. Any mismatch (including a
same-watermark altered response) is mapped to `InvalidPersistedState` before
an intent can reach the producer. Fresh/open/install/advance paths reject a
semantic authority advertising per-reservation semantics, and reject a
semantic-mode authority with the default-false/unknown pair attestation;
opaque legacy authorities remain on the opaque path. Only an explicitly
attested signer-journal pair may cross the semantic boundary. Sequence-zero facts remain
adapter-owned and are checked only for the nonzero structural contract; the
capability bytes are never compared or exposed by the journal. The schema1
handoff journal is opaque-only and now rejects semantic authorities before it
creates a database. A wrapper that fails to forward either
`semantic_per_reservation_v0` or `semantic_signer_journal_pair_v0` remains an
upstream integration gap and is not silently treated as production-safe.
The semantic test double now persists the semantic fields supplied at each CAS
while substituting an adapter-owned capability value; the journal checks only
the capability's structural presence and leaves exact capability
authentication to the adapter. The test double's records are therefore not
custody evidence. `read_validated_semantic_intent_v0` validates the target and its non-genesis
direct predecessor's lifecycle shape, referenced intent, event checksum, and
chain checksum. A semantic operational entry also performs the complete
append-only inventory audit before any producer call, so an in-place
historical-row mutation cannot hide behind an unchanged external head when the
semantic mode is stable. The positive
`semantic_journal_dispatch_binds_exact_intent_facts_and_never_opaque` test
checks the sequence-derived nonces. The altered-facts, predecessor-checksum,
per-reservation, unattested, contradictory-mode, and
`semantic_watermark_is_rejected_before_schema1_file_creation` tests retain
negative mutants proving the intended producer-call, lifecycle, and
constructor fences. The external authority's immutable mode-marker rename now
syncs its parent directory after the file fsync; crash/reopen evidence for that
cut remains unevaluated. The generic trait still exposes the mode, pair, and
per-reservation bits as separate dynamic `&self` calls; this run does not claim
an immutable lifecycle snapshot. A wrapper that flips those bits between
admission and dispatch remains a retained TOCTOU mutant and is an open
upstream interface gap; the accepted interface must capture one immutable
snapshot/token and fail closed on drift. Exact capability equality/authentication
and custody remain the adapter's responsibility and are not proven by the
journal.
This is a candidate-only source change; the tests are **not executed** here
because the pinned Rust toolchain is unavailable.

The following mutants remain retained and must not be deleted or weakened:

| ID | Mutation | Required outcome |
| --- | --- | --- |
| `M-R4C-01` | lower/stale Safety revision at same view | reject before sign |
| `M-R4C-02` | same-view/different-block transition | reject before sign |
| `M-R4C-03` | Core/Safety/Application root or receipt substitution | reject |
| `M-R4C-04` | signer watermark ahead/behind Safety | reject |
| `M-R4C-05` | stale, forked, or foreign checkpoint predecessor | reject |
| `M-R4C-06` | CAS commit with lost response | exact target/source/third-state split |
| `M-R4C-07` | coherent DB+WAL+lock+anchor rollback | reject before authority |
| `M-R4C-08` | producer before durable intent/watermark | quarantine; zero signature |
| `M-R4C-09` | duplicate intent/nonce with changed root | exact replay only |
| `M-R4C-10` | missing/altered Safety admission or app statement | reject |
| `M-R4C-11` | HSM unavailable/rotated/revoked or crash before event | replay or quarantine |
| `M-R4C-12` | raw private-key path in default node | compile/configuration rejection |
| `M-R4C-13` | pair=true while semantic_mode=false (contradictory lifecycle state) | reject before journal bytes or authority use |
| `M-R4C-14` | crash after immutable semantic mode-marker rename before directory sync | marker and sidecars remain coherent; otherwise halt |
| `M-R4C-15` | remote-timeout default pair mode performs one CAS per request | reject/quarantine until an explicit lifecycle bridge exists |
| `M-R4C-16` | historical semantic predecessor event/checksum or content mutation | reject before producer |
| `M-R4C-17` | lifecycle mode/pair bits flip between admission and external dispatch | fail closed before opaque or semantic CAS |

R4 rows assigned to A05 are R4-M07 (Safety intent), R4-M08 (Safety
persist/readback), R4-M09 (checkpoint CAS), R4-M10 (CAS response loss), R4-M14
(store skew), R4-M15 (coherent rollback), and R4-M16 (independent replay).
Every row is currently `NOT_EVALUATED` at process/fault scope.

## 6. Fault/replay matrix

| Boundary | Required cuts | Current result |
| --- | --- | --- |
| Safety tag-3 | pre-fsync, post-fsync/readback, restart | local unit/readback only; process matrix not evaluated |
| Application receipt/readback | pre-commit, post-commit response loss, queue ack | upstream A04 capability absent |
| Signer intent/watermark | before producer, producer response loss, event append | local journal tests only; no Safety/App witness |
| Whole-node CAS | stale source, applied-but-lost response, third state, restart | local daemon CAS only; no coherent anchor |
| Namespace durability | DB/WAL/SHM/lock/anchor clone, rename, torn write, disk full, power loss | not protected/evaluated |
| Semantic mode marker | atomic rename, parent-directory durability, semantic/opaque downgrade | parent `sync_data` implemented; crash/reopen not evaluated |
| Independent replay | clean clone, second implementation, arbitrary multi-block | blocked by A03/A04/A06 and toolchain |

No fault result is upgraded from `NOT_EVALUATED` to pass by this document.

## 7. Module-local closure assertions

The following assertions are the required local exit predicates. They remain
`not-evaluated` at process scope in this run, and none authorizes promotion:

| Assertion | Required predicate | This run |
| --- | --- | --- |
| Durable Safety/checkpoint gate | no signature escapes before exact Safety readback and whole-node checkpoint readback | not-evaluated; upstream admission absent |
| Mixed-cut fence | stale or mixed signer/Safety/Application facts fail before sign/vote/apply | candidate semantic-facts mutant implemented; cross-store predicate not-evaluated |
| Coherent rollback | copied/restored namespace is detected before authority use | not-evaluated; independent anchor absent |
| Custody boundary | default node has no raw private-key path | source inspection only; no production claim |

The direct signer-journal adapter and schema1 handoff constructor are guarded,
but `trnm-poco-lab-validator`'s `LabFileWatermark` wrapper currently does not
forward either lifecycle-mode bit. The remote-timeout service's production
path intentionally uses an explicit per-reservation constructor: its first
request claims sequence zero with request facts and each request consumes one
CAS. Its public default `from_binding` constructor advertises pair mode even
though `reserve_v1` follows that one-CAS/request shape, so the first request is
not the signer journal's adapter-owned synthetic genesis and the following
sequence is offset. That composition gap requires an owner decision; it is not
a locally promoted fix. The capability value remains
adapter-private and is checked structurally at this boundary; exact capability
custody and an immutable lifecycle snapshot remain upstream contracts. These
gaps are covered by the upstream ICRs and the `BLOCKED_UPSTREAM` terminal
classification.

## 8. Commands and exact results

```text
bash scripts/project-preflight.sh --audit
  PASS: errors=0 (approved linked-worktree warning only)
bash scripts/ci/check_canonical_development_plan.sh
  PASS
bash scripts/ci/check_poco_bft_mainline_truth.sh --pre-cutover
  BLOCKED: wrapper rc=1; cargo command not found (inner command rc=127); cargo metadata --locked --offline failed
(cd trillionnium && cargo test --locked -p trnm-consensus-safety-rules --all-targets)
  BLOCKED: cargo: command not found (exit 127)
(cd trillionnium && cargo test --locked -p trnm-consensus-safety-store --all-targets)
  BLOCKED: cargo: command not found (exit 127)
(cd trillionnium && cargo test --locked -p trnm-consensus-signer-journal --all-targets)
  BLOCKED: cargo: command not found (exit 127)
(cd trillionnium && cargo test --locked -p trnm-consensus-external-watermark --all-targets)
  BLOCKED: cargo: command not found (exit 127)
(cd trillionnium && cargo test --locked -p trnm-consensus-external-node-checkpoint --all-targets)
  BLOCKED: cargo: command not found (exit 127)
(cd trillionnium && cargo test --locked -p trnm-whole-node-checkpoint-types --all-targets)
  BLOCKED: cargo: command not found (exit 127)
(cd trillionnium && cargo test --locked -p trnm-consensus-remote-signer-protocol --all-targets)
  BLOCKED: cargo: command not found (exit 127)
(cd trillionnium && cargo test --locked -p trnm-consensus-remote-signer-service --all-targets)
  BLOCKED: cargo: command not found (exit 127)
(cd trillionnium && cargo test --locked -p trnm-consensus-unix-remote-signer --all-targets)
  BLOCKED: cargo: command not found (exit 127)
(cd trillionnium && cargo test --locked -p trnm-consensus-signer-journal --test external_watermark_contract_v0 altered_loaded_semantic_facts_fail_before_next_producer_call)
  BLOCKED: cargo: command not found (exit 127)
(cd trillionnium && cargo test --locked -p trnm-consensus-signer-journal --test external_watermark_contract_v0 semantic_journal_dispatch_binds_exact_intent_facts_and_never_opaque)
  BLOCKED: cargo: command not found (exit 127)
(cd trillionnium && cargo test --locked -p trnm-consensus-signer-journal --test external_watermark_contract_v0 tampered_semantic_predecessor_fails_before_next_producer_call)
  BLOCKED: cargo: command not found (exit 127)
(cd trillionnium && cargo test --locked -p trnm-consensus-signer-journal --test external_watermark_contract_v0 per_reservation_external_authority_is_rejected_before_journal_creation)
  BLOCKED: cargo: command not found (exit 127)
(cd trillionnium && cargo test --locked -p trnm-consensus-signer-journal --test external_watermark_contract_v0 unattested_semantic_authority_is_rejected_before_journal_creation)
  BLOCKED: cargo: command not found (exit 127)
(cd trillionnium && cargo test --locked -p trnm-consensus-signer-journal --test external_watermark_contract_v0 contradictory_pair_attestation_is_rejected_before_journal_creation)
  BLOCKED: cargo: command not found (exit 127)
(cd trillionnium && cargo test --locked -p trnm-consensus-signer-journal --lib semantic_watermark_is_rejected_before_schema1_file_creation)
  BLOCKED: cargo: command not found (exit 127)
bash scripts/ci/check_preprovisioned_rust_toolchain.sh --toolchain 1.95.0
  BLOCKED: rc=1; /root/.rustup is absent (script line 82: cd: /root/.rustup: No such file or directory)
bash scripts/ci/check_agent_development_docs_v1.sh
  NOT RUN: guard exists only on observed control tip 8bfd73f0; candidate base lacks the script
```

The mandatory Rust 1.95.0/X230 toolchain is not installed (`/root/.rustup` is
absent). These are environment failures, not test passes; a clean-clone rerun
is required after provisioning. `cargo fmt` and Clippy were not attempted
because the same `cargo` executable is absent.

## 9. Rollback and operator recovery

This run changes no database, WAL, anchor, key, activation, release, or
machine-truth state. Reverting the package commits removes only the candidate
implementation and its test/documentation records; no data migration is needed.
Unaccepted ICRs remain pending. Recovery requires a fresh clean-clone run
after provisioning Rust 1.95.0/X230 and must never restore or copy a production
database/WAL/anchor namespace or alter a truth flag to bypass a fence.

## 10. Evidence envelope and terminal decision

The machine-readable handoff is the exact object below (also mirrored in the
YAML/TOML ledgers). `head_commit` is `null` only while the isolated branch is
uncommitted; the post-commit envelope and Draft PR body must replace it with
the final 40-hex package head. `head_tree` and the implementation/metadata
commit trees are recorded in the surrounding source envelope because the
canonical handoff schema intentionally carries only `head_commit`.

```json
{
  "schema": "trnm-agent-handoff-v1",
  "agent_id": "A05",
  "package_id": "G1_R4_SAFETY_CHECKPOINT_V1",
  "status": "BLOCKED_UPSTREAM",
  "base_commit": "6e0189e351015ef3230f217ca7ff86149baedcf0",
  "base_tree": "efea864cb2fbc4835a59a089b3dbab8934e71231",
  "head_commit": null,
  "changed_paths": [
    "docs/development/packages/TRNM_G1_R4C_GAP_LEDGER_V1.yaml",
    "docs/development/packages/TRNM_G1_R4C_INTERFACE_CHANGE_REQUESTS_V1.md",
    "docs/development/packages/TRNM_G1_R4C_MANIFEST_V1.toml",
    "docs/development/packages/TRNM_G1_R4C_SAFETY_CHECKPOINT_V1.md",
    "trillionnium/crates/trnm-consensus-signer-journal/src/sqlite.rs",
    "trillionnium/crates/trnm-consensus-signer-journal/src/model.rs",
    "trillionnium/crates/trnm-consensus-signer-journal/src/handoff_sqlite_v1.rs",
    "trillionnium/crates/trnm-consensus-signer-journal/tests/external_watermark_contract_v0.rs",
    "trillionnium/crates/trnm-consensus-external-watermark/src/lib.rs",
    "trillionnium/crates/trnm-consensus-external-watermark/README.md"
  ],
  "gaps_closed": [],
  "gaps_open": [
    "G1-R4C-001", "G1-R4C-002", "G1-R4C-003", "G1-R4C-004",
    "G1-R4C-005", "G1-R4C-006", "G1-R4C-007", "G1-R4C-008",
    "G1-R4C-009", "G1-R4C-010", "G1-R4C-011", "G1-R4C-012", "G1-R4C-013"
  ],
  "commands": [
    "bash scripts/project-preflight.sh --audit: PASS; errors=0",
    "bash scripts/ci/check_canonical_development_plan.sh: PASS",
    "bash scripts/ci/check_poco_bft_mainline_truth.sh --pre-cutover: BLOCKED; wrapper rc=1; cargo rc=127",
    "(cd trillionnium && cargo test --locked -p trnm-consensus-safety-rules --all-targets): BLOCKED; cargo rc=127",
    "(cd trillionnium && cargo test --locked -p trnm-consensus-safety-store --all-targets): BLOCKED; cargo rc=127",
    "(cd trillionnium && cargo test --locked -p trnm-consensus-signer-journal --all-targets): BLOCKED; cargo rc=127",
    "(cd trillionnium && cargo test --locked -p trnm-consensus-external-watermark --all-targets): BLOCKED; cargo rc=127",
    "(cd trillionnium && cargo test --locked -p trnm-consensus-external-node-checkpoint --all-targets): BLOCKED; cargo rc=127",
    "(cd trillionnium && cargo test --locked -p trnm-whole-node-checkpoint-types --all-targets): BLOCKED; cargo rc=127",
    "(cd trillionnium && cargo test --locked -p trnm-consensus-remote-signer-protocol --all-targets): BLOCKED; cargo rc=127",
    "(cd trillionnium && cargo test --locked -p trnm-consensus-remote-signer-service --all-targets): BLOCKED; cargo rc=127",
    "(cd trillionnium && cargo test --locked -p trnm-consensus-unix-remote-signer --all-targets): BLOCKED; cargo rc=127",
    "(cd trillionnium && cargo test --locked -p trnm-consensus-signer-journal --test external_watermark_contract_v0 semantic_journal_dispatch_binds_exact_intent_facts_and_never_opaque): BLOCKED; cargo rc=127",
    "(cd trillionnium && cargo test --locked -p trnm-consensus-signer-journal --test external_watermark_contract_v0 altered_loaded_semantic_facts_fail_before_next_producer_call): BLOCKED; cargo rc=127",
    "(cd trillionnium && cargo test --locked -p trnm-consensus-signer-journal --test external_watermark_contract_v0 tampered_semantic_predecessor_fails_before_next_producer_call): BLOCKED; cargo rc=127",
    "(cd trillionnium && cargo test --locked -p trnm-consensus-signer-journal --test external_watermark_contract_v0 per_reservation_external_authority_is_rejected_before_journal_creation): BLOCKED; cargo rc=127",
    "(cd trillionnium && cargo test --locked -p trnm-consensus-signer-journal --test external_watermark_contract_v0 unattested_semantic_authority_is_rejected_before_journal_creation): BLOCKED; cargo rc=127",
    "(cd trillionnium && cargo test --locked -p trnm-consensus-signer-journal --test external_watermark_contract_v0 contradictory_pair_attestation_is_rejected_before_journal_creation): BLOCKED; cargo rc=127",
    "(cd trillionnium && cargo test --locked -p trnm-consensus-signer-journal --lib semantic_watermark_is_rejected_before_schema1_file_creation): BLOCKED; cargo rc=127",
    "bash scripts/ci/check_preprovisioned_rust_toolchain.sh --toolchain 1.95.0: BLOCKED; rc=1; /root/.rustup absent",
    "bash scripts/ci/check_agent_development_docs_v1.sh: NOT RUN; candidate base lacks the guard script",
    "git diff --check: PASS",
    "YAML/TOML parse: PASS after provisional handoff sentinel"
  ],
  "failed_tests": [
    "all nine package cargo suites: exit 127 (cargo command not found)",
    "all seven focused semantic/handoff tests: exit 127 (cargo command not found)",
    "check_poco_bft_mainline_truth.sh: wrapper rc=1; inner cargo rc=127",
    "check_preprovisioned_rust_toolchain.sh: rc=1; /root/.rustup absent"
  ],
  "retained_mutants": [
    "M-R4C-01", "M-R4C-02", "M-R4C-03", "M-R4C-04", "M-R4C-05", "M-R4C-06",
    "M-R4C-07", "M-R4C-08", "M-R4C-09", "M-R4C-10", "M-R4C-11", "M-R4C-12",
    "M-R4C-13", "M-R4C-14", "M-R4C-15", "M-R4C-16", "M-R4C-17"
  ],
  "evidence_scope": "crate",
  "authority": "candidate",
  "classification": "candidate-non-normative",
  "known_gaps": [
    "A03 Safety admission and A04 Application finalization/readback interfaces absent",
    "whole-node external anchor/coherent rollback and HSM/KMS custody absent",
    "dynamic lifecycle bits lack an immutable attestation snapshot (TOCTOU open)",
    "A06 LabFileWatermark does not forward lifecycle bits",
    "remote public from_binding Pair default is offset from one-CAS/request timeout records",
    "exact capability authentication and process/fault evidence are unverified"
  ],
  "interface_requests": [
    "G1-R4C-ICR-A03-SAFETY-ADMISSION-CHECKPOINT-V1",
    "G1-R4C-ICR-A04-APPLICATION-FINALIZATION-CAS-V1",
    "G1-R4C-ICR-WHOLE-NODE-EXTERNAL-ANCHOR-V1",
    "G1-R4C-ICR-REMOTE-SIGNER-CUSTODY-ADMISSION-V1",
    "G1-R4C-ICR-A05-SIGNER-JOURNAL-LIFECYCLE-ATTESTATION-V1",
    "G1-R4C-ICR-A06-LAB-WATERMARK-LIFECYCLE-MODE-V1"
  ],
  "downstream_invalidation": [
    "A04 finalization/readback; A05 signer/checkpoint evidence; A06 fault/replay; A07 campaign",
    "G1-S02/G1-S03/G1 exit; G2F; light-client and release readiness evidence"
  ],
  "next_action": "Obtain six owner decisions and exact interface digests, provision Rust 1.95.0/X230, rerun focused mutants and clean-clone process/fault replay, then revalidate candidate/control refs before the next run."
}
```

Source-envelope metadata (including the final `head_tree`) is kept adjacent
to this exact handoff object in the manifest and gap ledger. The implementation
commit is `dd3699c7a3bfe5438369e9d74ad0ca2817faab44` with tree
`4d345c48ae49462be8a7e216d65e461408a74d31`; the publication metadata/head
commit and tree are populated in the Draft PR/final handoff after the final
revalidation. The frozen pre-change package head was
`202d4b9ab719fe596b00b189acb1e2372bcb99fa` with tree
`8209d4a8089b9260e754ec3519af4c2deb23b48f`.

Terminal outcome: **`BLOCKED_UPSTREAM`**. A03 and A04 must accept and publish
the exact version/digest for their capabilities, and A00 must designate the
independent anchor/custody authority. The toolchain must then be provisioned
and all R4-M07/M08/M09/M10/M14/M15/M16 rows rerun from a clean clone. Until
that occurs, no A05 module closure, Gate G1 exit, production signer, or release
claim is valid.

Downstream invalidation on any accepted interface or source/tree change:
A05 adapters and evidence, A06 fault/replay, A07 network campaign,
G1-S02/G1-S03/G1 exit, G2F whole-node/light-client evidence, and release
readiness.

Deterministic next action: obtain owner decisions for the six ICRs, record
their exact interface digests, revalidate the candidate and live control
SHA/tree, provision the pinned toolchain, then run the complete cross-store
fault/replay matrix from a clean clone.
