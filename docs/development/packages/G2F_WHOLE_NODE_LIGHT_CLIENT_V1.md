# G2F whole-node authority, state sync and light client v1

Status: **STOP_CONDITION (upstream blockers retained / candidate-only)**. This
is a subordinate package contract and gap ledger for A16. A candidate safety
mutant was observed and is retained below; the current hardening rejects it,
but independent review is still required. This is not a protocol or normative
freeze, a Gate exit, a release decision, a private-alpha authorization, or a
production activation record.

The machine-readable companion records are:

- [`trnm-g2f-manifest-v1.toml`](trnm-g2f-manifest-v1.toml)
- [`G2F_WHOLE_NODE_LIGHT_CLIENT_V1_GAP_LEDGER.json`](G2F_WHOLE_NODE_LIGHT_CLIENT_V1_GAP_LEDGER.json)
- [`G2F_INTERFACE_CHANGE_REQUESTS_V1.json`](G2F_INTERFACE_CHANGE_REQUESTS_V1.json)
- [`G2F_AGENT_HANDOFF_V1.json`](../../evidence/g2f/G2F_AGENT_HANDOFF_V1.json)

## 1. Authority and exact source boundary

All observations in this package are bound to the following source tuple. The
default branch, a documentation branch tip, or an older local checkout must not
be silently substituted for it.

| Field | Value |
| --- | --- |
| repository | `TrillionniumFoundation/Trillionnium-Chain` |
| candidate ref | `refs/heads/feature/chain-g1-r4c-full-gap-closure-20260829` |
| base commit | `6e0189e351015ef3230f217ca7ff86149baedcf0` |
| base tree | `efea864cb2fbc4835a59a089b3dbab8934e71231` |
| package branch | `feature/chain-g2f-whole-node-light-client-v1-20260829` |
| implementation head (evidence snapshot) | `b8f7d130858f341117502bc306a12a2a4c42d111` |
| implementation tree (evidence snapshot) | `dd7c6d9bd3130b799f2646a517825750e8bbab06` |
| assessed Plan ref | `refs/heads/docs/chain-poco-bft-mainline-20260825` |
| assessed Plan commit/tree | `8198fea0307eb368df34ff77ffc272a6b0e655ec` / `a1be71bba1b54c428493d186fafb656d081b31a9` |
| Plan SHA-256 | `aba99ae6be2ff8a4aac4d6355e1f778e49a7075a80b09453f16984f85bb0b6cd` |
| evidence contract SHA-256 | `f524f06e3395ce5a097a6ce98ff06c4863c68cbfbd18a4a91dfff451dfe1f401` |
| protocol manifest SHA-256 | `ca41347d4559934e706aea13d242625e905b99d956b6187f7df449c1c27299aa` |
| machine truth SHA-256 | `19baef8a393d235b4f87a1351e2b8cdf2e7bb1f2eea8770ecc67d3e18966c6be` |
| Cargo.lock SHA-256 | `ee1e9a8382092a397f1b041107cf6b86e468d521af3aa7963e5f6e714e6c3382` |
| truth snapshot observed | `refs/remotes/origin/truth/current-snapshot-20260829-8bfd73f0@a0f873eda03054adeed676b2e24bc5b483607600` / `f840339cf90ca64a13b8abdd5816307860be81c4` |
| scope / authority / classification | `crate|fixture|process` / `candidate` / `candidate-non-normative` |

The package branch starts at the exact candidate commit. The implementation
evidence snapshot is the head/tree above; a later metadata-only handoff commit
must not be mistaken for a new source baseline. Re-run this check at the
beginning and end of every run:

```sh
git fetch --prune origin '+refs/heads/*:refs/remotes/origin/*' '+refs/tags/*:refs/tags/*'
git rev-parse refs/remotes/origin/feature/chain-g1-r4c-full-gap-closure-20260829
git rev-parse refs/remotes/origin/feature/chain-g1-r4c-full-gap-closure-20260829^{tree}
```

Expected output is the base commit/tree above. A changed candidate tuple is a
`BASE_DRIFT`; retain this ledger, compute the changed authority inputs, and
invalidate the affected evidence before doing any implementation work.

The control/documentation branch remains live at
`origin/docs/agent-fleet-plan-v1-20260829@8bfd73f0cf1b785a29ae212f13212e51fe34231`
(`cfedd363147934f50d1352dae31b7d87d79aa8d9`). The truth snapshot ref advanced
from `8bfd73f0` to `a0f873ed` (`f840339c`) and only added provenance-generation
outputs; its assessed Plan commit/tree and all five locked digests above remain
unchanged. This is recorded as control-plane drift rather than a candidate-
source `BASE_DRIFT`.
The active control ledger still embeds the prior `d2c14fa686a7836e607661aaf1da34f971d12bc4`
observation as historical metadata; live refs always take precedence for
revalidation. It classifies A16 PR18 (`a370a208…`, model-only) and stacked A17
PR19 as `upstream-invalidated-candidate` because of the G15 stack-base drift;
this package is a new candidate-base branch and does not duplicate or append
to those PRs.
If any of those inputs changes, stop and emit `BASE_DRIFT`.

The canonical machine truth remains `stage=G1-native-host-incomplete`,
`production_candidate=false`, `production_consensus_activation=false`,
`v1_normative_freeze=false`, `v1_node_support=false`, and
`v1_release_ready=false`. This package never edits those flags.

## 2. Objective and explicit non-claims

A16 owns the candidate integration boundary that can eventually consume DA,
Agent/Task, execution/JMT, result/challenge, settlement and Order facts in one
whole-node authority, perform staged state sync, and expose independently
verifiable W3–W7 light-client proofs.

This package currently claims only candidate conformance surfaces and missing
interfaces. Existing local observations include a five-store fresh-readback
join, a bounded Rust Order verifier, a candidate composite-root/pre-vote seam,
manifest-bound process tests, a local Order tag-50 membership writer, and a
bounded staged state-sync model with copied/forked-residue quarantine. They are
useful candidate inputs, not authority.

### Safety stop recorded in this run

Before the quarantine hardening, adversarial replay found two P0 failures in the
candidate model: a same-label physical namespace copy could stage/commit a new
generation, and a rejected same-height fork left retained stage residue that
`reopen()` later treated as healthy. Both mutants are retained as
`G2F-M-NAMESPACE-COPY` and `G2F-M-ANCHOR-SAME-HEIGHT-FORK`; the fixes in
`dc9034d5d`/`1be57d57f` now reject and permanently quarantine those paths, with
37 tests and the runner's fault checks passing. Under the operating contract,
the observed safety failures require the terminal outcome
`STOP_CONDITION` until independent review and a clean-clone fault replay are
complete. A coordinated non-zero `ManifestView` replacement with a recomputed
`stage_digest` remains an open retained mutant because the model has no
independent owner-issued commitment for that view.

The following remain explicitly false until the signed G2F exit requirements in
the canonical Plan are independently replayed:

```text
authenticated_cross_plane_snapshot = false
cross_plane_atomic_multi_store_commit = false
canonical_application_jmt_root = false
canonical_application_jmt_order_binding = false
external_monotonic_anti_rollback_anchor = false
descriptor_bound_openat_namespace_identity = false
same_uid_rename_race_closed = false
staged_state_sync_atomic_swap = false
whole_node_process_authority = false
signer_custody_and_broadcast = false
restart_catchup_ordinary_tc_handoff = false
two_independent_light_clients = false
global_w3_w7_proof_coverage = false
complete_w0_w7_real_trace = false
g2f_global_complete = false
node_support = false
production_candidate = false
production_consensus_activation = false
release_ready = false
```

No private-alpha, validator, signing, voting, garbage-collection, settlement,
or release claim may be inferred from a local SQLite readback, candidate
composite root, process-pin file, or one light-client implementation.

## 3. Owned and forbidden surfaces

Owned candidate surfaces:

- cross-plane readback/global-execution/order-application/finality-verifier
  adapters and contracts;
- whole-node checkpoint, anti-rollback, staged state-sync and process-owner
  contracts;
- light-client proof-family adapters, conformance vectors and differential
  replay harnesses;
- package documentation, typed gap ledger, evidence index and A11–A15 ICRs.

Forbidden surfaces:

- source-plane transition semantics owned by A11–A15 (or A04/A05);
- changing the canonical CEV1/AgentTransaction/Order/JMT/settlement wire
  semantics without the owning agent's accepted ICR;
- treating a composite root, local store root, signed carrier, or operator pin
  as the application JMT or an external anti-rollback authority;
- production signer, activation, release, machine-truth or normative-freeze
  changes;
- merging this package's own PR.

## 4. Current candidate inventory and evidence boundary

The following observations are imported from the exact candidate source and
remain scoped candidate-non-normative:

| Candidate observation | Recorded result | Why it does not close G2F |
| --- | --- | --- |
| Five-plane fresh readback | 3 positive, 13 negative, 2 compile-fail controls; fresh reopen and same DA head/certificate snapshot | no authenticated cross-store commit, canonical Order authority, whole-node CAS, or full-store rollback protection |
| Bounded Order/checkpoint verifier | strict raw CEV1 decode, Ed25519/QC checks, sparse/tag-50 membership, successor-only checkpoint CAS; 15 verifier tests, 7 checkpoint tests | membership is not the application JMT in a finalized Order header; process and global authority remain false |
| Global execution candidate | previews all five kernels and commits a domain-separated candidate composite root | composite root is explicitly not the application JMT; no global Order carrier issuer or anti-rollback authority |
| Manifest-bound process tranche | recorded 7/7 process tests and five local negative classes (DA/Order mode drift, malformed temp, pin rollback, journal rollback) | path/hash/rusqlite checks do not retain openat/dirfd namespace identity or prevent same-UID rename; no production signer/broadcast |
| Namespace/anchor contract (package working tree) | candidate `PocoNodeG2fNamespaceGuardV1`/`PocoNodeG2fFileHandleV1` openat identity and `PocoNodeG2fAnchorRecordV1` successor-CAS contract with unit mutants | feature-gated candidate contract only; pre-fix copy/fork acceptance triggered STOP_CONDITION and is now quarantined; no external HSM/KMS backend, normal-node process wiring or production authority |
| Order-state membership writer | candidate tag-50 writer and canonical receipt projection | local writer does not commission canonical Node Order state or bind the application JMT |
| Light-client checker | standalone Python Order-finality checker and bounded Rust verifier are present as candidate inputs | no accepted two-client end-to-end W3–W7 replay; `global_light_client_complete=false` |
| G2F fixture conformance runner | 37 discovered and executed tests, 21 wire mutants, 7,548 A/B differential samples and 3,000 state-sync mutants; both clients agree and reject negatives | fixture-only synthetic carrier; no accepted upstream interfaces, real W0–W7 trace, 64-epoch campaign or production authority |

All counts above are observations from candidate metadata, status tranches and
source boundary scripts. They are not signed `TrnmGateEvidenceV1` bundles. The
default PATH used for this documentation run has no `cargo` executable; the
pinned Rust 1.95 toolchain was invoked explicitly and its feature-gated check,
test and clippy results are recorded separately as candidate-only evidence.

## 5. Frozen candidate interfaces (proposed, not accepted)

The following interfaces define the smallest cross-owner contracts A16 needs.
They are additive candidate proposals only. Their exact canonical bytes,
domains, bounds, errors and accepted digests must be supplied by the owning
agents through [`G2F_INTERFACE_CHANGE_REQUESTS_V1.json`](G2F_INTERFACE_CHANGE_REQUESTS_V1.json).

### 5.1 Authenticated multi-store snapshot

`AuthenticatedCrossPlaneSnapshotV1` is a non-`Clone` token containing one
`snapshot_generation` and authenticated records for DA, Agent/Task,
Verify/Challenge, MVCC/Fee, Settlement and canonical Order state. It carries
store instance IDs, namespace/file identity, sequence/height, journal tails,
all per-plane roots, the canonical application JMT root, and an authenticator.
The issuer is a Node-owned coordinator after fresh readback and durable fsync;
the caller cannot provide roots, IDs or certificates. Same generation/digest is
idempotently retryable; a lower generation, changed bytes, response-loss
uncertainty, sidecar/WAL drift or namespace replacement fails closed.

### 5.2 Canonical application-JMT/Order binding

`CanonicalExecutionJmtSnapshotV1` carries the exact execution receipt and
read/write versions, JMT key/value and sibling proof, `application_jmt_root`,
predecessor root, finalized height and Order proof digest. The proof domain is
`trnm.poco-ai.g2f.application-jmt-binding.v1`. A16 may consume only an
accepted A13 proof; it must reject a candidate composite root, sparse local
root, caller-supplied sibling list or mismatched Order height.

### 5.3 External monotonic anchor and namespace identity

`WholeNodeAnchorV1` is the proposed owner-issued contract. In the Python
fixture it binds generation, finalized height, epoch, validator-set hash,
manifest digest, file/device/inode/link-count/effective-UID identity and a
checkpoint digest to an authenticated store outside the rollbackable DB
(HSM/KMS, remote signer, or equivalent authenticated quorum). The candidate
Rust shapes (`PocoNodeG2fAnchorRecordV1` and
`PocoNodeG2fExternalMonotonicAnchorV1`) currently provide only a bounded
successor-CAS record and do **not** yet carry the canonical checkpoint/state
root or an explicit initial scope argument; they are not an external backend.
The Python fixture additionally requires a contiguous generation successor and
rejects same-height equivocation. `DescriptorNamespaceIdentityV1` (candidate
code names: `PocoNodeG2fNamespaceGuardV1` and `PocoNodeG2fFileHandleV1`)
retains the directory/file descriptors used for all subsequent operations and
revalidates identity before any mutable pragma, signing, voting, GC, sync or
settlement.

### 5.4 Staged state-sync swap

`StagedStateSyncManifestV1` verifies the weak-subjectivity anchor, Order/DA/
execution/JMT/result/settlement proofs, chunk roots, version transition and
validator membership before writing an isolated staging namespace. The swap is
an fsynced, predecessor-bound atomic rename/CAS followed by fresh source and
target readback. Old WAL/key/sidecar, partial/torn, copied, renamed, stale or
downgrade inputs are quarantined and never exposed to authority.

### 5.5 Independent light clients

Two independently authored clients must each verify these proof families:

1. Order (validator-set/epoch, proposal, Vote/QC/TC, three-chain finality and
   handoff);
2. DA (`BatchRef`, full-replication certificate, namespace and repair status);
3. execution (AgentTransaction authorization, deterministic receipt and
   application-JMT membership);
4. result/challenge (profile, evidence, maturity and challenge closure);
5. settlement (intent/receipt, fee/conservation and exactly-once terminal
   state); and
6. upgrade/state sync (weak-subjectivity anchor, version transition and
   downgrade rejection).

The current standalone Python and bounded Rust Order checkers are candidates;
independence and complete cross-family replay are unaccepted until both owners
publish signed differential evidence.

## 6. State machines and authority barriers

Whole-node checkpoint:

```text
UntrustedInput
  -> FreshAuthenticatedSnapshot
  -> JmtAndOrderProofVerified
  -> AnchorAndNamespaceVerified
  -> StagedCheckpointDurable
  -> SuccessorCAS
  -> FreshPostCommitReadback
  -> AuthorityEligible
```

Any stale/forked/root/identity/anchor mismatch transitions to `Quarantined`;
response-loss after a durable write transitions to `ReopenRequired`, where only
an exact successor may be retried. No `AuthorityEligible` state exists in the
current candidate source.

State sync:

```text
UntrustedManifest -> VerifiedManifest -> IsolatedStage -> FsyncedStage
  -> AtomicSwap -> FreshSourceTargetReadback -> SyncEligible
```

The Python state-sync model now recomputes its candidate header/checkpoint and
retains context, epoch and validator identity through the staged anchor. Its
latest hardening permanently quarantines copied namespaces, same-height fork
residue, duplicate generations, malformed sidecars, and full-store rollback
residue. The candidate Rust anchor record still does not yet carry a canonical
checkpoint/state-root field or an explicit scope argument on the initial
backend CAS. The descriptor sampler also cannot detect an owner-unsequenced
same-size A→B→A write, and its public identity deserializers are not an
authenticator. These remain retained mutants; the namespace/anchor rows are
`reopened` after the observed P0 failures and no anti-rollback authority is
claimed.

`SyncEligible` is not signing/voting eligibility; both require the external
anchor and process-owner proof. A failed check never falls back to a local
composite root or an older checkpoint.

## 7. Invariants

Safety and root integrity:

- every plane in a cross-plane cut has one authenticated generation and store
  identity;
- the finalized Order header/proof names the exact application JMT
  `post_state_root`; composite/local roots are rejected;
- predecessor-bound checkpoint and external anchor advance strictly once;
- insufficient Order weight, wrong epoch/domain, malformed proof, duplicate
  signer, profile downgrade or subjective result fails closed.

Durability and rollback:

- durable intent/receipt/checkpoint precedes any authority use;
- copied, renamed, stale, torn, sidecar, WAL, key, process-pin and complete
  database-file rollback are rejected before signing, voting, GC, sync or
  settlement;
- all failed and superseded artifacts/mutants remain retained and addressable.

Liveness and recovery:

- exact response-loss retries converge to one durable successor or quarantine;
- staged sync never exposes a partial namespace and can resume only from an
  authenticated predecessor;
- catch-up and Ordinary/TC/handoff progression are monotonic and cannot bypass
  the anchor.

Economic/custody:

- settlement remains exactly-once and conserves every asset; no PoCO weight is
  eligible from candidate evidence;
- no raw production key enters the node; signer custody and broadcast receipts
  are separate, authenticated interfaces.

## 8. Bounds and rejection classes

The following are candidate contract ceilings; an owner must publish accepted
values before implementation is authoritative.

| Resource | Candidate ceiling | Enforcement | Required error |
| --- | ---: | --- | --- |
| encoded snapshot/manifest bytes | 262,144 | decode before allocation | `ERR_SNAPSHOT_LIMIT_EXCEEDED` |
| per-plane objects | 4,096 | sorted unique typed IDs | `ERR_OBJECT_COUNT_EXCEEDED` |
| JMT depth/siblings | 256 | proof verifier | `ERR_JMT_DEPTH_EXCEEDED` |
| signatures/validator entries | 1,024 | quorum verifier | `ERR_SIGNATURE_WORK_LIMIT` |
| nested depth | 8 | canonical decoder | `ERR_DEPTH_LIMIT_EXCEEDED` |
| retries per generation | 1 exact successor | anchor/CAS | `ERR_STALE_GENERATION` |
| proof verification time | 2,000 ms | client budget | `ERR_PROOF_BUDGET_EXCEEDED` |

Unknown versions/fields, trailing bytes, duplicate IDs/signers, wrong domain or
chain, stale/forked roots, missing chunks, sidecars/WALs, namespace replacement,
anchor rollback and response-loss ambiguity are all fail-closed errors.

## 9. Positive vectors and retained mutants

Positive vectors must bind exact bytes, expected roots/errors, command and
evidence ID. Required candidate vectors include:

- one authenticated six-plane snapshot with canonical Order state;
- exact execution receipt to application-JMT inclusion and finalized Order
  membership;
- successor-only external-anchor CAS and exact response-loss retry;
- descriptor-bound openat identity across restart and same-UID rename attempt;
- verify–stage–fsync–swap state sync with fresh post-swap readback;
- one complete W0–W7 `AgentTransactionV1` trace;
- two clients accepting the same valid proof and rejecting the same mutants;
- 64-epoch/10,000-header jump and weak-subjectivity renewal vectors.

Every mutant is retained, even when a later positive run succeeds:

```text
G2F-M-ATOMIC-TORN                 G2F-M-ATOMIC-SIDECAR
G2F-M-ATOMIC-WAL                  G2F-M-ATOMIC-FULL-STORE-ROLLBACK
G2F-M-JMT-COMPOSITE-SUBSTITUTION G2F-M-JMT-WRONG-KEY
G2F-M-JMT-SIBLING-ORIENTATION    G2F-M-JMT-ORDER-HEIGHT
G2F-M-ANCHOR-LOWER-GENERATION    G2F-M-ANCHOR-OLD-EPOCH
G2F-M-ANCHOR-DB-ONLY-ROLLBACK     G2F-M-ANCHOR-MANIFEST-DRIFT
G2F-M-ANCHOR-CHECKPOINT-BINDING   G2F-M-ANCHOR-SCOPE
G2F-M-ANCHOR-SAME-HEIGHT-FORK     G2F-M-ANCHOR-GENERATION-GAP
G2F-M-NAMESPACE-SAME-UID-RENAME   G2F-M-NAMESPACE-COPY
G2F-M-NAMESPACE-ANCESTOR-SWAP     G2F-M-NAMESPACE-LINK-COUNT
G2F-M-NAMESPACE-ABA               G2F-M-NAMESPACE-UNBOUNDED-SIZE
G2F-M-NAMESPACE-FORGED-IDENTITY
G2F-M-SYNC-STALE-CHECKPOINT       G2F-M-SYNC-CHUNK-ROOT
G2F-M-SYNC-WAL                    G2F-M-SYNC-PARTIAL-SWAP
G2F-M-SYNC-DOWNGRADE              G2F-M-SYNC-CONTEXT-SCHEMA
G2F-M-SYNC-HEADER-HEIGHT-BINDING  G2F-M-LC-WRONG-EPOCH
G2F-M-LC-INSUFFICIENT-WEIGHT      G2F-M-LC-COMPOSITE-ROOT
G2F-M-LC-STALE-ANCHOR             G2F-M-LC-DOWNGRADE
G2F-M-TRACE-BATCHREF               G2F-M-TRACE-ORDER-HEIGHT
G2F-M-TRACE-RECEIPT-ROOT           G2F-M-TRACE-SETTLEMENT-RESULT
G2F-M-TRACE-RPC-DIGEST             G2F-M-PROCESS-DUPLICATE-OWNER
G2F-M-PROCESS-RAW-KEY              G2F-M-PROCESS-RESPONSE-LOSS
G2F-M-PROCESS-ORDINARY-SKIP        G2F-M-PROCESS-HANDOFF-DOWNGRADE
G2F-M-EVIDENCE-DIGEST-DRIFT        G2F-M-EVIDENCE-UNCLEAN-TREE
G2F-M-EVIDENCE-UNSCOPED-POSITIVE
G2F-M-UPGRADE-OLD-VERSION          G2F-M-UPGRADE-OLD-ANCHOR
G2F-M-UPGRADE-MISSING-EPOCH        G2F-M-UPGRADE-VALIDATOR-SUBSTITUTION
G2F-M-SYNC-COORDINATED-NONZERO-VIEW (retained open; no owner-issued view commitment)
```

The machine ledger retains 58 mutant references (53 unique IDs), including the
three P0 stop-condition records above. A passing candidate replay never removes
the failed pre-fix artifacts or promotes an authority claim.

The Python model's candidate header/height/context checks are unit-tested, and
the latest hardening permanently quarantines copied namespaces, same-height
fork residue, duplicate generations, malformed sidecars, and full-store
rollback residue. The Rust descriptor/anchor contract still lacks a canonical
checkpoint field, an explicit initial scope argument and an authenticated
external backend. Same-size owner-unsequenced A→B→A, forged-identity, and
coordinated non-zero view replacement mutants remain retained; the
namespace/anchor rows are reopened for independent review and no
anti-rollback authority is claimed.

## 10. Fault, crash and replay matrix

| Cut/mutant | Required residue | Restart/replay owner | Allowed result | Forbidden result |
| --- | --- | --- | --- | --- |
| kill before snapshot fsync | no authority token | snapshot issuer | quarantine/retry exact predecessor | partial snapshot consumed |
| response loss after durable multi-store commit | durable generation and anchor | Node coordinator | one exact successor or readback | duplicate commit or vote |
| torn/partial store row | retained failed bytes | owning plane + A16 | fail closed, mutant retained | fabricated root |
| copied or renamed directory/file | descriptor/inode mismatch | namespace owner | reject before open/write | same-UID acceptance |
| sidecar/WAL/key rollback | old identity or generation | anchor owner | reject before authority | DB-only rollback accepted |
| full database-file rollback | external anchor ahead | anchor + Node | quarantine and operator recovery | copied DB becomes authoritative |
| state-sync kill before swap | isolated staging residue | sync owner | discard or resume verified stage | partial live namespace |
| state-sync response loss after swap | predecessor/target both audited | Node coordinator | exact target readback | second target or downgrade |
| light-client malformed/fork proof | no client state advance | each independent client | identical rejection class | one client accepts |
| upgrade old anchor/version | old proof retained | both clients + sync owner | reject downgrade | validator/signing eligibility |

Process, kernel/host reboot, and power-loss-equivalent campaigns must be reported
separately; a unit test or SQLite transaction is not a power-loss result.

## 11. Exact commands and current run result

Source and digest checks:

```sh
git fetch --prune origin '+refs/heads/*:refs/remotes/origin/*' '+refs/tags/*:refs/tags/*'
git rev-parse HEAD
git rev-parse HEAD^{tree}
git rev-parse refs/remotes/origin/feature/chain-g1-r4c-full-gap-closure-20260829
git rev-parse refs/remotes/origin/feature/chain-g1-r4c-full-gap-closure-20260829^{tree}
sha256sum docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md \
  docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_ENGINEERING_EVIDENCE_CONTRACT_V1.md \
  docs/protocol/poco-ai-native-v1/spec-manifest.toml config/consensus-mainline.json \
  trillionnium/Cargo.lock
```

Candidate boundary/replay commands (must be rerun from a clean clone after
interfaces are accepted):

```sh
bash scripts/ci/check_trnm_poco_cross_plane_readback_v1_boundary.sh --candidate-index-only
bash scripts/ci/check_trnm_poco_cross_plane_checkpoint_v1_boundary.sh --static-only
bash scripts/ci/check_trnm_poco_global_execution_v1_boundary.sh --static-only
bash scripts/ci/check_poco_ai_native_v1_order_finality_light_client.sh
cargo test --manifest-path trillionnium/Cargo.toml --locked --offline
cargo clippy --manifest-path trillionnium/Cargo.toml --locked --offline --all-targets -- -D warnings
PYTHONDONTWRITEBYTECODE=1 ./scripts/g2f/check_g2f_conformance.sh
```

Documentation-run result on 2026-08-29 (latest local candidate replay):

```text
base tuple: matched 6e0189e351015ef3230f217ca7ff86149baedcf0 /
            efea864cb2fbc4835a59a089b3dbab8934e71231
control ref: live 8bfd73f0cf1b785a29ae212f13212e51fe34231 /
            cfedd363147934f50d1352dae31b7d87d79aa8d9; truth snapshot a0f873eda03054adeed676b2e24bc5b483607600 /
            f840339cf90ca64a13b8abdd5816307860be81c4 (provenance-only control-plane drift)
sha256 plan/evidence/protocol/machine/Cargo.lock: matched manifest values
JSON/TOML package files: PASS (`python3 -m json.tool`; Python `tomllib` parse)
light-client shell: Python checker PASS; OpenSSL cross-check NOT RUN (`xxd` unavailable, exit 127)
candidate conformance runner: PASS (37 discovered and executed tests; 21 wire mutants;
  7,548 differential samples with 0 exceptions/0 disagreements; 3,000
  state-sync mutants rejected; copied-same-label, fork-residue, staged swap/CAS
  and rollback fences PASS); runner terminal_status=STOP_CONDITION
normal PATH cargo test/clippy: NOT RUN (`cargo` executable unavailable in the
  default environment); isolated Rust 1.95 candidate feature check/test/clippy:
  PASS (135 tests, `-D warnings`), not a normal-build or release assertion
accepted evidence/signatures: none
GitHub Actions historical check on the pre-follow-up published head
`06d71c8eab3c05547f5d5c0b564a8985d3cff304` failed job `99099957089`
(`Payload replay and G1-R4A recovery contracts`) at the payload-replay truth
boundary; it is retained as an external CI failure and is not represented as a
passing source result.
GitHub Actions run `33254312493` / job `99105261590` on published head
`4936caeba16656dd196e95a60dc7455d9cca43d3` also failed at `Verify canonical
development plan` after recovery/process and cargo-input steps passed; no green
external CI claim is made.
```

The absence of `cargo` is an environment limitation, not a source pass/fail;
the failed command and environment must remain visible in the final handoff.

## 12. Typed gap ledger

The authoritative machine-readable rows are in
[`G2F_WHOLE_NODE_LIGHT_CLIENT_V1_GAP_LEDGER.json`](G2F_WHOLE_NODE_LIGHT_CLIENT_V1_GAP_LEDGER.json).
Statuses use the package template vocabulary: `open`, `working`,
`blocked-upstream`, `closed-candidate`, `invalidated`, or `reopened`.

| Gap ID | Severity | Status | Dependency | Evidence boundary | Next deterministic action |
| --- | --- | --- | --- | --- | --- |
| `G2F-ATOMIC-001` | P0 | blocked-upstream | A11–A15 | five-store readback only | accept five snapshot ICRs; implement authenticated cut |
| `G2F-JMT-001` | P0 | blocked-upstream | A10, A13 | sparse/tag-50 and composite-root candidate only | accept JMT digest; bind proof in finalized Order |
| `G2F-ANCHOR-001` | P0 | reopened | A16-owned (coordinate A05/A17) | candidate contract/unit mutants; same-height fork stop retained; no backend | independent review, then finish external monotonic anchor and rollback matrix |
| `G2F-NAMESPACE-001` | P0 | reopened | A16-owned | candidate descriptor/openat contract; copied-namespace stop retained; process integration absent | independent review, then finish race mutants and independent replay |
| `G2F-SYNC-001` | P0 | blocked-upstream | A11–A15 | restart v0 chain/checkpoint binding only | freeze staged-swap manifest; run crash/restart campaign |
| `G2F-LC-001` | P0 | blocked-upstream | A10–A15 | bounded Order clients only | two independent clients and six proof families |
| `G2F-TRACE-001` | P0 | blocked-upstream | A10–A15 | local co-observation only | signed real W0–W7 trace and clean-clone replay |
| `G2F-PROCESS-001` | P0 | blocked-upstream | A10–A15 (coordinate A05/A17) | 7/7 candidate process tests | normal-build owner/custody/broadcast/recovery matrix |
| `G2F-FAULT-001` | P1 | open | A16-owned | local negatives only | execute full copied/renamed/torn/WAL/full-store matrix |
| `G2F-EVIDENCE-001` | P1 | open | A16-owned | no signed G2F bundle | envelope, raw artifacts, independent review/replay |
| `G2F-UPGRADE-001` | P1 | blocked-upstream | A10, A11, A13–A15 | bounded handoff candidate | version/anchor transition vectors in both clients |

No row is `closed-candidate` in this run. The package terminal outcome is
`STOP_CONDITION`; upstream request rows independently remain
`BLOCKED_UPSTREAM`. A missing or changed upstream interface creates a typed ICR
and keeps the integration rows `blocked-upstream`; A16 must not edit the other
owner's source semantics.

## 13. Evidence envelope and closure criteria

Each future evidence bundle must use the engineering evidence contract and
`trnm-agent-handoff-v1`, including:

```text
evidence_id, gate_id, package_id, plan_id, plan_sha256,
source_commit, source_tree_hash, protocol_manifest_sha256,
machine_truth_before, machine_truth_after, toolchain_lock,
artifact_sha256, exact_commands, topology_manifest, workload_manifest,
fault_schedule, raw_artifact_index, negative_controls, known_gaps,
reviewers, signature_set, scope, authority, classification, data_scope
```

Candidate evidence must use `scope=crate|fixture|process`,
`authority=candidate`, `classification=candidate-non-normative`; no unscoped
positive flag may appear. Failed runs, mutants and superseded bundles remain
retained. A source/protocol/schema/parameter/Order/validator-set digest change,
new Critical/High finding or failed invariant invalidates the affected rows and
all downstream evidence.

`MODULE_CLOSED_CANDIDATE` is permitted only when all of the following are
machine-checkable on the exact package head and independently replayed:

1. copied, renamed, stale, torn, sidecar, WAL and full-store rollback mutants
   fail before authority use;
2. two independent clients agree on Order, DA, execution/JMT, result,
   settlement and upgrade proofs, including malformed/fork/replay negatives;
3. a real `AgentTransactionV1` trace binds every W0–W7 digest and survives
   clean-clone replay, crash/restart and old-anchor tests;
4. process owner, custody, state-sync swap and fresh post-commit readback are
   evidenced without changing production/activation truth; and
5. an independent reviewer signs the bundle and the owner does not merge its
   own PR.

Until the retained stop conditions are independently reviewed and all upstream
interfaces are accepted, the honest package terminal state is
`STOP_CONDITION` with `BLOCKED_UPSTREAM` blockers (and local `open`/`reopened`
rows retained), not Gate acceptance.

## 14. Rollback, invalidation and next action

Documentation changes are reversible by reverting the package PR. No runtime,
machine truth or production data is mutated by this package. If an interface,
source tree, plan digest, protocol manifest, parameter, validator set or proof
root changes, mark affected rows `invalidated`, retain old evidence, compute the
minimum rerun set (`all G2F rows`, W0–W7 trace, both clients, state-sync and
rollback matrix), and request fresh independent review.

The next deterministic action is:

1. obtain independent review of the copy/fork quarantine and the
   `G2F-M-SYNC-COORDINATED-NONZERO-VIEW` commitment gap;
2. send `G2F-ICR-A11-001` through `G2F-ICR-A15-001` to the owning agents;
3. after review and accepted interfaces, run the full process/power-loss
   matrix and revalidate the exact candidate commit/tree and all plan/machine
   digests;
4. rerun the focused boundary and independent-client commands from a clean
   clone; and
5. publish the package head SHA/tree, changed paths, evidence IDs, failed tests,
   mutants, scope/authority/classification, invalidation set and next action in
   the signed handoff.

## 15. Independent review

Required reviewers are outside A16 and cover source-plane interface ownership,
cross-plane fault/replay, safety/cryptography, economic conservation,
light-client interoperability and signer custody/operations. The A16 owner may
prepare evidence and a Draft PR but may not independently accept, merge or
promote it.
