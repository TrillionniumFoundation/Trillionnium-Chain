# Native signed Vote replay contract V1

Status: candidate implementation with local source regressions passed; independent
acceptance pending. Production activation remains false.
Primary module: M15 Node Host. Producers: M03 signer journal, M08 Safety and native
application stores; consumer: M15 bounded laboratory recovery owner. M02 supplies
comparison-only SafetyState predicates. This document specifies one operation;
the sole development plan remains `docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md`.

## Operation and trust boundary

`M15-OP-NATIVE-SIGNED-VOTE-REPLAY-V1` opens an existing laboratory native authority
root and releases the exact Vote signature already present in its signer journal.
The owner never receives a `SignatureProducerV0`, never activates a pinned signer,
and never invokes Core, acknowledges a validation, executes an application,
persists Safety, advances a checkpoint, or repairs a watermark. No decoded enum,
digest, scalar checkpoint, or caller-provided signature is accepted as signing
authority. Output is historical signed-message replay, not permission to vote on
another block or to continue a recovered consensus runtime.

The node API is behind `lab-validator-runtime`; its fixture is behind
`lab-validator-runtime-test-support`. Default node activation and every existing
pending-sign recovery refusal remain unchanged. The M03 pinned readback is a
general read-only journal operation and cannot generate a signature.

The commissioned Core configuration, native application configuration, canonical
existing root, and injected external signer watermark are trusted startup inputs.
SQLite checkpoint storage has the existing laboratory trust boundary: equality
with that separately opened checkpoint is required, but a coherent rollback of
all locally administered namespaces is not thereby solved. No production or
independent custody claim follows from the local fixture.

## Admitted durable cuts

The selected authorizing record must be an authenticated NativeValid Safety
record with exactly one current ordinary Proposal Valid completion and one
pending Vote whose authorizing revision equals that record's revision. Its
post-ack action must be RequestSignature. The exact K row must be Acked, have no
outbox, and retain the same P/D/C binding. The durable native execution history
row must be Prepared, not Committed. Only the latest checkpoint-matching cut is
admitted; this operation is not a historical Vote archive query.

Two Safety shapes may be recognized without constructing Core:

1. Current NativeValid record still holds that pending Vote.
2. Current Ordinary record is the exact durable signature-release successor of
   its immediately retained NativeValid predecessor: clear only pending_sign,
   increment revision by exactly one, and compare the entire remaining state.

The second shape is the normal successful `sign_exact_vote_v0` result. The first
can occur after a durable signed checkpoint and before the release barrier.
Both require a freshly confirmed already-signed journal row. A missing or
unsigned row is Unavailable; neither shape authorizes completing an unsigned
intent.

## Exact readback sequence and join

1. Authenticate the existing root and all required private regular files before
   any store open that could initialize a missing namespace. Hold the existing
   cross-store root lock and each store's lifetime owner for the replay lifetime.
   Local SQLite recovery/open bookkeeping is not a new logical application or
   consensus transition; any such failure prevents output.
   The pre-open existence check plus existing store open is not an atomic
   descriptor-relative existing-only opener. Same-UID concurrent rename or
   replacement outside the cooperating root-lock discipline remains outside
   this candidate guarantee; no absence of filesystem initialization is claimed
   under such a race.
2. Pin the signer read-only and freshly confirm exact local/external watermark
   equality. Local-one-ahead is Unavailable; no external CAS is attempted.
3. Authenticate the complete retained Safety chain, profile and current head.
   Select the authorizing NativeValid record from one of the two admitted shapes.
   Build a canonical Vote intent solely as comparison input from that record and
   the commissioned local validator context; verify its root and revision.
4. Read and freshly validate the exact K binding and complete native execution
   artifact. Use inert execution-history readback, not a newly minted P or Valid
   capability. Compare chain/genesis/set, route, validation generation, block,
   parent, height/view/time, all application commitments, source artifact,
   overlay, native store identity, K owner/scope/sequence, D digest, Safety record
   digest, and Vote root with the authorizing record.
5. Load the existing whole-node checkpoint in its exact signer scope. Compare
   current Safety journal/profile/revision/record/chain and current signer
   journal/profile/external watermark. Recompute all native-K application
   projection fields using the **authorizing** Safety record, including the
   Safety binding and recovery closure hashes. The post-release current Safety
   checksum cannot replace its predecessor in those application hashes.
6. Read the exact canonical signer intent and strictly verify its stored Ed25519
   signature without activating the journal or calling a producer. Revalidate
   the pinned external head and all joined store readbacks before exposing the
   private replay carrier. Construct and verify exactly that Vote; no signature
   bytes supplied by a caller are admitted.

The canonical Vote, canonical sign intent and journal encodings are unchanged
V0 encodings. No new network schema, sign domain, conflict key or protocol byte
is introduced. Limits remain those of the commissioned Core/Safety/signer
profiles and existing bounded native-store codecs. New local operation and
result labels are not wire-level peer verdicts.

## Results and failure semantics

Success returns a non-cloneable recovery owner retaining the joined stores and
a private carrier containing exactly one existing verified Vote. Repeated open
or explicit readback may return identical signed bytes after the complete fresh
join. Journal intent/event counts, external signer watermark, Safety revision,
P/K sequences, checkpoint generation and application committed head do not
advance. The owner exposes no raw Core, mutable store, key, intent-submission,
producer, or generic effect-driving API.

Unavailable covers missing retained authority/artifact, unsupported Safety cut,
unsigned or absent exact signature, external watermark repair requirement,
nonterminal K, a checkpoint which does not bind all current owner effects, and
storage availability errors during native P/K readback. Corrupt
checksums/signatures, wrong commissioned context/profile or K owner, inconsistent
bindings, namespace replacement, or an external fork reject recovery. A readback failure
returns no Vote. A partially opened owner is discarded; the caller may try a
fresh existing-only recovery after the underlying condition is resolved.
Unavailable never labels a valid block or certificate canonically invalid.
An already returned owner fences itself after any subsequent replay readback
failure. Repairing bytes does not make that owner reusable; reopen a fresh owner.

## Validation and acceptance

Required source regressions use a real live laboratory Proposal-to-P/D/C/K-to-Vote
fixture, real SQLite stores, and strict Ed25519. Tests must establish identical
Vote replay after drop/reopen with zero additional producer calls and unchanged
durable counters; unsigned intent Unavailable; foreign/stale checkpoint,
foreign context/K/overlay and corruption rejection; and owner-lifetime/freshness
checks. Fixture watermark custody is explicitly test-only.

The implementation is `trillionnium/crates/trnm-poco-node/src/native_vote_recovery.rs`:
`open_existing_native_signed_vote_replay_v1` returns
`PocoNodeNativeSignedVoteReplayOwnerV1`, whose `replay_exact_vote_v1` returns
`PocoNodeReplayedNativeVoteV1` or `PocoNodeNativeSignedVoteReplayErrorV1`.
M03 supplies `PinnedSqliteSignerJournalV0::read_signed_intent_exact_v1` in
`trillionnium/crates/trnm-consensus-signer-journal/src/sqlite.rs`, returning
`Option<ConfirmedSignedIntentReadbackV1>` after fresh exact-head checks.
M02 supplies comparison-only
`SafetyState::matches_durable_signature_released_successor_of_v1` in
`trillionnium/crates/trnm-consensus-core/src/model.rs`. The existing native-K
checkpoint writer and replay consumer share `native_k_application_projection_v1`
in `trillionnium/crates/trnm-poco-node/src/external_node_checkpoint.rs`; the
projection itself grants no authority.

Seven source regression tests in
`trillionnium/crates/trnm-poco-node/tests/native_signed_vote_replay.rs` passed:

| Exact test selector | Required observed result |
| --- | --- |
| `live_native_vote_reopens_exactly_without_new_signatures_or_logical_writes` | Real live h4 Vote equals repeated reopened replay; all five stores' logical rows and external watermark unchanged. |
| `unsigned_native_vote_remains_unavailable_and_never_calls_custody` | `Unavailable { stage: "unsigned_signer_tail" }`; no new custody call or logical row change. |
| `stale_or_foreign_checkpoint_cannot_release_the_signed_vote` | Pre-signature checkpoint is `Unavailable` at `checkpoint_owner_join`; foreign checkpoint returns no Vote. |
| `missing_or_corrupt_native_artifacts_reject_without_initializing_replacements` | Missing/empty K file stays missing/empty; corrupt application head prevents live replay and reopen. |
| `pinned_journal_readback_returns_only_existing_signatures_and_observes_external_changes` | Signed row returns identical signature; unsigned/absent exact row returns None; changed external head prevents readback. |
| `every_local_store_corruption_rejects_and_live_external_change_fences_replay` | Independent Safety, signer, K and P mutations prevent output; external head change fences that owner even after the fixture head is restored. |
| `foreign_local_validator_profile_is_rejected_before_logical_store_changes` | Wrong commissioned local validator prevents output without logical writes. |

Run from the repository root:

```bash
cargo test --manifest-path trillionnium/Cargo.toml -p trnm-poco-node --test native_signed_vote_replay --features lab-validator-runtime-test-support --locked --offline
```

Each fixture has one prior live producer call, including the deliberately failed
unsigned case. Tests assert the total remains one after recovery: **zero new**
calls. These are four-validator fixtures within one local test process, with
real SQLite/native execution/Ed25519 and injected in-memory watermark custody.
They do not establish separate process or machine recovery. The positive replay
covers the normal durable release successor; the recognized signed-before-release
cut is not claimed as an exercised crash-cut acceptance result.

The default Core regression
`durable_signature_release_comparison_accepts_only_the_exact_persisted_successor_v1`
passed, and the default node library regression
`external_node_checkpoint::tests::real_native_k_uncertain_whole_node_cas_releases_only_inert_request_signature_v0`
passed with exact persisted projection equality and ten individual projection-field
substitution rejections. These remain source regressions. Independent positive/negative
golden vectors, authenticated specialist review, process kill/power-loss,
independently administered whole-node rollback authority and real deployment
acceptance remain open. No source regression can close those requirements.
