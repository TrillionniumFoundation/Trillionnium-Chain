# Operation gap design v1

Status: **implementation-ready contract; candidate only; semantic and independent acceptance remain open**  
Owner: M17 documentation authority. The operation registry (`config/documentation-operations-v1.json`) is the identity source; this document supplies the design needed to implement each currently registered foundation operation. It does not enlarge the operation catalogue, promote a module, or convert a repository regression into an independent vector.

This document exists because a registry row alone is not a complete design. Every operation below has an explicit authenticated input, durable identity, state transition, error class, crash rule, bounded concurrency rule, and acceptance vector. A missing external dependency is recorded as `open`; an engineer may implement the repository portion without claiming production activation.

## Common implementation contract

### Ownership and durable boundary

The caller supplies bytes and a request identity only. The owner derives chain/genesis, profile, role, validator set, epoch/height/view or nonce, parent/root, and generation from an authenticated predecessor or its own durable namespace. An operation may return a capability only after the durable boundary named in its section has completed and fresh readback agrees with the request digest.

Use one exclusive owner for each namespace. The durable record must contain a schema/version tag, domain-separated operation identity, source and target digest (when applicable), owner generation, and monotonic sequence. Write data and its head/anchor in one transaction where the store permits it; otherwise write the immutable record, sync it, publish the head, sync the parent directory, and reread both. A write or sync error after the first durable write is `uncertain`, never an automatic retry. Exact source/target readback decides whether retry is safe; any third state fences the owner.

### Error and publication classes

* `reject` means authenticated input or protocol data is invalid; retain the prior durable state.
* `unavailable` means a bounded local resource, missing commissioned dependency, or unsupported profile prevents a decision; it is not peer Byzantine evidence.
* `uncertain` means a side effect may have happened; preserve evidence and recover by exact readback.
* `halt` means the recovered authority is inconsistent or an anti-rollback/safety invariant failed; require a new owner or external intervention.

No operation below publishes a finality receipt, authorizes a production signer, or advances an epoch unless a separate owner explicitly supplies that capability. A local positive test is source-regression evidence only.

### Determinism and resource accounting

Decode and verify before allocating unbounded state. Enforce the limits named by the registry row (bytes, signatures, retained records, CPU/verification budget, and queue size) before durable mutation. Concurrent calls use an owner lock plus a request key; same key and same digest are idempotent, same key with a different digest is a safety error. A deterministic replay must produce the same state digest, effect kind, error class and durable record bytes independent of task interleaving. Timing, host names and queue scheduling are evidence metadata, never consensus input.

Each operation needs four vector families: a canonical positive vector, malformed/substitution negatives, crash-cut source/target recovery, and a deterministic-concurrency replay. Independently authored bytes, an independently administered signer/anchor, and multi-host or physical-fault runs remain open until attached by the external evidence process.

## M02 order and consensus operations

### M02-OP-VOTE-BARRIER

**Owner and input.** `trnm-consensus-core::step` owns the deterministic transition. The authenticated `Input::Vote` carries the commissioned chain/genesis context, validator identity, epoch, height, view, certified parent/proposal digest and the expected `CanonicalSignIntentV0`; the signer domain is `DOMAIN_VOTE` and the intent domain is `DOMAIN_SIGN_INTENT`. The input bytes must fit `MAX_CEV0_CANONICAL_SIGN_INTENT_BYTES` and the Core retained-resource bound. The caller cannot provide a validator set, watermark or replacement parent.

**State and durable rows.** The owner state is `(CoreState, safety_generation, pending_intent_digest, pending_kind)`. On an admissible vote, Core emits `PersistSafetyState(next_state, intent_digest)` and no signing capability. M03 stores a row keyed by `(chain_id, validator_id, kind=Vote, epoch, height, view)` containing the canonical intent bytes, intent digest, predecessor Safety revision and owner generation. Only the exact `StorageAck(intent_digest, revision)` releases `RequestSignature`; only a matching verified signature can release the broadcast. The broadcast carries the same intent digest and revision.

**Transitions.** `Ready -> PersistRequested -> Persisted -> SignatureRequested -> Signed -> Broadcasted`. `Busy` leaves `Ready` unchanged. A stale or protocol-invalid input rejects before persistence. A recovery owner starts at `RecoveredPending` and may request the exact same intent; it may not construct a replacement. Receipt publication is a consensus vote only; it is not application finality.

**Recovery and concurrency.** If the persistence response or signer response is lost, reread the Safety and journal rows by the exact digest. `source` means no intent/released signature; `target` means the exact persisted intent and, if present, its signature; any different digest, revision or watermark is `halt/InvalidRecovery`. The owner lock serializes one in-flight intent; duplicate exact calls return the recorded result and do not call the producer again. Parallel proposals cannot consume the same signer owner.

**Vectors and open work.** Keep `vote_signing_is_persist_ack_sign_verify_broadcast` and `persisted_sign_intent_is_re_requested_after_recovery` as repository regressions. Add independent expected intent/signature bytes for every `Input` variant, wrong epoch/height/view and reordered ACK/signature messages; add two-process socket, nonzero-epoch and HSM liveness tests. The registry's independent vectors and persistent host/multi-host qualification remain **open**.

### M02-OP-TIMEOUT-BARRIER

This operation uses the same barrier and row layout as Vote, with `Input::Timeout`, `DOMAIN_TIMEOUT`, and an intent kind that binds epoch, height, view and the timeout certificate context. A timeout does not require an application finality proof and cannot unlock or finalize a fork by itself.

The transition is `TimeoutReady -> PersistRequested -> Persisted -> SignatureRequested -> Signed -> Broadcasted`; each row is keyed by the exact timeout intent identity. A stale timeout, wrong domain or conflicting same-round intent retains the prior state. Lost ACK/signature recovery is exact source/target readback and never remints a timeout. Concurrent timeout and vote requests serialize through the Core owner; only the selected successor may issue a signature request.

`timeout_signing_uses_the_same_durable_barrier` and `persisted_sign_intent_is_re_requested_after_recovery` are retained source regressions. Independent timeout bytes/signatures, exact precedence among `Busy`, protocol and recovery errors, nonzero epoch, socket/persistent host and HSM tests remain **open**.

### M02-OP-TC-ADVANCE

**Input and admission.** `on_timeout_certificate_bytes_v0` accepts bounded canonical CEV0 TC bytes plus a caller work budget. `decode_timeout_certificate_v0_exact_with_trusted_genesis_and_budget` must bind the commissioned epoch-zero GenesisQC, chain context, epoch/height/view, signer identities and aggregate-share cap. `DOMAIN_TIMEOUT` and `DOMAIN_TIMEOUT_CERTIFICATE` are distinct; no ordinary ancestry is inferred when it is absent.

**State and durable rows.** Before mutation reserve both verification costs (including the second Core verification). The host record stores `(tc_digest, source_view, target_view, epoch, validator_set_digest, genesis_qc_digest, safety_revision, owner_generation, state)`. The Core transition is `TimeoutInput -> PersistSafetyState -> StorageAck -> TimerEffect`; it invokes no signer producer. The Safety row and host record are reread before returning the timer/view effect.

**Errors and recovery.** Malformed bytes, wrong signature or context are `reject/InvalidCertificate`; an unsupported ordinary ancestry is `unavailable/AuthenticatedAncestryRequired`; caller budget exhaustion is `unavailable/Admission`; a post-write storage error is `uncertain/Host` and fences until exact readback. A failed verification cannot advance the view. Parallel TCs with the same digest are idempotent; same `(epoch,height,view)` with another digest is a conflict and halts the owner.

**Vectors and open work.** Retain the feature-gated panic/drop cuts and SQLite metadata-tamper tests in `trnm-poco-node`. Add independently authored TC bytes/signatures/error-precedence vectors, ordinary-QC ancestry and nonzero-epoch handoff, network listener/pacemaker partition-heal runs, SIGKILL/power-loss cuts and HSM evidence. These remain **open**; the current four-instance run is one-process fixture custody.

## M03 safety and signer operation

### M03-OP-SIGN-EXACT

**Input.** `trnm-consensus-signer-journal::sign_exact_v0` accepts only a canonical `CanonicalSignIntentV0` whose chain, profile, author, validator set, role, epoch/height/view/nonce, statement digest and predecessor Safety revision match the commissioned `SignerJournalProfileV0`. Its bytes are domain-separated with `DOMAIN_SIGN_INTENT` and bounded by `MAX_CEV0_CANONICAL_SIGN_INTENT_BYTES`.

**Durable state.** The journal namespace has a lifetime owner lock and rows keyed by `(author, kind, epoch, height, view, intent_digest)`. Persist `Prepared(intent_digest, intent_bytes, predecessor, generation)` and sync it before invoking `SignatureProducerV0`. On a returned signature, verify it against the exact intent and persist `Signed(signature, signature_digest, producer_generation)`, then advance and reread the external watermark. Exact retry returns the stored signature without producer invocation. Per-kind view and Safety revision must be monotonic.

**Errors/recovery/concurrency.** A same-round different digest is `halt/SameRoundDifferentIntent`; a producer or capacity failure is `unavailable/SignatureProducer` and never authorizes a replacement; uncertain journal or watermark CAS is `uncertain/CommitUncertain` and requires source/target readback. A watermark rollback, fork or ahead state fences the journal. The lock prevents two producer calls for the same key; cross-process takeover requires the external generation and watermark to agree.

The existing SQLite journal tests cover exact replay, conflicts and injected watermark rollback. They do not prove SafetyRules composition, HSM custody, physical power loss, or independently administered watermark evidence. Those and independent byte/signature vectors remain **open**.

## M04 authenticated ingress operations

The two M04 records intentionally share one replay namespace and differ only in the durable boundary that is allowed to expose a receipt.

### M04-OP-PERSIST-INGRESS

`admit_verified` receives a source-verified `BoundIngressV0` and peer frame. Bind session, chain, peer identity, node generation, replay nonce, operation domain and frame digest; enforce `MAX_CANDIDATE_PEER_FRAME_BYTES_V0` and `MAX_INGRESS_FRAME_BYTES_V0`. The journal key is `(session_id, peer_id, generation, nonce)` and stores `Pending(frame_digest, canonical_frame, source_generation, stage=Admitted)`. Write and sync this row before returning it to M02/M15; no vote, finality, TLS session or peer ACK is implied.

On restart, reopen the same pending row and replay it to the same authority consumer. Exact duplicate bytes are idempotent. A changed frame for the key, wrong session/generation/nonce, malformed boundary or local resource exhaustion rejects while retaining the floor. In-memory/durable disagreement is `halt/InMemoryStateMismatch`; filesystem uncertainty fences until a fresh owner performs exact readback. The repository's `crash_before_ack_reopens_pending_and_exact_ack_is_idempotent` is the positive recovery case; independent parser vectors, cross-platform persistence, coherent rollback anchor, full multi-peer resource policy and real multi-host transport remain **open**.

### M04-OP-ACK-PREPARED

`acknowledge_prepared` accepts only the exact Prepared receipt produced for the pending frame: `(session, peer, generation, nonce, frame_digest, operation_digest, receipt_digest)`. The transaction writes `PreparedAck(receipt_digest, frame_digest, nonce)` and advances the replay floor to `nonce+1` (or the protocol's exact next floor) before peer acknowledgement. The old pending row remains available for exact recovery until the floor/receipt readback is complete, then may be compacted under the retention rule.

Wrong receipt, stage, peer, session or digest is `reject/PreparedReceiptMismatch` and leaves the floor unchanged. A durable mismatch is `halt/InMemoryStateMismatch`; a write response that may have applied is `uncertain` and must be resolved from the journal. Same receipt retries are read-only; a same nonce with a different receipt is a conflict. Add tests for reordered ACKs, duplicate frames, floor rollback, journal tamper and two peers contending for one owner. Production handshake/authentication, rollback anchor and multi-host evidence remain **open**.

## M08 finality and ledger operations

### M08-OP-COMMIT-STRICT

**Admission.** `commit_poco_finality_bytes_v0` decodes exact CEV0 proof bytes and `FinalityExpectationV0` under `DOMAIN_FINALITY_PROOF` and the supported `POCO_THREE_CHAIN_PROOF_CLASS_V0`. The commissioned validator set, parameters, trusted parent timestamp and expected oldest block/parent/application roots come from the Core/application owner. Verify the proof once at admission, charge the second verification budget, then verify again immediately before the durable application commit.

**Durable identity and state.** The prepared execution artifact is keyed by `(chain, application_version, parent_root, target_block_id, artifact_digest)`. The commit row stores proof digest/class, validator-set digest, expected roots, artifact digest, owner generation and `Prepared|Committed` state. The application commit is idempotent: exact target returns the existing committed row; a different proof/artifact for the same target rejects. On success, reread the committed row and roots before publishing a non-clone receipt carrier.

Unsupported class is `reject/UnsupportedProofClass`; local verification exhaustion is `unavailable/ReverificationBudget`; nested application errors require exact source/target readback and are `uncertain/Application` only when a write may have occurred. A concurrent commit takes the owner lock; exact duplicate waits/reads, conflicting target or parent fences. This operation does not commission Core, advance a checkpoint, publish a receipt or activate an epoch.

Add independent expected proof bytes and malformed/mutation vectors, crash cuts around application commit and readback, parent ancestry and nonzero epoch handoff, and checkpoint/receipt integration. Current strict proof tests remain source regressions; those independent and physical-fault items are **open**.

### M08-OP-READ-STRICT

`read_poco_finalized_bytes_v0` accepts the same exact proof class/context but only reads a row already in `Committed` state. It must not promote `Prepared`, infer finality from a local head, or mutate the application. Read the durable target row and proof bytes under the owner lock, recompute the expected roots and proof identity, and return a non-Clone `(proof, committed_record)` carrier. Missing, stale, malformed or conflicting rows map to reject/unavailable according to the existing application error; no caller-supplied replacement is accepted.

A read racing a commit retries only after observing a committed row with the exact target; a read racing a conflicting commit fences. Crash recovery is read-only and requires exact source/target identity. Add independent expected read bytes, prepared-state negative, stale parent and concurrent replacement tests. Checkpoint/receipt publishing and physical crash evidence remain **open**.

### M08-OP-RECOVER-EXPECTED-LEDGER

`open_existing_expected` loads the complete `ExternalNodeCheckpointV0` history from the caller-retained namespace, schema `SCHEMA_V1`, and bounded `MAX_RECORDS_V1`, `RECORD_BYTES_V1`, and `HEAD_BYTES_V1`. The caller must provide exact source and target expectations; the operation does not authenticate that file as an independent anti-rollback authority. Validate every record's `ANCHOR_DOMAIN_V1`/`RECORD_DOMAIN_V1` link, chain/genesis context, endpoint identity, sequence, head and observed live checkpoint prefix before any cleanup.

The owner state is `(source_record_digest, target_record_digest, live_sequence, owner_generation, poisoned)`. Exact target replay is read-only. A coherent rewritten prefix with a higher head is rejected because the previously observed live sequence must retain the same checkpoint and record digest. A third terminal state, unexpected entry, corrupted older record or observed rollback is `halt/ThirdState` or `InvalidState`; a post-write I/O ambiguity is `uncertain/Io`. Foreign expectations must leave old head and temporary evidence unchanged. Concurrent opens require one owner and revalidate namespace identity before each destructive action; unsupported same-UID replacement races remain outside the guarantee.

Keep the five ledger source regressions. Add independent expected record/head bytes, full-history and compaction budget measurements, adversarial filesystem replacement, disk/power fault and multi-host anchor tests. Scalable authenticated compaction and independent preservation remain **open**.

### M08-OP-APPEND-EXACT-LEDGER

`append_exact_successor` uses the same schema, domains, limits and owner lock as recovery. It accepts only an exact successor `(source_seq, source_digest) -> (target_seq, target_digest)` with matching chain, root, endpoint, lock and anchor identities. Validate the complete existing history and the observed live prefix first; write one complete successor record, fsync it, publish/sync the head and replay the exact target before returning success. If the target already exists exactly, return read-only success; never append a duplicate.

A wrong relation is `reject/TargetNotSuccessor`; a third terminal state or historical corruption is `halt/ThirdState`/`InvalidState`; write/sync/readback ambiguity is `uncertain/Io`. Set the owner poisoned before recovery or write and clear it only after fresh complete validation; cold rollback of both namespace and caller expectation remains unsupported. Concurrent appenders serialize on the owner; same source/target is idempotent, competing target is a conflict.

Retain the exact-target, context-mismatch, rollback, corrupted-record and valid-extension regressions. Independent record bytes, physical storage faults, adversarial replacement, scalable compaction and externally administered anchor evidence remain **open**.

## M15 node recovery operations

### M15-OP-RECOVER-SESSION

`trnm-poco-node-production-v0::recover` starts with no trusted current receipt and accepts only exact node identity/generation plus a complete `AuthorityReceiptV0` from the coordinator. A verified receipt binds operation domain `trnm.node.operation.v0`, node authority domain `trnm.node.authority-record.v0`, predecessor digest, claim digest and generation. The state machine is `Recovering -> Ready` only after complete fresh readback; a clean no-receipt result is `Ready` with no write capability; `Quarantine` never becomes ready.

Store the receipt under `(node_id, generation, operation_id)` with a complete/partial marker and source digest. A lost response leaves `Recovering`; replay the same operation and compare exact receipt bytes. Wrong predecessor/fact is `reject/ReceiptSubstitution`; no readiness is `halt/NotReady`; a possibly applied coordinator call is `uncertain/Coordinator`. The owner lock and generation prevent two recoveries from publishing different current receipts. Legacy stage labels remain inert and grant no vote/finality/production authority.

Existing production-v0 tests are source regressions. Replace caller/reference fact producers with reviewed domain sources, then add process-kill, persistent rollback/custody, multi-host and independently authenticated receipt vectors. Those commissioning and qualification obligations remain **open**.

### M15-OP-ADVANCE-VERIFIED-FACT

`advance_verified` requires `Ready`, one exact current predecessor receipt, and a non-clone `VerifiedAuthorityFactV0` whose claim, source operation, generation, identity and predecessor digest match the recovered owner. The proposed successor is validated before delegation; the delegated write is followed by complete fresh readback before the new receipt becomes current. Keep source and target records keyed by `(node, generation, operation, sequence, claim_digest)`.

Substituted or missing facts reject without mutation; a non-ready owner halts; a lost delegated response is `uncertain/Coordinator` and requires exact source/target readback. Concurrent advances serialize on the current predecessor and reject two successors for one sequence. This inert legacy operation cannot issue a signature, finality receipt or activation capability. Independent producer/consumer review, production commissioning, rollback custody and multi-host qualification remain **open**.

### M15-OP-NATIVE-SIGNED-VOTE-REPLAY-V1

`open_existing_native_signed_vote_replay_v1` is a read-only laboratory replay. Before opening generic stores, require all five nonempty database namespaces, root lock, exact node profile and generation. Join Safety, signer journal, native application/K and whole-node checkpoint owners twice; require a terminal `Acked` K, retained `NativeValid` predecessor, exact already-signed `CanonicalSignIntentV0`, and equality with the local/external watermark. Recompute native-K projection fields from the authorizing Safety record; do not copy mutable successor fields.

The durable replay identity is `(vote_intent_digest, safety_revision, journal_revision, native_k_digest, checkpoint_digest, owner_generation)`. A successful call performs no signer producer call, watermark CAS, Safety/application/K/checkpoint logical write, Core continuation or unsigned-intent completion. Missing/unsigned/unsupported retained authority is `unavailable/Unavailable`; context/checksum/signature/join mismatch is `reject/Rejected`; any post-join failure fences the owner (`halt/owner_fenced`) until a fresh owner reopens. Exact duplicate replay returns identical bytes; any foreign or stale checkpoint is a conflict.

Keep the nine source regressions, including unsigned refusal, foreign checkpoint, store corruption, sticky fencing and durable successor comparison. Add an independent signed-before-release crash-cut vector, independently administered rollback anchor, process-kill and power-loss tests, same-UID namespace replacement race tests where the platform supports them, and specialist producer/consumer review. Production activation remains **open**.

## Closure record

The design above closes the documentation gap for the thirteen currently registered operations: an implementer can identify the owner, authenticated fields, durable key, transition order, forbidden effects, error class and required recovery/vector work. It intentionally does **not** set `operation_catalog_complete`, `semantic_acceptance`, `implementation_acceptance`, or `production_authority` to true. Remaining open requirements are independently authored cryptographic vectors, trusted producer/HSM and monotonic-anchor custody, nonzero-epoch/ordinary-ancestry composition, production transport and listener ownership, process/power/disk fault evidence, external rollback authority, multi-host qualification, and independent specialist review.

The documentation checker remains a lexical source/reference gate. It must continue to report `operation_catalog_complete=false`, `independent_golden_vector_count=0`, and `not-assessed` acceptance until the external evidence process supplies those artifacts.
