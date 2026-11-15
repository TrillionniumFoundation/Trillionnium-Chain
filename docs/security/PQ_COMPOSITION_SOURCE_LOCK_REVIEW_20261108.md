# PQ composition source-lock review — 2026-11-08

**HOLD. Declared-path source consistency; no new quantum or runtime qualification.**

## Exact reviewed source

Both current source mappings refer to commit `0f0592ace4b08a1d39e1ffad31beee76ddc4fd66`,
tree `24f08f4a72a7a4be83fa8e5a664642c4e9b6feb0`. The immutable Git object bytes
were compared with descriptor-bound reads of each current regular file before
the new hashes were recorded. Each original pin was also checked against its
declared historical Git blob. This checks source consistency, not authenticated
provenance or the correctness of those implementations.

| Register | Required paths | Changed paths | Scope |
| --- | ---: | ---: | --- |
| Lifetime event owners | 15 | 7 | Declared event paths only |
| Authority/effect register | 44 | 8 | Seven curated interfaces and source categories |

There are 57 distinct paths across the two sets
and 14 distinct changed paths. No path, route, category or refusal
condition was dropped. The lifetime experiment revision and lock revision move
together. The authority checker fixes both the reviewed revision and the
canonical whole-table digest; its positive test retains an independent literal
revision assertion. There is no CI auto-refresh path.

The [machine review](../../evidence/pq-composition-source-lock-review-20261108/review.json) retains all old/new
hashes, exact Git blob IDs, file modes, byte counts, full patches and the review
decision for every path. The [evidence index](../../evidence/pq-composition-source-lock-review-20261108/README.md)
describes the raw refusal records and the earlier failed administrative scan.

## Changed-path review

| Source | Reviewed change and retained boundary |
| --- | --- |
| [trnm-crypto-primitives/src/lib.rs](../../trillionnium/crates/trnm-crypto-primitives/src/lib.rs) | Exports grouped-fresh-seal and PQ content-auth modules. Existing authentication implementations in this entry file are not changed; the curated lock does not become a complete primitive/module closure. |
| [trnm-data-availability/src/cell/discovery/pq/tests.rs](../../trillionnium/crates/trnm-data-availability/src/cell/discovery/pq/tests.rs) | Adds real TCP refusal controls for durable manifest-quota source fairness and receipt-time equivocation surviving later-source delay/expiry. These source references do not count as executed native test evidence. |
| [trnm-data-availability/src/cell/discovery/pq/transport.rs](../../trillionnium/crates/trnm-data-availability/src/cell/discovery/pq/transport.rs) | Interleaves source records within the original bounded discovery round before the persistent quota, retains conflicts eligible at actual receipt, and rechecks current record/key/monotonic expiry before directory admission. Original connection/byte/signature/deadline budgets remain. |
| [trnm-data-availability/src/cell/discovery/transport.rs](../../trillionnium/crates/trnm-data-availability/src/cell/discovery/transport.rs) | Applies the same bounded source fairness and receipt-time conflict/current-time admission distinction to classic discovery; adds test-only server readiness observation. Effects remain provider directory/content cache, without payment or final-use authority. |
| [trnm-data-availability/src/cell/manifest.rs](../../trillionnium/crates/trnm-data-availability/src/cell/manifest.rs) | Adds a read-only chunk_bytes getter; manifest validation and signature/commitment rules in this file are unchanged. |
| [trnm-data-availability/src/cell/pq.rs](../../trillionnium/crates/trnm-data-availability/src/cell/pq.rs) | Exports a distinct V3 version-authorization module while retaining the V2 release domain. This entry-file pin does not include the new module as a dependency closure. |
| [trnm-mvcc-fee/src/pon_executor.rs](../../trillionnium/crates/trnm-mvcc-fee/src/pon_executor.rs) | Adds explicit funded-service configuration/command/task dispatch checks and promotes repeated-sender speculative-state skipping while retaining the old oracle for differential tests. Account profile selection and prepared authentication owner dispatch remain separate; new task-module dependencies are outside this 44-file table. |
| [trnm-pon-node/src/ingress.rs](../../trillionnium/crates/trnm-pon-node/src/ingress.rs) | Factors the same submit owner/context/work/admission/publication pipeline into a decode-callback entry shared by transport representations. Decode, cancellation, owner locking and late publication checkpoints remain in order. |
| [trnm-pon-node/src/pq_rollback_witness.rs](../../trillionnium/crates/trnm-pon-node/src/pq_rollback_witness.rs) | Adds the isolated M12 full-generation-effect witness binding V3, committing complete context, generation and distinct witness/writer pins; network-policy matching additionally requires its original namespace prefix. Independent witness retention and rollback coverage are not established by this source check. |
| [trnm-pon-node/src/store.rs](../../trillionnium/crates/trnm-pon-node/src/store.rs) | Adds generation/task/demand/packet and local-owner observation entrypoints, read-only reconciliation for existing ordinary backends, common activation/recovery selection helpers, and ordinary Legacy replay/root-arithmetic reuse with same-writer/post-write fences. PQ/Growth exclusions remain explicit for the Legacy optimization. Newly reached modules and runtime behavior require their separate validation; the curated seven-route scopes are not expanded. The composed source also dispatches Growth history/confirmation observations to their explicit backend and refuses the legacy non-Sync confirmation callback for Growth. R2 consistently renames the private InitializeOrRecover observation field and leaves ExistingPqOwner mapped to (false, true); no wire or persisted schema changes arise from that naming repair. |
| [trnm-pon-node/src/store/funding/payment.rs](../../trillionnium/crates/trnm-pon-node/src/store/funding/payment.rs) | Recognizes explicit funded-service arbitrator decisions, binds readback to native money epochs, and exposes retained-anchor replay as historical evidence without activation or current-settlement authority. Exact transition replay and original source/beneficiary/subject checks remain in the path. |
| [trnm-protocol/src/pon_wire.rs](../../trillionnium/crates/trnm-protocol/src/pon_wire.rs) | Adds typed funded-service reservation/decision decoding for nonlegacy lengths of tags 2/5; exact legacy 80/64-byte payload paths remain. Decoding is not authentication or authorization. |
| [trnm-release-bundle/src/pq_release.rs](../../trillionnium/crates/trnm-release-bundle/src/pq_release.rs) | Separates cheap complete quorum/pin/length preflight from mathematical verification, checking both old and new signer sets before root rotation work. Every supplied signature still verifies and no positive authentication result is cached. Replaces the literal signature size with the protocol constant. |
| [trnm-service-settlement/src/native_budget.rs](../../trillionnium/crates/trnm-service-settlement/src/native_budget.rs) | Exports separate evidence/task-operation modules and allows a recorded fulfilled Task contribution/evaluation or serving Quota contract fee for NoGain only with effect receipt and exact native payment observation. NoGain still grants no Release/Reward allocation or model-adoption/chainwork claim. |

The Node store includes the composed observation/recovery interface. The
earlier R1 compilation failure from inconsistent private observation field
names remains in the parent campaign; it is not relabelled a successful native
run. The reviewed revision fixes that production naming consistently. R2's
all-target strict Clippy also found an old field name in
store/pq_existing_owner_tests.rs; that failure stays in the parent campaign.
That test file is outside both curated path sets. Its repair changes no
declared path and cannot replace the final whole-source native checks. The wire
formats, persisted namespaces and the limits of the seven source routes are
not promoted by this mapping review. Fresh native validation belongs to the
final composition campaign, and no previous branch result is imported here.

## Current mappings and retained history

The lifetime lock bytes hash to `8771ac5c7bfff29266a89e7b65bf1d57a021fd38a0461b7cc937db58c34557b0`.
The canonical authority table digest is `4638bd340c2456dd735418f74ec27e01953432c2495b3db596f57d9fc31acb04`.
The old mappings and the two pre-update CLI refusals remain in the new evidence
directory, while the historical `pq-seven-layer-composition-20261108` evidence
and its original source identities remain unchanged. Current live documentation
identifies its new mapping separately from the original generation examples.

The immutable reviewed revision precedes this metadata update. Later commits
can pass these path checks only while every declared path still equals the
reviewed bytes; the check does not assert that the entire later tree equals
that revision. A change to a declared path needs another explicit review.

## Remaining obligations

The 15/44 path sets do not form a dependency closure. Newly exported version,
content-authentication, funded-service, generation and observation modules
remain subject to their own source and native validation. Literal-name source
references are retained as bounded review observations, not a complete call
graph or proof of absent dynamic consumers.

The eight unknown event terms, four unknown shared-primitive query budgets,
unknown complete actual lifetime bound, pure root-policy scope and all false
whole-chain/activation claims remain unchanged. No new signing, custody,
external payment, proof generation, production activation or independent
operator execution is performed by this review. Full source verification and
all original final composition gates remain separate required checks.
