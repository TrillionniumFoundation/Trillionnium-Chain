# Cell storage owner convergence, development V1

Status: reusable candidate components; HOLD / NO-GO. This specification adds no
network activation, perpetual-retention promise, provider payment or ordinary
Hepta FinalUse authority. Every execution observation identifies its own complete
source and original resource limits. The authoritative plan remains
[the single project plan](../../TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md).

## 1. Source and protocol boundaries

The continuation preserves the existing six-capability integration lineage.
Its starting composition, `6244d34a5d9a1da993125e00facfb91a846ec489`, retains
#821, #823, #814 and #816. Only complete-version RAM residency is ported from
#818. The two branches' V3 discovery encodings, signed domains and SQLite
schemas differ despite coincident magic/version labels. They are not silently
reinterpreted or migrated.

| Profile | Responsibility | Original owner retained |
| --- | --- | --- |
| TCM1 / TCX1 / TCV1 / TCV2 | Immutable chunks, explicit delta, complete model/environment identity and content | Independent content and loader contexts |
| TCA3 / CVA3 | Complete-version duty and independently retained catalog anchor | TCR1 physical arena and M12 funding/effect journal |
| CPS1 | Finite immutable periodic full-snapshot policy | Complete TCA3 history and independently funded member tasks |
| CRC1 / CSP1 | Original RS(6,4) codeword and physical provider slot | Original chunk, placement policy and TCR1 arena |
| CRP1 | Complete protected set to every manifest/chunk slot | Current TCA3 anchor, CSP1 identities and native tasks |
| CHB1 | Sealed model/environment bytes bound to current dual-context observation | Original CPV4 observation and task admission |

New stored/wire profiles have distinct magic, domains and namespace-refusal
tests. Existing signed domains and entry points retain their original meanings.

## 2. Immutable content and complete retention

A complete version contains both model and environment closures, referenced
TCM1 manifests, required roles, payload lengths/hashes and independently selected
loader contexts. The closures may have different selected generations. Recovered
untrusted manifests cannot manufacture their own expected policy.

TCX1 reconstructs one pinned target from one TCM1 base plus explicit changes; it
does not recursively follow an unbounded chain. TMR1's finite parent identities
are provenance, not a multi-hop delta-depth bound. TCA3 and every CPS1 snapshot
retain complete materialized target bytes. A recipe never substitutes for the
promised payload.

[TCA3](../../../../trillionnium/crates/trnm-data-availability/src/cell/version_retention.rs)
stores the full canonical contract and physical member contracts in one Pending
intent before allocation. Pending, Unknown and expired-unretired duties keep
protecting all dependencies. Active requires actual target readback for every
member. One catalog transaction covers both closures; a metadata boolean cannot
stand in for either payload.

An independently retained minimum anchor detects older/changed catalog history.
It does not protect against restoring every physical owner, journal and external
anchor together. Original M12/witness/current-chain obligations remain separate.
The finite profile caps historical duties at 128, protected versions at 16,
metadata at 64 MiB and individual contracts at 16 MiB. Retired identities still
count toward historical bounds. Admission includes pending promises, unreclaimed
physical slots and original 4 KiB alignment/fragmentation. Exhaustion refuses new
work without silently dropping protected duties.

## 3. Finite periodic full snapshots

[CPS1](../../../../trillionnium/crates/trnm-data-availability/src/cell/snapshot_schedule.rs)
is a 152-byte immutable policy binding responsible owner, store, initial
operation/contract, first due height, positive interval and at most 127 snapshots.
Checked arithmetic rejects signed-height overflow. The independently pinned
policy is created exclusively, fsynced and read back; namespace, length,
replacement, symlink/hardlink and independent-pin mismatches refuse admission.

The cursor derives from complete TCA3 history, including Retired duties. Each
snapshot retains its ordinal, original due height and predecessor. Direct
catalog entries receive the same continuity, scope and lease-coverage checks.
Restart, retirement or a late tick cannot reset the sequence, replace a Pending
operation or redate the obligation.

`reserve_due` writes complete Pending metadata. The independently funded native
owner performs materialization. CPS1 creates neither payments, free lease
extensions nor background activation. `reconcile_pending` accepts no source
cache/peer: it reads original targets only. Recovering a historical ACK after
expiry does not grant a new service window.

## 4. Physical slots and complete placement

[CSP1](../../../../trillionnium/crates/trnm-data-availability/src/cell/erasure/provider.rs)
persists its bounded immutable descriptor before arena reservation. It binds the
original chunk/manifest, all six CRC1 shard hashes, complete placement, exact
slot, generation, operations, owner/repair owner and lease/repair limits. A
funding digest is an identity, not proof of money.

Reads consume actual acknowledged arena bytes. The bounded reader pins the real
row/file descriptor and hashes the returned buffer; it cannot substitute source
CAS data. Lost/uncertain results retain the original operation and irreversible
copy/repair debits. Reconcile reads targets without redispatch or renaming.

[CRP1](../../../../trillionnium/crates/trnm-data-availability/src/cell/erasure/retained_plan.rs)
derives every protected root from the actual TCA3 owner. It persists the exact
anchor, retained commitment, full manifest/chunk union and six original slots per
chunk, bounded to 64 roots, 128 chunks and 2 MiB. A self-consistent caller subset
is rejected. Pending or expired-unretired roots cannot count as complete current
service. An anchor change invalidates the old complete-set assertion; original
slot identities remain recoverable under their original owners.

[The native executor](../../../../trillionnium/crates/trnm-pon-node/src/store/storage_service/shard/plan.rs)
checks every real claim, beneficiary, subject, resource lane, provider identity
and current catalog before its first provider effect. A caller-owned non-clone
budget commits the conservative whole-plan verification allowance before the
first provider call. Later failures do not return it. Actual codec admission is
reported separately; neither counter is measured WAN traffic or CPU time.
Success requires all six actual readbacks and reconstruction against every
original TCM1 chunk hash. Only one codeword's payloads are resident at a time.
M12/provider journals retain partial effects; there is no second progress ledger.

The 128-chunk ceiling is the first published CRP1 design. Its earlier local
64-chunk preparation and observations remain historical evidence only: the
269,060,552-byte real model requires 65 original 4 MiB chunks before its other
model/environment members. New controls admit complete 65- and 128-chunk TCA3
catalogs after source deletion, refuse 129 before staging and retain the 2 MiB
wire/file ceiling. Existing TCA, M12, CPU and wall-clock limits are unchanged.

[Automatic local recovery](../../../../trillionnium/crates/trnm-pon-node/src/store/storage_service/shard/plan/recovery.rs)
prechecks the complete fixed plan, current catalog and original Storage/Repair
claims. Before any provider read it commits a conservative whole-plan reading,
reconstruction and potential-repair allowance. Only recognized payload digest
damage can enter reconstruction; metadata, identity, SQL, I/O, CPU and deadline
errors refuse the operation. Four actual original CRC1 shards are required.
Each repair uses a separately authorized original native Repair task and its
original Pending/Done semantics; missing authority is never synthesized.
Success rereads all six slots, checks every original chunk and rechecks the
current catalog/anchor. The operation is explicitly invoked; it adds neither
a network daemon nor an independent payment or progress ledger.

Declared operator, region and failure-domain identifiers permit placement
audits. Six directories on one host do not prove six independent facilities,
administrators, power supplies or network paths.

## 5. Funding, repair, renewal and retirement

[Native version retention](../../../../trillionnium/crates/trnm-pon-node/src/store/storage_service/version.rs)
and [native shard effects](../../../../trillionnium/crates/trnm-pon-node/src/store/storage_service/shard.rs)
use original Node funding observations and M12 journals. Complete-version and
physical member tasks have distinct real subjects and byte-block claims. Member
intents precede the outer effect. Only a New monetary effect may copy a source;
Pending and Done reconcile targets. Scheduler Pending metadata is distinct from
the monetary replay state and does not prevent an independently authorized
first copy.

Repair requires its own original native Repair task, correct beneficiary,
explicit repair operation, cumulative physical budget, original lease window and
real thread-CPU observation. Interrupted repairs stay Unknown until target
reconciliation. Chain changes do not rewind local history, refund completed work
or grant new funding.

Retirement reobserves the original completed effect under the current native
owner anchor while preserving protected dependencies and successor obligations.
An expired, previously acknowledged damaged object need not become healthy
again after its repair deadline merely to retire. Pending duties, unresolved
repairs and Unknown targets stay protected. The original physical owner controls
actual reclamation: catalog retirement is not itself free-space or erasure proof.

Funding admission is not irreversible escrow, payment to an independent provider,
a slashing proof or evidence of future byte-block service. Renewal needs a new
independently funded obligation and current readback. Permanent retention of
every upload requires continuing funding and capacity; this finite profile makes
no perpetual promise.

## 6. Authenticated discovery and retained resource usage

The #823 authenticated epoch owner remains the baseline. Live quota reclamation
is distinct from historical records. Bootstrap replies bind independently
pinned source authentication to the exact query context. This continuation
preserves its wire profile and all original budgets.

[The discovery owner](../../../../trillionnium/crates/trnm-data-availability/src/cell/discovery/pq/auth.rs)
selects current active records before bounded withdrawal history. Cheap current
authority checks precede provider-verification slots; expired/revoked authorities
cannot occupy those scarce slots. Announcement signing, dial/read and ACK share
the original deadline clamped by the sealed receipt's actual monotonic expiry.
A still-live wall-clock lease cannot replace that boundary.

Observed APIs retain discovery counters and underlying session connections and
actual received bytes even on failure. Signing and verification attempts are
separate; the legacy verification-slot counter keeps its original meaning. Old
wrappers preserve their public signatures and discard observations only at the
existing compatibility boundary.

Authentication does not guarantee honest recommendations, availability,
independent sources or freedom from eclipse. Pinned multi-source policy,
per-source limits, complete failure observations and original total deadlines
remain necessary. A colluding or unreachable authorized source set is still a
liveness boundary.

## 7. Actual bytes, joint residency and next use

Complete retained recovery restores real arena bytes into the original bounded
CAS and checks both independently pinned closures. Complete-version residency
admits the combined immutable payload under one task allowance, checks both
current loader contexts and invokes a task only after both succeed. Bad
environment bytes, wrong generation, cancellation and insufficient joint
allowance cannot invoke a partial-model callback. A later task can consume the
same allocation after the restored CAS has been removed.

[CHB1](../../../../trillionnium/crates/trnm-data-availability/src/cell/host_handoff.rs)
binds actual sealed model/environment members to the current authenticated
dual-context observation. Worker-source SHA-256 and environment-closure ID have
different fields and meanings. Exact worker/config paths refer to the same
sealed bytes that were verified, never a later mutable-path read. An old
single-context authorization is not reinterpreted as CHB1.

The fresh Linux research entry point
[cell_sealed_research_next_use_v1](../../../../trillionnium/crates/trnm-data-availability/examples/cell_sealed_research_next_use_v1.rs)
captures complete input files through their original regular no-follow FDs,
commits and ACKs both closures to TCA3, deletes its publisher cache, reopens the
owner at the independently retained anchor and restores an empty consumer.
After CPV4 checks and joint admission, it removes that consumer cache and sends
the same kernel-sealed members through SCM_RIGHTS with CLOEXEC preserved.
The fixed bootstrap and worker check the complete roster, role, length, kernel
seals and independent digests, then load original project modules, configuration,
model and adapter from those admitted bytes. Two different requests execute
through the original model loader, request parser, forward and wait4 supervisor
under one absolute deadline. Ready/results publish only after complete fsync.
The interpreter and third-party native libraries retain the original independently
pinned host-runtime snapshot boundary; they are not represented as sealed-FD
transport. Historical material bridging remains an explicit exact contract.
Research observations grant no ordinary Hepta CURRENT/FinalUse or M12 authority.

The project-source compiler explicitly disables inherited future flags so that
sealed original modules retain the semantics of ordinary source loading. Their
own explicit future imports still apply. Once the original supervisor returns,
a completion event cancels the pre-handshake accept and post-handshake Ready
waits within their bounded polls. The original absolute deadline, actual child
exit and wait4 reaping remain authoritative; cancellation cannot mint success.

Only the actual `torch.ops` and `torch.classes` virtual namespaces may map their
non-path markers to their exact pinned owner source. Loader/spec identity,
source bytes, package relation, exact class and initializer globals, and the
same registry/root/owner singleton are all required. Failed checks cannot fall
back to ordinary paths. Other relative origins refuse; executable mappings
and ordinary file digests keep the original runtime boundary.

Joint payload admission is one obligation. Tensor expansion, activation
workspace, device allocation and child-process peak memory still require their
original admission and enforcement. Hashes, byte callbacks and descriptors alone
are not successful model forwards, ordinary installed Hepta execution or
next-task acknowledgements. Actual consumer observations must identify these
same byte owners and keep research next-use separate from ordinary FinalUse.

The [recorded third research operation](../../../../evidence/cell-storage-convergence-f2568-20261109/README.md)
on commit `097f59f505f8ec42f72e3b8255e6cb7822a70646` recovered 30 members,
280,269,602 payload bytes and 95 chunks, removed both caches, and completed
30 sealed-FD handoffs and two real forwards in 17.552772522 seconds. The
original 300-second research limit and 8 GiB worker RSS allowance remained.
Both action scores favor yes and the second fixed probe is incorrect. This
is execution evidence, not effectiveness, four-second service qualification,
independent custody, provider payment or ordinary Hepta authority.

Deduplication is measured over exact stored representations. Fine-tuning does
not guarantee unchanged serialized chunks: tensor order, container metadata,
encoding, quantization and update scheme can alter many bytes. Report actual
unchanged chunks and logical/physical bytes for each fixed representation; a
training-method label cannot stand in for that measurement.

## 8. Exact-source verification and evidence

Independent Python vectors cover TCA3 envelope/events and CSP1, CHB1, CPS1
framing. Native tests consume the same fixed vectors. Complete DA execution and
the full Node storage-service module retain old regressions plus new state,
funding, failure/replay, cold-readback and complete-plan controls. Exact named
checks reject empty or accidentally filtered runs.

Discovery evidence distinguishes the original #823 server red controls, identical
candidate green controls, and the candidate with only its monotonic clamp
removed. Compilation/setup failure is not a valid red control. The clamp
mutation is not an original #823 observation.

Final gates bind the exact committed HEAD/tree and clean complete source before
and after execution, Rust/provider inputs, persistent native filesystem,
original resources/deadlines, locked Cargo graphs, strict all-target/all-feature
Clippy, formatting, source-integrity negative controls and documentation links.
Uncommitted preparation runs remain separate. Every failure remains visible
after a repair.

Local gates do not replace original release, x86_64/ARM64, head/prospective-merge,
packet, History, service, pressure, export or Hepta lanes. The four-second service
requirement and separate thirty-second pressure observation retain their own
meanings. Operational qualification and production activation remain false
until their original owners and independent evidence satisfy those obligations.
