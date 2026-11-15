# Root recovery and original-effect continuity: V6 continuation

Status: research candidate / HOLD. No production activation or PoN change.
This continuation belongs to the existing PN0/PN4 recovery and effect owners;
the sole implementation plan remains
[the development plan](../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md).

## Source and ownership

The Chain candidate starts from PR #940, commit
8970e2c81abbf48e2a4d3f0802d79624ab20fadd, including the copied-Lease regression.
It extends the existing Root V5 transport and ProviderEvidenceJournalV4.
It does not create a parallel business-effect ledger or change Root V3 signing
messages, V4 provider records, PoN voting, chainwork, or fork choice.

The companion Hepta work uses the original automation dispatch-attempt store and
actual Agentd provider driver on PR #4332. Its independent source, tests and
publication must be recorded separately; a Chain pass cannot qualify it.

## Provider history floor

A fresh Root witness authenticates the Root journal. It does not establish that
a separate provider evidence file is the latest surviving version. V5 provider
readback therefore requires an explicit ProviderHistoryFloorV6, including for a
newly created local file. Creating a different path for a historical enrollment
does not supply that history.

The floor's new canonical namespace binds the complete provider enrollment,
original historical operation, absolute byte boundary, record count and record
hash chain. Full replay must find that exact prefix at the complete header or a
complete frame boundary. A later valid suffix is allowed, including an unanswered
readback. The existing live-session full-head guard remains active.

A caller can install the same floor or advance it after both old and new prefixes
are checked. Clearing or lowering it is refused. Wrong operation, enrollment,
length, count or chain refuses without changing the file. Any error fences that
opened owner. A missing floor refuses V5 provider callbacks before any new request.

The export method produces a local observation. It neither installs a floor nor
authenticates custody. Importing a pin authenticates only its closed encoding.
The caller must authenticate and retain the pin independently of the recovered
provider file. Exporting a restored file and importing that value is not evidence
of freshness. A genesis pin is justified only by independently authorized first
registration, not by absence of a local file.

**Exact guarantee:** detect rollback or replacement relative to the independently
retained prefix. This is not a claim that the newest provider head is known.
The negative control deliberately shows that a suffix which never reached the
external floor can be lost after cold rollback. Provider pending is an unanswered
read, not an external effect's MayHaveBeenSent state.

## Persisted original witness acknowledgements

The V6 durable witness is usable through the existing RootWitnessTransportV5 and
WitnessedRootOwnerV5 path. The existing SQLite register kernel is versioned,
while V5 wire messages and signature verification remain unchanged. V5 databases
are not silently migrated or reclassified.

The new storage namespace retains the original writer request and approvals,
original receipt and witness approvals in a bounded, canonical, hash-chained
archive. Actual CAS commit and synchronization precede signing; the original
signed exchange must then be committed and synchronized before the ACK returns.
Reopening requires the externally retained exact head and archive checkpoint,
complete replay and verification of both signature families.

CAS and receipt persistence use separate transactions. If CAS commits but signing
or archive commit fails, the head may have advanced without a returned durable
ACK. The owner fences; it does not roll the head back or invent successful
acknowledgement. Historical receipt readback does not sign, perform a CAS, restore
cold CAS retry permission or grant current authorization.

A captured request cannot consume new receipt capacity: duplicate request digest
is rejected before the capacity check, CAS and signer callback, without fencing
an otherwise healthy owner. Cold replay also rejects duplicate archived requests.
Unique authenticated requests remain subject to the declared finite capacity;
there is no silent pruning, capacity renewal or production liveness claim.

## Stable identities and external effects

These identities must remain separate:

| Identity | Meaning |
| --- | --- |
| Chain RootStatementV3 operation | Commitment to a particular authorization statement, including nonce/generation/sequence; a new statement has a different identity. |
| Chain provider historical operation | Exact original Root operation retained by ProviderEnrollmentV4; readback challenges and orphan epochs do not replace it. |
| Hepta ProviderEffectKey | Original owner/run/step occurrence identity; dispatch attempts and fencing are separate. |
| Application business intent | Must survive any decision to create a new run; occurrence-level deduplication alone cannot infer two new runs mean the same business intent. |

The external-effect protocol remains:

Prepared -> DurableIntent -> Authorized -> MayHaveBeenSent ->
Confirmed / ProvenNoEffect / Unknown.

The original dispatch owner must persist the original provider key, exact payload
and destination before send. A timeout, disconnect, ambiguous server error or
ordinary not-found query cannot alone establish ProvenNoEffect. Unknown is
reconciled under the original provider identity. Current authority and the
provider's atomic deduplication contract are prerequisites for any retry that
could create a first effect.

The companion Hepta change pins the original provider context in that same durable
attempt reservation. Its purpose is to prevent a different endpoint, contract or
provider environment under the same nominal scope from reinterpreting an old
pending operation. Historical unbound attempts stay unknown; they are not
backfilled from current configuration. A local historical terminal receipt is
read under its original identity.

## Required evidence and unresolved gates

The original native runner is extended to require the complete original suites,
all provider-floor controls and all V6 receipt controls, with no ignored or
filtered target methods. The source integrity corpus and reviewed dependency map
must bind all changed/new sources; they are not security qualification.

The candidate evidence must distinguish registration counts, actual process exit,
exact test names, raw logs, frozen source/tree and environment. Cloud interruptions
and transport timeouts remain UNKNOWN until the same original operation is
reconciled. Format/source checks never substitute for native execution.

The following are still separate obligations:

1. Independently operated administrators, devices, keys and backup failure domains,
   with authenticated latest-state recovery evidence surviving the declared
   co-restore set. A same-key second register under another path must be excluded.
2. A complete distributed witness protocol: concurrent ordering, recovery
   incarnation, fresh quorum reads, partial certificates and joint reconfiguration.
   The static inequalities 2q-n>f and q<=n-f do not supply these mechanisms.
3. A complete witnessed system-state tuple containing Root and revocation frontier,
   all relevant provider journal heads and business-operation frontier. The present
   caller-supplied provider floor is not an automatically updated remote witness.
4. Ordinary production M15/FinalUse/effect-sink assembly and real provider
   reconciliation, with original failure/timeout/cost denominators.
5. Application intent continuity across creation of a new run, current authorization
   on eligible retries, bounded provider retention and atomic deduplication plus
   mutation. No unlimited exactly-once conclusion is justified.
6. The original service campaigns and whole-chain PQ/lifetime requirements remain
   unchanged. Their prior failures and unknown bounds remain in force.

If every relevant observable authority is restored to the same old state and
can still produce consistent old signatures, the forgotten history is not
distinguishable. A fresh nonce does not change that information boundary.

## Primary research and provider references

- [DISC 2025: TEE Is Not a Healer](https://drops.dagstuhl.de/entities/document/10.4230/LIPIcs.DISC.2025.39):
  explicit crash/recovery/rollback models; recovery must not mix old acknowledgements
  across incompatible incarnations.
- [Key Transparency Architecture draft-11](https://www.ietf.org/archive/id/draft-ietf-keytrans-architecture-11.html):
  work in progress, published 1 November 2026; state loss and independent monitoring
  remain application obligations.
- [C2SP Witness v1.1.0](https://c2sp.org/tlog-witness@v1.1.0):
  checkpoint consistency is useful, but the monitoring GET may be delayed and is
  not a fresh Root authorization read.
- [Stripe idempotent requests](https://docs.stripe.com/api/idempotent_requests):
  API v1 may prune a key once it is at least 24 hours old; reused pruned keys can
  initiate a new request. API versions and provider contracts must stay explicit.
