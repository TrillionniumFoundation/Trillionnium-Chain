# Root recovery bridge: lifetime and independence obligations V2

Status: **research component; HOLD / NO-GO**. This document supplements the
[V1 root/recovery policy](PQ_ROOT_RECOVERY_POLICY_V1.md) and the
[PQ128 lifetime contract](PQ128_LIFETIME_BUDGET_V1.md). It records the obligations
of connecting real dual-family verification to a durable research journal and
an external-anchor interface. It grants no production root, M15 release,
consensus, deployment or application permission.

An actual OpenSSL verification result establishes a mathematical check for the
supplied key and bytes under the selected implementation. A successful SQLite
transaction establishes the observed local transition under that storage
environment. Neither result establishes independent custody, an independently
retained fresh anchor, complete effect reconciliation, or a whole-chain
failure bound. The evidence record must identify which of these operations
actually ran and which remain interfaces or assumptions.

The companion source roles are:

- [Signature bridge](../../formal/pon-nakamoto-v1/pq_root_recovery_signatures_v2.py): bind the actual
  suite and canonical public keys to complete statements and require both
  signature families.
- [Research journal](../../formal/pon-nakamoto-v1/pq_root_recovery_journal_v2.py): retain bounded research
  root/policy state, nonce and revocation history, effect records and journal
  commitments; coordinate pending local writes with the anchor interface.
- [Provider readback](../../formal/pon-nakamoto-v1/pq_root_effect_readback_v2.py): verify a pinned
  dual-family provider declaration for the exact operation, protected intent
  digest, fresh request and reorganization epoch; grant no effect dispatch.

The journal snapshot covers the complete **research schema**: the policy and
public-key DER, retained nonce history, monotone revoked-key identities,
enrolled anchor/writer/provider policies and public keys, external-effect
phases and receipts, and chain-reorganization observations. The actual
approval signatures and successor possession signatures are retained in the
root-operation events; provider events retain their requests, signed receipts
and approval rows.

Its SHA-512 event chain commits to canonical full snapshots under the fresh
`TRNM/RootRecoveryJournal/` V2 domains. This is not a snapshot of every native
chain, account, provider, release or Hepta state owner. The retained-history
limit of 128 nonces is a hard exhaustion/refusal boundary; it supplies no
permission to prune consumed nonces or restart their history at a new epoch.

Before using retained state, the journal recomputes the canonical enrollment
root and every bounded event's predecessor and full-state commitment, then
compares the reconstructed head and state with the current row. The enrollment
record is the immutable starting record of this history contract, not storage
an attacker is physically unable to modify. Checking all those commitments
does not independently authenticate a consistently rewritten history; the
external current frontier supplies that comparison. Signature bytes are
retained for audit, with actual cryptographic checks on admission; this cold
history check does not claim a fresh OpenSSL verification of every historical
signature. Opening a database also requires an independently supplied
`expected_scope` and pinned identities, so a coherent database for another
owner cannot select its own expected scope.

Both sides of the anchor exchange are authenticated. `verify_anchor_request`
requires the complete writer request to carry ML-DSA-87 2-of-3 AND
SLH-DSA-SHA2-256s 2-of-3 under a separately pinned writer policy and public-key
roster. The writer signs the action, scope, challenge and expected/target
frontiers in a distinct role domain. The anchor response is verified under
its own enrolled dual-family policy and binds the fresh challenge, complete
request digest, scope and journal count/root. Enrollment of an external
frontier is explicit; reopening a missing owner database does not silently
create one or register a replacement anchor.

The local protocol commits a pending row before external CAS and finalizes
only the exactly acknowledged target. An uncertain write remains fenced.
These source mechanisms and their executed fault controls must be reported
separately from deployment qualification. All local signing and anchor roles
remain on the same test host; no independently administered production service
or native M15 root deployment is established.

## 1. What the new component can and cannot cover

The intended root condition remains **ML-DSA-87 2-of-3 AND
SLH-DSA-SHA2-256s 2-of-3** for normal operations, rotation, revocation, recovery
and policy replacement. Current authority must approve one complete statement;
a successor policy must preserve the condition for every route. A new-key
possession check, where required, is additional evidence and cannot replace
authorization by the current roster.

This is stronger evidence than approval labels only when both families really
verify the identical canonical bytes. NIST's
[PQC FAQ on dual signatures](https://csrc.nist.gov/projects/post-quantum-cryptography/faqs)
requires successful verification of all components on a common message. This
does not certify the application policy, its key custody or its current state.

The separate native release profile in
[`pq_release.rs`](../../trillionnium/crates/trnm-release-bundle/src/pq_release.rs)
is `TRNM/Release/PQ/ML-DSA-65/v1`. Its old-root and new-root quorum checks are
not the two different algorithm families required here. Passing research
bridge controls cannot rename that profile or qualify the
[M15 release owner](../../trillionnium/crates/trnm-pon-node/src/release_owner.rs).
Connecting the complete policy, current state, final authorization and effect
boundary inside that actual owner remains a separate integration obligation.

The existing
[lifetime register](../../config/pon/pq128-lifetime-budget-v1.json) binds fifteen
declared event paths at `12e510b211110d93d9ead07e02c07a1eecc28ae9` through its
[reviewed source lock](../../config/pon/pq128-source-lock-v1.json). Its signature
term names `pq_auth.rs`, `pq_profile_auth.rs`, SHAKE128 and SHAKE256. It does not
list the new root bridge or the SLH-DSA SHA2 dependency mapping. An unchanged
passing checker therefore remains evidence about those declared paths only.
This supplemental document neither replaces that source lock nor extends its
coverage by assertion.

## 2. Cryptographic dependency and query accounting

The following is a dependency checklist for review, not an instantiated
security reduction or an exhaustive implementation inventory.

| Component or use | Required primitive mapping | Outstanding lifetime obligation |
| --- | --- | --- |
| ML-DSA-87 keys and signatures | SHAKE128 and SHAKE256; exact parameter set and pure-signature message interface | Quantum multi-user and multi-message forgery bound, all key epochs, signing permissions, malformed verification attempts and allowed auxiliary state |
| SLH-DSA-SHA2-256s keys and signatures | SHA-256 and SHA-512 internally; HMAC-SHA-512 in signing; MGF1-SHA-512 in the message-hash construction | Exact role and input mapping, key/message dimensions, signing randomness, verifier behavior and the applicable reduction |
| Public-key identifiers | Domain-separated SHA-512 over the suite and complete canonical public-key bytes | Exact suite/OID and encoding binding; collision or substitution event and its place in the common reduction |
| Complete policy, statement and semantic operation identities | Domain-separated SHA-512 with the specified complete encodings | Binding of context, payload, predecessor, nonce, policy and successor; no reliance on signature bytes or the chosen witness subset for one-use identity |
| Journal/state commitments and anchor comparisons | Domain-separated SHA-512 over the exact retained semantic state | Completeness of the committed state, canonical serialization, predecessor/CAS binding and crash-recovery invariants |
| Writer, anchor and provider authorizations | The same two fixed signature families under separately pinned role rosters; SHA-512 for request and intent commitments | All additional role keys and adaptive signing/verification calls; cross-role replay, freshness and current provider declarations |
| Provider, entropy and process boundary | Exact OpenSSL provider/build, operating-system interfaces and key handling | Implementation refinement, entropy and compromise assumptions; no probability assigned from a successful local test |

The V2 source distinguishes the following roles. A displayed `\0` below denotes
the final zero byte, not two textual characters. The exact length framing and
canonical serialization remain part of the source contract.

| Role | Exact domain | Bytes or decision bound |
| --- | --- | --- |
| Key identity | `TRNM/RootRecoveryNativeKey/v2\0` | SHA-512 over framed suite and canonical SPKI DER; the accepted OID and public-key length are fixed per suite |
| Current-root approval | `TRNM/RootRecoveryNativeApproval/v2\0` | Framed complete V1 statement; the complete message is verified, and its SHA-512 identifies the statement |
| Successor possession | `TRNM/RootRecoveryNativePossession/v2\0` | Complete transition, suite and successor signer ID; all six successor keys must supply this additional evidence |
| Semantic operation | `TRNM/RootRecoveryNativeOperation/v2\0` | SHA-512 over the framed complete statement; no signature bytes or chosen approval subset |
| Journal state | `TRNM/RootRecoveryJournal/State/v2\0` | SHA-512 over version, predecessor, event and full research state |
| Anchor writer | `TRNM/RootRecoveryJournal/AnchorWriter/v2\0` | Complete dual-signed current/CAS request, including scope, challenge and expected/target frontiers |
| Anchor receipt | `TRNM/RootRecoveryJournal/Anchor/v2\0` | Complete dual-signed receipt, including challenge, request digest, scope, count/root and result |
| Anchor request | `TRNM/RootRecoveryJournal/AnchorRequest/v2\0` | SHA-512 of the complete request bound into the receipt |
| Journal scope | `TRNM/RootRecoveryJournal/Scope/v2\0` | SHA-512 binding network, genesis and owner identity |
| Effect intent | `TRNM/RootRecoveryJournal/Effect/v2\0` | SHA-512 of the complete effect payload for reconciliation |
| Provider declaration | `TRNM/RootRecoveryJournal/ProviderReadback/v2\0` | Complete dual-signed receipt, binding the operation, intent digest, fresh request, provider, outcome and explicit reorganization reconciliation |
| Provider request | `TRNM/RootRecoveryJournal/ProviderReadbackRequest/v2\0` | SHA-512 of the complete request, including the exact `orphaned_at` epoch |

The complete V1 policy and statement serialization are reused beneath these
fresh bridge domains. The source fixes canonical SPKI algorithm identifiers,
including refusing the same-sized SLH SHAKE parameter set in place of the
required SHA2 set. It signs the complete approval and possession messages;
their diagnostic hashes do not replace the message supplied to OpenSSL.

[FIPS 204, Section 3.7 and Table 1](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf)
specifies the SHAKE dependencies and the ML-DSA-87 parameter set. For the chosen
SLH family, [FIPS 205, Section 11.2.2](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf)
uses both SHA-256 and SHA-512, with the message-hash and signing-PRF constructions
listed above. NIST's
[algorithm-validation prerequisites](https://csrc.nist.gov/Projects/cryptographic-algorithm-validation-program/prerequisites)
also distinguish these key-generation, signing and verification dependencies.
The name `SHA2-256s` does not mean that SHA-512 is absent.

The [OpenSSL 3.5 ML-DSA interface](https://docs.openssl.org/3.5/man7/EVP_SIGNATURE-ML-DSA/)
and [SLH-DSA interface](https://docs.openssl.org/3.5/man7/EVP_SIGNATURE-SLH-DSA/)
distinguish pure message processing from test-only or externally encoded
processing. A bridge must fix its context and mode, reject unintended algorithm
substitutions, and record the actual provider. Successful use of an algorithm
named in a FIPS document is not evidence of a FIPS-validated module or approved
operating mode. The complete application statement must remain bound even when
the library performs its own internal message hashing.

Different domain tags separate intended encodings; they do not turn the fixed
public SHA-512 function into a new independently budgeted primitive. In
particular, SLH's internal SHA-512 uses and the bridge's key, statement and
journal identities cannot receive unrelated lifetime budgets solely because
their callers or tags differ. The reduction must specify the shared interfaces
and which adversary, honest-party, simulator and extractor queries it counts.
Internal HMAC/MGF calls require the theorem's own transformation; counting one
high-level signature as one hash query is not an established conversion.

Include key-generation/setup work, online and offline activity, preprocessing,
retained advice, failed or cancelled verifications, unpublished signing/search
attempts, retries, recursive help and surviving authority after retirement.
Measured local calls are observations. They neither cap an adversary's unseen
queries nor justify resetting the budget at a recovery or key rotation.
No new numerical error term follows from this dependency table.

## 3. What AND composition actually implies

Fix one experiment, including signer corruption, permitted signing queries,
message/roster binding and the full adaptive adversary state. Under the
conditions that each accepted quorum contains an uncompromised signer and
that neither family was permitted to approve the offending statement, define
`F_M` and `F_S` as the respective family-forgery events. If the implementation
faithfully enforces both quorums on that statement, then

\[
B_{\mathrm{crypt}}\subseteq F_M\cap F_S.
\]

If two concrete bounds apply in this same experiment, set inclusion gives

\[
\Pr[B_{\mathrm{crypt}}]
\le\min\{\Pr[F_M],\Pr[F_S]\}
\le\min\{\epsilon_M,\epsilon_S\}.
\]

This argument does not multiply `epsilon_M` and `epsilon_S`. Different
algorithm designs do not establish independence of compromise, implementation
failures, preprocessing, random-number generation or the adversary's strategy.
Likewise, two signatures from a three-key family do not automatically square
a single-key bound; the theorem must handle the relevant corruption and
multi-user game. Bounds in incompatible conditional games cannot be placed
inside this minimum without a valid reduction.

An unauthorized root effect can also arise from the wrong current policy,
changed message bytes, stale state, a compromised quorum, duplicate execution,
or a bypass of the effect owner. Those events are outside the pure signature
intersection. They need separate coverage or justified assumptions. If the
argument only holds under assumptions `H`, it is conditional on `H`; this
document supplies no number for `Pr[not H]`.

An emergency route accepting either family changes the accepted-event
structure. It cannot inherit the AND argument. Unsupported suites, parameters,
mode flags or fallback fields must be refused explicitly. Algorithm
replacement requires a versioned complete successor policy, authorization
under the current policy, new-key possession where applicable, and a reviewed
dependency/reduction mapping. Requiring a migration certificate is not itself
proof that a proposed replacement has adequate security.

## 4. Complete local rollback is indistinguishable without surviving state

The following is a direct indistinguishability argument for the stated model,
not an empirical security estimate.

Let `L` contain every durable fact available to the restarting verifier: its
database, journal, consumed nonces, revocations, local witness, cached anchors,
keys/configuration and any other locally retained authority metadata. Suppose
an adversary can restore all of `L` to an earlier valid snapshot `L0`. Assume
the verifier obtains no authenticated observation correlated with the later
history from outside that rollback domain.

Consider two histories with the same code and configuration:

1. **No transition:** the system reaches `L0`, performs no later operation,
   then restarts with `L0`.
2. **Transition and restoration:** starting at `L0`, the system advances to
   `L1`, consumes nonce `n` and possibly executes an external effect; the
   adversary then restores every local fact to `L0` and restarts it.

Supply the same subsequent request and the same distribution of available
inputs in both histories. The verifier's initial view is identical. Couple its
fresh random coins identically; by induction on each local execution step its
view and decision remain identical. Hence, for every restart verifier `V`,

\[
\Pr[V\text{ accepts}\mid\text{no transition}]
=\Pr[V\text{ accepts}\mid\text{transition and restoration}].
\]

If it usefully accepts the first history with probability `p`, it accepts the
stale second history with the same probability. It can refuse both, but it
cannot both accept the valid history and reliably detect the restored one
using only these inputs. More local copies, hash chains and signatures over
`L0` preserve the equality when they are rolled back together. Fresh local
randomness also does not reveal which history occurred.

This result depends on the model's absence of surviving information. A
protected monotonic hardware register, an independently retained service, or a
fresh authenticated provider record can break the equality if it actually
retains a distinguishing fact. A trusted clock alone is insufficient when
both histories can present the same time and that time does not encode the
missing state transition. An untrusted or jointly restored clock supplies no
such distinction either.

### Conditions an external anchor must supply

For the root protocol, a useful external anchor must retain the current
network/genesis, owner generation, policy/epoch, sequence and complete state
commitment independently of the local snapshot. Its authenticated response
must bind the verifier's fresh challenge and the intended context. The service
must enforce monotonic updates or compare-and-swap against the expected
predecessor, and the actual root-effect owner must enforce the resulting
decision at use time.

A new challenge prevents replay of a response prepared for an old challenge.
It does **not** prevent a rolled-back witness with its still-valid signing key
from issuing a fresh signature over stale state. Both response freshness and
independent retention of the authoritative frontier are required. Distinct
files, processes, ports, hosts or key identifiers do not prove that two stores
have independent administrators, backups or compromise domains.

Authenticating the writer prevents an unapproved caller from advancing the
anchor through that request interface. It does not establish that an approved
writer, its recovery process, or the anchor's storage administrator cannot
restore the same old history. These are separate obligations.

An unavailable, conflicting, expired or uncertain anchor must not authorize a
fresh effect. If an external CAS may have succeeded before local failure,
recovery needs authenticated readback of that exact operation and predecessor;
blindly repeating it or locally clearing the uncertainty loses the guarantee.
The research interface and controlled fault tests are useful evidence about
this contract. They do not establish that a deployed external service has the
required independence, key custody, availability or lifetime retention.

## 5. Reorganizations and external effects

A chain reorganization changes canonical chain history. It cannot, by itself,
undo a completed provider payment, API call or resource consumption. The root
and application owners therefore need a durable effect history whose one-use
identity survives reorganization and recovery.

The semantic operation identity must bind the complete intent, context and
original terms while excluding randomized signature bytes and the selected
quorum subset. A second valid signature or a different two-of-three witness
pair cannot create a new right to perform the same effect. A reorganization
also cannot remove a consumed nonce, reinstate a revoked root, erase a known
liability or change the original deadline.

Before invoking an external provider, persist the intent and its stable
idempotency key at the required durable boundary. If the outcome is uncertain,
retain `Unknown` and reconcile with an authenticated provider readback using
that identity. An uncertain result is neither an automatic failure/refund nor
permission to send a new operation. Where a provider cannot support suitable
idempotency or readback, the implementation must expose the unresolved effect;
a local journal cannot manufacture exactly-once execution at that provider.

At the final local dispatch-reservation boundary, `enter_effect` rechecks the
original validity interval against the caller-supplied current height, the
current owner generation, key epoch and policy identity, and revocation of
the actual approving signers. A reservation admitted before expiry, rotation
or revocation cannot silently confer later authority. The current-height
input still needs a trustworthy owner in a deployed integration; this research
API does not independently establish chain height or a production time source.

An orphaned chain action with an already completed effect remains a
reconciliation obligation. Compensation, when supported and authorized, is a
new explicit effect with its own identity and outcome; it does not delete the
original event. Recovery must reconcile provider state, outstanding holds,
known liabilities and possible partial effects before resuming affected use.
Local journal state-machine tests exercise these cases without establishing
that real funds or real service providers were reconciled.

The V2 provider adapter now verifies real dual-family signatures against keys
enrolled before the response is received. Its owner-generated request binds
`operation_id`, the full stored intent's `intent_sha512`, provider identity,
scope, a fresh challenge and the current `orphaned_at`. The provider signs the
complete response, including a digest of that exact request. The raw effect
payload remains in the protected journal; the provider wire carries its digest,
so the intent-binding argument still depends on the specified SHA-512 mapping.

An `applied` or `not-applied` outcome alone does not clear an orphaned
liability. Reconciliation is a separate explicit declaration bound to the exact
orphan epoch: `applied/liability-retained`, `not-applied/not-applied`, or
`compensated/compensated`. `unknown` supplies no reconciliation. A previously
signed success, a different fresh request or an earlier orphan epoch cannot
replace this declaration. The journal retains these observations and leaves
recovery fenced while a required reconciliation or uncertain effect remains.
An authenticated provider declaration establishes who asserted the outcome;
the current test provider does not establish an actual payment or service
effect, economic compensation, or independently administered custody.

## 6. Custody evidence must describe failure domains

The roster establishes distinct public-key identities and suites. It does not
establish distinct controllers. To assess the requested custody condition,
retain evidence for the actual people or organizations administering each
key, the signing devices, access and approval paths, entropy/key-generation
procedures, backup custodians, and recovery procedures. Record shared
administrators, credentials, software, provisioning, cloud accounts, backups
and emergency controls as common failure domains.

Exercises should show that a single compromised custodian or recovery channel
cannot reconstruct or use the required quorums, that lost devices can be
replaced without a weaker path, and that revocation reaches the actual signing
and effect owners. Such observations have a defined scope and date. They do
not prove a numerical independence model or a probability of compromise.

Generating all six research keys in one process, using one provider, or placing
them in six directories provides cryptographic test fixtures. Timing those
keys on one machine is performance evidence under that fixture, not evidence
of independently operated custody. Different family names do not remove the
shared process, entropy source or administrator. Neither test result is
promoted to a production-custody attestation here.

## 7. The eight lifetime domains remain open

| Existing domain | Evidence the root bridge may add | Qualification still required |
| --- | --- | --- |
| Signature | Actual verification of the selected ML and SLH suites for root, successor possession, writer, anchor and provider roles | Concrete joint-game forgery reductions, all signing interfaces and epochs, corruption/custody conditions and actual-provider refinement |
| Commitment | Exact encodings and domain-separated identities for keys, policies, statements and retained state | Complete dependency closure, binding properties, shared-hash model, query transformations and concrete error terms |
| Proof | No W1 proof qualification follows from root authorization | Complete native/proof relation refinement and the exact backend's quantum commitment, Fiat-Shamir and recursion obligations |
| Ledger | Explicit distinction between canonical-chain state and irreversible local effect history | Joint W1 work, DAA, timestamp, network, stopping and confirmation analysis; root signatures do not establish finality |
| Transport | Dual-authenticated anchor writer/response messages and fresh provider readback bind context and freshness | Actual channel and peer ownership, all replay/eclipsing and timeout paths, resource costs and independent service deployment |
| Recovery | Persistent nonce/revocation state and controlled rollback/CAS refusal cases | Full rollback-domain coverage, independent fresh frontier, crash and uncertain-result reconciliation, and recovery without weaker approval |
| Release | A candidate stronger root policy and its transition checks | Actual native M15 owner integration, current loaded bytes, atomic handoff, revocation and final-use enforcement |
| Application | Durable semantic operation identities, signed provider declarations, exact orphan-epoch reconciliation and explicit unresolved effects | Real provider state and payments/holds/partial effects, economic liabilities across reorg, and complete cross-owner refinement |

The old register's eight null terms, four unknown query budgets and unmet
assumptions are retained. A new dependency inventory or successful regression
suite does not instantiate those terms. A future reviewed register must cover
the actual combined source and explain every new use of a shared primitive;
it cannot transfer a numerical result from a different source or profile.

## 8. Native controls retain the complete-rollback counterexample

The
[native journal controls](../../formal/pon-nakamoto-v1/test_pq_root_recovery_journal_native_v2.py)
exercise real OpenSSL signatures and actual SQLite files. Their assertions
cover all five root operations, nonce and revocation persistence, same-head
state tampering, wrong-owner database substitution, full local rollback while
the anchor retains its newer head, lost-CAS-reply recovery, pre-CAS failure,
two contenders for one original head, replayed anchor responses, malformed
writer authentication, final-use expiry/rotation/revocation, and
reorganization plus uncertain provider outcomes.
Run results, source identity, budgets and observed failures belong in the
execution receipts; enumerating the source controls is not an assertion that
every execution passed.

The explicitly named
`test_full_owner_and_anchor_rollback_counterexample_stays_unqualified` restores
**both** the owner and anchor databases to the same old snapshots. It then
obtains fresh, real signatures and accepts the restored history. That is the
counterexample proved in Section 4: every retained distinguishing fact was
restored. Keeping this test successful means the suite continues to expose
the missing independent retention assumption. It does **not** mean the
complete-rollback security gate passed.

The separate
[native provider controls](../../formal/pon-nakamoto-v1/test_pq_root_effect_readback_native_v2.py)
exercise real signatures, including missing or corrupted families, changed
requests, later orphan epochs, a different pinned provider and root-approval
domain substitution. The
[provider contract controls](../../formal/pon-nakamoto-v1/test_pq_root_effect_readback_v2.py)
exercise parsing, freshness, explicit reconciliation semantics and the
unchanged refusal to authorize another dispatch. These are distinct evidence
scopes; a structural verifier double is not a native cryptographic execution.

The qualification output therefore remains:

```text
status = HOLD
actual_lifetime_failure_bound = null
whole_chain_pq_qualified = false
composition_coverage_proved = false
```

Changing this status requires a reviewed complete bad-event reduction, concrete
applicable bounds and query/resource transformations, independently justified
currentness/custody assumptions, and actual effect-owner integration. Allocating
`2^-128` across eight labels supplies none of those missing premises.
