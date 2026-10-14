# Release finality V2: executable, disabled protocol contract

Status: executable reference candidate; no native runtime activation. This is a
bounded protocol supplement to the sole Chain development plan, not a replacement
plan, a second Hepta owner, or an automatic PoN fallback.

## Decision and source authority

Continue the native integration candidate `6861cdcd74ddb236ef01a5c6d9cc6b08d94e683f`
(tree `111e3c0f7244dc7f5a951c2c2751537a155f7d5f`). The October 14 finality draft
`a598d586239b9c019d4a1cd4df01d70c1d39f387` is two commits after an older main, not a
successor of this native candidate. Port its disabled finality contract narrowly;
do not replace the newer node, owner, CI or recovery source with that old branch.
The existing PoN protocol remains the selected, experimental work-chain profile.

The development decision for this increment is an ISOLATED release-finality
candidate: an explicit membership manifest, distinct genesis from PoN, fresh
namespace, no shared vote weight, no automatic fallback, no PoN-history import.
It orders release commitments and their epoch transitions. It does not transform
PoN depth into deterministic finality. The release network is NOT deployed.
Changing the sole active network still requires a separately reviewed activation.

The V1 numeric defect is repaired by fixing that original disabled profile to
exactly four actual members, f=1, q=3. Its minimum is no longer an open-ended n.
Dynamic membership uses the explicit V2 domain and validates ACTUAL membership.
An n=5,f=1,q=3 manifest must refuse; n=5,f=1,q=4 is admissible.

## Ownership and claims

`formal/release-finality-v2/protocol.py` is the executable reference; it is not a
new Cargo node, production signer, operation log, trainer or model installer.
M00 remains the protocol-schema owner, M01 owns cryptographic verification, M08
owns finality/recovery, M10/M11 own release/evaluation, and M17 owns qualification.
Production adapters must use their existing owners. The reference SQLite outbox
models durable-before-send signing solely for replay and process-crash tests.

Every decision observation explicitly denies Hepta FinalUse, model-quality
acceptance, long-term availability and production activation. The application
validity callback is a REQUIRED trusted input, not a default success stub. Tests
pin a synthetic evaluation root; that is not an actual product evaluation receipt.
A future native adapter must obtain the real evaluated release from the existing
Hepta evaluation/artifact/selection owners and current withdrawal/generation state.

## Wire and cryptographic grammar

All objects have the EXACT field sets in the reference. Unknown fields refuse.
Encoding is ASCII JSON with sorted keys, no whitespace, `ensure_ascii=true`, and
separators `,` and `:`. Raw decoder input must exactly equal its re-encoding.
Duplicate keys and nonfinite constants refuse. Signed integer fields are JSON
integers in [0,2^63), never booleans; height and voting views are positive. Hashes
and keys are exactly 64 lowercase hexadecimal characters; signatures are 128.
The reference caps each encoded object and model byte witness at 2 MiB and the
committee at 32 members. This small byte-witness profile is NOT a full LLM DA plane.

Define D as the ASCII bytes `TRNM-RELEASE-FINALITY-V2` followed by one zero byte.
`id(x) = SHA256(D || canonical(x))`. Signatures cover `D || canonical(body)`.
Public-key and signature verification reuse the existing, unchanged
`formal/pon-nakamoto-v1/strict_signature.py` blob
`b0cedca3a0423f2563359a8645ba322f966804dc`: canonical curve encoding, small-order
public-key/R rejection, S<L, then the installed Ed25519 verifier. This is a public
input verifier, not Python signing-scalar arithmetic. Existing V1 signature domains
cannot be promoted to V2. No permissive crypto fallback is used.

A signed object is `{signer, body, signature}`. Quorum signatures are sorted by
signer and unique. An untrusted sender cannot supply its own trusted roster.
The stand-alone reader requires separately supplied committee and context pins.

### Strict signed-byte binding

Every nested vote body receives its own exact field/type validation. Context,
phase, view and value bind through canonical byte equality, never Python numeric
or dictionary equality: true/false and floating aliases cannot replace integers.
The separate reader verifies each signature over that vote's actual body bytes,
not reconstructed enclosing-certificate bytes. The protocol reader follows the
same contract through its own implementation. New-view reports, bundled/stored
contexts, retained outbox retries and epoch acknowledgements preserve exact byte
identity as well. Valid V2 bytes, domain, signatures and quorum rules are unchanged;
this enforces the existing grammar rather than introducing a protocol successor.

`test_strict_bindings.py` adds signed and unsigned numeric-alias controls, all four
vote phases, each signer position, context/manifest types, changed fields, duplicate
signers, new-view reports and retained outbox retries. The original protocol and
campaign suites remain unchanged. A passing local differential suite supplies no
independent-operator, native, model-quality, physical-storage or activation claim.

### Manifest

`{schema, genesis, epoch, members, fault_bound, quorum}` with schema
`trnm-release-committee-v2`. Members are sorted, unique strict Ed25519 public keys.
Let n be the actual list length, f the fault bound, q the vote threshold. Require:

    n >= 3f+1; 2q-n > f; q <= n-f; 1 <= n <= 32.

These enforce honest quorum intersection AND a live quorum despite f absent
members. Reference tests enumerate admitted quorums through n=9. Weighted voting
is not implemented; do not reinterpret these inequalities as stake arithmetic.
One administrator with multiple keys is not independent control.

### Context and release statement

Context is `{profile, genesis, epoch, committee, height, parent, parent_model}`.
Profile is `trnm-release-finality-v2`, committee is id(manifest). Parent is the
previous FINALIZED release statement identity; parent_model is its exact model.
At genesis both are externally pinned. Subsequent contexts derive only from an
accepted decision or a verified epoch handoff, not untrusted JSON context claims.

Statement is `{context, model, evaluation, availability, retention_height,
state_root, next_committee}`. Context is id(context); model is SHA256 of exact
artifact bytes. Evaluation, availability and state_root are commitments. The
retention height is at least the statement height. next_committee is null or the
exact successor manifest id. All fields participate in the value identity.
The reference does not itself prove the economic/application state transition.

### Votes and certificates

A vote body is `{context, view, phase, value}`. Context and value are the identities
above. Phase is availability, prepare, precommit or commit. Availability uses
view 0; other phases use positive views. A QC is `{body, votes}` containing q..n
signatures over that exact body. Phase mixing, replay, duplicate identities,
unknown members, modified roots and a prepare-QC masquerading as finality refuse.

Availability signers receive and hash actual model bytes and run the required
application predicate before signing the complete statement including retention.
Consensus voters require the availability QC AND their own byte retrieval/check.
This supplies a bounded availability-at-vote condition under the fault assumption,
not evidence of long-term retention or real independent storage operators.

## Per-height protocol state machine

This reference uses a serial-per-height three-phase design inspired by Basic
HotStuff, not chained HotStuff and not a claim to HotStuff's communication bounds.
It deliberately carries complete signed new-view reports and unaggregated votes.
Primary reference: Yin et al., *HotStuff: BFT Consensus in the Lens of Blockchain*,
https://arxiv.org/html/1803.05069v6, Section 4. The paper does not certify this code.

Durable state: context, current view, highest known prepare QC, locked precommit
QC, decided value, and epoch-ready state. The durable outbox is keyed by context,
phase and view (availability additionally by statement). Exact retries return the
same signature. Different bytes in the same voting slot refuse DOUBLE_SIGN.

| Event | Preconditions | Durable change before output | Result |
|---|---|---|---|
| Local timeout / start view v | v>=current, undecided, epoch ready | persist v and signed new-view report carrying highest prepare QC | new-view message; no unlock |
| Leader proposal | leader=(v-1) mod n; q signed reports for exact context/v | leader message signs reports, statement, availability QC | highest reported prepare QC determines value, or fresh admitted value if none |
| Replica prepare | current view, legitimate leader/reports, available application-valid bytes, safe lock | unique prepare vote | prepare signature |
| Prepare QC | exact context/value and complete proof | retain highest QC monotonically; current-view unique precommit vote | precommit signature; out-of-view QC only updates knowledge |
| Precommit QC | matching actual prepare QC, current view, compatible/nonregressing lock | persist locked QC and commit vote atomically; high QC never regresses | commit signature |
| Commit QC | full application/availability checks; any view at current height | persist decided value and exact decision bundle atomically | finality observation only |
| Ordinary next height | decided, next_committee=null | new context height+1, parent=decided value, parent_model=decided model; reset per-height locks | new height; old outbox and decision retained |
| Epoch boundary | decided and next_committee non-null | old context remains sealed | old committee cannot advance |

Safe prepare condition: no lock, same value as lock, or a verified proposed highest
prepare QC with view strictly greater than the locked QC view. Merely advancing
a timer, receiving a higher view number or seeing a different leader never unlocks.
A new-view QC must precede the proposed view. A signed report cannot be changed
within its already signed slot after learning another QC; proceed to a later view.
Commit proofs remain admissible after a local timeout; do not discard a valid
late decision just because the local view advanced.

After a prepare QC, a receiver may participate without having seen the original
proposal, but must independently retrieve the statement, artifact, availability
QC and application admission. Before voting commit it receives the actual matching
prepare QC; a successful boolean does not replace that predecessor proof.

### Safety argument and limits

At most f admitted keys are Byzantine. With 2q-n>f, any two quorums share an honest
signer. Per-slot persistence prevents an honest double vote. A commit QC requires
q commit voters, at least q-f honest replicas having durably locked its precommit
QC. Suppose a first higher-view conflicting prepare QC exists. Its quorum must
intersect those honest locked replicas. Such a replica cannot vote for the
conflict without an earlier higher-view conflicting prepare QC, contradicting
minimality. Same-view conflicts require an honest double prepare vote. Induction
across finalized height/parent contexts supplies a single finalized prefix.

This argument is conditional on authentication, correct application predicates,
trusted initial context, the fault bound, retained signing/lock state and unique
key ownership. It is not a mechanized full-system proof. Disk restore, key cloning,
malicious administrators, changing trusted initial contexts, independent directory
owners and physical power loss are NOT covered by a SQLite process-crash test.

### Liveness and pacemaker boundary

After network stabilization, q responsive replicas must overlap in a view whose
honest leader obtains the necessary reports, bytes and successful application
checks. The leader reproposes the highest reported prepare QC. The safe-node rule
and durable knowledge prevent hidden locks from requiring an unsafe reset.
A real pacemaker must increase deadlines until this overlap exists, bound incoming
view reports, and preserve the absolute attempt budget. This reference exposes
new_view(v) to a controlled scheduler; it does not implement a WAN timer service.
Neither timeout counts nor passing local schedules establish public liveness.
Finite view/height encoding and unpruned reference history are explicit product
limits requiring native resource-lifetime design, not a claim of indefinite scale.

## Epoch transition and recovery

The old committee finalizes a statement committing the successor manifest. The
new manifest must share genesis, have epoch+1, and independently satisfy quorum
rules. Old ordinary advance refuses EPOCH_SEALED. New replicas begin pending and
cannot start a view or vote until handoff activation.

Each new member verifies the old commit and availability certificate, retrieves
the exact boundary artifact, runs its trusted application check and persists an
`epoch_ready` signature before sending it. Body fields are phase, predecessor
statement id, old_context id and new_committee id. A new quorum of these ACKs plus
the old commit QC authorizes the new context at old height+1. No overlap between
old and new sets is assumed; BOTH certified transitions are checked. Duplicate
ACKs, wrong epoch/genesis, substitution and missing quorums refuse. Long-range key
compromise and an external trust-anchor distribution policy remain open obligations.

The reference holds an exclusive advisory lock and uses SQLite WAL with
synchronous=FULL. State/outbox/decision writes share one transaction. Fault
controls include actual child exit before and after SQL commit, retained votes
and locks after reopen, lost output, and exclusive-owner refusal. Physical durable
storage and anti-rollback signing must be supplied by the real existing owner.

## Learning and performance acceptance joins

`campaign_gate.verify_learning_packet` invokes the EXISTING
`verify_parent_bound_generation_sequence` V3 with externally pinned source pair,
initial model, history and campaign. It preserves all original V1/V2/V3 semantics
and false authority flags. Its separate full-checkout test uses the existing
signed fixture owners, including adopt/no_update and actual wrong-parent refusal.
It does not synthesize user tasks or install models. Real predecessor installation,
new authorized experience, independent untouched future windows, strongest controls,
withdrawal/recovery and honest no-update outcomes remain required external runs.
Different signature keys or controller labels alone do not establish independence.

`pipeline_observation` reads the existing native continuous_pipeline summary.
It recomputes confirmed transactions divided by WHOLE campaign duration, including
startup and confirmation drain. All requested transactions remain the denominator
for unsuccessful/unobserved outcomes. Stage counts must conserve work. Failed runs
remain failed and cannot produce a speedup claim. Cross-pattern, security-profile,
genesis, pacing, workload-size or hardware comparisons refuse. Inclusion TPS,
executor rates and correlated per-block samples never replace confirmed goodput.
Model download-to-first-use stays null when this transfer workload cannot measure it.

The additive CI executes current reference controls, original signed-learning
suites, and the original continuous native pipeline for hot/disjoint4/growth on
x64/ARM64 head and actual-main-merge. This is a baseline decomposition, not an
unimplemented optimized arm or a saturated WAN benchmark. Existing baseline and
pair workflows are not removed, replaced or granted automatic success.

## Reproduction and remaining exits

    python3 scripts/ci/test_finality_profile.py
    python3 formal/release-finality-v2/run_conformance.py --out NEW_DIRECTORY
    python3 formal/release-finality-v2/check_existing_learning_owner.py
    python3 formal/release-finality-v2/verify_certificate.py \
      --committee NEW_DIRECTORY/n4/committee.json \
      --context NEW_DIRECTORY/n4/context.json --bundle NEW_DIRECTORY/n4/bundle.json

The exported keys are reproducible PUBLIC TEST FIXTURE keys, never deployments.
The separate reader shares the strict crypto primitive but imports no consensus
reference code. It is separately written by the same author, not an independent
external reviewer. Third parties receive exact grammar, positive/negative bytes,
local raw logs and scope; their actual independently executed acceptance is still
required. No native, paired, learning, physical or WAN success is inferred from it.
