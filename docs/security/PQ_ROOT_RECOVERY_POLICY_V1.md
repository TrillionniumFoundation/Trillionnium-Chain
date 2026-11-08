# Root and recovery policy refusal model V1

Status: **research only; HOLD / NO-GO**. The
[model](../../formal/pon-nakamoto-v1/pq_root_recovery_policy_v1.py) checks a bounded
hypothetical authorization policy. It never verifies a signature, grants runtime
authority, consumes a nonce, writes a durable owner journal, changes a root, or
reconciles an external effect. Its
[tests](../../formal/pon-nakamoto-v1/test_pq_root_recovery_policy_v1.py) use
fabricated public identifiers and approval **claims**, without cryptographic
keys or signature substitutes.

This work extends the path coverage of the root-signature experiment in
[PR #796](https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/796),
whose reviewed head was
[`01e2c4c010c3cf65d1cf094368961efc1abab445`](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/01e2c4c010c3cf65d1cf094368961efc1abab445).
That experiment's complete verifier already requires two ML-DSA-87 approvals
and two SLH-DSA-SHA2-256s approvals over one complete rotation proposal. Its
separate ML-only cost observation cannot satisfy the complete verifier. The
read-only review and its 18 existing tests did not reproduce an OR bypass of
that verifier. This document records an additional lifecycle coverage
obligation; it does not mislabel an unimplemented recovery path as an exploited
production vulnerability.

## 1. All accepted root paths have the same minimum policy

The closed policy contains exactly the five paths below. Every path requires
`ML-DSA-87: 2-of-3 AND SLH-DSA-SHA2-256s: 2-of-3`. Each family has exactly three
distinct declared key identifiers. Identifier aliasing between families is
refused; this syntactic distinction does not establish separate physical
custody, operators, entropy, HSMs, software or failure domains.

| Path | Authorizing roster | Additional model requirement | Remaining actual effect obligation |
| --- | --- | --- | --- |
| `normal` | Current policy, both families | Exact action, state, epoch, sequence and nonce binding | Bind current authorization to the actual loaded or executed bytes |
| `rotate` | Current policy, both families | Complete successor policy also preserves every path's AND requirement | Verify new-key possession, installation and atomic handoff |
| `revoke` | Current policy, both families | Already revoked signers cannot contribute to the quorum | Persist revocation, invalidate live capabilities and bind actual use |
| `recover` | Current policy, both families | Complete successor policy, matching anchor and retained nonce history | Establish independently retained anti-rollback evidence and reconcile external effects |
| `policy-change` | Current policy, both families | Successor cannot weaken any normal or recovery path | Make policy replacement and its current-use owner atomic and durable |

The full current policy is checked before the selected action. A policy whose
normal path uses AND but whose recovery path uses OR is refused even when the
requested action is `normal`. The same check applies to every proposed successor
policy. There is no fallback field or unknown-operation extension point.
One-family recovery, a weaker parameter set, an unknown family, a 1-of-3 quorum,
a duplicate signer, a cross-family key, or a signer from only the proposed new
roster cannot satisfy this model.

The model deliberately represents an **authorizing** epoch and expected
sequence. It does not define or execute the resulting state's transition, the
identity being revoked, key destruction, or a live migration protocol. A
complete successor policy is required for rotation, recovery and policy change;
normal and revoke carry no successor policy in this V1 grammar. Effects outside
that grammar need an explicitly versioned follow-up protocol and tests.

Requiring both families has an availability consequence: losing either required
quorum makes the operation unavailable. An emergency OR switch would change the
security policy and must not be introduced implicitly to restore availability.

## 2. Message binding and operation identity

[NIST's PQC FAQ](https://csrc.nist.gov/projects/post-quantum-cryptography/faqs)
describes dual signatures as two signatures on the same message, with all
components required to verify. The actual complete verifier must implement that
rule. This policy model checks only that all four declared approval rows name
the same canonical statement digest and keys in the current rosters.
`signatures_verified` remains `false` even when all those rows are well formed.

The fresh namespaces are:

| Purpose | Domain |
| --- | --- |
| Complete policy identity | `TRNM/RootRecoveryResearchPolicy/v1\0` |
| Canonical complete statement | `TRNM/RootRecoveryResearchStatement/v1\0` |
| Semantic operation identity | `TRNM/RootRecoveryResearchOperation/v1\0` |

The statement contains the schema, action, network, genesis, current owner
generation, current key epoch, previous state, current policy identity, expected
sequence, nonce, validity window, complete payload bytes, and the complete
successor policy where applicable. The V1 reference serialization is sorted,
compact ASCII JSON with all u64 values represented as canonical decimal
strings. Unknown or duplicate JSON fields, invalid UTF-8, nonfinite/fractional
JSON numbers, oversized input and excessive nesting are refused. Exact fixture
commitments in the tests pin the encoding and fresh domains.

The policy digest is SHA-512 over its domain, an eight-byte big-endian byte
length and the complete canonical policy. The statement digest is SHA-512 over
the complete domain-prefixed statement. The operation identity is SHA-512 over
its distinct domain, the eight-byte statement length and the complete
statement. The payload itself is present in the statement. These are research
identities; hashing an identifier or legacy digest does not demonstrate a
complete application dependency commitment.

Neither signature bytes nor the selected two witnesses from a three-key roster
appear in the operation identity. All nine valid pairs of 2-of-3 choices therefore
name the same operation when the intent is unchanged. Reordering approval rows
also leaves it unchanged. Changing an action, nonce, epoch, payload or successor
policy changes both its statement and operation identities.

This distinction matters even if signatures are mathematically valid. A
randomized signer can produce multiple valid signatures for one message, and
composite signatures can admit recombinations after repeated signing. See
[RFC 10073, Section 9.2.2](https://www.rfc-editor.org/rfc/rfc10073.html#section-9.2.2).
A signature hash must not become the one-use operation key. The model separately
rejects reuse of a retained nonce, including reuse with a changed intent and
therefore a different operation digest. Epoch advancement or choosing `recover`
does not erase supplied history.

These checks are observations over the supplied history. This process neither
persists that history nor proves it complete. Its bound of 128 retained rows is
a refusal limit for a scenario, not a safe pruning rule or a lifetime limit.

## 3. Currentness, independent custody and recovery evidence

The statement's network, genesis, owner generation, key epoch, previous state,
current policy identity and next sequence must match the separately supplied
scenario context. Current height must fall within the signed interval. The
scenario anchor must match that context's network, genesis, generation, epoch,
previous state, current policy identity and last sequence. Stale or mismatching
anchors are refused before declared approvals can satisfy the model.

The context remains a hypothetical input. A production owner would have to
obtain its expected values independently of the request, detect concurrent
changes at use time, and atomically record the irreversible boundary. It cannot
use an attacker-selected JSON context as the trusted expected state.

Each of four scenario observations is explicitly `unknown` or
`scenario-assumed`:

- Current authority.
- Independent custody.
- An independently retained anti-rollback anchor.
- External-effect reconciliation.

An unknown observation produces `HOLD_UNRESOLVED_SCENARIO`. Marking every value
`scenario-assumed` produces only `SCENARIO_CONSTRAINTS_SATISFIED`; the overall
`status` remains `HOLD`. Values such as `verified`, `attested` or `true` are
refused as unsupported evidence claims. Neither different key IDs nor different
family names attest independent custody.

Every result from `inspect` preserves these false fields:

| Field | Meaning of `false` |
| --- | --- |
| `authorization_granted` | This diagnostic is not a capability or approval |
| `root_effect_executed` / `activation_performed` | No root or deployment effect occurred |
| `production_qualified` | No production or whole-chain security qualification |
| `signatures_verified` | No mathematical signature check took place |
| `custody_verified` / `currentness_verified` | No actual custody or current-authority evidence was established |
| `anchor_independence_verified` | The declared anchor's location, failure domain and retention were not verified |
| `external_effects_reconciled` | No real external operation journal was compared |
| `history_persisted` | No replay, revocation or one-use record was saved |

Recovery must reconcile the actual effect state before resuming use. It needs a
rollback domain independent of the state being restored, and durable operation
and revocation history which does not rewind with a chain reorganization. Two
files restored from one snapshot, or two keys controlled by one compromised
owner, cannot establish that independence merely by having different labels.
This model exposes those obligations; it does not implement their evidence
collection, persistence, availability or trust bootstrap.

## 4. Algorithm categories and composition remain separate obligations

[FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) assigns ML-DSA-65 to category
3 and ML-DSA-87 to category 5. [FIPS 205](https://csrc.nist.gov/pubs/fips/205/final)
standardizes SLH-DSA. Those algorithm classifications cannot be rewritten as a
whole-chain quantum security bit count. Two families also do not multiply their
concrete failure probabilities without additional, justified independence and
composition hypotheses.

For one fixed experiment and properly bound acceptance events, requiring both
means the forgery event is contained in the intersection of the applicable
component break events; a bound by the smaller applicable component bound may
be available. Multiplying bounds is a different claim. Accepting either family
on an alternate recovery path instead introduces a union of acceptable break
paths. Shared dependencies, currentness failures, custody compromise and effect
replay require their own terms and mappings.

The [lifetime budget contract](PQ128_LIFETIME_BUDGET_V1.md) remains the place to
state lifetime, users, messages, adversary resources, shared primitives and
applicable reductions. This new module supplies no cryptographic probability,
no QROM theorem, no custody attestation and no whole-chain bound.

## 5. Reproduce the bounded model and its counterexamples

Run from the repository root:

```sh
python -m unittest discover -s formal/pon-nakamoto-v1 -p test_pq_root_recovery_policy_v1.py -v
python formal/pon-nakamoto-v1/pq_root_recovery_policy_v1.py --example
```

The suite contains 26 tests, including 45 combinations of five paths and nine
witness pairs; recovery-only OR, lower thresholds, missing/unknown families,
duplicate/cross-family/revoked signers, cross-statement claims, stale expected
state, stale anchors, successor downgrades, new-roster self-authorization,
replay, changed-intent nonce reuse, epoch changes with retained history,
self-reported evidence and parser bounds.

The example emits a structurally consistent `recover` scenario with all four
real-world observations unknown. It must report `status: HOLD`,
`model_decision: HOLD_UNRESOLVED_SCENARIO` and
`authorization_granted: false`. A zero CLI exit status means only that the
hypothetical structure passed. It must never be used as a release or activation
gate. `--input PATH` inspects a bounded JSON scenario without modifying it.

These controls reproduce policy counterexamples to a weakened model. They are
not forged native signatures or evidence that the original fixed AND verifier
accepted such a path. Native verification, complete runtime entrypoint
coverage, independent custodians, trusted currentness, durable external anchors,
and external-effect reconciliation remain explicit unresolved obligations.
