# Native provider readback evidence V4

Status: **HOLD / RESEARCH ONLY**. This component authenticates provider
**declarations** and retains their local history. It does not execute an external
effect or grant M15 entry, installation, launch, FinalUse, payment, compensation
or redispatch authority. Actual external effects and whole-chain PQ security
remain unqualified; the lifetime failure bound is unknown.

The implementation is
[effect_readback_v4.rs](../../trillionnium/crates/trnm-pon-node/src/root_recovery_v3/effect_readback_v4.rs).
It is compiled only with the existing Linux `pq-root-v3` feature. The parent
[V3 owner](PQ_ROOT_RECOVERY_NATIVE_V3.md) keeps its existing signed formats and
SQLite schema. The V4 provider protocol and append-only evidence file have
separate, explicit namespaces. There is no implicit conversion of a V3 intent
observation into an effect capability.

## Exact readback enrollment

`RootOwnerV3::provider_readback_enrollment_v4` accepts the original semantic root
operation, a nonzero provider identity, an independently supplied full provider
roster, and the actual selected bundle, contract and artifact bytes. The caller
also supplies the expected use kind and attempt identifier. The implementation:

1. Checks the original budget before constructing or hashing material. Existing
   intent bounds apply before copying or hashing; the budget is checked again
   after construction.
2. Requires an explicitly configured recovery floor. This is a caller trust pin,
   not evidence of independent custody or freshness.
3. Replays the complete retained signed root history under that floor, refuses
   pending root transitions, and authenticates a fresh exact anchor head.
4. Selects the exact historical normal operation from the same SQLite snapshot.
   Bundle, contract, artifact digest and length, use kind and attempt must match.
5. Refuses provider keys found in the pinned writer/anchor rosters or any root
   roster in the retained initial/successor history.

The private-field `ProviderEnrollmentV4` binds the owner scope, original root
operation, immutable root initial head, that operation's committed head,
complete intent, provider identity and all six provider keys. The caller must
retain this expected enrollment separately and supply it when reopening its
evidence file. After process restart, the original operation, material and provider
pins can reconstruct this value through the authenticated retained-root path.
No constructor adopts an existing file's claimed enrollment.

This is a **historical readback identity**. It intentionally remains usable for
an operation whose original authority has since rotated or expired, so outcome
reconciliation does not require granting the old operation authority again.
The current-intent API still refuses an operation invalidated by rotation.

Every new readback requires the live root owner and repeats complete signed
replay, floor/anchor checking and provider-key separation both before and after
the callback. A later valid root rotation that imports a provider key therefore
refuses new readback. This covers the complete retained history of this bounded
owner, not the unknown population of all deployments, keys and generations over
the chain lifetime.

## Request and signed receipt

The owner generates a fresh 32-byte challenge using the OS random source. The
canonical request binds owner scope, original root operation, complete intent
and enrollment commitments, exact provider identity, fresh challenge and the
exact current orphan epoch, if one has been locally observed.

The provider signs a distinct V4 receipt containing all those binding fields,
the exact request digest, a nonzero receipt identity, an outcome and explicit
reconciliation information. Verification requires **ML-DSA-87 2-of-3 AND
SLH-DSA-SHA2-256s 2-of-3** under the separately pinned provider roster. A missing
family, changed field, wrong challenge, wrong request or invalid signature is
refused. Neither response content nor a transport callback may select new keys.

Provider outcomes are `Unknown`, `Applied`, `NotApplied` and `Compensated`.
These are declarations by that provider. A signature does not prove that a real
payment, API call or resource operation occurred, that compensation was paid,
or that the provider is independently administered.

The transport trait has one method: **readback**. It has no execute, retry,
compensate, install or FinalUse method. Its request carries no effect-entry
capability. This protocol authenticates the provider's response; it does not
implement provider-side client authentication or a network transport. The provider
roster is fixed for this enrollment; provider-key rotation, revocation, expiry and
migration are not implemented. This evidence protocol cannot substitute for the
current provider authority checks that an actual effect adapter would need.

## Persistent unknown outcomes and original operation

`ProviderEvidenceJournalV4` is a bounded, append-only local evidence file opened
through a held descriptor. Creation is exclusive, reopening requires exact
expected enrollment, and an exclusive file lease prevents a second owner.
The file and its canonical parent must have private modes `0600` and `0700`,
respectively, and belong to the current effective UID. Symlinks, hard-linked
files, persistent pathname/inode replacement, foreign formats, truncated
records and unexpected trailing bytes are refused.

The file contains complete enrollment followed by length-bounded records and a
SHA-512 record chain. There are at most 128 records, 256 KiB per record, 64 KiB
enrollment bytes and 16 MiB total file bytes. A readback reserves capacity for
its request and response before transport. These are local refusal limits;
they are not adversary query budgets or a universal resource bound.

For each lookup:

1. Revalidate the live root and replay the retained evidence.
2. Append the complete fresh request and synchronize file and parent directory
   **before** invoking the provider callback.
3. Check the original budget identity, deadline and cancellation on callback
   success and error. A callback cannot replace or replenish the original budget.
   Errors fence the current journal object.
4. Revalidate the live root again and authenticate the complete signed receipt.
5. Append and synchronize the receipt. Reopening replays records and verifies
   every retained provider signature under the original enrollment.

A missing or uncertain callback result leaves the exact read request retained
and pending. A later explicit lookup uses a fresh challenge for the **same
original operation**. It does not create or resend an effect. `Unknown` cannot
erase a previously known provider outcome. Contradictory final declarations,
such as `Applied` followed by `NotApplied`, are refused; the retained outcome
survives. A later `Compensated` declaration can follow `Applied`.

There is no implicit tail repair, adoption, history pruning, allowance reset,
or deletion on failure. A partial local write may make reopening refuse until
an independently justified recovery process is supplied. This retains
uncertainty instead of asserting a successful readback.

## Orphan responsibility

`observe_orphan_epoch` records an explicit monotonically increasing caller
observation. It does not itself verify a chain reorganization. A new epoch
requires reconciliation and invalidates any outstanding old-epoch lookup.
A normal success receipt cannot clear this requirement.

**This bounded interface refuses a further orphan notification while the prior
epoch is still unresolved.** The refusal leaves the prior record intact and
fences the current journal object. The caller must retain the later notification
outside this component and retry recording it only after reopening and explicitly
reconciling the prior epoch. The newest receipt cannot erase an older unresolved
obligation. No automatic reorganization feed or multi-epoch liability queue is
claimed. Returned evidence includes a bounded `orphan_history` map for every
retained epoch, so an older `LiabilityRetained` declaration remains visible after
a newer epoch is reconciled. The latest-epoch fields do not erase this history.

A provider may explicitly reconcile the exact requested epoch as:

| Signed outcome | Explicit reconciliation | Retained meaning |
| --- | --- | --- |
| `Applied` | `LiabilityRetained` | Provider declares the effect remains applied and liability remains |
| `NotApplied` | `NotApplied` | Provider declares the original effect was not applied |
| `Compensated` | `Compensated` | Provider declares it compensated the original effect |
| `Unknown` | None only | No resolution of the current orphan epoch |

A receipt naming an earlier, later or absent epoch cannot resolve the current
one. Even a valid signed `NotApplied` declaration grants no redispatch. A valid
signed `Compensated` declaration is not proof of actual external compensation.

## Validation and limits

The standalone native integration suite is
[root_effect_readback_v4_native.rs](../../trillionnium/crates/trnm-pon-node/tests/root_effect_readback_v4_native.rs).
It uses real native dual-family signatures and a real local evidence file, with
a same-process provider/anchor fixture. Its exact named tests cover complete
binding, both signature families, original budgets including a callback that
replaces the budget then returns an error, durable pending/Unknown outcomes,
reopen, no-authority outputs, orphan epochs and unresolved successive
notifications, conflicting declarations, historical reconciliation after
rotation, later cross-role key reuse, and private file/format/length refusals.

These tests do not prove that independently administered providers, operators,
devices, backups or recovery procedures exist. Neither an enrollment commitment
nor the evidence file's record chain establishes independently surviving
currentness. Restoring every local file, the root and all external freshness
owners together remains outside the guarantee. Held descriptors also do not
protect file contents from a malicious same-UID administrator.

There is no production network adapter, provider-side request authentication,
M15 effect sink, actual payment/API/resource evidence, verified reorganization
feed or independently executed compensation. Those integrations still require
the original effect owner, stable operation identity, exact loaded bytes,
current effect-entry authorization and end-to-end liability records. The
[dependency register](PQ_ROOT_DEPENDENCY_REGISTER_V3.md) remains a finite
inventory with unknown bounds, not a concrete security theorem.

```text
status = HOLD
provider_declaration_can_be_verified = true
actual_external_effects_verified = false
authorization_granted = false
redispatch_permitted = false
native_m15_production_integration_complete = false
whole_chain_pq_qualified = false
actual_lifetime_failure_bound = null
production_activation = false
```
