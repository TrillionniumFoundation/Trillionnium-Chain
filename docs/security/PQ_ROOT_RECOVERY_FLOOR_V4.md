# Externally pinned recovery floor V4 and custody review

Status: **HOLD / RESEARCH ONLY**. Independent custody, an independently surviving
fresh currentness source, production M15/FinalUse integration and whole-chain PQ
qualification remain unverified. The actual lifetime failure bound is `null`.

This continuation adds an explicit lower-bound check to the
[native V3 root owner](PQ_ROOT_RECOVERY_NATIVE_V3.md). It preserves the existing
V3 signed encodings and SQLite namespace. A new in-memory pin uses the fresh
`TRNM/RootOwner/RecoveryFloorEnrollment/v4` domain with its terminating null byte.
It also provides a read-only inventory review for custody and recovery evidence.
Neither component creates an independent operator, device or backup.

## Native recovery lower bound

The [pin type](../../trillionnium/crates/trnm-pon-node/src/root_recovery_v3/recovery_floor.rs)
binds two values supplied by the recovery caller:

| Value | Binding |
| --- | --- |
| Complete enrollment commitment | SHA-512 over the fresh domain and the canonical complete V3 enrollment, including network, genesis, owner, initial root policy and time, writer roster and anchor roster |
| Exact minimum history head | Both retained journal version and complete 64-byte journal root |

`RecoveryFloorV4::from_external_pin` validates the input shape and constructs that
binding. The caller must already have authenticated the pin through its own
separate recovery procedure. The method does **not** authenticate a supplied
head, establish its age or prove how it was retained. In particular, a head read
from the same restored journal or the same restored anchor adds no independent
currentness evidence.

`RootOwnerV3::open_existing_with_recovery_floor` installs this immutable pin in
the opened owner. A complete-enrollment mismatch is refused before opening the
journal or calling the anchor. On every subsequent replay, the owner requires
the exact pinned head to appear in the authenticated history. A higher current
version alone does not satisfy the pin. Root signatures, state transitions,
predecessor commitments, retained state and journal-head computations are still
checked in full.

The existing signed fresh-challenge anchor check remains mandatory. The pin is
an additional lower bound; it does not replace current anchor observation,
revocation, policy generation, signed expiry, original operation budget or
cancellation checks. The new accessor `recovery_floor()` reports the configured
pin only. Presence is not an attestation.

The pin has no local-storage loader, serializer or mutable setter. A changed
floor requires a deliberate new open with a newly provisioned pin. Default V3
`create` and `open_existing` preserve their prior behavior and have no floor.
An adapter requiring V4 protection must explicitly require the protected open;
it cannot silently retry with the default V3 constructor after a refusal.

### A pending transition

A pin can name the retained pending target after an uncertain compare-and-set.
In that case the owner replays the **complete signed pending transition** against
a cloned predecessor state and verifies its exact target. Matching a stored
counter or target digest without that replay is insufficient. Opening then still
requires a fresh authenticated anchor response at the exact pending target.

This path does not commit, discard or resubmit the transition. The original
`resume_pending` operation must explicitly finish the same pending target.
An anchor still at the predecessor remains a refusal; this continuation does
not introduce the unavailable predecessor retry/discard protocol. No new CAS is
sent during completed-target reconciliation.

### What the check establishes conditionally

If the complete enrollment and floor were authenticated and retained outside the
restored state, and the signature/commitment assumptions hold, an admitted replay
must contain that exact head. It cannot stop before the supplied head or replace
its ancestry with another head at the same version. This is the scope of the
new engineering check.

The floor alone does not establish that no newer operation exists. A stale but
otherwise valid externally supplied floor can omit later revocations. The
caller still needs a sufficiently fresh, independently retained source of
currentness, an authenticated acquisition procedure, a defined age policy and
recovery failure behavior. V3 caller time remains trusted input. Restoring every
currentness source together remains outside the guarantee; this change does not
erase or reinterpret the existing boundary.

## Custody declaration and evidence review

The [review manifest](../../config/pon/pq-root-custody-review-v1.json) records one
declared snapshot of four distinct rosters: root, writer, anchor and provider.
Each complete roster contains three ML-DSA-87 and three SLH-DSA-SHA2-256s keys.
Every key declares opaque failure-domain labels for operator, device, backup and
recovery control, and references an evidence record. The public manifest must
not contain secret keys, login credentials or sensitive personal details.

The checked-in manifest deliberately has empty key inventories and no fabricated
evidence. The result lists the missing inventories, external floor and four
currentness evidence categories. It does not fill these gaps with fixture data.

The [review checker](../../scripts/ci/pq_root_custody_review_v1.py) performs the
following bounded operations:

1. Refuse unknown fields, duplicate or cross-role key identities, suite aliases,
   incorrect family sizes, empty custody-axis mappings and ambiguous JSON.
2. For each complete roster and each declared failure-domain class, compute the
   minimum number of listed domains whose combined key access reaches **two
   ML-DSA keys AND two SLH-DSA keys**. The exact set-union calculation has at most
   64 key masks. It does not multiply family probabilities or assume family
   custody independence.
3. Report a single declared domain controlling both family quorums, and any
   declared domain shared between root, writer, anchor or provider roles.
4. Check evidence references, bounded regular-file reads and exact SHA-256 file
   bytes. Symlinks, unsafe paths, absent files and changed bytes are refused.

Different opaque labels do not establish different real people or machines.
The calculation is conditional on the supplied incidence map being complete and
true. Shared administrators, passwords, backup credentials, firmware or recovery
procedures may correlate labels that the map treats separately. Correlations
between different domain classes also remain outside this finite calculation.
The manifest is not a complete lifetime key/epoch population or a native
cryptographic verification of its listed key identities.

The external-floor section distinguishes the complete enrollment/head from four
evidence references:

| Reference | Evidence still requiring independent review |
| --- | --- |
| Authenticated source | Identity and authorization of the external pin source, complete request/response binding and pin provenance |
| Independent survival | Which administrators, storage and backup/restore operations can affect that source, and why a common restore cannot rewind all sources |
| Age policy | Allowed age, trusted clock or freshness mechanism, expiry and failure behavior; a recent file modification time is insufficient |
| Recovery drill | Original operation identities, separately retained expected head, observed recovery result and all failure/Unknown outcomes |

The checker verifies referenced bytes, **not** the truth or authenticity of
those assertions. It never installs a floor, invokes a key, contacts an external
service or activates a release. Complete synthetic declarations and matching
files still return `HOLD` with independence/freshness/qualification flags false.
An externally authenticated review and actual operational evidence remain
necessary.

Run from the repository root:

```sh
python3 scripts/ci/pq_root_custody_review_v1.py --root .
python3 scripts/ci/test_pq_root_custody_review_v1.py
```

Exit zero means that the declaration grammar and any supplied local evidence
bytes are consistent. Inspect `declared_inventory_complete`,
`declared_separation_consistent` and `missing_evidence` to see the declared
coverage. Malformed or promoting declarations return `REFUSE` and exit two.
These booleans are not production or cryptographic qualification gates.

## Validation scope and unresolved obligations

The [new native test target](../../trillionnium/crates/trnm-pon-node/tests/recovery_floor_v4_native.rs)
checks exact signed ancestry across append/reopen, complete enrollment binding,
refusal of wrong or unavailable floors, signed pending-target verification,
explicit completion and preservation of fresh anchor authentication. These tests
share the existing same-process real-signature fixture; they do not claim
independent custody or a WAN recovery drill. Existing V3 test bodies and names
remain unchanged in their separate target.

The [custody review controls](../../scripts/ci/test_pq_root_custody_review_v1.py)
include an independent exhaustive reference for the small incidence calculation,
cross-role and single-domain controls, malformed evidence refusal and checks
that even complete synthetic data cannot promote qualification.

The [anchor callback controls](../../trillionnium/crates/trnm-pon-node/tests/root_budget_v4_native.rs)
also require original-budget identity, deadline and cancellation observation
after both successful and failing writer/transport callbacks. A callback's error
cannot bypass those checks. An observed external cancellation is latched before
the error is propagated, so clearing the external signal afterward cannot restore
permission. An unchanged, unexpired, uncancelled callback error remains the
original error. A signal set and cleared entirely between observations remains
outside the stated cancellation guarantee.

The new SHA-512 enrollment commitment remains part of the shared lifetime query
scope described by the [dependency register](PQ_ROOT_DEPENDENCY_REGISTER_V3.md).
It does not receive an independent resettable query budget. Actual root/writer/
anchor/provider custody, complete key generations, source authentication,
sufficient freshness, common-restore exclusion, real external effects and all
eight actual risk bounds remain open.

```text
status = HOLD
independent_custody_verified = false
anchor_independence_verified = false
freshness_source_authenticated = false
recovery_floor_installation_authorized = false
actual_lifetime_failure_bound = null
whole_chain_pq_qualified = false
production_activation = false
```
