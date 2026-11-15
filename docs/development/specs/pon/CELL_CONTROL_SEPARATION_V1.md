# Cell control-separation material review V1

This is an additional read-only input review for the existing learning campaign.
It does not replace the native Hepta trust owner, authenticate a source document,
establish organizational independence, admit a model, settle a task, or issue
FinalUse. A complete material review keeps all those acceptance flags false.

The [reader](../../../../formal/release-finality-v2/control_separation.py)
checks externally pinned source, campaign, policy and original-owner bindings;
joins known common control transitively; and retains conflicts and unresolved
materials separately. It reports actual sharing present in the supplied material
even outside the policy's mandatory separation pairs. A different key, process,
node, host or IP does not create a separate controller.

## Existing native authority remains authoritative

In the paired Hepta source
[`ed19100d2fceea6447cead52e97484bb08063854`](https://github.com/TrillionniumFoundation/hepta-private-ci/blob/ed19100d2fceea6447cead52e97484bb08063854/codex-rs/hepta-learning-ledger/src/signed_evidence.rs),
`TrustedLearningSignerV1.controller_id` is a `StableId`, included in the original
trust digest. `verify_signed_actor_separation` still owns native actor separation.
This reader does not issue or verify a replacement native attestation.

`controller_id` carries that original `StableId::as_str()` unchanged. Its
[stable-v1 grammar](https://github.com/TrillionniumFoundation/hepta-private-ci/blob/ed19100d2fceea6447cead52e97484bb08063854/codex-rs/hepta-types/src/identity.rs)
is 1-128 ASCII bytes drawn from letters, digits, `.`, `_`, `-`, and `:`. It is
not reinterpreted as `Digest32`, case-folded, normalized or hashed separately
for each signing key. Host-owned mappings remain necessary: similar labels do
not establish shared real-world identity, and different labels do not establish
independence. Known aliases across owner domains need explicit control links.

Every role binding contains exactly:

| Field | Meaning |
| --- | --- |
| `role` | One of the seven roles below. |
| `signer` | Original owner-checked signing-key digest, lowercase 64-hex. |
| `controller_id` | Original stable controller identity, preserved byte for byte. |
| `owner_digest` | Independently retained digest of the relevant original owner observation or trust snapshot. |

The caller must first run the existing native signature, role, epoch, revocation
and actor-separation checks. It then supplies its own `expected_bindings` from
those readbacks. The submitted manifest must match those rows exactly; it cannot
rename a controller or substitute its own owner digest. Publisher, storage and
release-key custody require their own original owner bindings. They are not
silently treated as roles already covered by the Hepta learning signer schema.

## Public interface and independent inputs

```python
report = review_control_separation(
    manifest_raw, policy_raw,
    expected_manifest=retained_manifest_pin,
    expected_policy=current_policy_pin,
    expected_campaign=campaign_owner.campaign,
    expected_pair=campaign_owner.source_pair,
    expected_revision=campaign_owner.policy_revision,
    expected_bindings=original_owner_readbacks,
    now=current_owner_time,
)
```

`expected_pair` has exactly `chain_source`, `chain_tree`, `hepta_source`, and
`hepta_tree`, each a full lowercase 40-hex git identity. Both policy and manifest
bind that pair and the same campaign. The current revision and time come from
the caller, not from candidate fields. The current owner must recheck these
inputs when they are used; a retained review cannot freeze subsequent revocation.

The byte inputs use the existing strict canonical ASCII JSON decoder. Duplicate
keys, additional fields, noncanonical encodings, floats or booleans in integer
fields, malformed identities and oversized inputs are refused. Each wire input
is limited to 1 MiB, role bindings and control vertices to 128, reviewers to 32,
and each relation/review list to 1,024. Existing canonical-output limits also
apply. Collections have explicit sorted, duplicate-free order.

`policy_digest` and `manifest_digest` use separate V1 hash domains. They are
publication helpers. Computing an expected pin from the candidate bytes in the
same acceptance call would remove the independent input boundary and is not a
valid integration. All malformed or misbound inputs raise `protocol.Refusal`,
a `ValueError` subclass. Valid incomplete materials produce an unresolved report.

## Frozen policy

The policy schema is `trnm-cell-control-separation-policy-v1`, with exactly
`schema`, `pair`, `campaign`, `revision`, `valid_from`, `valid_until`,
`maximum_evidence_age_seconds`, `minimum_role_components`,
`required_separations`, `minimum_reviewer_components`, and `reviewers`.
The current time must lie in the half-open policy validity interval.

`minimum_role_components` must cover all seven roles: `task_publisher`,
`trainer`, `evaluator`, `version_selector`, `storage`,
`release_key_custodian`, and `consumer`. Every minimum is positive. More than
one requested component additionally requires that role's self-separation pair.
These counts are bounds in the supplied control graph, never measured numbers
of independent operators.

V1 fixes the following minimum required pairs. The pinned policy may strengthen
them; it cannot omit any of them, even with a newly computed policy digest.

| Mandatory pair | Material question |
| --- | --- |
| Trainer / evaluator | Can the training controller also control the evaluation? |
| Task publisher / evaluator | Can task publication control its own evaluation? |
| Trainer / version selector | Can the producer select itself? |
| Evaluator / version selector | Is the acceptance choice independently controlled? |
| Trainer / consumer | Is the next-task consumer also the training controller? |
| Version selector / consumer | Can the selector generate its own consumer observation? |
| Trainer / release-key custodian | Does the trainer control the publication authority? |
| Storage / storage | Are the declared replicas under common control? |

Storage therefore needs at least two controller identities with pair-review
materials; duplicate keys from one controller cannot satisfy it. Roles beyond
these mandatory pairs can still share control, and such sharing is always
reported. This is not a statement that the seven roles are fully independent.

Each `reviewers` row is exactly `{authority, controller_id}`. `authority` is
the original reviewer signing-key digest in the **same namespace** as
`bindings[].signer`; it is not an arbitrary document-author label. The original
owner must supply and verify that mapping. A key appearing in both collections
must have the identical original controller ID; a re-pinned policy cannot grant
that same key another controller identity. A consistent same-key/same-controller
entry still cannot review its own role's separation.

`minimum_reviewer_components` counts distinct known controller components of
usable reviewers, not keys or documents. A reviewer controlled by either side
of a required pair is excluded. Two reviewer keys with the same controller count
once. These are checks of the pinned reviewer mapping, not authentication of
the reviewers or proof that their control mapping is complete.

## Manifest and domain-bound evidence references

The manifest schema is `trnm-cell-control-separation-manifest-v1`, with exactly
`schema`, `pair`, `campaign`, `policy`, `revision`, `valid_from`, `valid_until`,
`bindings`, `inventories`, `common_control`, and `separation_reviews`. Its
validity interval must fit inside the policy interval and contain the trusted
current time. `policy` is the independent domain-separated policy digest.

| Collection | Exact row fields and purpose |
| --- | --- |
| `bindings` | Original-owner `{role, signer, controller_id, owner_digest}` rows; sorted by role and signer. |
| `inventories` | `{controller_id, administrators, key_custodians, evidence}`. Every referenced controller, including reviewers and intermediary controllers, needs an inventory. |
| `common_control` | `{controllers, kind, evidence}`. A sorted two-controller pair; `kind` is `same_operator`, `shared_administrator`, `shared_release_custody`, or `declared_control`. |
| `separation_reviews` | `{controllers, evidence}` for a sorted two-controller pair and a policy-listed reviewer. Duplicate pair/reviewer rows are refused. |

Administrator and key-custodian lists contain original stable control IDs.
The graph joins a controller to those actual-control principals, and also joins
all explicit common-control edges. A common administrator discovered through
an intermediate controller therefore connects the endpoints. The same person
listed once as administrator and once as custodian still joins the same graph.
Shared network addresses or unrelated hosting suppliers are not control edges.

Every `evidence` object has exactly `domain`, `authority`, `document_sha256`,
`statement_sha256`, `observed_at`, and `valid_until`. The three domains are:

- `trnm.cell.control-inventory.v1`;
- `trnm.cell.common-control.v1`;
- `trnm.cell.separation-review.v1`.

`statement_sha256` is computed by `evidence_statement_digest` over the selected
evidence domain, campaign, policy digest, revision, and the exact row excluding
`evidence`. An inventory reference cannot be reused as a separation statement;
changing a controller pair, campaign or policy requires a different statement.
The policy-listed authority, validity interval and maximum evidence age are
checked. Evidence expiry is exclusive; future or stale observations are refused.

`document_sha256` is only a retained content reference. This reader does not
fetch documents, verify their signatures, establish their scientific truth or
assert that an inventory contains every hidden control relationship. Original
owners and an external review must supply and authenticate those facts. No
`independent: true` or `complete: true` field can create that authority.

## Reports and remaining acceptance

The report schema is `trnm-cell-control-separation-review-v1`. It retains the
source pair, campaign, exact pins, revision, time and original-binding digest,
plus every conflict, unresolved item, role observation, known control component,
mandatory pair review, and role overlap. Its own ID uses a fresh report domain.

| `status` | Meaning |
| --- | --- |
| `CONFLICT` | Known common control violates a required separation or role minimum. Other missing materials remain in `unresolved`. |
| `UNRESOLVED` | A role, controller inventory, replica, or sufficient usable pair review is absent. Distinct names cannot repair this state. |
| `MATERIAL_REVIEW_COMPLETE` | The pinned materials satisfy this frozen review policy. No claim about actual independence, model use or production follows. |

Every result retains `source_documents_authenticated`, `hidden_control_excluded`,
`independent_control_accepted`, `physical_installation_accepted`,
`hepta_final_use`, and `production_activation` as false. Known component counts
are only upper bounds conditional on the original mappings and retained facts.
Unknown common-control links can reduce them.

This check composes with the existing signed NoUpdate/parent-chain verifier.
The composition binds the source pair and campaign, but does not yet associate
the signed V3 learning actors with the additional role-control materials.
`review_learning_control_material` therefore retains
`learning_actor_control_binding_verified=false` and lists the original
learning actor-to-control binding as missing. The integration fixture deliberately
uses independent synthetic control identities; passing it does not establish
that its role controllers are the participants in the signed learning records.
It does not change legitimate NoUpdate, native CURRENT, settlement, protected
installation, or the next task's model selection. The ordinary handoff remains
subject to its [original owner boundary](CELL_ORDINARY_HOST_HANDOFF_V2.md).

## Executed controls

Run from `formal/release-finality-v2`:

```sh
python3 -B -m unittest -v test_control_separation.py
```

The test-only `fixture()` returns `(manifest, policy, trusted_kwargs)` for
integration tests. Its documents and owner identities are synthetic and carry
no external authority. Controls exercise same-controller key rotation, original
owner substitution, transitive and cross-role common control, shared replica
custody, self-controlled reviewers, duplicated reviewer keys, missing roles and
inventories, omitted minimum pairs, stale and misbound material, StableId
preservation, cross-collection signing-key/controller contradictions, canonical
encodings and the false authority flags.
