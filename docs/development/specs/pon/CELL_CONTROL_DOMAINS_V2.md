# Cell administration, failure, funding and custody material review V2

The [four-domain reader](../../../../formal/release-finality-v2/control_domains.py)
extends the existing [seven-role material review](CELL_CONTROL_SEPARATION_V1.md).
It reads actual canonical source-document bytes, retains the original role and
signer bindings, and checks the same parties across four dependency domains.
It does not appoint operators, authenticate documentary facts, grant native
authority, or establish deployed independence. All acceptance flags remain false.

## Why an additional gate is necessary

The V1 inventory describes administrators and key custodians. It cannot express
a pair of separately named storage operators financed by one controlling party,
or replicas lost by the same declared failure event. A reviewer funded by an
audited party can also survive the V1 material check when the funding relation is
absent from its schema. V2 makes those supplied dependencies visible. A complete
V1 review remains byte-for-byte unchanged and is embedded in the V2 result.

The existing WAN V4 maximum-matching audit in
[PR #742](https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/742)
continues to own its frozen WAN roster, sampling window and repair subsets. This
reader does not replace it or add separate marginal counts to invent a joint
independent-operator count. V2 checks each mandatory role pair on the very same
controller IDs and always reports `joint_independent_operator_count: null`.

## Trust inputs and interface

```python
report = review_control_domains(
    original_control_manifest_bytes,
    original_control_policy_bytes,
    domain_manifest_bytes,
    actual_document_bytes_by_sha256,
    expected_domains=independently_retained_domain_manifest_pin,
    **original_owner_control_trusted,
)
```

`original_owner_control_trusted` is the unchanged V1 keyword input: independent
manifest and policy pins, current policy revision, campaign, source pair, current
time and original owner-checked role/signer/controller bindings. The V1 verifier
runs inside this call. A supplied V1 report cannot be substituted for execution.
The expected V2 pin must be retained by that owner before inspecting a candidate;
hashing candidate bytes into the expected input would destroy this boundary.

The additional `review_learning_control_domains` entry in
[campaign_gate.py](../../../../formal/release-finality-v2/campaign_gate.py) calls
the unchanged signed V3 parent/NoUpdate verifier before this material review.
It retains `learning_actor_control_binding_verified=false`: matching campaign and
source IDs do not yet bind the additional controller inventory to the original
learning actors. The native owner still owns that association and current use.

## Exact V2 wire contracts

The manifest schema is `trnm-cell-control-domains-manifest-v2`. Its exact fields
are `schema`, `pair`, `campaign`, `control_manifest`, `control_policy`, `revision`,
`valid_from`, `valid_until`, and `inventories`. Source pair, campaign, revision and
both V1 pins must equal the current V1 owner inputs. The validity interval must
fit inside the original manifest interval and contain the current owner time.
V2 uses a fresh `TRNM-CELL-CONTROL-DOMAINS-MANIFEST-V2\0` SHA-256 domain.

Every inventory row has exactly these fields:

| Field | Requirement |
| --- | --- |
| `controller_id` | Original stable identity present in the V1 graph, including reviewers and intermediary controllers. |
| `domains` | Exactly `administration`, `failure`, `funding`, and `key_custody`, each a sorted, duplicate-free list of stable domain IDs. |
| `document_sha256` | SHA-256 of the complete supplied canonical statement bytes. |
| `observed_at` | Integer observation time within the original policy window, no later than current time and no older than the original maximum evidence age. |
| `valid_until` | Exclusive expiry, later than current time and no later than the V2 manifest expiry. |

Domain IDs preserve the original reviewer's stable namespace. Re-labelling a
principal by node, key, process, IP, role or axis does not create independence.
`funding` denotes parties with funding control, not every incidental customer or
unrelated payment processor. `failure` denotes declared common failure
dependencies; sharing a region label is not, by itself, proof of common
administrative control. A genuinely self-funded operator still needs a recorded
funding-control identity. An empty list means **unknown**, never no dependency.
Facts about alias equivalence and complete dependency closure remain external.

Each actual document is canonical ASCII JSON with exactly the body returned by
`document_statement`: schema `trnm-cell-control-domains-document-v2`, source pair,
campaign, both original pins, revision, and the exact inventory row excluding
`document_sha256`. Thus a correctly hashed document for another controller,
snapshot, domain assignment or time interval cannot support the submitted row.
The reader checks actual bytes, not only a declared digest. This equality does
not verify a signature or make the document's real-world assertions true.

Input bounds are 1 MiB per manifest, 128 controller inventories, 32 domain IDs per
axis per controller, 128 supplied documents, 64 KiB per document and 8 MiB for
all document bytes. The complete byte population is bounded before document
parsing or hashing. Duplicate fields, extra fields, noncanonical JSON, boolean
integer aliases, floats, unsorted/duplicate identities and unreferenced supplied
documents are refused. A missing referenced document produces an unresolved
finding; it is not silently removed from the required-document denominator.

## Dependency and reviewer joins

The authority graph begins with every original V1 component. Administration,
funding control and key custody share a principal namespace. A common identity
across any of those axes joins the affected controllers transitively. If a domain
ID is itself an original controller ID, that controller joins too. Known adverse
declarations remain restrictive even when their supporting document is missing;
withholding a document cannot delete an already pinned conflict.

For every mandatory role pair, V2 checks both the resulting common authority
component and the intersection of declared failure dependencies. A failure-domain
collision is reported separately and does not manufacture an authority edge.
Storage minimums and pair checks therefore refer to the same original replica
controllers, not a count of distinct keys or disconnected per-axis populations.

V1's usable reviewers are reconsidered after this join. A reviewer in either
party's resulting authority component is excluded. A missing reviewer inventory,
missing source document, or unknown administration/funding/custody axis also
prevents that reviewer from satisfying the threshold. Reviewer keys in a shared
authority component count once. Existing V1 exclusions cannot be undone by V2.

## Report and qualification

The report is `trnm-cell-control-domains-review-v2`, with a distinct report hash
domain. It retains the entire original V1 result, current pins/source/time,
conflicts, unresolved findings, same-party pair observations, authority components,
role domain inventories and the exact checked-document byte count/digests.

`CONFLICT` takes precedence when either layer has a known required separation
violation. Otherwise any missing inventory, unknown axis, missing document or
insufficient reviewer evidence yields `UNRESOLVED`. `MATERIAL_REVIEW_COMPLETE`
only means these pinned inputs satisfy the frozen material policy. Component
counts are conditional upper bounds; undisclosed links can lower them.

Every outcome keeps `source_documents_authenticated`, `hidden_control_excluded`,
`independent_control_accepted`, `physical_installation_accepted`, `hepta_final_use`
and `production_activation` false. No actual independent administrator, funding
controller, fault domain or key custodian was created by running these tests.
The original real WAN, funded retention/payment, current-revocation and native
consumer obligations remain open.

## Regression entry

```sh
python3 -B formal/release-finality-v2/test_control_domains.py -v
```

The existing full reference conformance runner discovers this `test_*.py` file
automatically. Tests use explicitly synthetic parties/documents and real existing
V3 signature verification. They exercise shared domains, transitive cross-axis
authority, funded reviewers, same-actor storage comparisons, missing documents,
document substitution, current-time and original-pin failures, input bounds, and
preservation of NoUpdate and all false acceptance flags.
