# Declared common control and signer availability V2

Status: **HOLD / RESEARCH ONLY**. This is a bounded, read-only declaration and
local-file consistency review. It cannot authenticate independent operators,
backups, network or power suppliers, recovery procedures, fresh external state
or deployment qualification. All verification and activation claims remain
false, and the actual lifetime failure bound remains `null`.

The [V2 checker](../../scripts/ci/pq_root_custody_review_v2.py) extends the
[V1 custody review](PQ_ROOT_RECOVERY_FLOOR_V4.md) without changing V1's schema,
root signatures, journal, recovery-floor API or effect permissions. Its fresh
`trnm-pq-root-custody-review-v2` declaration namespace embeds a complete V1
manifest under `custody_v1`. Existing V1 consumers do not silently gain V2
coverage. The [default V2 manifest](../../config/pon/pq-root-custody-review-v2.json)
contains no invented operators, keys, evidence, common-control review or floor.

## Separate key access from service loss

The fixed signature policy requires two of three ML-DSA-87 keys **AND** two of
three SLH-DSA-SHA2-256s keys for each of root, writer, anchor and provider roles.
The declaration model distinguishes these two events:

| Event | Finite incidence predicate | Domain axes used |
| --- | --- | --- |
| Listed control reaches both quorums | At least two listed keys in each signature family are accessible | operator, device, backup, recovery |
| Listed failure prevents a quorum | At least two keys in either signature family are unavailable | all four control axes plus network and power |

For the second event, a declared key controller is assumed able to withhold that
key's signature. Network and power declarations only remove availability. Even a
shared network or power factor reaching every key contributes **zero** key access.
Signature/key verification, actual network delivery and real power continuity
are not simulated by these calculations. Keys can have multiple declared domains;
any one of those domains is a listed cause affecting the corresponding key.

`availability_domains` adds exactly one mapping for every listed key identity,
with nonempty `network` and `power` domain lists and custody-observation evidence
references. Missing mappings or missing evidence remain explicit missing items;
a role with incomplete availability mappings has null availability minima.
Unknown keys, duplicate mappings, empty axes and wrong-kind evidence are refused.
All six axes are checked for directly shared domains across roles.

## Explicit cross-axis common causes

Separate per-axis labels can conceal one administrator who controls an operator
credential and several backup/recovery credentials. `common_control_review`
therefore records whether a correlation review was supplied and an explicit
bounded list of groups. Each group is one declared common cause referencing two
to 32 existing `(axis, domain)` pairs and local evidence references. At most 128
groups are accepted. Unknown axes/domains, duplicate members/group identities
and oversized lists are refused. `coverage=unprovided` cannot carry evidence or
groups; `coverage=declared` is only a supplier assertion of review coverage.

Every individual domain and group is a listed factor. A group reaches precisely
the union of the keys reached by its named domains. Its key-control projection
uses only the four control axes; its availability projection can use all six.
Groups project directly. Two groups naming one common domain do not establish an
unstated transitive control relationship over their other members.

The checker calculates exact minima over subsets of those listed factors using
at most 64 key masks per role. It reports single factors reaching both key
quorums, single factors blocking either family quorum, and groups spanning roles.
Tests compare the algorithm with an independent exhaustive subset enumeration.
The reported minima are **minima over listed factors only**, not certified lower
bounds on real compromise cost, independent failure probabilities or the number
of actual independent operators. Omitted causes could reduce the real minimum.

Even complete declarations with distinct labels and matching evidence bytes do
not prove that the map is complete or true. Names, keys, processes, directories,
cloud accounts and signed statements do not authenticate independent management,
backup administration, network, power or recovery. Common suppliers and hidden
credentials require external review and actual operational evidence.

## Recovery and qualification boundary

The embedded V1 floor retains all four required categories: authenticated pin
provenance, independent survival, age policy and recovery drill. V2 neither
constructs nor installs a recovery floor, contacts an anchor, dispatches an
effect, signs a message or grants FinalUse. A stale but valid pin cannot prove
that a later revocation does not exist. The original common owner-plus-all-anchor
restore boundary remains open until sufficiently fresh authenticated state is
shown to survive that common restore outside its failure domain.

All local evidence is read through the existing bounded regular-file reader,
with exact SHA-256 comparison and a 16 MiB aggregate ceiling. Matching bytes do
not authenticate the content of assertions. Paths with symlinks, missing or
changed evidence, ambiguous JSON and any attempted qualification promotion are
refused. Inspection leaves supplied files unchanged.

Run from the repository root:

```sh
python3 scripts/ci/pq_root_custody_review_v2.py --root .
python3 scripts/ci/test_pq_root_custody_review_v2.py
```

Exit zero means declared grammar and supplied local bytes are consistent.
Missing items are reported in `missing_evidence`; `declared_separation_consistent`
requires complete declarations with no listed single-factor quorum failure or
cross-role sharing. Neither boolean qualifies the deployment. Every successful
report remains `HOLD`, including complete synthetic declarations, with all of:

```text
evidence_authenticity_verified = false
availability_independence_verified = false
cross_axis_control_coverage_verified = false
independent_operational_qualification = false
independent_common_restore_exclusion_proved = false
recovery_floor_installation_authorized = false
actual_lifetime_failure_bound = null
whole_chain_pq_qualified = false
production_activation = false
```
