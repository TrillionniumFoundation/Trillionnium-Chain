# Five-dimensional decentralization audit v1

Status: source audit and bounded declared-control accounting. Independently
administered deployment, permissionless utility, PN5 and production acceptance
remain unqualified. This work continues PN3–PN6 in the
[sole development plan](../../../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md)
and uses the existing M09/M11/M12/M15/M17 owners. It adds no consensus vote,
release key, deployment authority or alternative monetary ledger.

The baseline source reviewed here is the existing #688 candidate
`513e92dfc27044ef3e0c9d62e7ae504fa5bea38f`. The
[source inventory](../../../../evidence/pon-decentralization-20261106/source-inventory.json)
records the full source commit and exact reviewed file hashes. That inventory
does not claim that this candidate has run an independent network. New
implementation and test identities belong to the
[execution record](../../../../evidence/pon-decentralization-20261106/README.md).

## Five separate questions

Decentralization is a vector of independently assessed properties. An increase
in node, IP address, key, replica advertisement or witness count does not answer
any of the following questions by itself.

| Dimension | Current source capability | Evidence still required |
| --- | --- | --- |
| Work production | Native complete-work verification, parent/task binding, target and cumulative-work selection; explicit development mining and task profiles. The operator-actor profile adds no global source allowlist. | Whether new producers can actually obtain admissible material, reach the service, compete under the same rules and complete honest work under the original hostile-load budgets; measured concentration of valid work and its controlling operators. |
| Data distribution | Content and complete-release identities, configured peers, bounded signed discovery hints, physical retention, repair and complete byte verification. | Complete usable replicas across genuinely independent administration and failure domains; authenticated retrieval after publisher/provider loss; repair, renewal and funding within frozen limits. |
| Evaluation | Frozen development rosters, exact signatures, author-key exclusion, native replay in selected model profiles, real commit/reveal aggregation and conflict handling. | Independent evaluators and data custody, declared and hidden common control, author/evaluator conflicts, governance of admission and replacement, prospective evaluation and dispute acceptance. |
| Release roots and upgrades | Pinned PQ roots, separate key roles, exact threshold verification, old/new root rotation, version monotonicity and retired-key rejection. | Actual custody and control of every approving, blocking, replacing and recovery authority; independent root/role holders, operational separation and reviewed recovery of deployed consumers. |
| Funding and hardware | Bounded native escrow/resource accounting and scoped component cost observations. | A complete, time-bounded population of funding and productive capacity, beneficial/control attribution, unknown shares, common infrastructure dependencies and authenticated resource observations. |

A successful local reader can establish that supplied declarations satisfy
stated arithmetic rules. It cannot establish that an administrator declaration
is true, that a key is held exclusively, that a data copy is physically
independent, or that a reported observation occurred. There is no aggregate
score that can compensate for a missing dimension.

## Source audit: profiles and actual authority

### Work production and access

The native [Node owner](../../../../trillionnium/crates/trnm-pon-node/src/store.rs)
rechecks packet context, current parent/task eligibility, exact input material,
complete work and deterministic execution before admitting a block. Selected
local owner policies and original resource limits remain applicable. The
[operator-actor contract](OPERATOR_ACTORS_V1.md) distinguishes explicit role and
bootstrap custody from its existing funded-requester/source lifecycle; it does
not add a global source allowlist or certify truthful demand.

Keep four questions distinct: the mathematical admissibility of work from a
producer, access to its input material and task authorization, network service
under load, and competitive cost. Protocol-level producer neutrality cannot
establish that the cheapest effective work is widely accessible. Conversely,
an operator registry used for evidence must never become an unreviewed miner
allowlist or supply work weight. Count actual accepted valid work with its
original denominator and interval, not endpoints or advertised GPU capacity.

### Evaluation keys and controllers

The current [development configuration](../../../../config/pon/devnet-v1.json)
contains `evaluation_signers = 3`, `evaluation_threshold = 2` and
`explicit-attested-dev-profile-not-permissionless-utility`. These are development
rules and do not prove three independent administrators or open utility admission.

The explicitly selected
[native quorum V2](NATIVE_EVALUATION_QUORUM_V2.md) is a different profile. Its
[registry](../../../../config/pon/public-evaluation-quorum-v2.json) describes four
controlled development keys. A candidate freezes the non-author roster and a
threshold `ceil(2*n/3)`; with three non-author keys, two matching real reveals
can close the candidate. Full native model checks remain required in the
supported profiles. Neither a smaller absence-tolerant quorum nor native replay
establishes independence, prospective model quality or Byzantine finality.

The actual [evaluation owner](../../../../trillionnium/crates/trnm-mvcc-fee/src/public_evaluation.rs)
and [quorum implementation](../../../../trillionnium/crates/trnm-mvcc-fee/src/public_evaluation/quorum_v2.rs)
operate on cryptographic identities. Excluding an author's exact key is not a
test for the author's other keys or entities under common control. An evidence
audit must therefore report author/control-group intersections as well as
literal key overlap. It cannot alter the frozen consensus roster, shrink its
denominator or relabel missing votes as approved evaluations.

### Data distribution and physical domains

The existing [Cell peer contract](CELL_P2P_V1.md),
[provider-discovery contract](../../../development/specs/pon/CELL_PROVIDER_DISCOVERY_DEV_V1.md)
and [retention owner](../../../development/specs/pon/CELL_RETENTION_V1.md) distinguish
verified bytes from custody, future service and execution permission. A signed
provider record is a bounded location hint. A physical readback proves scoped
possession of the requested bytes at that observation; it does not prove the
provider is independent of the publisher or other providers.

Evaluate replicas for the full pinned release and dependency closure. Three
sets of partial chunks, three advertisements for one file, or three paths into
one physical backing store are not three independent complete replicas.
Publisher-loss and forbidden-origin tests must include the publisher's known
control aliases; changing a provider ID must not evade the exclusion.

Administrative control and infrastructure dependency are separate relations.
Different tenants of the same cloud provider are not automatically one
administrator, but they retain a shared provider risk. Different regions do not
prove different cloud-account custody; separate cloud providers do not prove
different administrators. Report known shared provider, account, host and failure
dependencies separately and retain unknown facts. A JSON control map cannot
replace physical retrieval and failure experiments.

### Release, upgrades and recovery

The [PQ release kernel](../../../../trillionnium/crates/trnm-release-bundle/src/pq_release.rs)
has distinct offline-root, node-software, protocol-configuration, Cell-manifest
and Cell-activation key sets. `PqReleaseRootV1::validate` prevents reuse of the
same key across roles. `verify_quorum` verifies distinct pinned keys; root
rotation requires both current and successor offline-root thresholds over the
same successor root. These checks authenticate signatures and role rules.

Distinct key IDs are not distinct custodians. A controller with two keys in a
2-of-3 role can authorize that role alone; holding different keys across roles
does not violate literal cross-role key separation. This is a custody evidence
gap, not a signature-verification failure. Do not change V1 signed root bytes
or silently make a local declaration part of that signature contract.

An administrative audit must cover every route that can approve, replace,
disable or recover the active authority: offline root, online roles, deployment
and update credentials, emergency mechanisms, retained recovery pins and
witness custodians. Observing diversified online release keys while omitting
one actor's root-replacement or recovery power gives an incomplete result.
The [recovery boundary](../../../security/PQ_RECOVERY_RELEASE_TRANSPORT_BOUNDARIES_V1.md)
also requires a fresh independently retained expected checkpoint. Multiple
witness processes with common custody do not create that independence.

Bind a control declaration to the exact root/role roster and generation being
assessed. A known key that is omitted, an unknown controller or an unobserved
alternate authority prevents a complete assessment. A new deployment generation,
root rotation, custody change or expiration requires fresh evidence. The local
`trnm-governance-guard` component supplies no network governance authority, as
specified in the [source ownership inventory](../../../../config/portability-inventory-v1.json).

### Financial and hardware concentration

Funding control, signing control, hardware ownership, hosting dependency and
current measured valid-work share are different variables. Retain them as
different observations. A shared sponsor can indicate economic dependence
without proving the sponsor can use the recipients' keys; a shared recovery or
cloud administrator can confer operational control without owning the hardware.
Record the actual relation and evidence rather than deducing it from a name.

Use one explicit observation interval, unit and population for each share.
Preserve unknown and unmeasured shares in the original denominator. Computing
percentages only among known operators can make missing observations look like
diversification. Zero measured activity is not missing data. Heterogeneous GPU
counts, nominal FLOPS, cash, token balances and work confirmations cannot be
summed into one capacity unit. Controlled local benchmark results neither
identify the cheapest adversary nor establish a live network's market share.

## Declared-control accounting boundary

The evidence model keeps raw identities and known common-control relations.
Transitive relatedness matters: A under B and B under C cannot become three
independent controllers merely by listing only direct relationships. Connected
control declarations supply conservative candidate groups, not authenticated
legal identity or an inference that unrelated labels prove independence.
Missing ownership stays unknown and receives no independent-domain credit.

Role analysis must retain both the native key threshold and control-group
concentration. For an unweighted `t`-of-`n` key role:

- The minimum approving coalition is the smallest number of declared control
  groups whose keys can reach `t`.
- The minimum blocking coalition is the smallest number of declared control
  groups whose withheld keys leave fewer than `t` available keys.

These are different quantities. They are evidence diagnostics over a complete
declared roster, not new consensus rules. Overlapping key custody and unmodeled
replacement authorities need explicit treatment before claiming a complete
coalition bound. A surviving threshold must never be obtained by deleting an
unavailable, conflicted or unknown controller from the denominator.

Declared candidate metrics are useful for rejecting obvious concentration and
finding missing evidence. They cannot authenticate hidden common control.
Signatures bind a statement to a key; trustworthy appointment, exclusivity of
custody, independence and current validity still need their original external
evidence and review. A hash-shaped field or `verified: true` supplied by the
candidate cannot be an independent acceptance authority.

## Executable input and report

The existing M17 evidence layer supplies
[`scripts/pon_decentralization_audit.py`](../../../../scripts/pon_decentralization_audit.py)
and its exact
[installed policy](../../../../config/pon/decentralization-audit-v1.json).
The CLI takes one strict JSON object containing `registry` and `audit`.

| Object | Exact schema and scope |
| --- | --- |
| Installed policy | `trnm-decentralization-policy-v1`; exact equality with the reader's versioned policy is required. |
| `registry` | `trnm-control-registry-v1`; bounded subject/controller/alias/evidence declarations, context, validity interval and exact subject-list digest. |
| `audit` | `trnm-decentralization-audit-v1`; policy/registry bindings, expected context, observation window and all five axes. |
| Output | `trnm-decentralization-report-v1`; conditional metrics, missing evidence, source/profile bindings and `status: HOLD`. |

`canonical_sha256` hashes UTF-8 JSON with sorted keys, compact separators,
ASCII escaping and nonfinite values forbidden. Registry, subject-list, roster,
policy and audit digests use that exact routine. Evidence-file hashes identify
the actual referenced bytes under their separately stated contract; they are
not interchangeable with canonical-object hashes. The parser rejects duplicate
JSON keys, floats and nonfinite numbers. Input is at most 4 MiB; each inventory
has at most 4,096 rows. Identifiers are bounded and integer quantities are
unsigned 64-bit values. Unknown fields and unsupported schema values reject.

The required context entries are `chain_source_sha256` and `profile_sha256`.
An incomplete source-only audit may omit unavailable `hepta_source_sha256`,
Chain/Hepta binary identities and network/genesis/parameter identities; output
lists them in `missing_context_fields`. Omission never supplies a deployed
context. The explicit WAN V3 composition requires the complete eight-field
context. Its caller passes the original expected context and registry digest
to `ControlMap`; matching a candidate's self-consistent metadata alone is not
external authentication.

Controllers have `id`, `parents` and `evidence_sha256`; aliases have `left`,
`right` and `evidence_sha256`. Subjects have `id` plus the required nullable
fields `controller`, `key_sha256` and `evidence_sha256`. Evidence entries contain their
digest, validity interval and declared `current`, `revoked` or `unknown` status.
A `current` status only controls arithmetic eligibility in the supplied window:
the reader does not fetch the object, verify its signature or appoint its issuer.
Different subject IDs carrying the same declared key fingerprint collapse
control claims; a quorum cannot count that fingerprint twice. The original
key/roster authentication remains an external obligation.

The reusable API keeps these distinctions explicit:

- `ControlMap.group_for(subject)` returns a group only when its declared control
  evidence covers the complete requested window; otherwise it returns `None`.
- `declared_group_for` and `related` retain the declared relation closure even
  when a link's evidence becomes stale, revoked or unresolved. Changing only
  that status cannot make related forbidden sources appear independent.
- `summarize` reports raw subject count, resolved declared groups and unresolved
  subjects separately. An empty supplied inventory does not mean zero real
  operators exist.
- `quorum` reports approving and blocking control-group minima only when the
  complete key/control denominator is resolved. The separate
  `known_groups_sufficient_to_approve` and `known_groups_sufficient_to_block`
  fields identify an already sufficient known coalition even when unknown keys
  prevent a claim about the full minimum. Neither is an independence proof.

Each work audit supplies the four named facets `work_rule`, `task_admission`,
`network_service` and `resource_access`, using `open`, `restricted` or `unknown`
with the applicable evidence reference. Data inventories distinguish providers,
discovery and replicas. Evaluation includes the roster digest, original total
key slots, threshold, authors and completeness. Missing configured keys remain
unidentified slots; unresolved author control prevents claiming an
author-separated candidate quorum. No consensus roster or native vote changes.

Authority input lists every declared route separately, under required roles
`root`, `release`, `upgrade`, `recovery` and `witness`. Missing roles, incomplete
inventories, unresolved routes and a route controlled by one declared group
remain findings. A role name or an `inventory_complete` declaration cannot prove
that the externally deployed alternative authority inventory was exhausted.
The report additionally exposes declared cross-role controller groups and
evaluator/authority overlap, including retained stale relationships. These are
relationship diagnostics; they do not automatically prove a conflict of interest
or establish the authenticity of the claimed control.

Funding and hardware each use one declared unit, unit-definition reference,
original `total_units`, explicit `unknown_units`, and distinct asset/receipt
allocations. Known shares use the complete original denominator with integer
parts-per-million rounding down; unidentified listed ownership is added to the
unknown portion. Missing denominators remain `null`, not zero, and do not
produce percentages. Duplicate asset or receipt references reject rather than
manufacture capacity. These are conditional declared shares, not measured
network market shares.

```sh
python3 scripts/pon_decentralization_audit.py \
  --input evidence/pon-decentralization-20261106/current-input.json \
  --output /tmp/trnm-current-decentralization-assessment.json
python3 -m unittest discover -s scripts/ci -p test_pon_decentralization_audit.py -v
python3 -m unittest discover -s scripts/ci -p test_pon_wan_control_domains.py -v
```

Exit 0 means the reader processed the supplied records; its report still says
`HOLD`. Invalid input exits 2. Output files are create-only, so retained reports
cannot be silently overwritten. The
[synthetic fixture](../../../../scripts/ci/fixtures/pon_decentralization_v1.json)
tests accounting only. The actual
[source-only current input](../../../../evidence/pon-decentralization-20261106/current-input.json)
uses real source/configuration hashes and explicitly empty unknown deployment
inventories. Its retained
[initial derived report](../../../../evidence/pon-decentralization-20261106/development-assessment-v1.json)
has no authenticated operators, known approving/blocking minimum or measured
funding/hardware denominator. The source facts and execution evidence retain
their distinct identities.

## Required counterexamples

The executable controls must cover same-controller nodes/IPs/keys/witnesses,
transitive aliases, author/evaluator overlap, common-controller retrieval and
repair providers, concentrated approval and veto power, unknown ownership,
unobserved alternative authorities, missing share denominators, expired/swapped
input context, duplicate identities/JSON fields and bounded hostile input.
Positive synthetic data must retain all independence and activation non-claims.
No fixture run becomes a physical network, an external reviewer or a deployed
custodian. Exact selectors and observed outcomes belong in the execution record.

## Closure remains with the existing owners

| Gate | Actual evidence required to close it |
| --- | --- |
| Work access | Source-bound new-producer tests of task/material acquisition, full native admission and honest confirmation under the original public-service and hostile-load contracts; independently attributed valid-work and full-cost observations. |
| Data custody | Complete-release readback from independently administered and independently failing replicas; publisher/provider loss, repair, renewal, funding exhaustion, recovery and retention/GC tests within the original frozen resource and time limits. |
| Evaluation independence | Authenticated current evaluator custody and conflict disclosures; author alias/control review; exact frozen roster and dataset provenance; independent prospective results and the required dispute/replacement governance. |
| Release and upgrades | Authenticated custody for the complete deployed root/role/update/recovery inventory; independent approval/blocking analysis; real rotation, revoked-key, rollback, restore and unavailable-custodian tests with the original consumer owners. |
| Funding/hardware | Verified whole-population denominator and original observation window, control attribution, explicit unknown portions, real valid-work/capacity and funding evidence, and independent economic assessment. |

The [PN5 WAN accounting contract](WAN_EVIDENCE_ACCOUNTING_V1.md) retains at
least three independently administered operators and failure domains, an
authenticated preregistered load/fault plan, complete original cohorts and
at least 72 hours of real operation. Meeting these minimums alone is not a
production-security proof. An accelerated clock, duplicated receipt, renamed
administrator, additional local machine or repeated key generation cannot
close the gate. The current audit has no such external campaign evidence.

Neither this contract nor a passing candidate reader grants independent
acceptance, public readiness, permissionless utility, whole-chain security,
model quality, CURRENT/FinalUse or production activation. Each result keeps
its source, profile, original failures and exact scope.
