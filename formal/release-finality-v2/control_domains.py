"""Join four declared dependency domains to the existing seven-role review.

This is a bounded, read-only material check. It verifies actual supplied document
bytes and known conflicts; it cannot authenticate the facts in those documents
or discover an undisclosed controller. Native authority remains with its owner.
V1 inputs and outputs retain their original semantics.
"""
from __future__ import annotations

import hashlib
from control_separation import (
    MAX_BYTES, MAX_CONTROLLERS, ROLES, _controller_id, _controller_list,
    _fields, _source_pair, review_control_separation,
)
from protocol import canonical, decode, digest, integer, require


AXES = ("administration", "failure", "funding", "key_custody")
AUTHORITY_AXES = ("administration", "funding", "key_custody")
SCHEMA = "trnm-cell-control-domains-manifest-v2"
DOCUMENT_SCHEMA = "trnm-cell-control-domains-document-v2"
REPORT_SCHEMA = "trnm-cell-control-domains-review-v2"
MANIFEST_DOMAIN = b"TRNM-CELL-CONTROL-DOMAINS-MANIFEST-V2\0"
REPORT_DOMAIN = b"TRNM-CELL-CONTROL-DOMAINS-REVIEW-V2\0"
MAX_DOMAINS_PER_AXIS = 32
MAX_DOCUMENT_BYTES = 64 * 1024
MAX_TOTAL_DOCUMENT_BYTES = 8 * 1024 * 1024


def domains_manifest_digest(raw):
    require(type(raw) is bytes and len(raw) <= MAX_BYTES, "DOMAINS_WIRE_LIMIT")
    return hashlib.sha256(MANIFEST_DOMAIN + raw).hexdigest()


def document_statement(manifest, row):
    """Exact document body; publication does not supply an independent pin."""
    return dict(schema=DOCUMENT_SCHEMA, pair=manifest["pair"],
                campaign=manifest["campaign"],
                control_manifest=manifest["control_manifest"],
                control_policy=manifest["control_policy"],
                revision=manifest["revision"],
                inventory={key: value for key, value in row.items()
                           if key != "document_sha256"})


def review_control_domains(manifest_raw, policy_raw, domains_raw, documents, *,
                           expected_domains, **control_trusted):
    """Run the original V1 check, then join pinned four-axis inventory bytes.

    control_trusted is the original owner's V1 trust input, including its current
    time and exact bindings. expected_domains is retained independently of the
    candidate. documents maps raw SHA-256 identities to the actual canonical
    statement bytes. Hash agreement is not authentication or real independence.
    """
    digest(expected_domains)
    require(domains_manifest_digest(domains_raw) == expected_domains, "DOMAINS_PIN")
    # Bound the entire document population before parsing or hashing any file.
    require(type(documents) is dict and len(documents) <= MAX_CONTROLLERS,
            "DOMAINS_DOCUMENT_COUNT")
    total_bytes = 0
    for key, raw in documents.items():
        digest(key)
        require(type(raw) is bytes and len(raw) <= MAX_DOCUMENT_BYTES,
                "DOMAINS_DOCUMENT_LIMIT")
        total_bytes += len(raw)
    require(total_bytes <= MAX_TOTAL_DOCUMENT_BYTES, "DOMAINS_TOTAL_DOCUMENT_LIMIT")

    control = review_control_separation(manifest_raw, policy_raw, **control_trusted)
    original, policy, manifest = decode(manifest_raw), decode(policy_raw), decode(domains_raw)
    _fields(manifest, "schema pair campaign control_manifest control_policy revision "
            "valid_from valid_until inventories", "DOMAINS_MANIFEST_FIELDS")
    require(manifest["schema"] == SCHEMA, "DOMAINS_SCHEMA")
    _source_pair(manifest["pair"])
    require(manifest["pair"] == control_trusted["expected_pair"], "DOMAINS_SOURCE_PAIR")
    for field in ("campaign", "control_manifest", "control_policy"):
        digest(manifest[field])
    require(manifest["campaign"] == control_trusted["expected_campaign"], "DOMAINS_CAMPAIGN")
    require(manifest["control_manifest"] == control_trusted["expected_manifest"] and
            manifest["control_policy"] == control_trusted["expected_policy"],
            "DOMAINS_CONTROL_BINDING")
    integer(manifest["revision"], 1)
    require(manifest["revision"] == control_trusted["expected_revision"], "DOMAINS_REVISION")
    integer(manifest["valid_from"]); integer(manifest["valid_until"], 1)
    now = control_trusted["now"]
    require(original["valid_from"] <= manifest["valid_from"] <= now < manifest["valid_until"]
            <= original["valid_until"], "DOMAINS_TIME")

    parents = {}
    for component in control["known_control_components"]:
        for actor in component["controllers"]:
            parents[actor] = component["component"]

    def root(actor):
        while actor != parents[actor]:
            parents[actor] = parents[parents[actor]]
            actor = parents[actor]
        return actor

    def join(a, b):
        a, b = sorted((root(a), root(b)))
        parents[b] = a

    require(type(manifest["inventories"]) is list and
            len(manifest["inventories"]) <= MAX_CONTROLLERS, "DOMAINS_INVENTORY_LIMIT")
    inventories, ordering, required_documents = {}, [], set()
    for row in manifest["inventories"]:
        _fields(row, "controller_id domains document_sha256 observed_at valid_until",
                "DOMAINS_INVENTORY_FIELDS")
        actor = row["controller_id"]
        _controller_id(actor)
        require(actor in parents, "DOMAINS_UNKNOWN_CONTROLLER")
        _fields(row["domains"], " ".join(AXES), "DOMAINS_AXES")
        for ids in row["domains"].values():
            _controller_list(ids, MAX_DOMAINS_PER_AXIS, "DOMAINS_IDENTITIES")
        integer(row["observed_at"]); integer(row["valid_until"], 1)
        require(policy["valid_from"] <= row["observed_at"] <= now < row["valid_until"]
                <= manifest["valid_until"], "DOMAINS_OBSERVATION_TIME")
        require(now - row["observed_at"] <= policy["maximum_evidence_age_seconds"],
                "DOMAINS_OBSERVATION_AGE")
        digest(row["document_sha256"])
        required_documents.add(row["document_sha256"])
        inventories[actor] = row
        ordering.append(actor)
    require(ordering == sorted(set(ordering)), "DOMAINS_INVENTORY_ORDER_OR_DUPLICATE")
    # No supplied document can disappear silently from the audit denominator.
    require(set(documents) <= required_documents, "DOMAINS_UNREFERENCED_DOCUMENT")

    unresolved, conflicts, usable_inventories = [], [], set()
    for actor in sorted(parents):
        row = inventories.get(actor)
        if row is None:
            unresolved.append(dict(code="DOMAINS_INVENTORY_MISSING", controller_id=actor))
            continue
        for axis in AXES:
            if not row["domains"][axis]:
                unresolved.append(dict(code="DOMAINS_AXIS_UNKNOWN", controller_id=actor, axis=axis))
        raw = documents.get(row["document_sha256"])
        if raw is None:
            unresolved.append(dict(code="DOMAINS_DOCUMENT_MISSING", controller_id=actor,
                                   document=row["document_sha256"]))
            continue
        require(hashlib.sha256(raw).hexdigest() == row["document_sha256"],
                "DOMAINS_DOCUMENT_DIGEST")
        require(canonical(decode(raw)) == canonical(document_statement(manifest, row)),
                "DOMAINS_DOCUMENT_STATEMENT")
        usable_inventories.add(actor)

    # Known adverse declarations still restrict the result when their document
    # is missing. Withholding evidence must not erase a common-control edge.
    # The three authority axes share one principal namespace: the same custodian
    # named as administrator or funding controller cannot gain a second identity.
    owners = {}
    for actor, row in inventories.items():
        for axis in AUTHORITY_AXES:
            for domain in row["domains"][axis]:
                if domain in parents:
                    join(actor, domain)
                if domain in owners:
                    join(actor, owners[domain])
                else:
                    owners[domain] = actor

    # A reviewer's inventory is part of the same population, not a free pass.
    # V1 already excludes its known control component. Re-evaluate those usable
    # keys after funding and cross-axis authority dependencies have been joined.
    reviewers = {row["authority"]: row["controller_id"] for row in policy["reviewers"]}
    observations = []
    for prior in control["separation_observations"]:
        a, b = prior["controllers"]
        data = dict(roles=prior["roles"], controllers=prior["controllers"])
        authority_shared = root(a) == root(b)
        shared_failure = sorted(set(inventories.get(a, {}).get("domains", {}).get("failure", [])) &
                                set(inventories.get(b, {}).get("domains", {}).get("failure", [])))
        if authority_shared:
            conflicts.append(dict(code="DOMAINS_REQUIRED_COMMON_AUTHORITY", **data,
                                  component=root(a)))
        if shared_failure:
            conflicts.append(dict(code="DOMAINS_REQUIRED_COMMON_FAILURE", **data,
                                  domains=shared_failure))
        usable, rejected = [], []
        party_roots = {root(a), root(b)}
        for authority in prior["usable_reviewers"]:
            actor = reviewers[authority]
            row = inventories.get(actor)
            if (root(actor) in party_roots or actor not in usable_inventories or
                    not all(row["domains"][axis] for axis in AUTHORITY_AXES)):
                rejected.append(authority)
            else:
                usable.append(authority)
        count = len({root(reviewers[key]) for key in usable})
        if count < policy["minimum_reviewer_components"]:
            unresolved.append(dict(code="DOMAINS_REVIEWER_SEPARATION_INCOMPLETE", **data,
                required=policy["minimum_reviewer_components"], observed=count))
        observations.append(dict(data, common_authority=authority_shared,
            shared_failure_domains=shared_failure, usable_reviewers=usable,
            rejected_dependent_or_unobserved_reviewers=rejected,
            known_reviewer_components=count))

    role_observations = []
    for role in ROLES:
        actors = sorted({row["controller_id"] for row in original["bindings"] if row["role"] == role})
        authority_components = len({root(actor) for actor in actors})
        if actors and authority_components < policy["minimum_role_components"][role]:
            conflicts.append(dict(code="DOMAINS_ROLE_COMMON_AUTHORITY", role=role,
                required=policy["minimum_role_components"][role], observed=authority_components))
        # These separate counts must never be combined into a joint independent
        # replica count; every required pair above is checked on the same actors.
        role_observations.append(dict(role=role, controllers=actors,
            known_authority_component_upper_bound=authority_components,
            declared_domains={axis: sorted({domain for actor in actors
                for domain in inventories.get(actor, {}).get("domains", {}).get(axis, [])})
                for axis in AXES}))

    components = {}
    for actor in sorted(parents):
        components.setdefault(root(actor), []).append(actor)
    report = dict(schema=REPORT_SCHEMA, campaign=control["campaign"],
        source_pair=control["source_pair"], control_report=control["id"],
        domain_manifest=expected_domains, revision=manifest["revision"], reviewed_at=now,
        status=("CONFLICT" if conflicts or control["status"] == "CONFLICT" else
                "UNRESOLVED" if unresolved or control["status"] == "UNRESOLVED" else
                "MATERIAL_REVIEW_COMPLETE"),
        original_control_material_review=control, conflicts=conflicts, unresolved=unresolved,
        separation_observations=observations, role_observations=role_observations,
        known_authority_components=[dict(component=k, controllers=v) for k, v in sorted(components.items())],
        checked_document_digests=sorted(documents), checked_document_bytes=total_bytes,
        required_document_count=len(required_documents),
        joint_independent_operator_count=None, component_count_is_independence_upper_bound_only=True,
        source_documents_authenticated=False, hidden_control_excluded=False,
        independent_control_accepted=False, physical_installation_accepted=False,
        hepta_final_use=False, production_activation=False)
    return dict(report, id=hashlib.sha256(REPORT_DOMAIN + canonical(report)).hexdigest())
