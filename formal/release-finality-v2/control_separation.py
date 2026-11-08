"""Review pinned control materials without granting independence or FinalUse.

The original Hepta owner still verifies its signers and controller_id bindings.
The caller supplies those bindings independently; this reader cannot replace
them with labels from a candidate packet. Publisher/storage/key-custody bindings
likewise need their own original owner observations. Document hashes and reviewer
names here are retained references, NOT authenticated observations of reality.
"""
from __future__ import annotations

import hashlib
from itertools import combinations, product
import string

from protocol import Refusal, canonical, decode, digest, integer, require


ROLES = (
    "consumer", "evaluator", "release_key_custodian", "storage",
    "task_publisher", "trainer", "version_selector",
)
PAIR_FIELDS = ("chain_source", "chain_tree", "hepta_source", "hepta_tree")
POLICY_SCHEMA = "trnm-cell-control-separation-policy-v1"
MANIFEST_SCHEMA = "trnm-cell-control-separation-manifest-v1"
REPORT_SCHEMA = "trnm-cell-control-separation-review-v1"
INVENTORY_DOMAIN = "trnm.cell.control-inventory.v1"
COMMON_CONTROL_DOMAIN = "trnm.cell.common-control.v1"
SEPARATION_DOMAIN = "trnm.cell.separation-review.v1"
POLICY_DOMAIN = b"TRNM-CELL-CONTROL-SEPARATION-POLICY-V1\0"
MANIFEST_DOMAIN = b"TRNM-CELL-CONTROL-SEPARATION-MANIFEST-V1\0"
EVIDENCE_DOMAIN = b"TRNM-CELL-CONTROL-SEPARATION-EVIDENCE-V1\0"
REPORT_DOMAIN = b"TRNM-CELL-CONTROL-SEPARATION-REVIEW-V1\0"
MAX_BYTES = 1024 * 1024
MAX_BINDINGS = 128
MAX_CONTROLLERS = 128
MAX_RELATIONS = 1024
MINIMUM_REQUIRED_SEPARATIONS = (
    ("consumer", "trainer"), ("consumer", "version_selector"),
    ("evaluator", "task_publisher"), ("evaluator", "trainer"),
    ("evaluator", "version_selector"), ("release_key_custodian", "trainer"),
    ("storage", "storage"), ("trainer", "version_selector"),
)


def _fields(value, names, code):
    require(type(value) is dict and set(value) == set(names.split()), code)


def _wire(raw):
    require(type(raw) is bytes and len(raw) <= MAX_BYTES, "CONTROL_WIRE_LIMIT")
    return raw


def policy_digest(raw):
    """Publication helper; a reviewer must retain the expected pin separately."""
    return hashlib.sha256(POLICY_DOMAIN + _wire(raw)).hexdigest()


def manifest_digest(raw):
    """Publication helper, never a substitute for the caller's independent pin."""
    return hashlib.sha256(MANIFEST_DOMAIN + _wire(raw)).hexdigest()


def evidence_statement_digest(domain, campaign, policy, revision, statement):
    require(domain in (INVENTORY_DOMAIN, COMMON_CONTROL_DOMAIN, SEPARATION_DOMAIN),
            "CONTROL_EVIDENCE_DOMAIN")
    digest(campaign); digest(policy); integer(revision, 1)
    body = dict(campaign=campaign, policy=policy, revision=revision, statement=statement)
    return hashlib.sha256(EVIDENCE_DOMAIN + domain.encode("ascii") + b"\0" + canonical(body)).hexdigest()


def _source_pair(pair):
    _fields(pair, " ".join(PAIR_FIELDS), "CONTROL_SOURCE_PAIR_FIELDS")
    for value in pair.values():
        require(type(value) is str and len(value) == 40 and
                all(c in "0123456789abcdef" for c in value), "CONTROL_SOURCE_ID")


def _list(value, maximum, code):
    require(type(value) is list and len(value) <= maximum, code)


def _controller_id(value):
    # Exact StableId::as_str() / stable-v1 grammar of the existing Hepta owner.
    # It is NOT Digest32 and is never renamed, case-folded or hashed per key.
    require(type(value) is str and 1 <= len(value) <= 128 and
            all(c in string.ascii_letters + string.digits + "._-:" for c in value),
            "CONTROL_CONTROLLER_ID")


def _controller_list(value, maximum, code):
    _list(value, maximum, code)
    for item in value:
        _controller_id(item)
    require(value == sorted(set(value)), code)


def _bindings(value):
    _list(value, MAX_BINDINGS, "CONTROL_BINDING_LIMIT")
    ordering, signer_controllers = [], {}
    for row in value:
        _fields(row, "role signer controller_id owner_digest", "CONTROL_BINDING_FIELDS")
        require(row["role"] in ROLES, "CONTROL_ROLE")
        for field in ("signer", "owner_digest"):
            digest(row[field])
        _controller_id(row["controller_id"])
        prior = signer_controllers.setdefault(row["signer"], row["controller_id"])
        require(prior == row["controller_id"], "CONTROL_SIGNER_CONTROLLER_ALIAS")
        ordering.append((row["role"], row["signer"]))
    require(ordering == sorted(set(ordering)), "CONTROL_BINDING_ORDER_OR_DUPLICATE")


def _policy(value, campaign, pair, revision, now):
    _fields(value, "schema pair campaign revision valid_from valid_until "
            "maximum_evidence_age_seconds minimum_role_components required_separations "
            "minimum_reviewer_components reviewers", "CONTROL_POLICY_FIELDS")
    require(value["schema"] == POLICY_SCHEMA, "CONTROL_POLICY_SCHEMA")
    _source_pair(value["pair"])
    require(value["pair"] == pair, "CONTROL_SOURCE_PAIR")
    digest(value["campaign"])
    require(value["campaign"] == campaign, "CONTROL_CAMPAIGN")
    integer(value["revision"], 1)
    require(value["revision"] == revision, "CONTROL_POLICY_REVISION")
    integer(value["valid_from"]); integer(value["valid_until"], 1)
    require(value["valid_from"] <= now < value["valid_until"], "CONTROL_POLICY_TIME")
    integer(value["maximum_evidence_age_seconds"], 1)
    minima = value["minimum_role_components"]
    _fields(minima, " ".join(ROLES), "CONTROL_ROLE_MINIMUM_FIELDS")
    for minimum in minima.values():
        integer(minimum, 1)
        require(minimum <= MAX_BINDINGS, "CONTROL_ROLE_MINIMUM")
    pairs = value["required_separations"]
    _list(pairs, len(ROLES) * (len(ROLES) + 1) // 2, "CONTROL_POLICY_PAIR_LIMIT")
    require(bool(pairs), "CONTROL_POLICY_NO_SEPARATIONS")
    for pair_roles in pairs:
        require(type(pair_roles) is list and len(pair_roles) == 2 and
                all(role in ROLES for role in pair_roles) and
                pair_roles == sorted(pair_roles), "CONTROL_POLICY_PAIR")
        if pair_roles[0] == pair_roles[1]:
            require(minima[pair_roles[0]] >= 2, "CONTROL_POLICY_SELF_SEPARATION")
    require(pairs == [list(p) for p in sorted(set(map(tuple, pairs)))],
            "CONTROL_POLICY_PAIR_ORDER_OR_DUPLICATE")
    require(set(MINIMUM_REQUIRED_SEPARATIONS).issubset(set(map(tuple, pairs))),
            "CONTROL_POLICY_REQUIRED_SEPARATION_MISSING")
    for role, minimum in minima.items():
        require(minimum == 1 or [role, role] in pairs, "CONTROL_POLICY_MULTIPLE_ROLE_REVIEW")
    integer(value["minimum_reviewer_components"], 1)
    require(value["minimum_reviewer_components"] <= 32, "CONTROL_REVIEWER_MINIMUM")
    reviewers = value["reviewers"]
    _list(reviewers, 32, "CONTROL_REVIEWER_LIMIT")
    require(bool(reviewers), "CONTROL_REVIEWER_MISSING")
    names = []
    for reviewer in reviewers:
        _fields(reviewer, "authority controller_id", "CONTROL_REVIEWER_FIELDS")
        digest(reviewer["authority"]); _controller_id(reviewer["controller_id"])
        names.append(reviewer["authority"])
    require(names == sorted(set(names)), "CONTROL_REVIEWER_ORDER_OR_DUPLICATE")
    return {row["authority"]: row["controller_id"] for row in reviewers}


def _evidence(row, domain, statement, manifest, policy, reviewers, now):
    _fields(row, "domain authority document_sha256 statement_sha256 observed_at valid_until",
            "CONTROL_EVIDENCE_FIELDS")
    require(row["domain"] == domain, "CONTROL_EVIDENCE_DOMAIN")
    for field in ("authority", "document_sha256", "statement_sha256"):
        digest(row[field])
    require(row["authority"] in reviewers, "CONTROL_EVIDENCE_AUTHORITY")
    expected = evidence_statement_digest(domain, manifest["campaign"], manifest["policy"],
                                         manifest["revision"], statement)
    require(row["statement_sha256"] == expected, "CONTROL_EVIDENCE_STATEMENT")
    integer(row["observed_at"]); integer(row["valid_until"], 1)
    require(policy["valid_from"] <= row["observed_at"] <= now < row["valid_until"]
            <= policy["valid_until"], "CONTROL_EVIDENCE_TIME")
    require(now - row["observed_at"] <= policy["maximum_evidence_age_seconds"],
            "CONTROL_EVIDENCE_AGE")


class _ControlGraph:
    def __init__(self):
        self.parents = {}

    def add(self, actor):
        _controller_id(actor)
        self.parents.setdefault(actor, actor)
        require(len(self.parents) <= MAX_CONTROLLERS, "CONTROL_GRAPH_LIMIT")

    def root(self, actor):
        while actor != self.parents[actor]:
            self.parents[actor] = self.parents[self.parents[actor]]
            actor = self.parents[actor]
        return actor

    def join(self, a, b):
        self.add(a); self.add(b)
        a, b = sorted((self.root(a), self.root(b)))
        self.parents[b] = a


def review_control_separation(manifest_raw, policy_raw, *, expected_manifest,
                              expected_policy, expected_campaign, expected_pair,
                              expected_revision, expected_bindings, now):
    """Read-only review of independently pinned source/control materials.

    expected_* and now belong to the existing qualification/current owner. In
    particular expected_bindings must be its own already checked role/signer/
    controller_id/owner_digest rows, NOT copied from the submitted manifest.
    Existing Hepta signed_actor separation checks still have to run first.

    Missing roles, inventories or pair reviews remain UNRESOLVED. Known shared
    control is joined transitively, including common administrators/custodians.
    MATERIAL_REVIEW_COMPLETE means only that these pinned inputs satisfy their
    frozen review policy. It NEVER authenticates source documents, proves the
    absence of hidden control, issues a native grant or establishes FinalUse.
    """
    for pin in (expected_manifest, expected_policy, expected_campaign):
        digest(pin)
    integer(expected_revision, 1); integer(now)
    _source_pair(expected_pair)
    _bindings(expected_bindings)
    require(manifest_digest(manifest_raw) == expected_manifest, "CONTROL_MANIFEST_PIN")
    require(policy_digest(policy_raw) == expected_policy, "CONTROL_POLICY_PIN")
    manifest, policy = decode(_wire(manifest_raw)), decode(_wire(policy_raw))
    reviewers = _policy(policy, expected_campaign, expected_pair, expected_revision, now)
    _fields(manifest, "schema pair campaign policy revision valid_from valid_until bindings "
            "inventories common_control separation_reviews", "CONTROL_MANIFEST_FIELDS")
    require(manifest["schema"] == MANIFEST_SCHEMA, "CONTROL_MANIFEST_SCHEMA")
    _source_pair(manifest["pair"])
    require(manifest["pair"] == expected_pair, "CONTROL_SOURCE_PAIR")
    digest(manifest["campaign"]); digest(manifest["policy"])
    require(manifest["campaign"] == expected_campaign, "CONTROL_CAMPAIGN")
    require(manifest["policy"] == expected_policy, "CONTROL_POLICY_BINDING")
    integer(manifest["revision"], 1)
    require(manifest["revision"] == expected_revision, "CONTROL_POLICY_REVISION")
    integer(manifest["valid_from"]); integer(manifest["valid_until"], 1)
    require(policy["valid_from"] <= manifest["valid_from"] <= now < manifest["valid_until"]
            <= policy["valid_until"], "CONTROL_MANIFEST_TIME")
    _bindings(manifest["bindings"])
    require(canonical(manifest["bindings"]) == canonical(expected_bindings),
            "CONTROL_ORIGINAL_OWNER_BINDINGS")
    # A reviewer authority is the original signing-key digest. One key cannot
    # acquire a second controller identity by moving from a role binding into
    # the reviewer policy. Consistent self-review is rejected by the graph below.
    signer_controllers = {row["signer"]: row["controller_id"]
                          for row in manifest["bindings"]}
    for authority, controller in reviewers.items():
        if authority in signer_controllers:
            require(signer_controllers[authority] == controller,
                    "CONTROL_REVIEWER_SIGNER_CONTROLLER_ALIAS")

    graph = _ControlGraph()
    role_controllers = {role: set() for role in ROLES}
    for binding in manifest["bindings"]:
        graph.add(binding["controller_id"])
        role_controllers[binding["role"]].add(binding["controller_id"])
    for controller in reviewers.values():
        graph.add(controller)
    sources = set()
    inventories, inventory_order = set(), []
    _list(manifest["inventories"], MAX_CONTROLLERS, "CONTROL_INVENTORY_LIMIT")
    for row in manifest["inventories"]:
        _fields(row, "controller_id administrators key_custodians evidence", "CONTROL_INVENTORY_FIELDS")
        graph.add(row["controller_id"])
        _controller_list(row["administrators"], MAX_CONTROLLERS, "CONTROL_ADMINISTRATORS")
        _controller_list(row["key_custodians"], MAX_CONTROLLERS, "CONTROL_CUSTODIANS")
        statement = {k: v for k, v in row.items() if k != "evidence"}
        _evidence(row["evidence"], INVENTORY_DOMAIN, statement, manifest, policy, reviewers, now)
        sources.add(row["evidence"]["document_sha256"])
        inventories.add(row["controller_id"])
        inventory_order.append(row["controller_id"])
        for controller in row["administrators"] + row["key_custodians"]:
            graph.join(row["controller_id"], controller)
    require(inventory_order == sorted(inventories), "CONTROL_INVENTORY_ORDER_OR_DUPLICATE")

    link_order = []
    _list(manifest["common_control"], MAX_RELATIONS, "CONTROL_LINK_LIMIT")
    for row in manifest["common_control"]:
        _fields(row, "controllers kind evidence", "CONTROL_LINK_FIELDS")
        _controller_list(row["controllers"], 2, "CONTROL_LINK_CONTROLLERS")
        require(len(row["controllers"]) == 2, "CONTROL_LINK_CONTROLLERS")
        require(row["kind"] in ("same_operator", "shared_administrator", "shared_release_custody",
                                "declared_control"), "CONTROL_LINK_KIND")
        statement = {k: v for k, v in row.items() if k != "evidence"}
        _evidence(row["evidence"], COMMON_CONTROL_DOMAIN, statement, manifest, policy, reviewers, now)
        sources.add(row["evidence"]["document_sha256"])
        link_order.append((*row["controllers"], row["kind"]))
        graph.join(*row["controllers"])
    require(link_order == sorted(set(link_order)), "CONTROL_LINK_ORDER_OR_DUPLICATE")

    reviews, review_order = {}, []
    _list(manifest["separation_reviews"], MAX_RELATIONS, "CONTROL_REVIEW_LIMIT")
    for row in manifest["separation_reviews"]:
        _fields(row, "controllers evidence", "CONTROL_REVIEW_FIELDS")
        _controller_list(row["controllers"], 2, "CONTROL_REVIEW_CONTROLLERS")
        require(len(row["controllers"]) == 2, "CONTROL_REVIEW_CONTROLLERS")
        _evidence(row["evidence"], SEPARATION_DOMAIN, {"controllers": row["controllers"]},
                  manifest, policy, reviewers, now)
        for controller in row["controllers"]:
            graph.add(controller)
        sources.add(row["evidence"]["document_sha256"])
        pair = tuple(row["controllers"])
        authority = row["evidence"]["authority"]
        reviews.setdefault(pair, set()).add(authority)
        review_order.append((*pair, authority))
    require(review_order == sorted(set(review_order)), "CONTROL_REVIEW_ORDER_OR_DUPLICATE")

    conflicts, unresolved, observations = [], [], []
    for controller in sorted(set(graph.parents) - inventories):
        unresolved.append(dict(code="CONTROL_INVENTORY_MISSING", controller_id=controller))
    role_observations = []
    for role in ROLES:
        controllers = sorted(role_controllers[role])
        components = {graph.root(controller) for controller in controllers}
        minimum = policy["minimum_role_components"][role]
        if not controllers:
            unresolved.append(dict(code="CONTROL_ROLE_MISSING", role=role))
        elif len(controllers) < minimum:
            unresolved.append(dict(code="CONTROL_ROLE_ROSTER_INCOMPLETE", role=role,
                                   required=minimum, observed=len(controllers)))
        elif len(components) < minimum:
            conflicts.append(dict(code="CONTROL_ROLE_COMMON_CONTROL", role=role,
                                  required=minimum, known_components=len(components)))
        role_observations.append(dict(role=role, controller_ids=controllers,
            signer_count=sum(row["role"] == role for row in manifest["bindings"]),
            known_control_component_count=len(components)))

    for a_role, b_role in policy["required_separations"]:
        a_set, b_set = sorted(role_controllers[a_role]), sorted(role_controllers[b_role])
        pairs = combinations(a_set, 2) if a_role == b_role else product(a_set, b_set)
        for a, b in pairs:
            pair = tuple(sorted((a, b)))
            observation = dict(roles=[a_role, b_role], controllers=list(pair))
            if graph.root(a) == graph.root(b):
                conflicts.append(dict(code="CONTROL_REQUIRED_SHARED_COMPONENT", **observation,
                                      component=graph.root(a)))
                observations.append(dict(observation, result="CONFLICT", usable_reviewers=[],
                                         rejected_self_controlled_reviewers=[], reviewer_components=0))
                continue
            usable, self_controlled = [], []
            party_components = {graph.root(a), graph.root(b)}
            for authority in sorted(reviews.get(pair, ())):
                target = self_controlled if graph.root(reviewers[authority]) in party_components else usable
                target.append(authority)
            reviewer_components = len({graph.root(reviewers[authority]) for authority in usable})
            enough = reviewer_components >= policy["minimum_reviewer_components"]
            if not enough:
                unresolved.append(dict(code="CONTROL_SEPARATION_REVIEW_INCOMPLETE", **observation,
                    required=policy["minimum_reviewer_components"], observed=reviewer_components))
            observations.append(dict(observation,
                result="REVIEWED_MATERIALS_ONLY" if enough else "UNRESOLVED",
                usable_reviewers=usable, rejected_self_controlled_reviewers=self_controlled,
                reviewer_components=reviewer_components))

    components = {}
    for controller in sorted(graph.parents):
        components.setdefault(graph.root(controller), []).append(controller)
    # Retain sharing outside the frozen mandatory pairs too; a completed input
    # review is not a claim that all seven functions have different controllers.
    overlaps = []
    for a_role, b_role in combinations(ROLES, 2):
        for a, b in product(sorted(role_controllers[a_role]), sorted(role_controllers[b_role])):
            if graph.root(a) == graph.root(b):
                overlaps.append(dict(roles=[a_role, b_role], controllers=sorted([a, b]),
                                     component=graph.root(a)))
    # Lists are derived from sorted input identities; neither node order nor key
    # rotation creates another component. Unknown edges can only lower this bound.
    report = dict(schema=REPORT_SCHEMA, scope="pinned-control-materials-not-independent-acceptance",
        campaign=expected_campaign, source_pair=decode(canonical(expected_pair)),
        manifest=expected_manifest, policy=expected_policy, revision=expected_revision, reviewed_at=now,
        owner_bindings_digest=hashlib.sha256(
            b"TRNM-CELL-ORIGINAL-CONTROLLER-BINDINGS-V1\0" + canonical(expected_bindings)).hexdigest(),
        status="CONFLICT" if conflicts else "UNRESOLVED" if unresolved else "MATERIAL_REVIEW_COMPLETE",
        conflicts=conflicts, unresolved=unresolved, role_observations=role_observations,
        known_control_components=[dict(component=k, controllers=v) for k, v in sorted(components.items())],
        observed_role_control_overlaps=overlaps,
        separation_observations=observations, retained_document_digests=sorted(sources),
        component_count_is_independence_upper_bound_only=True,
        source_documents_authenticated=False, hidden_control_excluded=False,
        independent_control_accepted=False, physical_installation_accepted=False,
        hepta_final_use=False, production_activation=False)
    return dict(report, id=hashlib.sha256(REPORT_DOMAIN + canonical(report)).hexdigest())
