#!/usr/bin/env python3
"""Source-bound control accounting; no JSON authenticates real-world independence.

Known shared control is transitive and survives stale evidence for exclusion.
Current evidence references permit only *declared* accounting. They are not read,
signature-verified, appointed, or accepted by this reader. Consensus is unchanged.
"""
from __future__ import annotations

import argparse
import collections
import hashlib
import json
import re
from pathlib import Path

MAX_BYTES = 4 * 1024 * 1024
MAX_ROWS = 4096
MAX_INT = 2**64 - 1
CONTEXT_FIELDS = {
    "chain_source_sha256", "hepta_source_sha256", "chain_binary_sha256",
    "hepta_binary_sha256", "profile_sha256", "network_sha256",
    "genesis_sha256", "parameters_sha256",
}
FACETS = ("work_rule", "task_admission", "network_service", "resource_access")
AUTHORITY_ROLES = ("root", "release", "upgrade", "recovery", "witness")
POLICY = {
    "schema": "trnm-decentralization-policy-v1",
    "registry_schema": "trnm-control-registry-v1",
    "audit_schema": "trnm-decentralization-audit-v1",
    "report_schema": "trnm-decentralization-report-v1",
    "max_input_bytes": MAX_BYTES, "max_rows_per_inventory": MAX_ROWS,
    "axes": ["work_production", "data_distribution", "evaluation", "authority", "resources"],
    "work_facets": list(FACETS), "required_authority_roles": list(AUTHORITY_ROLES),
    "evidence_scope": "declared references only; external authentication remains required",
    "common_control": "transitive parents, aliases and shared key fingerprints; stale edges retained",
    "unknown_control": "never contributes a controller group or an independence floor",
    "resource_scope": "one declared unit and one fixed denominator per resource and audit window",
    "independent_administration_verified": False, "permissionless_utility_accepted": False,
    "public_network_ready": False, "production_activation": False,
}


def require(ok, code):
    if not ok:
        raise ValueError(code)


def exact(value, fields, code):
    require(type(value) is dict and set(value) == set(fields), code)


def integer(value, code, minimum=0):
    require(type(value) is int and minimum <= value <= MAX_INT, code)
    return value


def name(value, code="IDENTITY"):
    require(type(value) is str and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:@/+=-]{0,127}", value) is not None, code)
    return value


def digest(value, code="DIGEST"):
    require(type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None, code)
    return value


def canonical_bytes(value, maximum=None):
    encoder = json.JSONEncoder(sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)
    chunks, size = [], 0
    try:
        for chunk in encoder.iterencode(value):
            raw = chunk.encode()
            size += len(raw)
            require(maximum is None or size <= maximum, "REGISTRY_BYTE_BOUND")
            chunks.append(raw)
    except (TypeError, RecursionError) as error:
        raise ValueError("CANONICAL_JSON_TYPE_OR_DEPTH") from error
    return b"".join(chunks)


def canonical_sha256(value):
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def parse_json(raw):
    require(type(raw) is bytes and len(raw) <= MAX_BYTES, "INPUT_BOUND")
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "DUPLICATE_JSON_KEY")
            result[key] = value
        return result
    def noninteger(_):
        raise ValueError("INTEGER_JSON_NUMBERS_REQUIRED")
    try:
        return json.loads(raw, object_pairs_hook=pairs, parse_constant=noninteger, parse_float=noninteger)
    except (UnicodeError, RecursionError) as error:
        raise ValueError("JSON_ENCODING_OR_DEPTH") from error


def context(value):
    require(type(value) is dict and {"chain_source_sha256", "profile_sha256"} <= set(value)
            and set(value) <= CONTEXT_FIELDS, "CONTEXT_FIELDS")
    for key, value in value.items():
        digest(value, key)


def sequence(value, code, maximum=MAX_ROWS):
    require(type(value) is list and len(value) <= maximum, code)
    return value


def indexed(value, fields, code, key="id"):
    result = {}
    for row in sequence(value, code):
        exact(row, fields, code)
        identity = digest(row[key], code) if key == "sha256" else name(row[key], code)
        require(identity not in result, "DUPLICATE_" + code)
        result[identity] = row
    return result


def interval(start, end):
    integer(start, "WINDOW_START")
    integer(end, "WINDOW_END", start + 1)


def minimum_coalition(weights, target):
    total = 0
    for count, weight in enumerate(sorted(weights, reverse=True), 1):
        total += weight
        if total >= target:
            return count
    return None


class ControlMap:
    """All groups are declarations. Current references are never authentication.

    `related` deliberately uses stale/revoked relations too: expiry must not turn
    a known alias of a forbidden source into a newly independent source.
    """
    def __init__(self, registry, *, expected_sha256, expected_context,
                 start_unix_ms, end_unix_ms):
        exact(registry, {"schema", "context", "valid_from_unix_ms", "valid_until_unix_ms",
                         "subjects_sha256", "controllers", "aliases", "subjects", "evidence"}, "REGISTRY_FIELDS")
        require(registry["schema"] == POLICY["registry_schema"], "REGISTRY_SCHEMA")
        digest(expected_sha256, "REGISTRY_DIGEST")
        encoded = canonical_bytes(registry, MAX_BYTES)
        require(hashlib.sha256(encoded).hexdigest() == expected_sha256, "REGISTRY_BINDING")
        registry = parse_json(encoded)
        context(expected_context); context(registry["context"])
        require(registry["context"] == expected_context, "CONTEXT_BINDING")
        interval(start_unix_ms, end_unix_ms)
        interval(registry["valid_from_unix_ms"], registry["valid_until_unix_ms"])
        self.registry_current = (registry["valid_from_unix_ms"] <= start_unix_ms
                                 and end_unix_ms <= registry["valid_until_unix_ms"])
        self.sha256, self.start, self.end = expected_sha256, start_unix_ms, end_unix_ms
        self.evidence = indexed(registry["evidence"], {"sha256", "valid_from_unix_ms",
                                "valid_until_unix_ms", "status"}, "EVIDENCE", "sha256")
        for row in self.evidence.values():
            interval(row["valid_from_unix_ms"], row["valid_until_unix_ms"])
            require(row["status"] in ("current", "revoked", "unknown"), "EVIDENCE_STATUS")
        self.controllers = indexed(registry["controllers"], {"id", "parents", "evidence_sha256"}, "CONTROLLER")
        self.subjects = indexed(registry["subjects"], {"id", "controller", "key_sha256", "evidence_sha256"}, "SUBJECT")
        digest(registry["subjects_sha256"], "SUBJECTS_DIGEST")
        require(canonical_sha256(registry["subjects"]) == registry["subjects_sha256"], "SUBJECTS_BINDING")
        self.parent = {key: key for key in self.controllers}
        edges, references = [], collections.defaultdict(set)
        for identity, row in self.controllers.items():
            self.reference(row["evidence_sha256"])
            references[identity].add(row["evidence_sha256"])
            parents = self.identifiers(row["parents"], self.controllers, "PARENT")
            require(identity not in parents, "SELF_PARENT")
            edges.extend((identity, parent) for parent in parents)
        aliases = set()
        for row in sequence(registry["aliases"], "ALIASES"):
            exact(row, {"left", "right", "evidence_sha256"}, "ALIAS_FIELDS")
            left, right = self.identifiers([row["left"], row["right"]], self.controllers, "ALIAS")
            pair = tuple(sorted((left, right)))
            require(pair not in aliases, "DUPLICATE_ALIAS")
            aliases.add(pair)
            self.reference(row["evidence_sha256"])
            references[left].add(row["evidence_sha256"])
            references[right].add(row["evidence_sha256"])
            edges.append(pair)
        key_owners = collections.defaultdict(list)
        for row in self.subjects.values():
            owner = row["controller"]
            if owner is None:
                self.reference(row["evidence_sha256"], nullable=True)
            else:
                name(owner)
                require(owner in self.controllers, "UNKNOWN_CONTROLLER")
                self.reference(row["evidence_sha256"], nullable=True)
            if row["key_sha256"] is not None:
                digest(row["key_sha256"], "KEY_FINGERPRINT")
                if owner is not None:
                    key_owners[row["key_sha256"]].append(owner)
        for owners in key_owners.values():
            edges.extend((owners[0], owner) for owner in owners[1:])
        for left, right in edges:
            a, b = self._find(left), self._find(right)
            self.parent[max(a, b)] = min(a, b)
        self.component_references = collections.defaultdict(set)
        for identity, refs in references.items():
            self.component_references[self._find(identity)].update(refs)
        self.key_groups = {key: self._find(owners[0]) for key, owners in key_owners.items()}

    @staticmethod
    def identifiers(values, known, code="SUBJECT"):
        result = sequence(values, code)
        for value in result:
            name(value, code)
            require(value in known, "UNKNOWN_" + code)
        require(len(set(result)) == len(result), "DUPLICATE_" + code)
        return result

    def reference(self, value, nullable=False):
        if value is None and nullable:
            return False
        digest(value, "EVIDENCE_REFERENCE")
        require(value in self.evidence, "UNKNOWN_EVIDENCE_REFERENCE")
        row = self.evidence[value]
        return (self.registry_current and row["status"] == "current"
                and row["valid_from_unix_ms"] <= self.start and self.end <= row["valid_until_unix_ms"])

    def _find(self, identity):
        while self.parent[identity] != identity:
            self.parent[identity] = self.parent[self.parent[identity]]
            identity = self.parent[identity]
        return identity

    def declared_group_for(self, subject):
        self.identifiers([subject], self.subjects)
        owner = self.subjects[subject]["controller"]
        return self.key_groups.get(self.subjects[subject]["key_sha256"]) if owner is None else self._find(owner)

    def group_for(self, subject):
        group = self.declared_group_for(subject)
        if (group is None or self.subjects[subject]["controller"] is None
                or not self.reference(self.subjects[subject]["evidence_sha256"], nullable=True)
                or not all(self.reference(ref) for ref in self.component_references[group])):
            return None
        return group

    def related(self, first, second):
        a, b = self.declared_group_for(first), self.declared_group_for(second)
        first_key, second_key = self.subjects[first]["key_sha256"], self.subjects[second]["key_sha256"]
        return first == second or (a is not None and a == b) or (first_key is not None and first_key == second_key)

    def summarize(self, subjects):
        subjects = self.identifiers(subjects, self.subjects)
        groups, unresolved = collections.defaultdict(list), []
        for subject in subjects:
            group = self.group_for(subject)
            if group is None:
                unresolved.append(subject)
            else:
                groups[group].append(subject)
        return {"subject_count": len(subjects), "declared_group_count": len(groups),
                "declared_groups": {key: sorted(value) for key, value in sorted(groups.items())},
                "unresolved_subjects": sorted(unresolved), "independent_administration_verified": False}

    def quorum(self, subjects, threshold, authors=(), *, total_key_slots=None, authors_complete=True):
        subjects = self.identifiers(subjects, self.subjects)
        require(type(authors) in (list, tuple), "AUTHOR_ARRAY")
        authors = self.identifiers(list(authors), self.subjects, "AUTHOR")
        total = len(subjects) if total_key_slots is None else integer(total_key_slots, "KEY_SLOTS")
        require(len(subjects) <= total <= MAX_ROWS, "KEY_SLOTS")
        integer(threshold, "KEY_THRESHOLD", 1)
        require(threshold <= total, "KEY_THRESHOLD")
        require(type(authors_complete) is bool, "AUTHOR_COMPLETENESS")
        keys = [self.subjects[subject]["key_sha256"] for subject in subjects]
        fingerprints = [key for key in keys if key is not None]
        require(len(set(fingerprints)) == len(fingerprints), "DUPLICATE_KEY_VOTE")
        weights = collections.Counter(self.group_for(subject) for subject, key in zip(subjects, keys)
                                      if key is not None and self.group_for(subject) is not None)
        unresolved = total - sum(weights.values())
        approve = minimum_coalition(weights.values(), threshold)
        block = minimum_coalition(weights.values(), total - threshold + 1)
        excluded = [subject for subject in subjects if any(self.related(subject, author) for author in authors)]
        author_unknown = not authors_complete or any(self.group_for(author) is None for author in authors)
        eligible = [subject for subject in subjects if subject not in excluded
                    and self.subjects[subject]["key_sha256"] is not None and self.group_for(subject) is not None]
        return {"total_key_slots": total, "key_threshold": threshold,
                "identified_unique_keys": len(fingerprints), "unidentified_key_slots": total - len(fingerprints),
                "unresolved_control_key_slots": unresolved, "declared_group_key_weights": dict(sorted(weights.items())),
                "minimum_approving_groups": approve if unresolved == 0 else None,
                "minimum_blocking_groups": block if unresolved == 0 else None,
                "known_groups_sufficient_to_approve": approve, "known_groups_sufficient_to_block": block,
                "coalition_scope": "declared control only; full minima withheld with unknown keys or control",
                "author_related_subjects": sorted(excluded), "author_control_unresolved": author_unknown,
                "author_separated_candidate_key_count": 0 if author_unknown else len(eligible),
                "author_separated_candidate_group_count": 0 if author_unknown else len({self.group_for(s) for s in eligible}),
                "author_separated_candidate_key_threshold_met": not author_unknown and len(eligible) >= threshold,
                "independent_administration_verified": False}


def inventory(value, controls):
    require(type(value["inventory_complete"]) is bool, "INVENTORY_COMPLETENESS")
    current = controls.reference(value["inventory_evidence_sha256"], nullable=True)
    require(not value["inventory_complete"] or value["inventory_evidence_sha256"] is not None, "INVENTORY_EVIDENCE_REQUIRED")
    return {"declared_inventory_complete": value["inventory_complete"],
            "inventory_reference_current": current,
            "accounting_inventory_current": value["inventory_complete"] and current}


INVENTORY = {"inventory_complete", "inventory_evidence_sha256"}


def resource_report(value, controls):
    exact(value, INVENTORY | {"unit", "unit_definition_sha256", "total_units", "unknown_units", "allocations"}, "RESOURCE_FIELDS")
    info = inventory(value, controls)
    unit = name(value["unit"], "RESOURCE_UNIT")
    unit_current = controls.reference(value["unit_definition_sha256"], nullable=True)
    groups, total_listed, unresolved, assets, receipts = collections.Counter(), 0, 0, set(), set()
    for row in sequence(value["allocations"], "ALLOCATIONS"):
        exact(row, {"subject", "asset_sha256", "units", "evidence_sha256"}, "ALLOCATION_FIELDS")
        subject = controls.identifiers([row["subject"]], controls.subjects)[0]
        asset = digest(row["asset_sha256"], "ASSET_IDENTITY")
        require(asset not in assets, "DUPLICATE_RESOURCE_ASSET")
        assets.add(asset)
        receipt = digest(row["evidence_sha256"], "RESOURCE_EVIDENCE")
        require(receipt not in receipts, "DUPLICATE_RESOURCE_EVIDENCE")
        receipts.add(receipt)
        current = controls.reference(receipt)
        units = integer(row["units"], "RESOURCE_UNITS")
        total_listed = integer(total_listed + units, "RESOURCE_SUM")
        group = controls.group_for(subject)
        if group is not None and current:
            groups[group] += units
        else:
            unresolved += units
    total = value["total_units"]
    if total is None:
        require(value["unknown_units"] is None and not value["inventory_complete"], "UNKNOWN_RESOURCE_DENOMINATOR")
        unknown = None
    else:
        integer(total, "RESOURCE_DENOMINATOR")
        unknown = integer(value["unknown_units"], "RESOURCE_UNKNOWN_UNITS")
        require(total_listed + unknown == total, "RESOURCE_DENOMINATOR_BINDING")
        require(not value["inventory_complete"] or unknown == 0, "INCOMPLETE_RESOURCE_INVENTORY")
        unknown += unresolved
    fractions = total is not None and total > 0 and unit_current and unit != "unknown"
    return {**info, "unit": unit, "unit_reference_current": unit_current, "total_units": total,
            "listed_units": total_listed, "unresolved_listed_units": unresolved, "unknown_owner_units": unknown,
            "declared_group_units": dict(sorted(groups.items())),
            "declared_group_share_ppm": {key: units * 1_000_000 // total for key, units in sorted(groups.items())} if fractions else None,
            "unknown_owner_share_ppm": unknown * 1_000_000 // total if fractions else None,
            "largest_declared_group_share_ppm": max(groups.values(), default=0) * 1_000_000 // total if fractions else None,
            "known_groups_sufficient_for_majority": minimum_coalition(groups.values(), total // 2 + 1) if fractions else None,
            "independent_administration_verified": False}


def evaluate(audit, registry):
    audit = parse_json(canonical_bytes(audit, MAX_BYTES))
    exact(audit, {"schema", "policy_sha256", "context", "control_registry_sha256", "window",
                  "work_production", "data_distribution", "evaluation", "authority", "resources"}, "AUDIT_FIELDS")
    require(audit["schema"] == POLICY["audit_schema"], "AUDIT_SCHEMA")
    digest(audit["policy_sha256"], "POLICY_DIGEST")
    require(audit["policy_sha256"] == canonical_sha256(POLICY), "POLICY_BINDING")
    exact(audit["window"], {"start_unix_ms", "end_unix_ms"}, "WINDOW_FIELDS")
    controls = ControlMap(registry, expected_sha256=audit["control_registry_sha256"],
                          expected_context=audit["context"], **audit["window"])
    findings, axes = [], {}
    def finding(axis, code):
        findings.append({"axis": axis, "code": code})
    def finish(axis, report):
        axes[axis] = report
        if not report.get("accounting_inventory_current", False):
            finding(axis, "INVENTORY_INCOMPLETE_OR_UNCURRENT")
    work = audit["work_production"]
    exact(work, INVENTORY | {"subjects", "facets"}, "WORK_FIELDS")
    facets = indexed(work["facets"], {"id", "status", "evidence_sha256"}, "WORK_FACET")
    require(set(facets) == set(FACETS), "WORK_FACET_COVERAGE")
    facet_report = {}
    for key, row in facets.items():
        require(row["status"] in ("open", "restricted", "unknown"), "WORK_STATUS")
        current = controls.reference(row["evidence_sha256"], nullable=True)
        require(row["status"] == "unknown" or row["evidence_sha256"] is not None, "WORK_EVIDENCE_REQUIRED")
        facet_report[key] = {"declared_status": row["status"], "reference_current": current, "openness_verified": False}
        if row["status"] != "open" or not current:
            finding("work_production", key.upper() + "_NOT_ESTABLISHED_OPEN")
    finish("work_production", {**inventory(work, controls), "facets": facet_report,
                               "producers": controls.summarize(work["subjects"])})
    if not work["subjects"]:
        finding("work_production", "PRODUCER_INVENTORY_EMPTY")
    data = audit["data_distribution"]
    exact(data, INVENTORY | {"providers", "discovery", "replicas"}, "DATA_FIELDS")
    summaries = {key: controls.summarize(data[key]) for key in ("providers", "discovery", "replicas")}
    for key, summary in summaries.items():
        if not summary["subject_count"] or summary["unresolved_subjects"]:
            finding("data_distribution", key.upper() + "_CONTROL_UNRESOLVED")
    finish("data_distribution", {**inventory(data, controls), **summaries})
    evaluation = audit["evaluation"]
    exact(evaluation, INVENTORY | {"roster", "roster_sha256", "total_key_slots", "threshold", "authors", "authors_complete"}, "EVALUATION_FIELDS")
    sequence(evaluation["authors"], "AUTHOR_ARRAY")
    digest(evaluation["roster_sha256"], "ROSTER_DIGEST")
    require(canonical_sha256(evaluation["roster"]) == evaluation["roster_sha256"], "ROSTER_BINDING")
    quorum = controls.quorum(evaluation["roster"], evaluation["threshold"], evaluation["authors"],
                             total_key_slots=evaluation["total_key_slots"], authors_complete=evaluation["authors_complete"])
    require(not evaluation["authors_complete"] or bool(evaluation["authors"]), "AUTHOR_INVENTORY_EMPTY")
    require(not evaluation["inventory_complete"] or quorum["unidentified_key_slots"] == 0, "KEY_INVENTORY_INCOMPLETE")
    finish("evaluation", {**inventory(evaluation, controls), **quorum})
    if quorum["unresolved_control_key_slots"] or quorum["author_control_unresolved"]:
        finding("evaluation", "EVALUATION_CONTROL_UNRESOLVED")
    if quorum["author_related_subjects"]:
        finding("evaluation", "AUTHOR_COMMON_CONTROL")
    if not quorum["author_separated_candidate_key_threshold_met"]:
        finding("evaluation", "AUTHOR_SEPARATED_KEY_THRESHOLD_NOT_ESTABLISHED")
    authority = audit["authority"]
    exact(authority, INVENTORY | {"routes"}, "AUTHORITY_FIELDS")
    routes = indexed(authority["routes"], {"id", "role", "roster", "roster_sha256", "total_key_slots", "threshold", "evidence_sha256"}, "AUTHORITY_ROUTE")
    route_reports, role_groups = [], collections.defaultdict(lambda: {"roles": set(), "routes": set(), "subjects": set()})
    key_uses = collections.defaultdict(lambda: {"subjects": set(), "roles": set(), "routes": set()})
    subject_uses = collections.defaultdict(lambda: {"roles": set(), "routes": set()})
    for identity, row in sorted(routes.items()):
        require(row["role"] in AUTHORITY_ROLES, "AUTHORITY_ROLE")
        digest(row["roster_sha256"], "ROSTER_DIGEST")
        require(canonical_sha256(row["roster"]) == row["roster_sha256"], "ROSTER_BINDING")
        current = controls.reference(row["evidence_sha256"], nullable=True)
        q = controls.quorum(row["roster"], row["threshold"], total_key_slots=row["total_key_slots"])
        route_reports.append({"id": identity, "role": row["role"], "route_reference_current": current, **q})
        for subject in row["roster"]:
            # Identity reuse is known even when no ownership group can be
            # credited. Aggregate bounded roster entries, never subject pairs.
            subject_uses[subject]["roles"].add(row["role"])
            subject_uses[subject]["routes"].add(identity)
            key = controls.subjects[subject]["key_sha256"]
            if key is not None:
                key_uses[key]["subjects"].add(subject)
                key_uses[key]["roles"].add(row["role"])
                key_uses[key]["routes"].add(identity)
            group = controls.declared_group_for(subject)
            if group is not None:
                role_groups[group]["roles"].add(row["role"])
                role_groups[group]["routes"].add(identity)
                role_groups[group]["subjects"].add(subject)
        if not current or q["unresolved_control_key_slots"]:
            finding("authority", "AUTHORITY_ROUTE_UNRESOLVED:" + identity)
        if q["known_groups_sufficient_to_approve"] == 1:
            finding("authority", "SINGLE_DECLARED_CONTROLLER_ROUTE:" + identity)
    missing_roles = sorted(set(AUTHORITY_ROLES) - {row["role"] for row in routes.values()})
    for role in missing_roles:
        finding("authority", "MISSING_AUTHORITY_ROLE:" + role)
    role_groups = {group: {key: sorted(values) for key, values in row.items()}
                   for group, row in sorted(role_groups.items())}
    evaluation_groups, evaluation_keys = collections.defaultdict(list), collections.defaultdict(list)
    evaluation_subjects = set(evaluation["roster"])
    for subject in evaluation["roster"]:
        key = controls.subjects[subject]["key_sha256"]
        if key is not None:
            evaluation_keys[key].append(subject)
        group = controls.declared_group_for(subject)
        if group is not None:
            evaluation_groups[group].append(subject)
    overlaps = [{"group": group, "evaluation_subjects": sorted(subjects),
                 "authority_roles": role_groups[group]["roles"], "authority_routes": role_groups[group]["routes"]}
                for group, subjects in sorted(evaluation_groups.items()) if group in role_groups]
    key_reuse = [{"key_sha256": key, "authority_subjects": sorted(row["subjects"]),
                  "authority_roles": sorted(row["roles"]), "authority_routes": sorted(row["routes"]),
                  "evaluation_subjects": sorted(evaluation_keys.get(key, []))}
                 for key, row in sorted(key_uses.items())
                 if len(row["routes"]) > 1 or key in evaluation_keys]
    subject_reuse = [{"subject": subject, "key_sha256": controls.subjects[subject]["key_sha256"],
                      "authority_roles": sorted(row["roles"]), "authority_routes": sorted(row["routes"]),
                      "evaluation_subjects": [subject] if subject in evaluation_subjects else []}
                     for subject, row in sorted(subject_uses.items())
                     if len(row["routes"]) > 1 or subject in evaluation_subjects]
    finish("authority", {**inventory(authority, controls), "routes": route_reports, "missing_roles": missing_roles,
                          "cross_role_control_groups": role_groups, "evaluation_authority_control_overlap": overlaps,
                          "key_fingerprint_reuse": key_reuse, "subject_identity_reuse": subject_reuse,
                          "identity_reuse_scope": "declared key fingerprints or repeated subject IDs, including unknown ownership; no control-group or acceptance credit",
                          "overlap_scope": "declared control including stale relations; diagnostic, not an automatic conflict verdict",
                          "alternate_route_scope": "each route stands separately; one route never hides another"})
    exact(audit["resources"], {"funding", "hardware"}, "RESOURCES_FIELDS")
    resources = {key: resource_report(value, controls) for key, value in audit["resources"].items()}
    for key, report in resources.items():
        if (not report["accounting_inventory_current"] or report["total_units"] is None
                or report["unknown_owner_units"] != 0 or not report["unit_reference_current"]):
            finding("resources", key.upper() + "_DENOMINATOR_OR_CONTROL_UNRESOLVED")
    axes["resources"] = resources
    missing_context = sorted(CONTEXT_FIELDS - set(audit["context"]))
    if missing_context:
        finding("context", "INCOMPLETE_DEPLOYMENT_CONTEXT")
    if not controls.registry_current:
        finding("context", "REGISTRY_WINDOW_NOT_CURRENT")
    finding("all", "EXTERNAL_INDEPENDENCE_ACCEPTANCE_NOT_PERFORMED")
    return {"schema": POLICY["report_schema"], "status": "HOLD", "audit_sha256": canonical_sha256(audit),
            "control_registry_sha256": controls.sha256, "policy_sha256": audit["policy_sha256"],
            "context": audit["context"], "window": audit["window"], "missing_context_fields": missing_context,
            "axes": axes, "findings": findings, "evidence_references_authenticated": False,
            "independent_administration_verified": False, "permissionless_utility_accepted": False,
            "public_network_ready": False, "production_activation": False}


def bounded_read(path):
    with Path(path).open("rb") as source:
        return parse_json(source.read(MAX_BYTES + 1))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, help="strict JSON object with registry and audit fields")
    parser.add_argument("--output", help="write report; otherwise print it (HOLD is not qualification)")
    args = parser.parse_args()
    try:
        policy = bounded_read(Path(__file__).resolve().parents[1] / "config/pon/decentralization-audit-v1.json")
        require(policy == POLICY, "INSTALLED_POLICY_BINDING")
        value = bounded_read(args.input)
        exact(value, {"registry", "audit"}, "INPUT_FIELDS")
        report = evaluate(value["audit"], value["registry"])
        text = json.dumps(report, indent=2, sort_keys=True) + "\n"
        if args.output:
            require(Path(args.output).resolve() != Path(args.input).resolve(), "OUTPUT_OVERWRITES_INPUT")
            with Path(args.output).open("x", encoding="utf-8") as target:
                target.write(text)
        else:
            print(text, end="")
    except (ValueError, OSError) as error:
        parser.exit(2, str(error) + "\n")


if __name__ == "__main__":
    main()
