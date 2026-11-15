#!/usr/bin/env python3
"""Read-only declared common control and signer availability; always HOLD.

Network and power failures can remove signer availability; they never confer
key access. All incidence calculations are conditional on the supplied map.
Different labels, verified file bytes and complete declarations do not establish
independent operators, fresh recovery state or deployment qualification.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

import pq_root_custody_review_v1 as v1
from pq_lifetime_budget import BudgetError, strict_json
from pq_source_reader import SourceReadError, read_regular

SCHEMA = "trnm-pq-root-custody-review-v2"
RESULT_SCHEMA = "trnm-pq-root-custody-review-result-v2"
DEFAULT_MANIFEST = "config/pon/pq-root-custody-review-v2.json"
AVAILABILITY_AXES = ("network", "power")
ALL_AXES = (*v1.AXES, *AVAILABILITY_AXES)
MAX_GROUPS = 128
MAX_GROUP_DOMAINS = 32
CLAIMS = {
    "availability_independence_verified": False,
    "cross_axis_control_coverage_verified": False,
    "independent_operational_qualification": False,
}
CustodyReviewError = v1.CustodyReviewError
require, fields, label, labels = v1.require, v1.fields, v1.label, v1.labels


def minimum_factors(keys, masks, both_families):
    """Exact listed-factor minimum on at most six keys, not a true-cost bound."""
    if len(keys) != 6:
        return None
    costs = {0: 0}
    for mask in masks:
        for present, cost in list(costs.items()):
            combined = present | mask
            costs[combined] = min(costs.get(combined, 7), cost + 1)
    candidates = []
    for mask, cost in costs.items():
        counts = [sum(bool(mask & (1 << index)) for index, key in enumerate(keys)
                      if key["suite"] == suite) for suite in v1.SUITES]
        if (all(count >= 2 for count in counts) if both_families
                else any(count >= 2 for count in counts)):
            candidates.append(cost)
    return min(candidates) if candidates else None


def validate_manifest(data):
    fields(data, ("schema", "custody_v1", "availability_domains", "common_control_review", "claims"),
           "manifest V2")
    require(data["schema"] == SCHEMA, "wrong V2 schema")
    fields(data["claims"], CLAIMS, "V2 claims")
    for key, expected in CLAIMS.items():
        require(type(data["claims"][key]) is bool and data["claims"][key] is expected,
                "unsupported assurance promotion: " + key)
    base = v1.validate_manifest(data["custody_v1"])
    evidence = {row["id"]: row for row in data["custody_v1"]["evidence"]}

    def evidence_refs(refs, where):
        labels(refs, where)
        for ref in refs:
            require(ref in evidence and evidence[ref]["kind"] == "custody-observation",
                    "missing or wrong-kind V2 evidence: " + where)
        return bool(refs)

    by_id = {key["key_id"]: (role, key) for role in v1.ROLES
             for key in data["custody_v1"]["rosters"][role]["keys"]}
    mappings = data["availability_domains"]
    require(type(mappings) is list and len(mappings) <= 24, "availability key count")
    availability = {}
    missing = list(base["missing_evidence"])
    for mapping in mappings:
        fields(mapping, ("key_id", *AVAILABILITY_AXES, "evidence_refs"), "availability mapping")
        key_id = mapping["key_id"]
        v1.hex_digest(key_id, 128, "availability key")
        require(key_id in by_id and key_id not in availability, "unknown or duplicate availability key")
        for axis in AVAILABILITY_AXES:
            labels(mapping[axis], axis, nonempty=True)
        if not evidence_refs(mapping["evidence_refs"], "availability"):
            missing.append("availability:key-evidence:" + key_id)
        availability[key_id] = mapping
    for key_id in sorted(set(by_id) - set(availability)):
        missing.append("availability:key-mapping:" + key_id)

    # Each domain is a listed causal factor. Control axes grant listed key
    # access and hence the ability to withhold signatures. Network/power only
    # disable availability. Groups project directly onto their listed domains;
    # sharing one domain does not create an unstated transitive control edge.
    domains = {}
    for key_id, (role, key) in by_id.items():
        for axis in ALL_AXES:
            names = (key["domains"][axis] if axis in v1.AXES
                     else availability.get(key_id, {}).get(axis, []))
            for name in names:
                domains.setdefault((axis, name), set()).add(key_id)
    factors = [("domain:" + axis + ":" + name, {(axis, name)})
               for axis, name in sorted(domains)]
    shared_domains = [
        {"axis": axis, "domain": name, "roles": sorted({by_id[key_id][0] for key_id in reached})}
        for (axis, name), reached in sorted(domains.items())
        if len({by_id[key_id][0] for key_id in reached}) > 1
    ]
    review = data["common_control_review"]
    fields(review, ("coverage", "groups", "evidence_refs"), "common-control review")
    require(review["coverage"] in ("unprovided", "declared"), "invalid common-control coverage")
    require(type(review["groups"]) is list and len(review["groups"]) <= MAX_GROUPS,
            "common-control group count")
    has_review_evidence = evidence_refs(review["evidence_refs"], "common-control review")
    if review["coverage"] == "unprovided":
        require(not review["groups"] and not review["evidence_refs"],
                "unprovided common-control review cannot carry declarations")
        missing.append("common-control:coverage")
    elif not has_review_evidence:
        missing.append("common-control:review-evidence")
    group_ids = set()
    group_roles = []
    for group in review["groups"]:
        fields(group, ("id", "domains", "evidence_refs"), "common-control group")
        label(group["id"], "common-control group id")
        require(group["id"] not in group_ids, "duplicate common-control group")
        group_ids.add(group["id"])
        require(type(group["domains"]) is list and 2 <= len(group["domains"]) <= MAX_GROUP_DOMAINS,
                "common-control member count")
        members = set()
        for member in group["domains"]:
            fields(member, ("axis", "domain"), "common-control domain")
            require(type(member["axis"]) is str and member["axis"] in ALL_AXES, "unknown domain axis")
            label(member["domain"], "common-control domain")
            identity = (member["axis"], member["domain"])
            require(identity in domains and identity not in members,
                    "unknown or duplicate common-control domain")
            members.add(identity)
        if not evidence_refs(group["evidence_refs"], "common-control group"):
            missing.append("common-control:group-evidence:" + group["id"])
        factors.append(("group:" + group["id"], members))
        roles = sorted({by_id[key_id][0] for member in members for key_id in domains[member]})
        if len(roles) > 1:
            group_roles.append({"group": group["id"], "roles": roles})

    control_minimums, availability_minimums, availability_by_axis = {}, {}, {}
    single_control, single_outage = [], []
    for role in v1.ROLES:
        keys = data["custody_v1"]["rosters"][role]["keys"]
        positions = {key["key_id"]: index for index, key in enumerate(keys)}

        def mask(members, control_only=False):
            reached = set().union(*(domains[member] for member in members
                                    if not control_only or member[0] in v1.AXES))
            return sum(1 << positions[key_id] for key_id in reached if key_id in positions)

        control_masks = [(name, mask(members, True)) for name, members in factors]
        outage_masks = [(name, mask(members)) for name, members in factors]
        control_minimums[role] = minimum_factors(keys, [m for _, m in control_masks], True)
        complete_availability = len(keys) == 6 and all(key["key_id"] in availability for key in keys)
        availability_minimums[role] = (minimum_factors(keys, [m for _, m in outage_masks], False)
                                       if complete_availability else None)
        availability_by_axis[role] = {
            axis: minimum_factors(keys, [mask({member}) for member in domains if member[0] == axis], False)
            if complete_availability else None for axis in AVAILABILITY_AXES
        }
        if len(keys) == 6:
            single_control.extend({"role": role, "factor": name} for name, value in control_masks
                                  if minimum_factors(keys, [value], True) == 1)
            single_outage.extend({"role": role, "factor": name} for name, value in outage_masks
                                 if minimum_factors(keys, [value], False) == 1)

    complete = not missing
    return {
        "schema": RESULT_SCHEMA, "status": "HOLD", "custody_v1": base,
        "declaration_contract_satisfied": True, "declared_inventory_complete": complete,
        "missing_evidence": sorted(missing),
        "declared_common_control_coverage": review["coverage"],
        "listed_factor_minimum_for_and_key_control": control_minimums,
        "listed_factor_minimum_to_block_and_quorum": availability_minimums,
        "listed_availability_axis_minimum_to_block_and_quorum": availability_by_axis,
        "single_listed_factor_key_control": single_control,
        "single_listed_factor_quorum_outages": single_outage,
        "declared_cross_role_shared_domains": shared_domains,
        "declared_cross_role_common_groups": group_roles,
        "declared_separation_consistent": (complete and base["declared_separation_consistent"]
                                           and not single_control and not single_outage
                                           and not shared_domains and not group_roles),
        "evidence_files_checked": False, "evidence_authenticity_verified": False,
        "independent_common_restore_exclusion_proved": False,
        "recovery_floor_installation_authorized": False,
        "actual_lifetime_failure_bound": None, "whole_chain_pq_qualified": False,
        "production_activation": False, **CLAIMS,
        "observation_scope": "declared-incidence-and-local-file-consistency-only",
        "minimum_scope": "minimum-over-listed-factors-only-not-a-certified-lower-bound",
    }


def inspect(root, manifest_path=DEFAULT_MANIFEST):
    try:
        raw = read_regular(Path(root), manifest_path, v1.MAX_BYTES)
        data = strict_json(raw)
        report = validate_manifest(data)
        checked, total = {}, 0
        for item in data["custody_v1"]["evidence"]:
            contents = read_regular(Path(root), item["path"], v1.MAX_BYTES)
            total += len(contents)
            require(total <= 16 * v1.MAX_BYTES, "total evidence byte limit")
            observed = hashlib.sha256(contents).hexdigest()
            require(observed == item["sha256"], "evidence byte mismatch: " + item["id"])
            checked[item["id"]] = observed
    except (SourceReadError, BudgetError) as error:
        raise CustodyReviewError(str(error)) from error
    report.update({"evidence_files_checked": True, "evidence_files_sha256": checked,
                   "manifest_sha256": hashlib.sha256(raw).hexdigest()})
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--manifest", default=DEFAULT_MANIFEST)
    args = parser.parse_args()
    try:
        report = inspect(args.root, args.manifest)
    except (CustodyReviewError, OSError, ValueError, TypeError) as error:
        print(json.dumps({"schema": RESULT_SCHEMA, "status": "REFUSE", "reason": str(error)},
                         sort_keys=True), file=sys.stderr)
        return 2
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
