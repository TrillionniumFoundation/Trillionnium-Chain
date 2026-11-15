#!/usr/bin/env python3
"""Read-only custody declarations and local evidence consistency; always HOLD.

Opaque labels describe declared failure domains. Their different spellings do
not authenticate different people, machines, administrators or recovery paths.
The small incidence calculation detects declared common control; it is not an
independence theorem, a cryptographic bound or permission to install a pin.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

from pq_lifetime_budget import BudgetError, strict_json
from pq_source_reader import SourceReadError, read_regular

SCHEMA = "trnm-pq-root-custody-review-v1"
RESULT_SCHEMA = "trnm-pq-root-custody-review-result-v1"
DEFAULT_MANIFEST = "config/pon/pq-root-custody-review-v1.json"
MAX_BYTES = 1024 * 1024
ROLES = ("root", "writer", "anchor", "provider")
AXES = ("operator", "device", "backup", "recovery")
SUITES = ("ML-DSA-87", "SLH-DSA-SHA2-256s")
FRESHNESS_REFS = {
    "authenticated_source_ref": "external-pin-provenance",
    "independent_survival_ref": "independent-survival-audit",
    "age_policy_ref": "freshness-policy",
    "recovery_drill_ref": "recovery-drill",
}
EVIDENCE_KINDS = {"custody-observation", *FRESHNESS_REFS.values()}
CLAIMS = {
    "independent_custody_verified": False,
    "anchor_independence_verified": False,
    "freshness_source_authenticated": False,
    "whole_chain_pq_qualified": False,
    "production_activation": False,
    "actual_lifetime_failure_bound": None,
}


class CustodyReviewError(ValueError):
    pass


def require(ok, message):
    if not ok:
        raise CustodyReviewError(message)


def fields(value, names, where):
    require(type(value) is dict and set(value) == set(names), "invalid fields: " + where)


def label(value, where):
    require(type(value) is str and re.fullmatch(r"[a-z][a-z0-9-]{0,63}", value) is not None,
            "invalid opaque label: " + where)


def hex_digest(value, width, where):
    require(type(value) is str and re.fullmatch(r"[0-9a-f]{" + str(width) + "}", value) is not None
            and value != "0" * width, "invalid digest: " + where)


def labels(value, where, maximum=8, nonempty=False):
    require(type(value) is list and int(nonempty) <= len(value) <= maximum, "invalid list: " + where)
    for item in value:
        label(item, where)
    require(len(set(value)) == len(value), "duplicate label: " + where)


def minimum_declared_domains(keys, axis):
    """Exact bounded set-union calculation on at most six declared keys."""
    if len(keys) != 6:
        return None
    domain_masks = {}
    for index, key in enumerate(keys):
        for domain in key["domains"][axis]:
            domain_masks[domain] = domain_masks.get(domain, 0) | (1 << index)
    costs = {0: 0}
    for mask in domain_masks.values():
        for present, cost in list(costs.items()):
            combined = present | mask
            costs[combined] = min(costs.get(combined, 7), cost + 1)
    qualified = []
    for mask, cost in costs.items():
        if all(sum(bool(mask & (1 << index)) for index, key in enumerate(keys)
                   if key["suite"] == suite) >= 2 for suite in SUITES):
            qualified.append(cost)
    return min(qualified) if qualified else None


def validate_manifest(data):
    fields(data, ("schema", "rosters", "evidence", "recovery_floor", "claims"), "manifest")
    require(data["schema"] == SCHEMA, "wrong schema")
    fields(data["claims"], CLAIMS, "claims")
    for key, expected in CLAIMS.items():
        require(type(data["claims"][key]) is type(expected) and data["claims"][key] == expected,
                "unsupported assurance promotion: " + key)
    require(type(data["evidence"]) is list and len(data["evidence"]) <= 128, "evidence count")
    evidence = {}
    paths = set()
    for item in data["evidence"]:
        fields(item, ("id", "path", "sha256", "kind"), "evidence entry")
        label(item["id"], "evidence id")
        require(item["id"] not in evidence, "duplicate evidence id")
        path = item["path"]
        require(type(path) is str and 0 < len(path) <= 512 and path.startswith("evidence/")
                and "\\" not in path and "\x00" not in path
                and all(part not in ("", ".", "..") for part in path.split("/")), "unsafe evidence path")
        require(path not in paths, "duplicate evidence path")
        paths.add(path)
        hex_digest(item["sha256"], 64, "evidence SHA-256")
        require(type(item["kind"]) is str and item["kind"] in EVIDENCE_KINDS, "unknown evidence kind")
        evidence[item["id"]] = item

    fields(data["rosters"], ROLES, "rosters")
    all_keys = set()
    domain_roles = {axis: {} for axis in AXES}
    minimums = {}
    missing = []
    for role in ROLES:
        roster = data["rosters"][role]
        fields(roster, ("keys",), "roster " + role)
        keys = roster["keys"]
        require(type(keys) is list and len(keys) <= 6, "roster key count")
        counts = {suite: 0 for suite in SUITES}
        for key in keys:
            fields(key, ("key_id", "suite", "domains", "evidence_refs"), "key")
            hex_digest(key["key_id"], 128, "key id")
            require(key["key_id"] not in all_keys, "key reused within or across roles")
            all_keys.add(key["key_id"])
            require(type(key["suite"]) is str and key["suite"] in SUITES, "wrong suite")
            counts[key["suite"]] += 1
            require(counts[key["suite"]] <= 3, "family roster exceeds three")
            fields(key["domains"], AXES, "key domains")
            for axis in AXES:
                labels(key["domains"][axis], axis, nonempty=True)
                for domain in key["domains"][axis]:
                    domain_roles[axis].setdefault(domain, set()).add(role)
            labels(key["evidence_refs"], "key evidence refs")
            for ref in key["evidence_refs"]:
                require(ref in evidence and evidence[ref]["kind"] == "custody-observation",
                        "key evidence reference missing or wrong kind")
            if not key["evidence_refs"]:
                missing.append(role + ":key-evidence:" + key["key_id"])
        if counts != {suite: 3 for suite in SUITES}:
            missing.append(role + ":complete-six-key-roster")
        minimums[role] = {axis: minimum_declared_domains(keys, axis) for axis in AXES}

    floor = data["recovery_floor"]
    fields(floor, ("source", "enrollment_commitment", "head", *FRESHNESS_REFS), "recovery floor")
    require(floor["source"] in ("unprovided", "externally-provisioned"), "local restore is not external provenance")
    if floor["enrollment_commitment"] is not None:
        hex_digest(floor["enrollment_commitment"], 128, "floor enrollment")
    else:
        missing.append("recovery-floor:enrollment")
    if floor["head"] is not None:
        fields(floor["head"], ("version", "root"), "floor head")
        require(type(floor["head"]["version"]) is int and 0 <= floor["head"]["version"] <= 128,
                "invalid floor version")
        hex_digest(floor["head"]["root"], 128, "floor head root")
    else:
        missing.append("recovery-floor:head")
    for field, kind in FRESHNESS_REFS.items():
        ref = floor[field]
        if ref is None:
            missing.append("recovery-floor:" + field)
        else:
            label(ref, field)
            require(ref in evidence and evidence[ref]["kind"] == kind,
                    "floor evidence reference missing or wrong kind: " + field)
    if floor["source"] == "unprovided":
        require(all(floor[field] is None for field in ("enrollment_commitment", "head", *FRESHNESS_REFS)),
                "unprovided floor cannot carry provenance or a pin")
        missing.append("recovery-floor:external-source")

    shared = [{"axis": axis, "domain": domain, "roles": sorted(roles)}
              for axis in AXES for domain, roles in sorted(domain_roles[axis].items()) if len(roles) > 1]
    single = [{"role": role, "axis": axis} for role in ROLES for axis in AXES
              if minimums[role][axis] == 1]
    return {
        "schema": RESULT_SCHEMA, "status": "HOLD", "declaration_contract_satisfied": True,
        "declared_inventory_complete": not missing, "missing_evidence": sorted(missing),
        "minimum_declared_domains_for_and_quorum": minimums,
        "single_declared_domain_quorums": single, "declared_cross_role_shared_domains": shared,
        "declared_separation_consistent": not missing and not shared and not single,
        "evidence_files_checked": False, "evidence_authenticity_verified": False,
        "enrolled_key_binding_verified": False,
        "signed_ancestry_verified": False, "independent_common_restore_exclusion_proved": False,
        "recovery_floor_installation_authorized": False,
        "observation_scope": "declarations-and-local-file-consistency-only", **CLAIMS,
    }


def inspect(root, manifest_path=DEFAULT_MANIFEST):
    try:
        raw = read_regular(Path(root), manifest_path, MAX_BYTES)
        data = strict_json(raw)
        report = validate_manifest(data)
        checked = {}
        total = 0
        for item in data["evidence"]:
            contents = read_regular(Path(root), item["path"], MAX_BYTES)
            total += len(contents)
            require(total <= 16 * MAX_BYTES, "total evidence byte limit")
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
