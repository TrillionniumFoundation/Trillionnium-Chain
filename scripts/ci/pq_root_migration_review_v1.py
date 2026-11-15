#!/usr/bin/env python3
"""Read-only material and continuity review for a proposed root migration.

This checker cannot authorize migration, verify a signature or prove a security
reduction. Even a complete packet remains HOLD. Artifact hashes bind reviewed
bytes, not the truth of their contents or an independent evidence producer.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

from pq_lifetime_budget import BudgetError, natural, relative_path, strict_json
from pq_source_reader import SourceReadError, read_regular

SCHEMA = "trnm-pq-root-migration-review-v1"
RESULT_SCHEMA = "trnm-pq-root-migration-review-result-v1"
EVIDENCE_SCHEMA = "trnm-pq-root-migration-review-evidence-v1"
DEFAULT_MANIFEST = "config/pon/pq-root-migration-review-v1.json"
MAX_BYTES = 1024 * 1024
MAX_ITEMS = 128
CURRENT_SUITES = ["ML-DSA-87", "SLH-DSA-SHA2-256s"]
ROLES = {"root-approval", "successor-possession", "anchor-writer",
         "anchor-response", "effect-provider"}
EVIDENCE_KINDS = (
    "transition-statement", "current-authority-envelope", "successor-possession-material",
    "transition-implementation", "history-continuity", "fresh-anchor",
    "effect-reconciliation", "new-profile-security-reduction",
    "shared-oracle-composition",
)
QUERY_COVERAGE = ["online", "offline", "preprocessing", "failed", "cancelled",
                  "unpublished", "recursive", "helpers", "all-key-epochs",
                  "surviving-authority-after-retirement"]
PRIMITIVES = {
    "FIPS180-4/SHA-256", "FIPS180-4/SHA-512",
    "FIPS202/SHAKE128", "FIPS202/SHAKE256",
}


class MigrationReviewError(ValueError):
    """A malformed or incomplete proposed review packet is refused."""


def require(ok, message):
    if not ok:
        raise MigrationReviewError(message)


def fields(value, names, where):
    require(type(value) is dict and set(value) == set(names),
            "unexpected or missing fields: " + where)


def text(value, where):
    require(type(value) is str and 0 < len(value) <= 4096
            and value.strip() == value and "\x00" not in value,
            "invalid text: " + where)
    try:
        value.encode("utf-8")
    except UnicodeError as error:
        raise MigrationReviewError("invalid Unicode: " + where) from error
    return value


def hex_id(value, size, where):
    require(type(value) is str and re.fullmatch(r"[0-9a-f]{" + str(size) + "}", value)
            and any(c != "0" for c in value), "invalid nonzero identity: " + where)
    return value


def count(value, where):
    try:
        number = natural(value, where)
    except BudgetError as error:
        raise MigrationReviewError(str(error)) from error
    require(number <= (1 << 64) - 1, "counter exceeds u64: " + where)
    return number


def rows(value, where, nonempty=False):
    require(type(value) is list and int(nonempty) <= len(value) <= MAX_ITEMS,
            "invalid bounded list: " + where)
    return value


def ids(value, where, size=128):
    rows(value, where)
    for item in value:
        hex_id(item, size, where)
    require(value == sorted(set(value)), "unsorted or duplicate identities: " + where)
    return set(value)


def digest(value):
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=False).encode("utf-8")
    return hashlib.sha512(b"TRNM/RootMigrationReview/Binding/v1\0" + encoded).hexdigest()


def profile(value, where, current=False):
    fields(value, ("id", "source_revision", "policy_commitment", "roster_commitment",
                   "generation", "combiner", "families", "primitive_ids"), where)
    text(value["id"], where + ".id")
    hex_id(value["source_revision"], 40, where + ".source_revision")
    hex_id(value["policy_commitment"], 128, where + ".policy_commitment")
    hex_id(value["roster_commitment"], 128, where + ".roster_commitment")
    count(value["generation"], where + ".generation")
    require(value["combiner"] == "AND", "migration review never allows an OR policy")
    families = rows(value["families"], where + ".families", True)
    require(len(families) == 2, "exactly two family descriptions required")
    suites = []
    for row in families:
        fields(row, ("suite", "quorum", "roster_size", "possession_required"), where)
        suites.append(text(row["suite"], where + ".suite"))
        require(type(row["quorum"]) is int and row["quorum"] == 2
                and type(row["roster_size"]) is int and row["roster_size"] == 3
                and type(row["possession_required"]) is int
                and row["possession_required"] == 3,
                "review requires both 2-of-3 quorums and all-six possession material")
    require(suites == sorted(set(suites)), "duplicate or unsorted family suites")
    if current:
        require(suites == CURRENT_SUITES, "current V3 family configuration differs")
    primitive_ids = rows(value["primitive_ids"], where + ".primitive_ids", True)
    for item in primitive_ids:
        text(item, where + ".primitive_id")
    require(primitive_ids == sorted(set(primitive_ids)), "duplicate or unsorted primitive identity")
    if current:
        require(set(primitive_ids) == PRIMITIVES, "current V3 primitive scope differs")


def population(value, where):
    result = {}
    key_suites, key_roles = {}, {}
    for row in rows(value, where, True):
        fields(row, ("key_id", "role", "generation", "suite"), where)
        key = hex_id(row["key_id"], 128, where + ".key_id")
        require(type(row["role"]) is str and row["role"] in ROLES, "unknown authority role")
        generation = count(row["generation"], where + ".generation")
        text(row["suite"], where + ".suite")
        require(key not in key_suites or key_suites[key] == row["suite"],
                "one key identity has conflicting suite labels")
        key_suites[key] = row["suite"]
        key_roles.setdefault(key, set()).add(row["role"])
        require(len(key_roles[key]) == 1
                or key_roles[key] <= {"root-approval", "successor-possession"},
                "isolated authority roles share a retained key identity")
        identity = (key, row["role"], generation)
        require(identity not in result, "duplicate key/role/epoch record")
        result[identity] = row
    return result


def liability_rows(value, where):
    result = {}
    for row in rows(value, where):
        fields(row, ("operation_id", "intent_sha512", "owner_id", "orphan_epoch",
                     "outcome", "liability_sha512"), where)
        key = hex_id(row["operation_id"], 128, where + ".operation_id")
        for field in ("intent_sha512", "owner_id", "liability_sha512"):
            hex_id(row[field], 128, where + "." + field)
        count(row["orphan_epoch"], where + ".orphan_epoch")
        require(row["outcome"] in ("entered", "unknown", "succeeded", "failed"),
                "unsupported retained effect outcome")
        require(key not in result, "duplicate retained effect operation")
        result[key] = row
    return result


def primitive_rows(value, where):
    result = {}
    for row in rows(value, where, True):
        fields(row, ("public_parameter_id", "prior_scope_id", "observed_queries",
                     "adversary_query_bound", "initial_advice_bound", "coverage"), where)
        identity = text(row["public_parameter_id"], where + ".public_parameter_id")
        hex_id(row["prior_scope_id"], 128, where + ".prior_scope_id")
        count(row["observed_queries"], where + ".observed_queries")
        require(row["adversary_query_bound"] is None and row["initial_advice_bound"] is None,
                "observed queries cannot supply an adversary or initial-advice bound")
        require(row["coverage"] == QUERY_COVERAGE, "incomplete lifetime query coverage")
        require(identity not in result, "shared public primitive has duplicate scopes")
        result[identity] = row
    return result


def continuity(value, before, after):
    fields(value, ("lifetime_id", "before", "after"), "continuity")
    hex_id(value["lifetime_id"], 128, "lifetime_id")
    snapshots = []
    for side in ("before", "after"):
        state = value[side]
        fields(state, ("lifetime_id", "key_epochs", "consumed_nonces", "revoked_keys",
                       "retained_effects", "primitives"), "continuity." + side)
        require(state["lifetime_id"] == value["lifetime_id"],
                "migration changed its lifetime identity")
        snapshots.append((
            population(state["key_epochs"], side + ".key_epochs"),
            ids(state["consumed_nonces"], side + ".consumed_nonces", 64),
            ids(state["revoked_keys"], side + ".revoked_keys"),
            liability_rows(state["retained_effects"], side + ".retained_effects"),
            primitive_rows(state["primitives"], side + ".primitives"),
        ))
    old, new = snapshots
    for snapshot, descriptor in ((old, before), (new, after)):
        generation = count(descriptor["generation"], "profile generation")
        require(all(count(row["generation"], "key generation") <= generation
                    for row in snapshot[0].values()),
                "key inventory contains a future generation")
        active = [row for row in snapshot[0].values()
                  if row["role"] == "root-approval"
                  and count(row["generation"], "key generation") == generation]
        active_suites = {row["suite"] for row in descriptor["families"]}
        require(len(active) == 6 and len({row["key_id"] for row in active}) == 6
                and {row["suite"] for row in active} == active_suites
                and all(sum(row["suite"] == suite for row in active) == 3
                        for suite in active_suites),
                "current root population differs from its six-key profile")
    for key, row in old[0].items():
        require(new[0].get(key) == row, "migration erased or rewrote prior key/epoch history")
    require(old[1] <= new[1], "migration erased consumed nonces")
    require(old[2] <= new[2], "migration erased revoked keys")
    for key, row in old[3].items():
        require(new[3].get(key) == row,
                "migration erased or rewrote an external effect or orphan liability")
    require(set(old[4]) == set(before["primitive_ids"]), "before primitive coverage differs")
    require(set(new[4]) == set(before["primitive_ids"]) | set(after["primitive_ids"]),
            "shared primitive union lost historical scope or invented an unused scope")
    for identity, row in old[4].items():
        successor = new[4][identity]
        require(successor["prior_scope_id"] == row["prior_scope_id"],
                "public primitive advice/query lifetime was reset")
        require(count(successor["observed_queries"], identity) >= count(row["observed_queries"], identity),
                "observed query history decreased")
    target_generation = count(after["generation"], "after generation")
    new_root = [row for row in new[0].values()
                if row["role"] == "root-approval"
                and count(row["generation"], "key generation") == target_generation]
    require(len(new_root) == 6, "successor root population must include exactly six key records")
    suites = {row["suite"] for row in after["families"]}
    require({row["suite"] for row in new_root} == suites
            and all(sum(row["suite"] == suite for row in new_root) == 3 for suite in suites),
            "successor root key populations differ from the profile")
    require(len({row["key_id"] for row in new_root}) == 6,
            "successor root keys must be distinct")
    require(all(row["key_id"] not in new[2] for row in new_root),
            "a revoked key was reintroduced as successor")
    isolated = {row["key_id"] for row in new[0].values()
                if row["role"] in ("anchor-writer", "anchor-response", "effect-provider")}
    require(all(row["key_id"] not in isolated for row in new_root),
            "successor root borrows an isolated writer/anchor/provider key")
    possession = [row for row in new[0].values()
                  if row["role"] == "successor-possession"
                  and count(row["generation"], "key generation") == target_generation]
    require(len(possession) == 6
            and {(row["key_id"], row["suite"]) for row in possession}
                == {(row["key_id"], row["suite"]) for row in new_root},
            "successor possession declarations do not cover all six exact successor keys")
    return {"retained_key_epoch_records": len(new[0]),
            "retained_effect_records": len(new[3]),
            "shared_primitive_ids": sorted(new[4]),
            "roles_with_submitted_records": sorted({row["role"] for row in new[0].values()}),
            "scope": "submitted-records-only-completeness-unverified"}


def material_reference(value, where):
    fields(value, ("path", "sha512", "bytes"), where)
    try:
        relative_path(value["path"], where + ".path")
    except BudgetError as error:
        raise MigrationReviewError(str(error)) from error
    hex_id(value["sha512"], 128, where + ".sha512")
    require(0 < count(value["bytes"], where + ".bytes") <= MAX_BYTES,
            "empty or oversized material")


def evaluate(data):
    fields(data, ("schema", "purpose", "proposal"), "manifest")
    require(data["schema"] == SCHEMA and data["purpose"] == "read-only-migration-review",
            "unsupported migration review contract")
    result = {
        "schema": RESULT_SCHEMA, "status": "HOLD", "proposal_present": False,
        "review_material_complete": False, "material_bytes_checked": False,
        "migration_authorized": False, "migration_implementation_verified": False,
        "cryptographic_verification_performed": False, "theorem_applicability_verified": False,
        "independent_custody_verified": False, "anchor_independence_verified": False,
        "actual_external_effects_verified": False, "whole_chain_pq_qualified": False,
        "complete_key_epoch_population_verified": False,
        "observed_query_counts_bound_adversary": False,
        "composition_coverage_proved": False, "actual_lifetime_failure_bound": None,
        "production_activation": False, "required_evidence_kinds": list(EVIDENCE_KINDS),
    }
    proposal = data["proposal"]
    if proposal is None:
        result["open_obligations"] = ["explicit-versioned-migration-implementation", *EVIDENCE_KINDS]
        return result
    fields(proposal, ("scope", "current_profile", "successor_profile", "transition",
                      "continuity", "evidence"), "proposal")
    fields(proposal["scope"], ("network", "genesis", "owner"), "scope")
    for field, item in proposal["scope"].items():
        hex_id(item, 64, "scope." + field)
    before, after = proposal["current_profile"], proposal["successor_profile"]
    profile(before, "current_profile", True)
    profile(after, "successor_profile")
    require(before["id"] != after["id"] and before["source_revision"] != after["source_revision"],
            "a migration needs a distinct explicit profile and implementation revision")
    require(before["policy_commitment"] != after["policy_commitment"]
            and before["roster_commitment"] != after["roster_commitment"],
            "a migration needs distinct complete policy and roster commitments")
    require(count(after["generation"], "successor generation")
            == count(before["generation"], "current generation") + 1,
            "generation continuity differs")
    transition = proposal["transition"]
    fields(transition, ("operation_id", "predecessor_head", "next_head", "before_sequence",
                        "after_sequence", "nonce", "statement_sha512", "current_profile_sha512",
                        "successor_profile_sha512", "scope_sha512"), "transition")
    for field in ("operation_id", "predecessor_head", "next_head", "statement_sha512",
                  "current_profile_sha512", "successor_profile_sha512", "scope_sha512"):
        hex_id(transition[field], 128, "transition." + field)
    hex_id(transition["nonce"], 64, "transition.nonce")
    require(transition["predecessor_head"] != transition["next_head"], "head did not advance")
    require(count(transition["after_sequence"], "after sequence")
            == count(transition["before_sequence"], "before sequence") + 1,
            "sequence continuity differs")
    require(transition["current_profile_sha512"] == digest(before)
            and transition["successor_profile_sha512"] == digest(after)
            and transition["scope_sha512"] == digest(proposal["scope"]),
            "transition profile or scope binding differs")
    counts = continuity(proposal["continuity"], before, after)
    require(transition["nonce"] not in proposal["continuity"]["before"]["consumed_nonces"]
            and transition["nonce"] in proposal["continuity"]["after"]["consumed_nonces"],
            "migration nonce was reused or not carried into successor history")
    binding = digest({key: proposal[key] for key in proposal if key != "evidence"})
    evidence = proposal["evidence"]
    fields(evidence, EVIDENCE_KINDS, "evidence")
    for kind, record in evidence.items():
        fields(record, ("schema", "kind", "proposal_sha512", "material"), "evidence." + kind)
        require(record["schema"] == EVIDENCE_SCHEMA and record["kind"] == kind
                and record["proposal_sha512"] == binding,
                "evidence is not bound to the complete same migration proposal")
        material_reference(record["material"], kind)
    result.update(proposal_present=True, proposal_sha512=binding,
                  declared_continuity_checked=True, declared_inventory=counts,
                  open_obligations=["actual-current-authority-verification",
                                    "actual-successor-possession-verification",
                                    "implementation-refinement", "independent-custody-and-freshness",
                                    "real-external-effects", "new-profile-concrete-security",
                                    "whole-chain-composition"])
    return result


def inspect(root, manifest=DEFAULT_MANIFEST):
    try:
        raw = read_regular(Path(root), manifest, MAX_BYTES)
        data = strict_json(raw)
        report = evaluate(data)
        if data["proposal"] is not None:
            checked = {}
            for kind, record in data["proposal"]["evidence"].items():
                ref = record["material"]
                content = read_regular(Path(root), ref["path"], MAX_BYTES)
                require(len(content) == int(ref["bytes"]), "material length differs: " + kind)
                require(hashlib.sha512(content).hexdigest() == ref["sha512"],
                        "material bytes differ: " + kind)
                if kind == "transition-statement":
                    require(ref["sha512"] == data["proposal"]["transition"]["statement_sha512"],
                            "actual statement bytes differ from the declared transition")
                checked[kind] = ref
            report.update(review_material_complete=True, material_bytes_checked=True,
                          material=checked,
                          material_scope="bound-input-bytes-only-not-authenticated-evidence")
        report["manifest_sha512"] = hashlib.sha512(raw).hexdigest()
        return report
    except (BudgetError, SourceReadError) as error:
        raise MigrationReviewError(str(error)) from error


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--manifest", default=DEFAULT_MANIFEST)
    args = parser.parse_args()
    try:
        report = inspect(args.root, args.manifest)
    except (MigrationReviewError, OSError, ValueError) as error:
        print(json.dumps({"schema": RESULT_SCHEMA, "status": "REFUSE", "reason": str(error),
                          "migration_authorized": False, "actual_lifetime_failure_bound": None},
                         sort_keys=True), file=sys.stderr)
        return 2
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
