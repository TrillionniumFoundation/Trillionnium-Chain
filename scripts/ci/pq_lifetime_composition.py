#!/usr/bin/env python3
"""Review the declared V1/root inventory union and conditional AND arithmetic.

The current-v3 entry retains the original v2 manifest by exact identity.
This is a research accounting contract, not a theorem checker. The two source
inventories do not instantiate one security game. No numeric declaration, source
checksum, or successful inspection can produce an actual lifetime bound.
"""
from __future__ import annotations

import argparse
import copy
from fractions import Fraction
import hashlib
import json
from pathlib import Path
import sys

import pq_lifetime_budget as legacy
import pq_lifetime_current_v2 as current_lifetime
import pq_root_dependency_register as root_register
from pq_source_reader import SourceReadError, read_regular

SCHEMA = "trnm-pq128-lifetime-composition-current-v3"
RESULT_SCHEMA = "trnm-pq128-lifetime-composition-current-result-v3"
ARITHMETIC_SCHEMA = "trnm-pq128-root-composition-arithmetic-v2"
DEFAULT_MANIFEST = "config/pon/pq128-lifetime-composition-current-v3.json"
REVIEW_BASE = "0f9b30549328e5be20f4d3e6e27bd132b42d90de"
EXPERIMENT_ID = "trnm-proposed-joint-lifetime-experiment-v2"
COMMON_GAME = "uninstantiated-common-root-game-v2"
MAX_BYTES = legacy.MAX_BYTES

INPUTS = {
    "legacy": {
        "path": legacy.DEFAULT_MANIFEST,
        "sha256": "0315e07ca2988b3b209a6fd2980ca6d9aa22a5bb3aa98b5444a041852b2f0afd",
        "declared_revision": "0f9b30549328e5be20f4d3e6e27bd132b42d90de",
        "revision_semantics": "declared-event-source-revision",
    },
    "root": {
        "path": root_register.DEFAULT_MANIFEST,
        "sha256": "2b641a5e2e1bf66ad924e17d85da21c8cf76d7431fe35c8f448ab921659ba725",
        "declared_revision": root_register.REVIEW_BASE,
        "revision_semantics": "review-base-context-not-all-source-revision",
    },
}
FROZEN_COMPOSITION = {'path': 'config/pon/pq128-lifetime-composition-v2.json', 'sha256': '5b527fbd56885bf7a7cba7516a45f0f911479b0d2867d03ff5361ee3e7a8b052'}
CURRENT_CORRESPONDENCE = {'path': 'config/pon/pq128-source-correspondence-current-v2.json', 'sha256': '2aa06a43b36deca1f6a4b3b6d345468fc50b9b60e0cc3ee764f3a14a289b0c93', 'source_snapshot_sha256': '5b409e39276cdd6df0a012625c31e75d382944f87d2c87725b51e089464a8140'}
PRIMITIVES = {
    "sha256": "FIPS180-4/SHA-256", "sha512": "FIPS180-4/SHA-512",
    "shake128": "FIPS202/SHAKE128", "shake256": "FIPS202/SHAKE256",
}
COVERAGE = [
    "online", "offline", "preprocessing", "failed", "cancelled", "rejected",
    "unpublished", "helpers", "recursive", "all-keys", "all-epochs",
    "shared-uses", "authority-surviving-retirement",
]
RESOURCE_VARIABLES = (
    "adversary_total_queries", "online_queries", "offline_search_queries",
    "preprocessing_queries", "honest_queries", "simulator_queries",
    "extractor_queries", "classical_advice_bits", "quantum_advice_qubits",
    "total_keys", "total_rosters", "total_epochs", "signing_queries",
    "verification_attempts",
)
LEAVES = {
    "common_failure": ("root-common-failure-whole-lifetime", "joint-root", "common"),
    "shared_game_loss": ("common-game-replacement-whole-lifetime", "joint-root", "shared"),
    "ml_event": ("threshold-family-whole-lifetime", "ML-DSA-87", "ml"),
    "ml_loss": ("family-reduction-whole-lifetime", "ML-DSA-87", "ml"),
    "slh_event": ("threshold-family-whole-lifetime", "SLH-DSA-SHA2-256s", "slh"),
    "slh_loss": ("family-reduction-whole-lifetime", "SLH-DSA-SHA2-256s", "slh"),
}


class CompositionError(ValueError):
    """A conflicting, incomplete or overclaiming declaration must be refused."""


def require(ok, message):
    if not ok:
        raise CompositionError(message)


def exact(value, expected, where):
    try:
        root_register.exact(value, expected, where)
    except root_register.RegisterError as error:
        raise CompositionError(str(error)) from error


def fields(value, names, where):
    require(type(value) is dict and set(value) == set(names.split()),
            "unexpected or missing fields: " + where)


def unknown_leaf(name):
    scope, profile, resource = LEAVES[name]
    return {
        "experiment_id": EXPERIMENT_ID, "game_id": COMMON_GAME,
        "model": legacy.MODEL, "scope": scope, "profile": profile,
        "resource_instance_id": resource, "status": "unknown",
        "bound": None, "theorem": None,
    }


def default_arithmetic():
    return {
        "schema": ARITHMETIC_SCHEMA, "purpose": "research-model",
        "experiment_id": EXPERIMENT_ID, "game_id": COMMON_GAME,
        "combiner": "common-plus-shared-plus-min-complete-family-bounds",
        "family_population": {
            "roles": list(root_register.ROLES),
            "required_by_role": {
                role: {"required": 3 if role == "successor-possession" else 2,
                       "roster_size": 3} for role in root_register.ROLES
            },
            "scope": "all-keys-all-epochs-including-retired-authority",
            "corruption_model": "unqualified",
            "threshold_to_forgery_reduction": "uninstantiated",
        },
        "inputs": {name: unknown_leaf(name) for name in LEAVES},
    }


def default_manifest():
    """Return reviewed declarations; never regenerate a source lock from files."""
    return {
        "schema": SCHEMA, "purpose": "research-obligation-bridge",
        "frozen_review_base_revision": REVIEW_BASE,
        "frozen_composition": copy.deepcopy(FROZEN_COMPOSITION),
        "current_lifetime_correspondence": copy.deepcopy(CURRENT_CORRESPONDENCE),
        "input_manifests": copy.deepcopy(INPUTS),
        "experiment": {
            "id": EXPERIMENT_ID, "model": legacy.MODEL,
            "profile": "proposed-native-pnw1-with-root-v2-v3-v4",
            "status": "uninstantiated", "horizon": None, "stopping_rule": None,
            "initial_state_and_advice": "unqualified",
            "prior_preprocessing_included": True,
            "authority_after_retirement_included": True,
            "joint_corruption_and_custody_model": "unqualified",
        },
        "scope_mappings": {
            "legacy_domains_to_current_candidate": "unproved",
            "root_to_legacy_domains": "unproved",
            "root_replaces_legacy_signature_term": False,
            "root_is_added_to_legacy_sum": False,
            "joint_bound_derived": False,
        },
        "primitive_scope_bridge": {
            primitive: {
                "public_parameter_id": identity,
                "budget_identity": "one-shared-lifetime-scope-across-both-registers",
                "maximum": None, "query_unit": None,
                "merge_rule": "identity-union-no-budget-sum-or-min",
                "reset_at_register_key_epoch_role_recovery": False,
            } for primitive, identity in PRIMITIVES.items()
        },
        "shared_substrates": {
            "keccak-p1600-24": {
                "interfaces": ["shake128", "shake256"],
                "reference": "https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf",
                "interface_level": "xof-to-permutation-mapping-uninstantiated",
                "resource_transform": None, "maximum_queries": None,
                "joint_oracle_replacement_bound": None,
                "independent_oracles_proved": False,
                "other_sha3_profiles_included": False,
            },
        },
        "resource_instances": {
            name: {
                "status": "uninstantiated", "theorem_reference": None,
                "query_unit": None, "quantum_access_model": None,
                "auxiliary_state_kind": "unknown",
                "advice_generation_scope": "unknown",
                "variables": {key: None for key in RESOURCE_VARIABLES},
                "coverage_labels": list(COVERAGE),
                "coverage_labels_are_disjoint_buckets": False,
                "theorem_resource_transform": None,
                "honest_simulator_extractor_inclusion": "theorem-dependent-uninstantiated",
                "node_limits_bound_external_queries": False,
            } for name in ("common", "shared", "ml", "slh")
        },
        "root_event_relation": {
            "statement": "Bad_root subset C union (B_ML intersection B_SLH)",
            "status": "unproved-for-project",
            "common_failure_obligations": [
                "same-complete-statement-purpose-and-current-roster",
                "thresholds-distinct-signers-and-successor-possession",
                "implementation-refinement-and-owner-authority",
                "corruption-custody-revocation-and-all-state-recovery",
                "actual-external-effects-and-surviving-liabilities",
            ],
        },
        "conditional_root_arithmetic": default_arithmetic(),
        "additional_loss_accounting": {
            "placement_in_eight_domains": "unproved", "total": None,
            "known_budget_headroom_is_not_a_security_bound": True,
        },
        "actual_lifetime_failure_bound": None,
        "composition_coverage_proved": False,
        "whole_chain_hash_query_scope_closed": False,
        "whole_chain_pq_qualified": False, "production_activation": False,
    }


def maybe_sum(values):
    """An unknown required additive term never becomes zero."""
    if any(value is None for value in values):
        return None
    return legacy.bounded_sum(values, "conditional composition sum")


def intersection_bound(values):
    """One valid marginal bound also bounds an intersection; no product rule."""
    known = [value for value in values if value is not None]
    return min(known) if known else None


def review_arithmetic(data):
    """Exact arithmetic on unverified common-game declarations, never promotion.

Each family total contains its own reduction loss before the minimum. Common
failure and a shared game replacement are separate mandatory additive inputs.
Even a numeric zero must be an explicit declaration, not an omitted loss.
"""
    fields(data, "schema purpose experiment_id game_id combiner family_population inputs",
           "arithmetic")
    expected = default_arithmetic()
    for key in ("schema", "experiment_id", "game_id", "combiner", "family_population"):
        exact(data[key], expected[key], "arithmetic." + key)
    require(data["purpose"] in ("research-model", "arithmetic-example"),
            "unsupported arithmetic purpose")
    fields(data["inputs"], " ".join(LEAVES), "arithmetic.inputs")
    values = {}
    for name, row in data["inputs"].items():
        prototype = unknown_leaf(name)
        fields(row, " ".join(prototype), "arithmetic.inputs." + name)
        for key in ("experiment_id", "game_id", "model", "scope", "profile", "resource_instance_id"):
            exact(row[key], prototype[key], name + "." + key)
        require(row["status"] in ("unknown", "declared-model-bound"),
                "unsupported status; a declaration cannot self-certify")
        if row["status"] == "unknown":
            require(row["bound"] is None and row["theorem"] is None,
                    "unknown input requires null bound and theorem")
            values[name] = None
        else:
            theorem = row["theorem"]
            fields(theorem, "reference locator applicability", name + ".theorem")
            for key, value in theorem.items():
                legacy.string(value, name + ".theorem." + key)
            values[name] = legacy.probability(row["bound"], name + ".bound")
    ml = maybe_sum([values["ml_event"], values["ml_loss"]])
    slh = maybe_sum([values["slh_event"], values["slh_loss"]])
    intersection = intersection_bound([ml, slh])
    uncapped = maybe_sum([values["common_failure"], values["shared_game_loss"], intersection])
    conditional = None if uncapped is None else min(Fraction(1), uncapped)
    return {
        "schema": "trnm-pq128-root-composition-arithmetic-result-v2", "status": "HOLD",
        "arithmetic_contract_satisfied": True,
        "experiment_identity_matches": True,
        "family_complete_declared_bounds": {"ML-DSA-87": legacy.rational(ml),
                                             "SLH-DSA-SHA2-256s": legacy.rational(slh)},
        "cryptographic_intersection_subtotal": legacy.rational(intersection),
        "uncapped_declared_sum": legacy.rational(uncapped),
        "conditional_root_declared_bound": legacy.rational(conditional),
        "unknown_inputs": [name for name in LEAVES if values[name] is None],
        "project_event_relation_proved": False,
        "theorems_applicable_to_common_experiment": False,
        "actual_lifetime_failure_bound": None,
        "whole_chain_pq_qualified": False, "production_activation": False,
        "note": "Conditional arithmetic only; references and matching labels do not establish the declared bounds or the project event relation.",
    }


QUERY_TAIL_LEAVES = (
    "bounded_query_failure", "query_budget_overrun", "bounded_game_reduction_loss",
)


def default_query_tail_arithmetic():
    """Separate declarations for a bounded game, resource tail and game lift.

    This does not instantiate a query counter or a global attacker cap. The
    event bound is on Bad intersect {Q <= q}, not a per-invocation estimate.
    A theorem about a truncated algorithm needs a justified lift to that event.
    """
    budget = {"maximum": None, "unit": None}
    return {
        "schema": "trnm-pq128-lifetime-query-tail-arithmetic-v1",
        "purpose": "research-model", "experiment_id": EXPERIMENT_ID,
        "game_id": "uninstantiated-lifetime-query-tail-game-v1",
        "model": legacy.MODEL,
        "scope": "all-keys-all-epochs-including-retired-authority",
        "query_count_definition": "total-lifetime-including-prior-work",
        "bounded_event": "Bad intersection {Q<=q}",
        "overrun_event": "{Q>q}",
        "coverage_labels": list(COVERAGE) + ["initial-state", "classical-advice", "quantum-advice"],
        "coverage_labels_are_disjoint_buckets": False,
        "node_limits_bound_external_queries": False,
        "reset_at_key_epoch_role_recovery": False,
        "query_budget": budget,
        "target": legacy.rational(Fraction(1, 1 << 128)),
        "inputs": {
            name: {"query_budget": copy.deepcopy(budget), "status": "unknown",
                   "bound": None, "theorem": None} for name in QUERY_TAIL_LEAVES
        },
    }


def review_query_tail_arithmetic(data):
    """Evaluate epsilon + P(Q>q) + delta on explicit unverified declarations.

    Whenever Q is a well-defined lifetime resource variable, partition Bad into
    {Q<=q} and {Q>q}. No independence is needed. Applicability of a bounded-game
    theorem, initial advice, resource transformations and the tail bound remain
    separate project obligations. A node timeout never supplies a zero tail.
    """
    expected = default_query_tail_arithmetic()
    fields(data, " ".join(expected), "query-tail arithmetic")
    for key in expected:
        if key not in ("purpose", "query_budget", "inputs"):
            exact(data[key], expected[key], "query-tail." + key)
    require(data["purpose"] in ("research-model", "arithmetic-example"),
            "unsupported query-tail arithmetic purpose")
    budget = data["query_budget"]
    fields(budget, "maximum unit", "query-tail.query_budget")
    if budget["maximum"] is None:
        require(budget["unit"] is None, "unknown query maximum requires unknown unit")
    else:
        legacy.natural(budget["maximum"], "query-tail.query_budget.maximum")
        legacy.string(budget["unit"], "query-tail.query_budget.unit")
    fields(data["inputs"], " ".join(QUERY_TAIL_LEAVES), "query-tail.inputs")
    values = {}
    for name in QUERY_TAIL_LEAVES:
        row = data["inputs"][name]
        fields(row, "query_budget status bound theorem", "query-tail." + name)
        exact(row["query_budget"], budget, "query-tail." + name + ".query_budget")
        require(row["status"] in ("unknown", "declared-model-bound"),
                "query-tail declaration cannot self-certify")
        if row["status"] == "unknown":
            require(row["bound"] is None and row["theorem"] is None,
                    "unknown query-tail input requires null bound and theorem")
            values[name] = None
        else:
            require(budget["maximum"] is not None,
                    "declared query-tail bounds require explicit query maximum and unit")
            fields(row["theorem"], "reference locator applicability", name + ".theorem")
            for key, value in row["theorem"].items():
                legacy.string(value, name + ".theorem." + key)
            values[name] = legacy.probability(row["bound"], name + ".bound")
    known = legacy.bounded_sum([v for v in values.values() if v is not None],
                               "known query-tail subtotal")
    total = maybe_sum(list(values.values()))
    target = legacy.probability(data["target"], "query-tail.target")
    return {
        "schema": "trnm-pq128-lifetime-query-tail-arithmetic-result-v1", "status": "HOLD",
        "arithmetic_contract_satisfied": True,
        "query_budget": copy.deepcopy(budget),
        "declared_input_bounds": {name: legacy.rational(v) for name, v in values.items()},
        "unknown_inputs": [name for name in QUERY_TAIL_LEAVES if values[name] is None],
        "known_declared_subtotal": legacy.rational(known),
        "uncapped_declared_sum": legacy.rational(total),
        "conditional_lifetime_declared_bound": legacy.rational(
            None if total is None else min(Fraction(1), total)),
        "target": legacy.rational(target),
        "remaining_target_after_known_inputs": legacy.rational(target - known),
        "declared_target_exceeded_by_known_inputs": known > target,
        "declared_target_met": None if total is None else total <= target,
        "target_comparison_is_arithmetic_only": True,
        "resource_random_variable_defined_for_project": False,
        "bounded_game_to_project_reduction_proved": False,
        "theorem_applicability_verified": False,
        "composition_coverage_proved": False,
        "whole_chain_hash_query_scope_closed": False,
        "actual_lifetime_failure_bound": None,
        "whole_chain_pq_qualified": False, "production_activation": False,
        "note": "Separate conditional accounting only. Matching counts, units and coverage labels do not define the project's resource variable, prove a tail bound, authenticate advice, or connect a bounded-game theorem to the project. This result is not substituted for or added to either existing register.",
    }


def merge_source_maps(legacy_files, root_files):
    """Do not let one reviewed source silently overwrite another."""
    merged = dict(legacy_files)
    for path, digest in root_files.items():
        require(path not in merged or merged[path] == digest,
                "conflicting source digest across registers: " + path)
        merged[path] = digest
    return dict(sorted(merged.items()))


def bridge_primitives(legacy_data, root_data):
    """Join fixed public identities, never add two budgets for the same oracle."""
    old = {row["id"]: row for row in legacy_data["primitives"]}
    new = root_data["primitives"]
    require(set(old) == set(new) == set(PRIMITIVES), "primitive scope mismatch")
    seen = set()
    out = {}
    for name, identity in PRIMITIVES.items():
        left, right = old[name], new[name]
        require(left["public_parameter_id"] == right["public_parameter_id"] == identity,
                "shared public primitive identity mismatch: " + name)
        require(identity not in seen, "duplicate shared primitive identity")
        seen.add(identity)
        require(left["fixed_across_epochs"] is True and right["fixed_across_epochs"] is True,
                "fixed public primitive cannot be reset")
        lq, rq = left["query_budget"], right["query_budget"]
        require(left["reset_at_epoch"] is False
                and all(rq[key] is False for key in (
                    "reset_at_key_epoch", "reset_at_recovery", "reset_at_role_boundary")),
                "query scope cannot reset at a register, role, key or epoch")
        require(lq["basis"] == rq["basis"] == "unknown"
                and lq["maximum"] is None and rq["maximum"] is None
                and rq["unit"] == "not-instantiated",
                "changed query bounds/units require a new joint review")
        out[name] = {
            "public_parameter_id": identity, "maximum": None, "query_unit": None,
            "legacy_term_ids": sorted(term["id"] for term in legacy_data["terms"]
                                      if name in term["primitive_ids"]),
            "root_use_ids": list(right["use_ids"]),
            "scope": "declared-use-union-only", "query_budget_proved": False,
        }
    return out


def validate_manifest(data):
    exact(data, default_manifest(), "composition manifest")
    return {
        "schema": RESULT_SCHEMA, "status": "HOLD", "inventory_contract_satisfied": True,
        "frozen_review_base_revision": REVIEW_BASE,
        "frozen_composition": copy.deepcopy(FROZEN_COMPOSITION),
        "current_lifetime_correspondence": copy.deepcopy(CURRENT_CORRESPONDENCE),
        "declared_source_union_consistent": False, "source_binding_scope": "unbound",
        "source_revision_bound": False, "deployment_identity_proved": False,
        "transitive_dependency_closure_proved": False,
        "conditional_root_arithmetic": review_arithmetic(data["conditional_root_arithmetic"]),
        "conditional_query_tail_arithmetic": review_query_tail_arithmetic(default_query_tail_arithmetic()),
        "scope_mappings": copy.deepcopy(data["scope_mappings"]),
        "resource_instances": copy.deepcopy(data["resource_instances"]),
        "shared_substrates": copy.deepcopy(data["shared_substrates"]),
        "additional_loss_placement": "unproved", "additional_loss_total": None,
        "allocation_sufficiency_under_declared_losses": None,
        "actual_lifetime_failure_bound": None, "joint_bound_derived": False,
        "composition_coverage_proved": False, "theorem_applicability_verified": False,
        "whole_chain_hash_query_scope_closed": False,
        "whole_chain_pq_qualified": False, "pq_128_qualified": False,
        "production_activation": False,
        "note": "The old domain experiment and the new root inventory are not a proved common experiment. No numeric bound is transferred, substituted, added or promoted.",
    }


def inspect(root, manifest_path=DEFAULT_MANIFEST):
    root = Path(root)
    try:
        raw = read_regular(root, legacy.relative_path(manifest_path, "manifest"), MAX_BYTES)
        data = legacy.strict_json(raw)
        result = validate_manifest(data)
        frozen_raw = read_regular(root, FROZEN_COMPOSITION["path"], MAX_BYTES)
        require(hashlib.sha256(frozen_raw).hexdigest() == FROZEN_COMPOSITION["sha256"],
                "input manifest differs from reviewed bytes: frozen composition")
        children = {}
        for name, item in INPUTS.items():
            child_raw = read_regular(root, item["path"], MAX_BYTES)
            require(hashlib.sha256(child_raw).hexdigest() == item["sha256"],
                    "input manifest differs from reviewed bytes: " + name)
            children[name] = legacy.strict_json(child_raw)
        current_result = current_lifetime.inspect(root)
        old_result = current_result['frozen_model']
        current_sources = current_result['current_source_correspondence']
        require(current_sources['map_sha256'] == CURRENT_CORRESPONDENCE['sha256']
                and current_sources['source_snapshot_sha256'] == CURRENT_CORRESPONDENCE['source_snapshot_sha256'],
                'current lifetime correspondence differs from the reviewed composition input')
        root_result = root_register.inspect(root)
        for name, child in (("legacy", old_result), ("root", root_result)):
            require(child["manifest_sha256"] == INPUTS[name]["sha256"],
                    "child manifest changed between inspections: " + name)
            require(child["actual_lifetime_failure_bound"] is None
                    and child["composition_coverage_proved"] is False
                    and child["whole_chain_pq_qualified"] is False
                    and child["production_activation"] is False,
                    "changed child qualification requires new review")
        require(old_result["experiment"]["source_revision"] == INPUTS["legacy"]["declared_revision"]
                and root_result["review_base_revision"] == INPUTS["root"]["declared_revision"],
                "child revision semantics mismatch")
        require(old_result["purpose"] == "research-model"
                and old_result["source_revision_bound"] is False
                and current_sources["source_files_checked"] is True
                and current_sources["source_revision_bound"] is False
                and root_result["source_files_checked"] is True,
                "source inventories must be checked research inputs")
        require(len(old_result["unknown_terms"]) == 8
                and all(value is None for value in root_result["domain_failure_bounds"].values()),
                "new component bounds require explicit experiment and coverage review")
        files = merge_source_maps(current_sources["source_files_sha256"], root_result["source_files_sha256"])
        shared_paths = sorted(set(current_sources["source_files_sha256"])
                              & set(root_result["source_files_sha256"]))
        source_counts = {
            "legacy": len(current_sources["source_files_sha256"]),
            "root": len(root_result["source_files_sha256"]),
            "shared": len(shared_paths), "union": len(files),
        }
        require(source_counts == {"legacy": 21, "root": 46, "shared": 1, "union": 66}
                and shared_paths == ["trillionnium/crates/trnm-release-bundle/src/pq_release.rs"],
                "declared source union changed; review the mapping")
        scopes = bridge_primitives(children["legacy"], children["root"])
        allocated = legacy.probability(old_result["allocated_sum"], "allocated sum")
        target = legacy.probability(old_result["target"], "target")
        result.update({
            "manifest_sha256": hashlib.sha256(raw).hexdigest(),
            "input_manifests": copy.deepcopy(INPUTS),
            "legacy_source_lock_sha256": current_result["frozen_model_identity"]["source_lock_sha256"],
            "legacy_frozen_model_identity": current_result["frozen_model_identity"],
            "legacy_current_source_correspondence": current_sources,
            "root_declared_source_snapshot_sha256": root_result["declared_source_snapshot_sha256"],
            "declared_source_union_consistent": True,
            "source_binding_scope": "declared-path-union-only",
            "source_counts": source_counts,
            "source_files_sha256": files,
            "shared_source_paths": shared_paths,
            "primitive_scope_union": scopes, "shared_primitive_scope_count": len(scopes),
            "unknown_lifetime_query_budgets": sorted(scopes),
            "unknown_role_lifetime_populations": list(root_register.ROLES),
            "legacy_declared_arithmetic": {
                "experiment": old_result["experiment"],
                "model_arithmetic_sum": old_result["model_arithmetic_sum"],
                "unknown_terms": old_result["unknown_terms"],
                "not_transferred_to_joint_experiment": True,
            },
            "allocation_headroom": legacy.rational(target - allocated),
            "allocation_is_target_only": True,
            "domain_failure_bounds": {name: None for name in root_register.DOMAINS},
        })
        return result
    except (legacy.BudgetError, root_register.RegisterError, SourceReadError,
            KeyError, TypeError) as error:
        raise CompositionError(str(error)) from error


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--manifest", default=DEFAULT_MANIFEST)
    args = parser.parse_args()
    try:
        report = inspect(args.root, args.manifest)
    except (CompositionError, OSError, ValueError) as error:
        print(json.dumps({"schema": RESULT_SCHEMA, "status": "REFUSE", "error": str(error),
                          "actual_lifetime_failure_bound": None, "whole_chain_pq_qualified": False,
                          "production_activation": False}, sort_keys=True))
        return 2
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
