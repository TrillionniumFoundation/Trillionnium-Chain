"""Read-only projection of four separate PoN propositions.

Replays supplied observations through existing research readers. It does not
attest real-world truth or execution provenance. CLI exit zero means reproduced
observations, never four proved propositions or permission to change anything.
"""
from __future__ import annotations
import argparse
import hashlib
import importlib
import json
import os
import re
from pathlib import Path
from fractions import Fraction
import sys

REFERENCE_SOURCE = "e2a02f9271b49f146e70806c8a66e161b5973971"
SCHEMA = "pon-four-propositions-evidence-view-v1"
INPUT_SCHEMA = "pon-four-propositions-evidence-input-v1"
PIN_SCHEMA = "pon-four-propositions-review-pins-v1"
MAX_BYTES = 4 * 1024 * 1024
SOURCE_BLOBS = {
    "formal/pon-nakamoto-v1/contract_wire.py": "37f62b2f0913e372bc1c75fed2cd3a3e1267870b",
    "formal/pon-nakamoto-v1/strict_signature.py": "b0cedca3a0423f2563359a8645ba322f966804dc",
    "formal/pon-nakamoto-v1/demand_evidence.py": "ebe593a26270b9a4ecf04c088342fa7cdae9cc7b",
    "formal/pon-nakamoto-v1/work_utility.py": "883e7126178c95221d3803459a24181490ae122b",
    "formal/pon-nakamoto-v1/upgrade_policy.py": "b88a4ed2a727cff06a12b0689e1503d214af22c6",
    "formal/pon-nakamoto-v1/work_profile_contract_v1.py": "f9f5784cb92399aaffd0463eec847c2800707d81",
    "formal/pon-nakamoto-v1/evaluation_bundle.py": "c0d1447b6caec75a64736150e651c127d8385f08",
    "formal/pon-nakamoto-v1/evaluation.py": "71fb186646c1e61672bf4cfdb56bbf46d5d3863a",
    "formal/pon-nakamoto-v1/model_contract.py": "eb5f30a1b4f67c9117d696da6233ff90655ae218",
    "formal/pon-nakamoto-v1/ledger.py": "ea90d7df31a6765302d59ae53a86ed5486dc7618",
    "formal/pon-nakamoto-v1/work_backend.py": "bc2f7ab213bd598c8028030da9907b40b2e20e1b",
    "formal/pon-nakamoto-v1/work_oracle.py": "9cbfccd2d50af48fc43522b967ffdfb1f45ec098",
    "formal/pon-nakamoto-v1/bounded_process.py": "b8579d1ea76e8c84214570f3f08d84595bfc77b6",
    "config/pon/ledger-v1.json": "f7d8dba05cd0267b716834d76774a7ce94a1276b",
    "config/pon/work-profile-v1.json": "54e43139d3691b62f76f9e8976e1d2a974e8524b",
    "config/pon/model-family-v1.json": "9a931f21ca86563cf7e5c6415acd20a0ced7da68",
    "config/pon/devnet-v1.json": "a60f403b2f0e7343aed61170ca2aef875a787790",
}
RESOURCE_UNITS = {
    "cpu_ns": "nanoseconds", "wall_ns": "cumulative-operation-nanoseconds",
    "operations": "declared-operation-count-not-a-cost-lower-bound",
    "bytes_read": "bytes", "bytes_written": "bytes",
    "memory_peak_bytes": "maximum-reported-operation-peak-not-concurrent-total",
    "gpu_ns": "nanoseconds-or-unknown",
}
AUTHORITY = dict(payment_authorized=False, adoption_authorized=False,
                 consensus_credit_authorized=False, production_activation=False)
OBLIGATIONS = {
    "computation": ("COMPUTATION_PROGRAM_INPUT_OUTPUT_BINDING", "COMPUTATION_ACTUAL_RELATION_VERIFICATION",
                    "COMPUTATION_NUMERIC_SEMANTICS", "COMPUTATION_EXECUTION_PROVENANCE"),
    "demand": ("DEMAND_COMMISSION_AUTHENTICITY", "DEMAND_CUSTOMER_INDEPENDENCE",
               "DEMAND_CURRENT_FUNDED_BUDGET", "DEMAND_DATA_RIGHTS", "DEMAND_COMPUTATION_BINDING",
               "DEMAND_DURABLE_IDENTITY"),
    "utility": ("UTILITY_PROSPECTIVE_EVALUATION", "UTILITY_INDEPENDENT_EVALUATOR",
                "UTILITY_MATCHED_CONTROLS", "UTILITY_COMPLETE_COST_COVERAGE",
                "UTILITY_MEASURED_COST_AUTHENTICITY", "UTILITY_DOWNSTREAM_USE", "UTILITY_NET_BENEFIT",
                "UTILITY_RETENTION", "UTILITY_RESULT_DEDUP"),
    "sybil": ("ALL_LEGAL_STRATEGIES", "INITIAL_SHARED_STATE", "COMPLETE_LIFECYCLE_COST",
              "PUBLIC_HELP_COVERAGE", "RESOURCE_MODEL_REDUCTION", "HASH_ORACLE_INSTANTIATION",
              "QUANTUM_LIFECYCLE", "TIME_DAA_CREDIT_COMPOSITION", "NATIVE_SUCCESS_BINDING"),
}


def require(condition, code):
    if not condition:
        raise ValueError("FOUR_" + code)


def fields(value, names):
    require(type(value) is dict and set(value) == set(names), "FIELDS")


def digest(value, length=64):
    require(type(value) is str and len(value) == length and
            all(c in "0123456789abcdef" for c in value), "DIGEST")
    return value


def canonical(value):
    def visit(item, depth=0):
        require(depth <= 40, "JSON_DEPTH")
        if item is None or type(item) in (bool, str):
            return
        if type(item) is int:
            require(-(1 << 63) <= item < (1 << 64), "INTEGER")
        elif type(item) is list:
            for child in item:
                visit(child, depth + 1)
        elif type(item) is dict and all(type(k) is str for k in item):
            for child in item.values():
                visit(child, depth + 1)
        else:
            raise ValueError("FOUR_JSON_TYPE")
    visit(value)
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    require(len(raw) <= MAX_BYTES, "INPUT_LIMIT")
    return raw


def sha(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def same(actual, expected, code):
    require(canonical(actual) == canonical(expected), code)


def loads(raw):
    require(type(raw) is bytes and 0 < len(raw) <= MAX_BYTES, "INPUT_LIMIT")
    def pairs(items):
        value = {}
        for key, item in items:
            require(key not in value, "DUPLICATE_KEY")
            value[key] = item
        return value
    def no_float(_):
        raise ValueError("FOUR_NONINTEGER_JSON")
    value = json.loads(raw, object_pairs_hook=pairs, parse_float=no_float, parse_constant=no_float)
    canonical(value)
    return value


def dependencies(root):
    """Check reviewed reader bytes, not a submitted report's execution identity."""
    root = Path(root).resolve()
    require(os.environ.get("TRNM_PON_EVALUATION_POLICY", "legacy-first-two-v3") ==
            "legacy-first-two-v3", "READER_ENVIRONMENT")
    for name, expected in SOURCE_BLOBS.items():
        path = root / name
        require(path.is_file() and not any(p.is_symlink() for p in (path, *path.parents)), "SOURCE_PATH")
        data = path.read_bytes()
        blob = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
        require(blob == expected, "SOURCE_BYTES:" + name)
    source = root / "formal/pon-nakamoto-v1"
    for name in SOURCE_BLOBS:
        if name.endswith(".py") and Path(name).stem in sys.modules:
            loaded = sys.modules[Path(name).stem]
            require(Path(loaded.__file__).resolve() == root / name, "LOADED_SOURCE")
    sys.path.insert(0, str(source))
    try:
        return {name: importlib.import_module(name) for name in
                ("contract_wire", "demand_evidence", "work_utility", "upgrade_policy", "work_profile_contract_v1")}
    finally:
        sys.path.pop(0)


def _demand(item, pins, binding, modules):
    fields(item, ("actions", "snapshot"))
    fields(pins, ("owner_keys", "registry_root", "bonus_cap", "max_records"))
    require(type(item["actions"]) is list and 0 < len(item["actions"]) <= 64, "DEMAND_LIMIT")
    reader = modules["demand_evidence"]
    book = reader.DemandEvidenceBook(context=binding["context"], **pins)
    observations = []
    for action in item["actions"]:
        fields(action, ("bundle", "expected_contract", "expected_anchor", "height", "observation"))
        terms = action["bundle"]["contract"]
        for key in ("context", "parent", "inputs", "output_spec", "qualified_work", "evaluation_protocol"):
            same(terms[key], binding[key], "DEMAND_BINDING:" + key)
        delivery = action["bundle"]["delivery"]
        if delivery is not None:
            same(delivery["body"]["payload"]["output"], binding["output_content"], "DEMAND_OUTPUT")
        observation = book.observe(reader.canonical(action["bundle"]),
            expected_contract=action["expected_contract"], expected_anchor=action["expected_anchor"],
            height=action["height"])
        same(observation, action["observation"], "DEMAND_REPORT")
        observations.append(observation)
    same(book.snapshot(), item["snapshot"], "DEMAND_SNAPSHOT")
    return dict(observations=observations, snapshot=book.snapshot(), supplied_bundle_replay=True)


def _utility(item, binding, modules):
    fields(item, ("initial_branch", "required_stages", "max_attempts", "max_events", "events", "snapshot"))
    require(type(item["required_stages"]) is list and type(item["events"]) is list and
            len(item["events"]) <= 8192, "UTILITY_LIMIT")
    reader = modules["work_utility"]
    observer = reader.UniqueUsefulOutputAccounting(context=binding["context"], current_branch=item["initial_branch"],
        required_stages=tuple(item["required_stages"]), max_attempts=item["max_attempts"], max_events=item["max_events"])
    for index, event in enumerate(item["events"], 1):
        require(type(event) is dict and type(event.get("sequence")) is int and event["sequence"] == index,
                "UTILITY_SEQUENCE")
        kind = event.get("kind")
        if kind == "attempt":
            for key in ("task_content", "output_content"):
                same(event[key], binding[key], "UTILITY_BINDING:" + key)
            observer.begin_attempt(**{k: event[k] for k in
                ("attempt", "branch", "task_content", "output_content", "function_fingerprint", "source", "partition")})
        elif kind == "cost":
            observer.record_cost(event["attempt"], event["stage"], observer=event["observer"], cost=event["cost"])
        elif kind == "verification":
            ratio = event["quality_gain"]
            require(type(ratio) is list and len(ratio) == 2 and
                    all(type(v) is str and len(v) <= 128 and re.fullmatch(r"-?(0|[1-9][0-9]*)", v) for v in ratio),
                    "QUALITY_RATIO")
            require(int(ratio[1]) > 0, "QUALITY_RATIO")
            gain = Fraction(int(ratio[0]), int(ratio[1]))
            same([str(gain.numerator), str(gain.denominator)], ratio, "QUALITY_CANONICAL")
            observer.finish_verification(event["attempt"], accepted=event["accepted"],
                                         quality_gain=gain, outcome=event["outcome"])
        elif kind == "adoption":
            observer.adopt_output(event["attempt"], consumer_operation=event["consumer_operation"],
                                  consumer=event["consumer"], observed_output=event["observed_output"])
        elif kind == "reorganization":
            observer.reorganize(new_branch=event["new_branch"], active_branches=event["active_branches"])
        else:
            raise ValueError("FOUR_UTILITY_EVENT")
        same(observer.events[-1], event, "UTILITY_EVENT_REPLAY")
    same(observer.snapshot(), item["snapshot"], "UTILITY_SNAPSHOT")
    return dict(snapshot=observer.snapshot(), supplied_event_replay=True)


def _upgrade(item, pins, binding, modules):
    fields(item, ("actions", "observation"))
    fields(pins, ("owner_key", "alpha", "bonus_cap", "max_attempts", "target_attempt"))
    require(type(item["actions"]) is list and 0 < len(item["actions"]) <= 256, "UPGRADE_LIMIT")
    reader = modules["upgrade_policy"]
    policy = reader.UpgradePolicy(context=binding["context"], **{k: pins[k] for k in
                                 ("owner_key", "alpha", "bonus_cap", "max_attempts")})
    plans = {}
    for action in item["actions"]:
        require(type(action) is dict, "UPGRADE_ACTION")
        kind = action.get("kind")
        if kind == "begin":
            fields(action, ("kind", "plan", "expected_plan", "current_parent", "height", "attempt"))
            plan = dict(action["plan"])
            require(plan.pop("schema", None) == reader.SCHEMA, "UPGRADE_SCHEMA")
            raw, plan_id = reader.freeze_plan(**plan)
            same(plan_id, action["expected_plan"], "UPGRADE_PLAN")
            attempt = policy.begin(raw, plan_id, current_parent=action["current_parent"], height=action["height"])
            same(attempt, action["attempt"], "UPGRADE_ATTEMPT")
            plans[attempt] = dict(plan_id=plan_id, plan=plan)
        elif kind == "evaluate":
            fields(action, ("kind", "attempt", "rows", "receipt", "current_parent", "height"))
            policy.evaluate(action["attempt"], action["rows"], action["receipt"],
                            current_parent=action["current_parent"], height=action["height"])
        elif kind == "cancel":
            fields(action, ("kind", "attempt", "reason", "height"))
            policy.cancel(action["attempt"], reason=action["reason"], height=action["height"])
        elif kind == "canary":
            fields(action, ("kind", "attempt", "observation", "receipt", "current_parent", "height"))
            policy.observe_canary(action["attempt"], action["observation"], action["receipt"],
                                  current_parent=action["current_parent"], height=action["height"])
        elif kind == "propose":
            fields(action, ("kind", "attempt", "receipt", "current_parent", "height"))
            policy.propose(action["attempt"], action["receipt"], current_parent=action["current_parent"], height=action["height"])
        else:
            raise ValueError("FOUR_UPGRADE_ACTION")
    observation = policy.observation()
    same(observation, item["observation"], "UPGRADE_OBSERVATION")
    target = digest(pins["target_attempt"])
    require(target in plans, "UPGRADE_TARGET")
    selected = plans[target]
    for key, target_key in (("context", "context"), ("parent", "parent"), ("candidate", "output_content"),
                            ("evaluation_protocol", "evaluation_protocol"), ("cost_unit", "cost_unit")):
        same(selected["plan"][key], binding[target_key], "UPGRADE_BINDING:" + key)
    return dict(observation=observation, target_attempt=target, selected_plan=selected,
                supplied_actions_replay=True, net_arithmetic_owner="existing-upgrade_policy.py")


def _project(value, pins, *, source_root=None):
    """Review pins are supplied separately from the producer's evidence.

    Digests bind supplied bytes, not their physical origin or omitted lifetime
    history. There is no qualification-granting path, even for signed inputs.
    """
    fields(value, ("schema", "source_commit", "binding", "resource_units", "demand", "utility", "upgrade"))
    fields(pins, ("schema", "source_commit", "input_sha256", "binding_sha256", "demand", "upgrade"))
    require(value["schema"] == INPUT_SCHEMA and pins["schema"] == PIN_SCHEMA, "SCHEMA")
    same(digest(value["source_commit"], 40), digest(pins["source_commit"], 40), "SOURCE_BINDING")
    same(sha(value), digest(pins["input_sha256"]), "INPUT_BINDING")
    binding = value["binding"]
    fields(binding, ("context", "parent", "inputs", "output_spec", "output_content", "task_content",
                     "qualified_work", "evaluation_protocol", "work_profile", "cost_unit"))
    for name in set(binding) - {"work_profile", "cost_unit"}:
        digest(binding[name])
    if binding["cost_unit"] is not None:
        digest(binding["cost_unit"])
    same(sha(binding), digest(pins["binding_sha256"]), "SCOPE_BINDING")
    same(value["resource_units"], RESOURCE_UNITS, "RESOURCE_UNITS")
    modules = dependencies(source_root or Path(__file__).resolve().parents[2])
    contract = modules["work_profile_contract_v1"]
    definition = contract.definition()
    same(binding["work_profile"], definition["work_profile"], "WORK_PROFILE")
    reports = {}
    for name in ("demand", "utility", "upgrade"):
        if name != "utility":
            require((value[name] is None) == (pins[name] is None), "MISSING_PINS:" + name)
        if value[name] is None:
            reports[name] = None
        elif name == "utility":
            reports[name] = _utility(value[name], binding, modules)
        elif name == "demand":
            reports[name] = _demand(value[name], pins[name], binding, modules)
        else:
            reports[name] = _upgrade(value[name], pins[name], binding, modules)
    demand = reports["demand"]
    deliveries = [] if demand is None else [{k: row[k] for k in ("contract", "bundle", "delivered", "output_key")}
        for row in demand["observations"] if row["delivery_observed"]]
    facts = {
        "computation": dict(specified_work_profile=definition["work_profile"],
            specified_numeric_semantics=definition["numeric_semantics"], signed_delivery_observations=deliveries,
            raw_computation_proof_verified_by_this_view=False),
        "demand": dict(composition=reports["demand"], data_rights_status="UNKNOWN",
                       customer_independence_status="UNKNOWN", funding_truth_status="UNKNOWN"),
        "utility": dict(output_accounting=reports["utility"], upgrade=reports["upgrade"],
                        cost_conversion_scope="only-the-frozen-upgrade-plan; resource-counters-not-added-to-utility",
                        complete_external_cost_coverage="UNKNOWN"),
        "sybil": dict(all_algorithm_cost_bound=None, original_research_qualification=dict(contract.QUALIFICATION),
            cost_bound_rule=definition["lifecycle"]["cost_bound_rule"], resource_model_status="UNKNOWN",
            original_research_contract_source=contract.BASELINE,
            original_historical_source_checker_executed=False),
    }
    utility_events = len(value["utility"]["events"]) if value["utility"] is not None else 0
    upgrade_actions = len(value["upgrade"]["actions"]) if value["upgrade"] is not None else 0
    demand_actions = len(value["demand"]["actions"]) if value["demand"] is not None else 0
    observed_count = utility_events + upgrade_actions + demand_actions
    cost_observed = reports["utility"] is not None and reports["utility"]["snapshot"]["cost_records"] > 0
    present = dict(computation=bool(deliveries), demand=demand_actions > 0,
                   utility=utility_events + upgrade_actions > 0, sybil=cost_observed)
    return dict(schema=SCHEMA, reviewed_reader_source=REFERENCE_SOURCE,
        declared_evidence_source=value["source_commit"], input_sha256=sha(value), review_pins_sha256=sha(pins),
        binding=json.loads(canonical(binding)), resource_units=dict(RESOURCE_UNITS), reader_blob_pins=dict(SOURCE_BLOBS),
        supplied_observations_replayed=observed_count > 0, supplied_observations_count=observed_count,
        execution_source_provenance_authenticated=False,
        cross_proposition_semantic_binding_authenticated=False,
        binding_scope="supplied-label-equality-only; no-derived-equivalence-between-task-content-inputs-and-evaluation",
        reader_source_scope="checked-source-bytes-only; no-loaded-code-or-execution-attestation",
        history_scope="complete-supplied-history-only; omitted-or-restored-global-history-not-detected",
        propositions={name: dict(observation_state="OBSERVED" if present[name] else "MISSING", proven=False,
             facts=facts[name], unresolved_obligations=list(OBLIGATIONS[name])) for name in OBLIGATIONS},
        authority=dict(AUTHORITY))


def project(value, pins, *, source_root=None):
    """Reject malformed supplied containers without leaking indexing exceptions."""
    try:
        return _project(value, pins, source_root=source_root)
    except (KeyError, TypeError, IndexError, AttributeError) as error:
        raise ValueError("FOUR_INPUT_SHAPE") from error


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--pins", type=Path, required=True)
    parser.add_argument("--source-root", type=Path)
    parser.add_argument("--check-view", type=Path, help="compare an earlier view; grants no qualification")
    args = parser.parse_args()
    def read(path):
        with path.open("rb") as source:
            return loads(source.read(MAX_BYTES + 1))
    result = project(read(args.input), read(args.pins), source_root=args.source_root)
    if args.check_view is not None:
        same(result, read(args.check_view), "VIEW_MISMATCH")
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(str(error) or type(error).__name__, file=sys.stderr)
        sys.exit(2)
