#!/usr/bin/env python3
from __future__ import annotations
import argparse
import copy
import hashlib
import json
from pathlib import Path
from typing import Any

class Reject(ValueError):
    pass

HEX = set("0123456789abcdef")
COMMON_SCENARIOS = {
    "normal-finality",
    "offline-minority-rejoin",
    "leader-crash-timeout-certificate",
    "validator-restart-catch-up",
    "state-sync-finalized-checkpoint",
    "epoch-key-rotation",
    "signer-fault",
    "disk-full-io-fault",
}
REQUIRED_BY_COUNT = {
    4: COMMON_SCENARIOS | {"partition-3-1-progress", "partition-2-2-safe-stall-heal"},
    7: COMMON_SCENARIOS | {"partition-5-2-progress", "partition-4-3-safe-stall-heal"},
}
OUTCOMES = {"progress", "safe-stall-then-heal", "recover-and-progress", "reject-and-fence"}

def pairs_no_dupes(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise Reject(f"duplicate-key:{key}")
        out[key] = value
    return out

def load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=pairs_no_dupes,
                      parse_constant=lambda x: (_ for _ in ()).throw(Reject(x)))

def hexstr(value: Any, length: int) -> bool:
    return isinstance(value, str) and len(value) == length and set(value) <= HEX

def quorum(total: int) -> int:
    if total <= 0:
        raise Reject("total-weight")
    return (2 * total) // 3 + 1

def validate_identity(identity: dict[str, Any]) -> None:
    for key in ("source_commit", "source_tree"):
        if not hexstr(identity.get(key), 40):
            raise Reject(f"identity:{key}")
    for key in ("plan_sha256", "protocol_manifest_sha256", "binary_sha256", "sbom_sha256", "genesis_sha256"):
        if not hexstr(identity.get(key), 64):
            raise Reject(f"identity:{key}")
    if identity.get("repository") != "TrillionniumFoundation/Trillionnium-Chain":
        raise Reject("repository")

def validate_validators(manifest: dict[str, Any]) -> None:
    validators = manifest.get("validators")
    if not isinstance(validators, list) or len(validators) not in {4, 7}:
        raise Reject("validator-count")
    ids = [v.get("validator_id") for v in validators]
    keys = [v.get("public_key") for v in validators]
    if any(not x for x in ids) or len(ids) != len(set(ids)):
        raise Reject("validator-id")
    if any(not hexstr(k, 64) for k in keys) or len(keys) != len(set(keys)):
        raise Reject("validator-key")
    weights = [v.get("weight") for v in validators]
    if any(not isinstance(w, int) or w <= 0 for w in weights):
        raise Reject("validator-weight")
    if any(v.get("proof_of_possession") is not True for v in validators):
        raise Reject("validator-pop")
    total = sum(weights)
    if manifest.get("total_weight") != total or manifest.get("quorum_weight") != quorum(total):
        raise Reject("quorum-weight")
    if len(validators) == 4 and len(set(weights)) != 1:
        raise Reject("four-validator-equal-weight")
    if len(validators) == 7 and len(set(weights)) == 1:
        raise Reject("seven-validator-unequal-weight-required")

def validate_topology(manifest: dict[str, Any]) -> None:
    validators = manifest["validators"]
    ids = {v["validator_id"] for v in validators}
    placement = manifest.get("placement")
    if not isinstance(placement, list) or {p.get("validator_id") for p in placement} != ids:
        raise Reject("placement-coverage")
    if len(placement) != len(ids):
        raise Reject("placement-duplicate")
    hosts = {p.get("host_id") for p in placement}
    operators = {p.get("operator_id") for p in placement}
    custody = {p.get("custody_domain") for p in placement}
    if None in hosts | operators | custody or "" in hosts | operators | custody:
        raise Reject("placement-field")
    counts = manifest.get("topology_counts", {})
    actual = {"processes": len(ids), "hosts": len(hosts), "operators": len(operators), "custody_domains": len(custody)}
    if counts != actual:
        raise Reject("topology-counts")
    if len(hosts) < 3:
        raise Reject("minimum-three-hosts")
    if len(operators) > len(custody):
        raise Reject("operator-custody-overclaim")

def validate_scenarios(manifest: dict[str, Any]) -> None:
    scenarios = manifest.get("scenarios")
    if not isinstance(scenarios, list):
        raise Reject("scenario-list")
    names = [s.get("id") for s in scenarios]
    if len(names) != len(set(names)):
        raise Reject("scenario-id")
    count = len(manifest["validators"])
    if set(names) != REQUIRED_BY_COUNT[count]:
        raise Reject("scenario-coverage")
    validator_ids = {v["validator_id"] for v in manifest["validators"]}
    host_ids = {p["host_id"] for p in manifest["placement"]}
    for scenario in scenarios:
        if scenario.get("expected_outcome") not in OUTCOMES:
            raise Reject("scenario-outcome")
        if not scenario.get("invariants"):
            raise Reject("scenario-invariants")
        target_type = scenario.get("target_type")
        target = scenario.get("target")
        if target_type == "validator" and target not in validator_ids:
            raise Reject("scenario-target")
        if target_type == "host" and target not in host_ids:
            raise Reject("scenario-target")
        if target_type not in {"validator", "host", "network", "validator-set"}:
            raise Reject("scenario-target-type")
        if target_type in {"network", "validator-set"} and target not in {"all", "partition"}:
            raise Reject("scenario-target")
        if scenario.get("duration_seconds", 0) <= 0:
            raise Reject("scenario-duration")
        active = scenario.get("active_validators")
        if not isinstance(active, list) or not active or len(active) != len(set(active)) or not set(active).issubset(validator_ids):
            raise Reject("scenario-active-set")
        weights = {v["validator_id"]: v["weight"] for v in manifest["validators"]}
        active_weight = sum(weights[v] for v in active)
        if scenario["expected_outcome"] in {"progress", "recover-and-progress"} and active_weight < manifest["quorum_weight"]:
            raise Reject("scenario-insufficient-active-weight")
        if scenario["expected_outcome"] == "safe-stall-then-heal" and active_weight >= manifest["quorum_weight"]:
            raise Reject("scenario-not-stalled")

def validate_entry(manifest: dict[str, Any]) -> None:
    entry = manifest.get("entry_gate", {})
    if entry.get("g1_r4_exit") not in {"open", "candidate", "accepted"}:
        raise Reject("g1-r4-status")
    executable = entry.get("campaign_execution_authorized")
    if executable is True and entry.get("g1_r4_exit") != "accepted":
        raise Reject("execution-before-g1-r4")
    if executable is not False and executable is not True:
        raise Reject("execution-authority")

def validate_results(manifest: dict[str, Any]) -> None:
    results = manifest.get("results")
    if not isinstance(results, dict):
        raise Reject("results")
    present = results.get("present")
    if present is False:
        if manifest["entry_gate"]["campaign_execution_authorized"] is True:
            raise Reject("authorized-run-missing-results")
        if results.get("validator_run_completed") is not False or results.get("transport_only") is not False:
            raise Reject("harness-result-flags")
        if results.get("reports") not in (None, []) or results.get("raw_trace_root") is not None or results.get("finalized_root") is not None:
            raise Reject("fabricated-harness-evidence")
        return
    if present is not True:
        raise Reject("results-present")
    if manifest["entry_gate"]["g1_r4_exit"] != "accepted":
        raise Reject("results-without-g1-r4")
    if results.get("validator_run_completed") is not True or results.get("transport_only") is not False:
        raise Reject("transport-smoke-substitution")
    if not hexstr(results.get("raw_trace_root"), 64):
        raise Reject("raw-trace-root")
    reports = results.get("reports")
    if not isinstance(reports, list) or len(reports) != len(manifest["validators"]):
        raise Reject("report-count")
    ids = {v["validator_id"] for v in manifest["validators"]}
    if {r.get("validator_id") for r in reports} != ids:
        raise Reject("report-coverage")
    if any(r.get("signed") is not True or not hexstr(r.get("report_root"), 64) for r in reports):
        raise Reject("unsigned-report")
    if any(r.get("double_sign") is not False for r in reports):
        raise Reject("double-sign")
    finalities = {(r.get("finalized_height"), r.get("finalized_block_id")) for r in reports}
    roots = {r.get("application_root") for r in reports}
    if len(finalities) != 1:
        raise Reject("conflicting-finality")
    if len(roots) != 1 or None in roots or "" in roots:
        raise Reject("state-root-divergence")
    if results.get("finalized_root") != next(iter(roots)):
        raise Reject("result-root-index")
    if results.get("conflicting_finality") is not False:
        raise Reject("conflicting-finality-flag")

def validate(manifest: dict[str, Any]) -> None:
    if manifest.get("schema") != "trnm-g1-r5-campaign-manifest-v1":
        raise Reject("schema")
    if manifest.get("classification") != "candidate-harness-only":
        raise Reject("classification")
    validate_identity(manifest.get("identity", {}))
    validate_validators(manifest)
    validate_topology(manifest)
    validate_scenarios(manifest)
    validate_entry(manifest)
    validate_results(manifest)
    nonclaims = manifest.get("nonclaims", {})
    required_false = (
        "g1_r5_exit", "validator_run_completed", "network_evidence_accepted",
        "production_candidate", "production_consensus_activation",
    )
    if any(nonclaims.get(key) is not False for key in required_false):
        raise Reject("nonclaim-drift")

def validators(count: int) -> list[dict[str, Any]]:
    weights = [1, 1, 1, 1] if count == 4 else [4, 3, 3, 2, 2, 1, 1]
    return [
        {
            "validator_id": f"v{i}",
            "public_key": hashlib.sha256(f"key-{count}-{i}".encode()).hexdigest(),
            "proof_of_possession": True,
            "weight": weights[i],
        }
        for i in range(count)
    ]

def scenarios(count: int) -> list[dict[str, Any]]:
    if count == 4:
        rows = [
            ("normal-finality", "network", "all", "progress", ["v0","v1","v2","v3"]),
            ("offline-minority-rejoin", "validator", "v3", "recover-and-progress", ["v0","v1","v2"]),
            ("leader-crash-timeout-certificate", "validator", "v0", "recover-and-progress", ["v1","v2","v3"]),
            ("partition-3-1-progress", "validator-set", "partition", "progress", ["v0","v1","v2"]),
            ("partition-2-2-safe-stall-heal", "validator-set", "partition", "safe-stall-then-heal", ["v0","v1"]),
            ("validator-restart-catch-up", "validator", "v1", "recover-and-progress", ["v0","v2","v3"]),
            ("state-sync-finalized-checkpoint", "validator", "v2", "recover-and-progress", ["v0","v1","v3"]),
            ("epoch-key-rotation", "validator-set", "all", "recover-and-progress", ["v0","v1","v2","v3"]),
            ("signer-fault", "validator", "v0", "reject-and-fence", ["v1","v2","v3"]),
            ("disk-full-io-fault", "host", "h0", "reject-and-fence", ["v1","v2"]),
        ]
    else:
        rows = [
            ("normal-finality", "network", "all", "progress", ["v0","v1","v2","v3","v4","v5","v6"]),
            ("offline-minority-rejoin", "validator", "v6", "recover-and-progress", ["v0","v1","v2","v3","v4","v5"]),
            ("leader-crash-timeout-certificate", "validator", "v0", "recover-and-progress", ["v1","v2","v3","v4","v5","v6"]),
            ("partition-5-2-progress", "validator-set", "partition", "progress", ["v0","v1","v2","v3","v4"]),
            ("partition-4-3-safe-stall-heal", "validator-set", "partition", "safe-stall-then-heal", ["v1","v2","v3","v4"]),
            ("validator-restart-catch-up", "validator", "v1", "recover-and-progress", ["v0","v2","v3","v4","v5","v6"]),
            ("state-sync-finalized-checkpoint", "validator", "v2", "recover-and-progress", ["v0","v1","v3","v4","v5","v6"]),
            ("epoch-key-rotation", "validator-set", "all", "recover-and-progress", ["v0","v1","v2","v3","v4","v5","v6"]),
            ("signer-fault", "validator", "v0", "reject-and-fence", ["v1","v2","v3","v4","v5","v6"]),
            ("disk-full-io-fault", "host", "h0", "reject-and-fence", ["v1","v2","v4","v5"]),
        ]
    return [
        {
            "id": i, "target_type": t, "target": target,
            "duration_seconds": 60, "expected_outcome": outcome,
            "active_validators": active,
            "invariants": ["no-conflicting-finality", "no-double-sign", "root-convergence-or-safe-stall"],
        }
        for i, t, target, outcome, active in rows
    ]

def fixture(count: int) -> dict[str, Any]:
    vals = validators(count)
    placement = [
        {
            "validator_id": v["validator_id"],
            "process_id": f"p{i}",
            "host_id": f"h{i % 3}",
            "operator_id": f"o{i % 3}",
            "custody_domain": f"c{i % 3}",
        }
        for i, v in enumerate(vals)
    ]
    return {
        "schema": "trnm-g1-r5-campaign-manifest-v1",
        "classification": "candidate-harness-only",
        "identity": {
            "repository": "TrillionniumFoundation/Trillionnium-Chain",
            "source_commit": "a" * 40,
            "source_tree": "b" * 40,
            "plan_sha256": "c" * 64,
            "protocol_manifest_sha256": "d" * 64,
            "binary_sha256": "e" * 64,
            "sbom_sha256": "f" * 64,
            "genesis_sha256": "1" * 64,
        },
        "validators": vals,
        "total_weight": sum(v["weight"] for v in vals),
        "quorum_weight": quorum(sum(v["weight"] for v in vals)),
        "placement": placement,
        "topology_counts": {
            "processes": count,
            "hosts": 3,
            "operators": 3,
            "custody_domains": 3,
        },
        "scenarios": scenarios(count),
        "entry_gate": {
            "g1_r4_exit": "candidate",
            "campaign_execution_authorized": False,
        },
        "results": {
            "present": False,
            "validator_run_completed": False,
            "transport_only": False,
            "reports": [],
            "raw_trace_root": None,
            "finalized_root": None,
        },
        "nonclaims": {
            "g1_r5_exit": False,
            "validator_run_completed": False,
            "network_evidence_accepted": False,
            "production_candidate": False,
            "production_consensus_activation": False,
        },
    }

def self_test() -> dict[str, Any]:
    four, seven = fixture(4), fixture(7)
    validate(four)
    validate(seven)
    mutants = []
    def add(name: str, value: dict[str, Any]) -> None:
        mutants.append((name, value))
    x = copy.deepcopy(four); x["validators"][1]["public_key"] = x["validators"][0]["public_key"]; add("duplicate-validator-key", x)
    x = copy.deepcopy(four); x["validators"][0]["proof_of_possession"] = False; add("missing-pop", x)
    x = copy.deepcopy(four); x["quorum_weight"] -= 1; add("quorum-mismatch", x)
    x = copy.deepcopy(seven); x["validators"] = [dict(v, weight=1) for v in x["validators"]]; x["total_weight"] = 7; x["quorum_weight"] = quorum(7); add("seven-equal-weight", x)
    x = copy.deepcopy(four); x["topology_counts"]["hosts"] = 4; add("topology-overclaim", x)
    x = copy.deepcopy(four); x["placement"] = [dict(p, host_id="h0") for p in x["placement"]]; x["topology_counts"]["hosts"] = 1; add("single-host", x)
    x = copy.deepcopy(four); x["scenarios"].pop(); add("missing-scenario", x)
    x = copy.deepcopy(four); x["scenarios"][0]["target"] = "unknown"; add("unknown-target", x)
    x = copy.deepcopy(four); x["entry_gate"]["campaign_execution_authorized"] = True; add("execute-before-r4", x)
    x = copy.deepcopy(four); x["results"]["transport_only"] = True; add("transport-smoke-as-result", x)
    x = copy.deepcopy(four); x["classification"] = "accepted-network-evidence"; add("premature-classification", x)
    x = copy.deepcopy(four); x["nonclaims"]["validator_run_completed"] = True; add("nonclaim-drift", x)

    rejected = []
    for name, value in mutants:
        try:
            validate(value)
        except Reject as exc:
            rejected.append({"case": name, "error": str(exc)})
        else:
            raise AssertionError(f"accepted:{name}")
    return {
        "schema": "trnm-g1-r5-campaign-contract-evidence-v1",
        "fixtures": [4, 7],
        "scenarios": {str(k): sorted(v) for k, v in REQUIRED_BY_COUNT.items()},
        "negative": rejected,
        "campaign_execution_authorized": False,
        "validator_run_completed": False,
        "g1_r5_exit": False,
    }

def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--manifest", type=Path)
    p.add_argument("--write-fixtures", type=Path)
    p.add_argument("--self-test", action="store_true")
    args = p.parse_args()
    if args.write_fixtures:
        args.write_fixtures.mkdir(parents=True, exist_ok=True)
        for count in (4, 7):
            (args.write_fixtures / f"{count}-validator.json").write_text(
                json.dumps(fixture(count), sort_keys=True, indent=2) + "\n", encoding="utf-8"
            )
    if args.manifest:
        validate(load(args.manifest))
        print("campaign manifest: valid")
    if args.self_test:
        print(json.dumps(self_test(), sort_keys=True, separators=(",", ":")))
    if not (args.write_fixtures or args.manifest or args.self_test):
        raise SystemExit("select an action")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
