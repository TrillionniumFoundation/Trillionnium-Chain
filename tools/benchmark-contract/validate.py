#!/usr/bin/env python3
from __future__ import annotations
import argparse
import copy
import json
from pathlib import Path
from typing import Any

class Reject(ValueError):
    pass

HEX40 = set("0123456789abcdef")
SEVERITIES = {"Critical", "High", "Medium", "Low"}
CLAIM_CLASSES = {"harness-only", "measurement", "surpass-candidate"}

def strict_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise Reject(f"duplicate-key:{key}")
        out[key] = value
    return out

def loads(raw: str) -> Any:
    return json.loads(raw, object_pairs_hook=strict_pairs,
                      parse_constant=lambda x: (_ for _ in ()).throw(Reject(x)))

def is_hex(value: Any, length: int) -> bool:
    return isinstance(value, str) and len(value) == length and set(value) <= HEX40

def validate_topology(topology: dict[str, Any]) -> None:
    processes = topology.get("processes")
    if not isinstance(processes, list) or not processes:
        raise Reject("topology-processes")
    ids = [row.get("process_id") for row in processes]
    if len(ids) != len(set(ids)) or any(not x for x in ids):
        raise Reject("process-id")
    hosts = {row.get("host_id") for row in processes}
    operators = {row.get("operator_id") for row in processes}
    regions = {row.get("region_id") for row in processes}
    custody = {row.get("custody_domain") for row in processes}
    if None in hosts | operators | regions | custody or "" in hosts | operators | regions | custody:
        raise Reject("topology-mapping")
    declared = topology.get("counts", {})
    actual = {
        "processes": len(processes),
        "hosts": len(hosts),
        "operators": len(operators),
        "regions": len(regions),
        "custody_domains": len(custody),
    }
    if declared != actual:
        raise Reject("topology-counts")
    if declared["operators"] > declared["custody_domains"]:
        raise Reject("operator-custody-overclaim")
    if topology.get("claim_label") != (
        f'{actual["processes"]}-process/{actual["hosts"]}-host/'
        f'{actual["operators"]}-operator/{actual["regions"]}-region'
    ):
        raise Reject("topology-claim-label")
    links = topology.get("links")
    if not isinstance(links, list) or not links:
        raise Reject("topology-links")
    known = set(ids)
    for link in links:
        if link.get("source") not in known or link.get("target") not in known:
            raise Reject("topology-link-target")
        if link.get("rtt_ms", -1) < 0 or not 0 <= link.get("loss_bps", -1) <= 10000:
            raise Reject("topology-link-bounds")

def validate_workload(workload: dict[str, Any]) -> None:
    profiles = workload.get("profiles")
    if not isinstance(profiles, list) or not profiles:
        raise Reject("workload-profiles")
    names = [p.get("id") for p in profiles]
    if len(names) != len(set(names)) or any(not n for n in names):
        raise Reject("workload-id")
    mix = 0
    for profile in profiles:
        if not is_hex(profile.get("exact_bytes_sha256"), 64):
            raise Reject("workload-bytes-root")
        if profile.get("bytes_per_operation", 0) <= 0:
            raise Reject("workload-size")
        bps = profile.get("mix_bps")
        if not isinstance(bps, int) or bps < 0:
            raise Reject("workload-mix")
        mix += bps
        if profile.get("enabled_ai_profile") is not None and profile.get("enabled_ai_profile") != "deterministic-reexecution-v1":
            raise Reject("unsupported-ai-profile")
    if mix != 10000:
        raise Reject("workload-mix-total")
    if workload.get("submitted_tps_is_goodput") is not False:
        raise Reject("submitted-tps-substitution")

def validate_faults(faults: dict[str, Any], topology: dict[str, Any]) -> None:
    events = faults.get("events")
    if not isinstance(events, list) or not events:
        raise Reject("fault-events")
    process_ids = {p["process_id"] for p in topology["processes"]}
    host_ids = {p["host_id"] for p in topology["processes"]}
    region_ids = {p["region_id"] for p in topology["processes"]}
    known = {"process": process_ids, "host": host_ids, "region": region_ids, "network": {"all"}}
    last = -1
    event_ids = set()
    for event in events:
        if event.get("event_id") in event_ids or not event.get("event_id"):
            raise Reject("fault-id")
        event_ids.add(event["event_id"])
        start = event.get("start_ms")
        duration = event.get("duration_ms")
        if not isinstance(start, int) or not isinstance(duration, int) or start < last or duration <= 0:
            raise Reject("fault-time")
        last = start
        kind = event.get("target_type")
        if kind not in known or event.get("target_id") not in known[kind]:
            raise Reject("fault-target")
        if event.get("fault") not in {
            "leader-crash", "process-kill", "host-power-loss", "partition",
            "packet-loss", "disk-full", "io-error", "signer-unavailable",
            "state-sync-restart", "key-rotation", "da-withholding", "ddos",
        }:
            raise Reject("fault-kind")

def validate_measurement(measurement: dict[str, Any], claim_class: str) -> None:
    if measurement.get("committed_goodput_definition") != "transactions finalized and replay-verified per second":
        raise Reject("goodput-definition")
    if measurement.get("finality_definition") != "proposal admission to three-chain finality event":
        raise Reject("finality-definition")
    if measurement.get("percentile_denominator") not in {"all-finalized-transactions", "all-finalized-blocks"}:
        raise Reject("percentile-denominator")
    for key in ("warmup_seconds", "duration_seconds", "replicates", "seed"):
        if not isinstance(measurement.get(key), int) or measurement[key] <= 0:
            raise Reject(f"measurement:{key}")
    if measurement.get("results_present") is False:
        if claim_class != "harness-only":
            raise Reject("results-required")
        if measurement.get("raw_trace_root") is not None or measurement.get("metrics"):
            raise Reject("harness-fabricated-result")
        return
    if not is_hex(measurement.get("raw_trace_root"), 64):
        raise Reject("raw-trace-root")
    metrics = measurement.get("metrics")
    if not isinstance(metrics, list) or not metrics:
        raise Reject("metrics")
    for metric in metrics:
        if not all(k in metric for k in ("name", "gate", "workload", "denominator", "raw_series_root")):
            raise Reject("orphan-metric")
        if not is_hex(metric["raw_series_root"], 64):
            raise Reject("metric-root")
        if metric["name"].lower() in {"tps", "submitted_tps", "ingress_tps"}:
            raise Reject("submitted-tps-metric")

def validate_threats(threats: dict[str, Any], activation: dict[str, Any]) -> None:
    rows = threats.get("rows")
    if not isinstance(rows, list) or not rows:
        raise Reject("threat-rows")
    ids = set()
    blocking_open = []
    for row in rows:
        if row.get("id") in ids or not row.get("id"):
            raise Reject("threat-id")
        ids.add(row["id"])
        if row.get("severity") not in SEVERITIES:
            raise Reject("threat-severity")
        if not all(row.get(k) for k in ("threat", "invariant", "mutant", "owner")):
            raise Reject("threat-binding")
        if row.get("status") not in {"open", "closed"}:
            raise Reject("threat-status")
        if row["status"] == "closed" and not is_hex(row.get("evidence_root"), 64):
            raise Reject("closed-threat-evidence")
        if row["status"] == "open" and row["severity"] in {"Critical", "High"}:
            blocking_open.append(row["id"])
    if blocking_open and (
        activation.get("public_testnet_ready") is not False
        or activation.get("production_candidate") is not False
        or activation.get("production_activation") is not False
    ):
        raise Reject("open-critical-high-activation")
    if activation.get("blocking_open_findings") != blocking_open:
        raise Reject("blocking-finding-index")

def validate(manifest: dict[str, Any]) -> None:
    if manifest.get("schema") != "trnm-benchmark-security-ops-manifest-v1":
        raise Reject("schema")
    claim_class = manifest.get("claim_class")
    if claim_class not in CLAIM_CLASSES:
        raise Reject("claim-class")
    identity = manifest.get("identity", {})
    for key in ("plan_sha256", "protocol_manifest_sha256", "binary_sha256", "sbom_sha256", "container_sha256"):
        if not is_hex(identity.get(key), 64):
            raise Reject(f"identity:{key}")
    for key in ("source_commit", "source_tree"):
        if not is_hex(identity.get(key), 40):
            raise Reject(f"identity:{key}")
    comparator = manifest.get("comparator", {})
    if not comparator.get("name") or not is_hex(comparator.get("artifact_digest"), 64):
        raise Reject("comparator")
    if comparator.get("same_hardware_required") is not True or comparator.get("same_workload_required") is not True:
        raise Reject("comparator-parity")

    validate_topology(manifest.get("topology", {}))
    validate_workload(manifest.get("workload", {}))
    validate_faults(manifest.get("fault_schedule", {}), manifest["topology"])
    validate_measurement(manifest.get("measurement", {}), claim_class)
    validate_threats(manifest.get("threat_register", {}), manifest.get("activation", {}))

    dependencies = manifest.get("dependencies", {})
    required = ("G0", "G1", "G1.5", "G2.0", "G2A", "G2B", "G2D", "G2C", "G2E", "G2F")
    if set(dependencies) != set(required):
        raise Reject("dependency-set")
    if claim_class != "harness-only" and any(dependencies[k] != "accepted" for k in required):
        raise Reject("dependency-not-accepted")
    if claim_class == "harness-only" and any(dependencies[k] not in {"open", "candidate", "accepted"} for k in required):
        raise Reject("dependency-status")

    claim = manifest.get("claim_policy", {})
    if claim.get("ingress_tps_is_committed_goodput") is not False:
        raise Reject("claim-goodput")
    if claim.get("surpass_claim_allowed") is not False:
        if claim_class != "surpass-candidate":
            raise Reject("surpass-class")
        if manifest["measurement"].get("results_present") is not True:
            raise Reject("surpass-results")
        if claim.get("independent_reproduction_teams", 0) < 2:
            raise Reject("surpass-independent-replay")
        if any(dependencies[k] != "accepted" for k in required):
            raise Reject("surpass-dependencies")
        if manifest["activation"]["blocking_open_findings"]:
            raise Reject("surpass-findings")
    if manifest.get("signatures") and claim_class == "harness-only":
        raise Reject("harness-signatures-misleading")

def fixture() -> dict[str, Any]:
    processes = []
    for i in range(7):
        host = f"h{i % 3}"
        operator = f"o{i % 3}"
        region = f"r{i % 2}"
        processes.append({
            "process_id": f"p{i}", "host_id": host, "operator_id": operator,
            "region_id": region, "custody_domain": f"c{i % 3}",
        })
    links = []
    for i in range(6):
        links.append({"source": f"p{i}", "target": f"p{i+1}", "rtt_ms": 20 + i, "loss_bps": 0})
    threats = [
        ("AI-001", "model/data substitution", "profile provenance is exact", "wrong-model-digest", "A14", "High"),
        ("DA-001", "certified withholding", "certified bytes remain retrievable", "withhold-certified-object", "A11", "Critical"),
        ("ECO-001", "duplicate settlement", "one intent has one terminal receipt", "replay-after-commit", "A15", "Critical"),
        ("KEY-001", "signer rollback", "external watermark never decreases", "rollback-signer-journal", "A05", "Critical"),
        ("SYNC-001", "state-root substitution", "sync root equals finalized Order root", "replace-sync-chunk", "A16", "Critical"),
        ("OPS-001", "incident evidence loss", "raw traces are immutable", "delete-failed-run", "A17", "High"),
    ]
    rows = [
        {"id": i, "threat": t, "invariant": inv, "mutant": m, "owner": o,
         "severity": s, "status": "open", "evidence_root": None}
        for i, t, inv, m, o, s in threats
    ]
    blocking = [r["id"] for r in rows if r["severity"] in {"Critical", "High"}]
    return {
        "schema": "trnm-benchmark-security-ops-manifest-v1",
        "claim_class": "harness-only",
        "identity": {
            "plan_sha256": "a" * 64,
            "protocol_manifest_sha256": "b" * 64,
            "source_commit": "c" * 40,
            "source_tree": "d" * 40,
            "binary_sha256": "e" * 64,
            "sbom_sha256": "f" * 64,
            "container_sha256": "1" * 64,
        },
        "comparator": {
            "name": "exact-comparator-placeholder",
            "artifact_digest": "2" * 64,
            "same_hardware_required": True,
            "same_workload_required": True,
        },
        "topology": {
            "processes": processes,
            "counts": {"processes": 7, "hosts": 3, "operators": 3, "regions": 2, "custody_domains": 3},
            "claim_label": "7-process/3-host/3-operator/2-region",
            "links": links,
        },
        "workload": {
            "submitted_tps_is_goodput": False,
            "profiles": [
                {"id": "W0", "exact_bytes_sha256": "3" * 64, "bytes_per_operation": 512, "mix_bps": 4000, "enabled_ai_profile": None},
                {"id": "W1", "exact_bytes_sha256": "4" * 64, "bytes_per_operation": 2048, "mix_bps": 4000, "enabled_ai_profile": None},
                {"id": "AI1", "exact_bytes_sha256": "5" * 64, "bytes_per_operation": 4096, "mix_bps": 2000, "enabled_ai_profile": "deterministic-reexecution-v1"},
            ],
        },
        "fault_schedule": {
            "events": [
                {"event_id": "f1", "fault": "leader-crash", "target_type": "process", "target_id": "p0", "start_ms": 1000, "duration_ms": 5000},
                {"event_id": "f2", "fault": "partition", "target_type": "region", "target_id": "r1", "start_ms": 10000, "duration_ms": 10000},
                {"event_id": "f3", "fault": "disk-full", "target_type": "host", "target_id": "h2", "start_ms": 25000, "duration_ms": 5000},
            ]
        },
        "measurement": {
            "committed_goodput_definition": "transactions finalized and replay-verified per second",
            "finality_definition": "proposal admission to three-chain finality event",
            "percentile_denominator": "all-finalized-transactions",
            "warmup_seconds": 60, "duration_seconds": 1800, "replicates": 3, "seed": 1,
            "results_present": False, "raw_trace_root": None, "metrics": [],
        },
        "threat_register": {"rows": rows},
        "activation": {
            "public_testnet_ready": False, "production_candidate": False,
            "production_activation": False, "blocking_open_findings": blocking,
        },
        "dependencies": {
            "G0": "open", "G1": "open", "G1.5": "candidate", "G2.0": "candidate",
            "G2A": "candidate", "G2B": "candidate", "G2D": "candidate",
            "G2C": "candidate", "G2E": "candidate", "G2F": "candidate",
        },
        "claim_policy": {
            "ingress_tps_is_committed_goodput": False,
            "surpass_claim_allowed": False,
            "independent_reproduction_teams": 0,
        },
        "signatures": [],
    }

def self_test() -> dict[str, Any]:
    base = fixture()
    validate(base)
    mutants: list[tuple[str, dict[str, Any]]] = []

    x = copy.deepcopy(base); x["claim_policy"]["ingress_tps_is_committed_goodput"] = True
    mutants.append(("submitted-tps-substitution", x))
    x = copy.deepcopy(base); x["topology"]["processes"][0]["operator_id"] = ""
    mutants.append(("missing-topology-mapping", x))
    x = copy.deepcopy(base); x["topology"]["counts"]["hosts"] = 7
    mutants.append(("topology-count-overclaim", x))
    x = copy.deepcopy(base); x["topology"]["processes"][1]["custody_domain"] = "c0"; x["topology"]["counts"]["custody_domains"] = 2
    mutants.append(("operator-custody-overclaim", x))
    x = copy.deepcopy(base); x["workload"]["profiles"][0]["mix_bps"] = 3999
    mutants.append(("workload-mix", x))
    x = copy.deepcopy(base); x["comparator"]["artifact_digest"] = None
    mutants.append(("missing-comparator-digest", x))
    x = copy.deepcopy(base); x["claim_policy"]["surpass_claim_allowed"] = True
    mutants.append(("premature-surpass-claim", x))
    x = copy.deepcopy(base); x["fault_schedule"]["events"][0]["target_id"] = "unknown"
    mutants.append(("unknown-fault-target", x))
    x = copy.deepcopy(base); x["measurement"]["results_present"] = True; x["measurement"]["metrics"] = [{"name": "p99"}]
    mutants.append(("orphan-metric", x))
    x = copy.deepcopy(base); x["threat_register"]["rows"][0]["severity"] = "P0"
    mutants.append(("severity-vocabulary", x))
    x = copy.deepcopy(base); x["activation"]["public_testnet_ready"] = True
    mutants.append(("open-high-testnet", x))
    x = copy.deepcopy(base); x["dependencies"]["G2F"] = "blocked"
    mutants.append(("invalid-dependency-status", x))
    x = copy.deepcopy(base); x["topology"]["links"][0]["loss_bps"] = 10001
    mutants.append(("link-bounds", x))
    x = copy.deepcopy(base); x["workload"]["profiles"][2]["enabled_ai_profile"] = "subjective-v1"
    mutants.append(("unsupported-ai-profile", x))

    rejected = []
    for name, value in mutants:
        try:
            validate(value)
        except Reject as exc:
            rejected.append({"case": name, "error": str(exc)})
        else:
            raise AssertionError(f"mutant accepted:{name}")
    return {
        "schema": "trnm-benchmark-security-ops-contract-evidence-v1",
        "positive": "harness-contract-valid",
        "negative": rejected,
        "claim_class": "harness-only",
        "results_present": False,
        "surpass_claim_allowed": False,
        "public_testnet_ready": False,
        "production_candidate": False,
    }

def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--manifest", type=Path)
    p.add_argument("--write-fixture", type=Path)
    p.add_argument("--self-test", action="store_true")
    args = p.parse_args()
    if args.write_fixture:
        args.write_fixture.parent.mkdir(parents=True, exist_ok=True)
        args.write_fixture.write_text(json.dumps(fixture(), sort_keys=True, indent=2) + "\n", encoding="utf-8")
    if args.manifest:
        validate(loads(args.manifest.read_text(encoding="utf-8")))
        print("manifest: valid")
    if args.self_test:
        print(json.dumps(self_test(), sort_keys=True, separators=(",", ":")))
    if not (args.write_fixture or args.manifest or args.self_test):
        raise SystemExit("select an action")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
