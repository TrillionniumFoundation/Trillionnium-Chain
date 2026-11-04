#!/usr/bin/env python3
"""Project retained original CI artifacts and a native W1 receipt without upgrading gates."""
import hashlib
import json
from pathlib import Path
import sys
import zipfile
from fractions import Fraction

ROOT = Path(sys.argv[1])
HEAD = "6f458c4fbf07a0a44d7d7a6f451aa960c1b0a029"
TREE = "76d3b416eccc6a810634062e036f646f22bffc76"
ARTIFACTS = {
    "f0": (41771598282, 13295252045, "b0d584b01e51bda9d5481aeb8c2a430dcf785c7f5eb2357939642291a4dfceca"),
    "campaign": (41771598274, 13295139319, "ac3f2a7bcbe21c6b9943e7c136959df4d09ed485f5ae9bb116294d0df99ac488"),
}


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def rational(value):
    return {"numerator": value.numerator, "denominator": value.denominator}


def original_failures():
    out = {"schema": "trnm-original-6f-failure-projection-v1", "head": HEAD,
           "tree": TREE, "artifacts": {}, "qualification_changed": False}
    for kind, (run, artifact, expected) in ARTIFACTS.items():
        path = ROOT / "readback" / f"chain-6f-{kind}.zip"
        actual = digest(path)
        assert actual == expected, (kind, "artifact digest")
        out["artifacts"][kind] = {"run_id": run, "artifact_id": artifact,
            "zip_sha256": actual, "zip_bytes": path.stat().st_size,
            "url": f"https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/{run}/artifacts/{artifact}"}
        with zipfile.ZipFile(path) as archive:
            def read(name):
                return json.loads(archive.read(name))
            if kind == "f0":
                result, final = read("execution/results.json"), read("finalization/result.json")
                assert result["head"] == HEAD and result["tree"] == TREE
                assert result["complete_success"] is False
                rounds = read("execution/raw/report.json")["all_planned_rounds"]
                assert len(rounds) == result["planned_confirmations"] == 6
                successes = sum(row["four_second_slo_met"] for row in rounds)
                assert successes == result["four_second_slo_successes"] == 0
                out[kind] = {"planned_confirmations": 6, "four_second_slo_successes": successes,
                    "failure": result["failure"], "controller_resources_complete": result["controller_resources_complete"],
                    "all_services_known_empty": final["all_services_known_empty"], "rounds": rounds}
            else:
                result = read("results.json")
                assert result["expected_head"] == HEAD and result["expected_tree"] == TREE
                assert result["planned_complete_runs"] == 3 and result["complete_success"] is False
                phases = []
                for run_index in range(1, 4):
                    report = read(f"run-{run_index}-raw/report.json")
                    assert [p["mode"] for p in report["phases"]] == ["baseline", "from-zero", "late-product"]
                    for phase in report["phases"]:
                        actual = {c["round"]: c for c in phase["confirmations"]}
                        assert len(actual) == len(phase["confirmations"]) and set(actual) <= {0, 1, 2}
                        rows = []
                        for index in range(3):
                            c = actual.get(index)
                            rows.append({"round": index, "observed": c is not None,
                                "confirmed": bool(c and c["confirmed_inside_pressure_window"]),
                                "started_ns": None if c is None else c["started_ns"],
                                "ended_ns": None if c is None else c["ended_ns"],
                                "elapsed_from_actual_start_ns": None if c is None else c["ended_ns"]-c["started_ns"]})
                        phases.append({"run": run_index, "mode": phase["mode"],
                            "state_backend": phase["state_backend"], "verifier_errors": phase["verifier_errors"],
                            "rounds": rows})
                rows = [row for phase in phases for row in phase["rounds"]]
                out[kind] = {"failure": result["failure"], "planned_complete_runs": 3,
                    "original_outer_timeout_seconds": result["original_campaign_outer_timeout_seconds"],
                    "planned_confirmations": len(rows), "observed_confirmed": sum(r["confirmed"] for r in rows),
                    "observed_unconfirmed": sum(r["observed"] and not r["confirmed"] for r in rows),
                    "unobserved": sum(not r["observed"] for r in rows), "phases": phases}
                assert (len(rows), out[kind]["observed_confirmed"], out[kind]["observed_unconfirmed"], out[kind]["unobserved"]) == (27, 3, 9, 15)
    return out


def legal_costs():
    directory = ROOT / "w1-current-source" / "w1-legal-strategy-v3"
    manifest_path = directory / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    assert manifest["result"] == "PASS" and manifest["source_changed"] is False
    assert manifest["source_before"] == manifest["source_after"]
    assert manifest["source_before"]["source_state"] == "committed-clean"
    assert manifest["expected_source_commit"] == manifest["source_before"]["commit"]
    assert len({manifest[k] for k in ("binary_sha256_before", "binary_sha256_after",
        "retained_binary_sha256_before", "retained_binary_sha256_after")}) == 1
    for name, expected in manifest["artifact_sha256"].items():
        assert digest(directory / name) == expected, name
    reader = manifest["reader"]
    assert reader["complete_fixed_grid"] and reader["observed_complete_shards"] == 30
    assert reader["semantic_alerts"] == [] and reader["qualification_status"] == "HOLD"
    rows = []
    for shard in reader["shards"]:
        costs = shard["strategy_costs"]
        assert len(costs) == 4 and all(c["actual_setup_calls"] == 8 for c in costs)
        assert len({(c["attempts"], c["actual_searches"], c["target_hits"], c["exhausted_searches"]) for c in costs}) == 1
        # The same fixed two strategies are compared in every cohort. No samplewise fastest oracle.
        baseline, candidate = costs[0], costs[3]
        advantage = Fraction(baseline["inclusive_cohort_total"]["cpu_ns"], candidate["inclusive_cohort_total"]["cpu_ns"])
        recorded_ratio = shard["eager_transposed_over_lazy_full_limb_cpu"]
        assert advantage == Fraction(recorded_ratio["numerator"], recorded_ratio["denominator"])
        q = Fraction(1, 4)
        rows.append({"selection": shard["selection"], "input_sha256": shard["input_sha256"],
            "material_setup_reported_separately": shard["material_setup"],
            "strategies": [{k: c[k] for k in ("strategy", "actual_setup_calls", "actual_searches", "attempts", "target_hits",
                "exhausted_searches", "inclusive_cohort_total", "setup_total", "proof_materializations", "serialized_proof_bytes", "native_outcome_counts", "verification")} for c in costs],
            "fixed_eager_transposed_over_lazy_full_limb_cpu": rational(advantage),
            "conditional_equal_target_model": {
                "assumed_adversarial_resource_share": rational(q),
                "ratio_of_mean_work_rates": rational(q*advantage/(1-q+q*advantage)),
                "equal_mean_work_resource_share": rational(1/(1+advantage)),
                "is_measured_network_share_or_finality_probability": False}})
    return {"schema": "trnm-w1-fixed-strategy-measured-sensitivity-v1",
        "scope": "finite local native observation; same fixed strategies and same target within each row",
        "source": manifest["source_before"], "binary_sha256": manifest["binary_sha256_before"],
        "manifest_sha256": digest(manifest_path), "artifact_inventory_verified": len(manifest["artifact_sha256"]),
        "build_profile": manifest["build_profile"], "compiler_channel": manifest["compiler_channel"],
        "target": manifest["target"], "build_environment_overrides": manifest["build_environment_overrides"],
        "cohorts_all_arms": 960, "searches_all_arms": sum(c["actual_searches"] for s in reader["shards"] for c in s["strategy_costs"]),
        "attempts_all_arms": sum(c["attempts"] for s in reader["shards"] for c in s["strategy_costs"]),
        "semantic_alerts": reader["semantic_alerts"], "shards": rows,
        "limitations": reader["limitations"] + [
            "The machine was shared with other authorized work; CPU timing is a diagnostic, not exclusive-host qualification.",
            "The conditional model assumes linear throughput, additive CPU budgets, equal targets and equal availability; shared material/evidence/verification/whole-node costs remain separate.",
            "These are source-specific intermediate observations and do not qualify a later composed commit."],
        "fastest_legal_lower_bound": False, "work_profile_qualified": False,
        "independent_hardware_qualified": False, "original_business_gate_passed": False,
        "whole_chain_quantum_security_qualified": False, "production_activation": False}


if __name__ == "__main__":
    for name, derive in [("current-6f-original-failures.json", original_failures),
                        ("w1-fixed-strategy-sensitivity.json", legal_costs)]:
        value = derive()
        path = ROOT / "readback" / name
        path.write_text(json.dumps(value, indent=2, sort_keys=True)+"\n")
        print(json.dumps({"path": str(path), "sha256": digest(path), "bytes": path.stat().st_size}))
