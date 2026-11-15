#!/usr/bin/env python3
"""Read all four original test-profile CPU artifacts, retaining failed rows."""
import hashlib
import json
from pathlib import Path
import re
import zipfile

ROOT = Path(__file__).resolve().parent
HEAD = "bebb1f3289cd7050fefde89ea8f2cf33c6c37588"
MERGE = "0153600a002c420d20128983c3280ff6c16e70c4"
TREE = "58c31e8a6220c6be20029b33cb060f3a2034d1a7"
ARTIFACTS = [
    (13244425730, "x64", "head", "2d45fc57b81d8e676a9546a8bceadc8d9cb4c144ea6a0aa85dca4f0cec83ace4"),
    (13243430730, "x64", "prospective-merge", "9683f8e94d9354d802cba5739d61ede68f69a9c936baa56427dce8c5ea2a929f"),
    (13244186644, "arm64", "head", "78157f65bedfdaaa721d87c1d243b8415e9812ff4d1316988577657a20857278"),
    (13244361752, "arm64", "prospective-merge", "bc0269742bbce4c5580ecbd346003575c221db2b75352ffa0926442ea3576111"),
]
SELECTORS = [
    "admitted_custom_genesis_over_eight_mib_keeps_original_held_schedule_and_cpu_owner",
    "authenticated_large_parent_original_schedule_supplementary_denominator",
]


def digest(data):
    return hashlib.sha256(data).hexdigest()


def embedded_rows(data):
    rows = []
    for line in data.decode().splitlines():
        offset = line.find("{")
        if offset < 0:
            continue
        try:
            row = json.loads(line[offset:])
        except ValueError:
            continue
        if isinstance(row, dict):
            rows.append(row)
    return rows


def stages_delta(before, after):
    old = {r["stage"]: r["totals"] for r in before.get("stages", [])}
    return {r["stage"]: {k: v - old.get(r["stage"], {}).get(k, 0)
                         for k, v in r["totals"].items()}
            for r in after.get("stages", [])}


def counter_delta(before, after):
    return {k: v - before.get(k, 0) for k, v in after.items()}


def main():
    outcomes = []
    for artifact_id, arch, kind, expected_digest in ARTIFACTS:
        path = ROOT / f"bebb-cpu-{artifact_id}.zip"
        data = path.read_bytes()
        assert digest(data) == expected_digest
        with zipfile.ZipFile(path) as archive:
            def read_json(name):
                return json.loads(archive.read(name))

            source_before = read_json("source-before.json")
            source_after = read_json("source-after.json")
            for source in [source_before, source_after]:
                assert source["candidate"] == HEAD
                assert source["tested_tree"] == TREE
                assert source["kind"] == kind
                assert source["tested_commit"] == (HEAD if kind == "head" else MERGE)
                assert source["tracked_worktree_verified"] is True
                assert source["tracked_entries"] == 7315
                assert source["tracked_bytes"] == 862029405
            build = read_json("build-artifact-check.json")
            assert build["result"] == "PASS"
            assert build["node_opt_level"] == "3" and build["m06_opt_level"] == "1"
            assert build["debug_assertions"] and build["overflow_checks"]
            assert build["features"] == ["default", "pq-native-openssl"]
            outcome = {"artifact_id": artifact_id, "archive_sha256": expected_digest,
                       "archive_bytes": len(data), "arch": arch, "source_kind": kind,
                       "source_before": source_before, "source_after": source_after,
                       "build_profile_evidence": build,
                       "test_step_exit": int(archive.read("test-step.exit")),
                       "selectors": [], "member_sha256": {}}
            for selector in SELECTORS:
                name = selector + ".log"
                log = archive.read(name)
                outcome["member_sha256"][name] = digest(log)
                native = embedded_rows(log)
                executions = []
                for auth in [False, True]:
                    matched = [r for r in native if r.get("authenticated_backend") == auth]
                    dispatch = [r for r in matched if r.get("schema") == "native-large-parent-original-dispatch-diagnostic-v1"]
                    stages = [r for r in matched if r.get("schema") == "native-large-parent-arithmetic-stages-v1"]
                    receipts = [r for r in matched if r.get("schema") == "native-large-parent-schedule-parity-v1"]
                    if not receipts:
                        continue
                    assert len(receipts) == len(dispatch) == len(stages) == 1
                    before, after = stages[0]["before"], stages[0]["after"]
                    previous_root = before["complete_root_arithmetic"]
                    current_root = after["complete_root_arithmetic"]
                    executions.append({
                        "authenticated_backend": auth,
                        "native_receipt": receipts[0],
                        "dispatch_observation": {k: v for k, v in dispatch[0].items()
                                                 if k not in ("arithmetic_before", "arithmetic_after")},
                        "stage_delta": stages_delta(before, after),
                        "stage_observation_failed_before": before["stage_observation_failed"],
                        "stage_observation_failed_after": after["stage_observation_failed"],
                        "root_arithmetic_counter_delta": counter_delta(previous_root["counters"], current_root["counters"]),
                        "root_arithmetic_before": previous_root,
                        "root_arithmetic_after": current_root,
                    })
                lines = log.decode().splitlines()
                outcome["selectors"].append({
                    "selector": selector,
                    "execution_reader_stdout": archive.read(selector + ".execution.json").decode(),
                    "native_result_lines": [line for line in lines if line.startswith("test result:")],
                    "failure_lines": [line for line in lines if "panicked at" in line or "called `Result::unwrap()`" in line],
                    "executions": executions,
                })
            # Growth is a different fixed-touched-set experiment, not a CPU-policy substitute.
            outcome["growth_scale_readback"] = read_json("growth-scale.readback.json")
            for name in ["source-before.json", "source-after.json", "build-artifact-check.json", "build-command.json",
                         "growth-scale.readback.json", "binary-before.sha256", "binary-after.sha256"]:
                outcome["member_sha256"][name] = digest(archive.read(name))
            outcome["build_command"] = read_json("build-command.json")
            outcome["binary_before_equals_after"] = archive.read("binary-before.sha256") == archive.read("binary-after.sha256")
            assert outcome["binary_before_equals_after"]
            outcomes.append(outcome)
    result = {"schema": "bebb-original-workspace-cpu-outcomes-v1", "head": HEAD, "tree": TREE,
              "actual_merge": MERGE, "run_id": 41658914609,
              "scope": "Four exact-source original workspace test-profile CPU selector executions; all failures retained. Stage spans are nested and are not summed. Outer dispatch Ok means a MeteredWorkFactOutcome was returned; its separate native result may be Err. Original CPU tail settlement follows the native outcome and does not rewrite it. A null active-state-refusal readback is unknown, not proof of unchanged state. Growth-scale results are separate denominators.",
              "outcomes": outcomes, "host_qualified": False, "production_activation": False}
    target = ROOT / "bebb-original-cpu-outcomes.json"
    target.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"path": str(target), "bytes": target.stat().st_size,
                      "sha256": digest(target.read_bytes())}))
    for lane in outcomes:
        for selector in lane["selectors"]:
            for row in selector["executions"]:
                receipt = row["native_receipt"]
                stage = row["stage_delta"]
                print(json.dumps({"arch": lane["arch"], "kind": lane["source_kind"],
                                  "selector": selector["selector"], "authenticated": row["authenticated_backend"],
                                  "native_result": receipt["native_result"],
                                  "cpu_ns": receipt["original_cpu_receipt"]["total_cpu_ns"],
                                  "commitment": stage.get("complete_commitment"),
                                  "root": stage.get("complete_state_root"),
                                  "root_counters": row["root_arithmetic_counter_delta"],
                                  "retained": row["root_arithmetic_after"]["retained_material"]}))


if __name__ == "__main__":
    main()
